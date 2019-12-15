#include "fw.h"
#include "ruler.h"
#include "logging.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/fcntl.h>

//netfilter API

MODULE_LICENSE("GPL");
struct file_operations fops = {
	.owner = THIS_MODULE,
	.read  = log_read,
	.open = log_open
};

static struct file_operations logps = {
	.owner = THIS_MODULE,
	.open = log_open,
	.read = log_read
};

struct nf_hook_ops fo_ops;
int major_number;
int log_major_number;
unsigned int loopback = 16777343;
struct class* fw_class = NULL;
struct class* log_class = NULL;

struct device* rule_dev = NULL;
struct device* log_dev = NULL;
struct device* reset_dev = NULL;

unsigned int forward_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	//get IP layer header
	struct iphdr *ip_header = (struct iphdr*)skb_network_header(skb);
	if(ip_header == NULL){
		printk("[firewall] error in parsing packer");
		return NF_DROP;
	}
	unsigned int src_ip = ip_header -> saddr;
	unsigned int dst_ip = ip_header -> daddr;
	int src_port = PORT_ANY;
	int dst_port = PORT_ANY;
	int ack = ACK_ANY;
	direction_t direction;
	log_piece* p;
	unsigned char protocol = ip_header -> protocol;
	if(compare_ip(src_ip, loopback, 8) || compare_ip(dst_ip, loopback, 8)){ //loopback packets
		return NF_ACCEPT;
	}
	if(ip_header-> protocol == PROT_UDP){ // UDP packet
		struct udphdr *udp_header = (struct udphdr*) skb_transport_header(skb);
		if(udp_header == NULL){
			printk("[firewall] error in parsing UDP");
			return NF_DROP;
		}
		src_port = ntohs(udp_header -> source);
                dst_port = ntohs(udp_header -> dest);

	}
	if(ip_header-> protocol == PROT_TCP){ //TCP packet
		struct tcphdr *tcp_header = tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		if(tcp_header == NULL){
			printk("[firewall] error in parsing TCP");
		}
                src_port = ntohs(tcp_header -> source);
                dst_port = ntohs(tcp_header -> dest);
		ack = tcp_header -> ack;//ntohl(tcp_header -> ack);
		if((tcp_header -> psh) && (tcp_header -> urg) && (tcp_header -> fin)){ // XMAS packet
			log_piece* p = create_log(src_ip, dst_ip, src_port, dst_port, PROT_TCP, 0, NF_DROP, REASON_XMAS_PACKET);
			if(p==NULL){
				printk("[firewall][null log piece]");
			}
			add_log(p);
			return NF_DROP;
		}
				
	}
	// find direction
	if(in != NULL && out != NULL){
		if(!(strlen(in -> name) == 4 && strlen(out -> name) == 4)){
			direction = -1;	
		}
		else{
			direction = strncmp(out -> name, "eth2", 4) ? DIRECTION_OUT : strncmp(out -> name, "eth1", 4) ? DIRECTION_IN : -1;
		}
	}
	else{
		// no direction - error. log and drop
		log_piece* p = create_log(src_ip, dst_ip, src_port, dst_port, protocol, num, NF_DROP, REASON_ILLEGAL_VALUE);
		if(p == NULL){
			printk("[firewall] error in create_log-returned NULL");
		}
		add_log(p);
		return NF_DROP;
	}

	if(direction == -1){
		return NF_ACCEPT;
	}
	if(protocol != PROT_TCP && protocol != PROT_ICMP && protocol != PROT_UDP){ // other protocols, ignore
		return NF_ACCEPT;
	}
	// search rule for the packet
	int idx = search_rule(direction, src_ip,dst_ip,src_port,dst_port,protocol,ack);

	if(idx >= 0){ // if rule found
		rule_t* found = get(idx);
		unsigned int ret = found->action; // NF_ACCEPT or NF_DROP
		log_piece* p = create_log(src_ip, dst_ip, src_port, dst_port, protocol, num, found -> action, idx);
		
		if(p == NULL){
			printk("[firewall] error in create_log - returned NULL");
			return ret;
		}
		// log
		add_log(p);
		return ret;
	} 
	//no rule found - DROP
        p = create_log(src_ip, dst_ip, src_port, dst_port, protocol, num, NF_DROP, REASON_NO_MATCHING_RULE);
        if(p == NULL){
		printk("[firewall] error in create_log- returned NULL");
	}
	// log
	add_log(p);
	return NF_DROP;
}

static DEVICE_ATTR(rules, 0666, ruler_display, ruler_modify);
static DEVICE_ATTR(reset, 0222, NULL, log_reset);

static __init int basic_fw_init(void){
        //hook setup
        fo_ops.hook = forward_hook;
	fo_ops.hooknum = NF_INET_FORWARD;
	fo_ops.pf = PF_INET;
        fo_ops.priority = NF_IP_PRI_FIRST;
	
	// reset dev and rules dev setup
	if ((major_number = register_chrdev(0, CLASS_NAME, &fops)) < 0){
		printk("[firewall] major reg' fail");
		return -1;
	}
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if(IS_ERR(fw_class)){
		printk("[firewall] class reg' fail");
		unregister_chrdev(major_number, CLASS_NAME);
		return -1;
	}
	rule_dev = device_create(fw_class, NULL, MKDEV(major_number, MINOR_RULES), NULL,  DEVICE_NAME_RULES);
	if(IS_ERR(rule_dev)){
        	printk("[firewall] rule device reg' fail");
		class_destroy(fw_class);
	        unregister_chrdev(major_number, CLASS_NAME);
		return -1;
        }
        reset_dev = device_create(fw_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);
    	if(IS_ERR(reset_dev)){
		printk("[firewall] reset/log device reg' fail");
                device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(fw_class);
                unregister_chrdev(major_number, CLASS_NAME);
                return -1;
        }
	if(device_create_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr)){
                printk("[firewall] log device file reg' fail");
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
                class_destroy(fw_class);
                unregister_chrdev(major_number, CLASS_NAME);
                return -1;
	}
        if(device_create_file(rule_dev, (const struct device_attribute*)&dev_attr_rules.attr)){
                printk("[firewall] rules device file reg' fail");
		device_remove_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr);
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));

                device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
                class_destroy(fw_class);
                unregister_chrdev(major_number, CLASS_NAME);
                return -1;
        }
	// log dev setup
	log_major_number = register_chrdev(0,CLASS_NAME "_" DEVICE_NAME_LOG, &logps);
	if(log_major_number < 0){
		device_remove_file(rule_dev, (const struct device_attribute*)&dev_attr_rules.attr);
		device_remove_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr);
                device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
                device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
                class_destroy(fw_class);
                unregister_chrdev(major_number, CLASS_NAME);
		return -1;
	}
	log_class = class_create(THIS_MODULE, CLASS_NAME "_" DEVICE_NAME_LOG);
	if(IS_ERR(log_class)){
		unregister_chrdev(log_major_number, CLASS_NAME "_" DEVICE_NAME_LOG);
		printk("[firewall] log class reg' fail");
device_remove_file(rule_dev, (const struct device_attribute*)&dev_attr_rules.attr);
                device_remove_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr);
                device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
                device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
                class_destroy(fw_class);
                unregister_chrdev(major_number, CLASS_NAME);
		return -1;
	}
	
	log_dev = device_create(log_class, NULL, MKDEV(log_major_number, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);	
	if (IS_ERR(log_dev)){
		printk("[firewall] log device reg' fail");
                device_remove_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr);
                device_remove_file(rule_dev, (const struct device_attribute*)&dev_attr_rules.attr);
                device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
                device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
                class_destroy(fw_class);
                unregister_chrdev(major_number, CLASS_NAME);
		class_destroy(log_class);
		unregister_chrdev(major_number, CLASS_NAME "_" DEVICE_NAME_LOG);
		return -1;
	}
	//register the hook
	nf_register_hook(&fo_ops);
	//init DS's
	log_reset(NULL, NULL, NULL, 0);
	printk("[Firewall] Registerd with majors %d and %d", major_number, log_major_number);
	return 0;
	
}

void basic_fw_exit(void){
	//cleanup
	log_reset(NULL, NULL, NULL,0);
	kfree(log_list);
	dec();
	for(int i = 0; i< rule_num; i++){
		kfree(&rule_list[i]);
	}
	// device cleanup
	device_remove_file(rule_dev, (const struct device_attribute*)&dev_attr_rules.attr);
	device_remove_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr);	
	device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
        device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
	class_destroy(fw_class);
	device_destroy(log_class, MKDEV(log_major_number, MINOR_LOG));
	class_destroy(log_class);
	//unregistration
	unregister_chrdev(log_major_number, CLASS_NAME "_" DEVICE_NAME_LOG);
        unregister_chrdev(major_number, CLASS_NAME);
        nf_unregister_hook(&fo_ops);
}

module_init(basic_fw_init);
module_exit(basic_fw_exit);

