#include "fw.h"
#include "ruler.h"
#include "logging.h"
#include "conn.h"

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
#include <net/tcp.h>

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
struct class* fw_class 	= NULL;
struct class* log_class = NULL;

int rules_file 	= 0;
int conn_file 	= 0;
int reset_file 	= 0;
int ftp_file 	= 0;

struct device* rule_dev	= NULL;
struct device* log_dev	= NULL;
struct device* reset_dev= NULL;
struct device* conn_dev	= NULL;
struct device* ftp_dev 	= NULL;

static DEVICE_ATTR(rules, 0666, ruler_display, ruler_modify);
static DEVICE_ATTR(reset, 0222, NULL, log_reset);
static DEVICE_ATTR(ftp, 0666, ftp_display, ftp_modify);
static DEVICE_ATTR(conns, 0444, conn_display, NULL);

void clean(void){
	if(!ftp_file)
		device_remove_file(ftp_dev, (const struct device_attribute*)&dev_attr_ftp.attr);
	if(!rules_file)
		device_remove_file(rule_dev, (const struct device_attribute*)&dev_attr_rules.attr);
	if(!reset_file)
		device_remove_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr);
	if(!conn_file)
		device_remove_file(conn_dev, (const struct device_attribute*)&dev_attr_conns.attr);
	
	if(ftp_dev != NULL && !IS_ERR(ftp_dev))
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
	if(rule_dev != NULL && !IS_ERR(rule_dev))
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
	if(reset_dev != NULL && !IS_ERR(reset_dev))
	        device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
	if(log_dev != NULL && !IS_ERR(log_dev))
		 device_destroy(log_class, MKDEV(log_major_number, MINOR_LOG));
	if(conn_dev != NULL && !IS_ERR(conn_dev))
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONN));
	
	if(log_class != NULL && !IS_ERR(log_class))
		class_destroy(log_class);
	if(fw_class != NULL && !IS_ERR(fw_class))
		class_destroy(fw_class);

	if(log_major_number >= 0)
		 unregister_chrdev(log_major_number, CLASS_NAME "_" DEVICE_NAME_LOG);
	if(major_number >= 0)
	 	unregister_chrdev(major_number, CLASS_NAME);
	return;
}

unsigned int forward_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	//get IP layer header
	skb_linearize(skb);
	struct tcphdr* tcp_header =NULL;
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
		tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		if(tcp_header == NULL){
			printk("[firewall] error in parsing TCP");
		}
                src_port = ntohs(tcp_header -> source);
                dst_port = ntohs(tcp_header -> dest);
		ack = tcp_header -> ack; //ntohl(tcp_header -> ack);
		if((tcp_header -> psh) && (tcp_header -> urg) && (tcp_header -> fin)){ // XMAS packet
			log_piece* p = create_log(src_ip, dst_ip, src_port, dst_port, PROT_TCP, 0, NF_DROP, REASON_XMAS_PACKET);
			if(p == NULL){
				printk("[firewall][null log piece]");
			}
			add_log(p);
			return NF_DROP;
		}
	}
	// find direction
	if(in != NULL){ //&& out != NULL){ // for change to pre routing
		if(!(strlen(in -> name) == 4)){// && strlen(out -> name) == 4)){
			direction = -1;	
		}
		else{
			direction = !strncmp(in -> name, "eth1", 4) ? DIRECTION_OUT : !strncmp(in -> name, "eth2", 4) ? DIRECTION_IN : -1;
			 // changed by the move to pre routing
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

	int is_ftp20 = 0;
	if(ack == 0 && protocol ==  PROT_TCP){
		int syn = tcp_header -> syn;
		int fin = tcp_header -> fin;
		int rst = tcp_header -> rst;
		is_ftp20 = is_matching(src_ip, src_port, dst_ip, dst_port, syn, fin, rst, get_ftp20());
	}
	// search rule for the packet
	if((ack == 0 &&	is_ftp20 == 0) || protocol != PROT_TCP){
		
		printk("[firewall] rulestable \n");
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
			printk("[firewall] static rule check\n");
			if(ret == NF_ACCEPT){
				add_new_connection(src_ip, src_port, dst_ip, dst_port, SYN_SENT);
				add_new_connection(dst_ip, dst_port, src_ip, src_port, SYN_RCVD);
			}
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
	else{ // (TCP, ack == 1 )=> check conn_table
		printk("[firewall] conn table \n");
		int syn = tcp_header -> syn;
                int fin = tcp_header -> fin;
                int rst = tcp_header -> rst;
                unsigned int ret = tcp_enforce(src_ip, src_port, dst_ip, dst_port, syn, ack, fin, rst);
		if(!tcp_header)
			return ret;
		if(tcp_header -> dest == htons(80) || tcp_header -> dest == htons(21)){
			//changing of routing
			ip_header->daddr = direction == DIRECTION_IN ? MY_IP_IN : MY_IP_OUT; //change to my ip
			tcp_header->dest = (tcp_header->dest == htons(80) ?
			 HTTP_PROXY_PORT : FTP_PROXY_PORT); // to proxy port
			//here start the fix of checksum for both IP and TCP
			int tcplen = (skb->len - ((ip_header->ihl )<< 2));
			tcp_header -> check = 0;
			tcp_header -> check = tcp_v4_check(tcplen, ip_header->saddr, ip_header -> daddr, csum_partial((char*)tcp_header, tcplen, 0));
			skb->ip_summed = CHECKSUM_NONE; //stop offloading
			ip_header->check = 0;
			ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
			return ret;
		}
		else{
			return ret;
		}
	}	
}

static __init int basic_fw_init(void){
        //hook setup
        fo_ops.hook = forward_hook;
	fo_ops.hooknum = NF_INET_FORWARD;
	fo_ops.pf = PF_INET;
        fo_ops.priority = NF_IP_PRI_FIRST;
	// reset dev, rules dev, log dev and conn dev setup
	if ((major_number = register_chrdev(0, CLASS_NAME, &fops)) < 0){
		clean();
		printk("[firewall] major reg' fail");
		return -1;
	}
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if(IS_ERR(fw_class)){
		printk("[firewall] class reg' fail");
		clean();
		return -1;
	}
	rule_dev = device_create(fw_class, NULL, MKDEV(major_number, MINOR_RULES), NULL,  DEVICE_NAME_RULES);
	if(IS_ERR(rule_dev)){
        	printk("[firewall] rule device reg' fail");
		clean();
		return -1;
        }
        reset_dev = device_create(fw_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);
    	if(IS_ERR(reset_dev)){
		printk("[firewall] reset/log device reg' fail");
                clean();
		return -1;
        }
	if((reset_file = device_create_file(reset_dev, (const struct device_attribute*)&dev_attr_reset.attr))){
                printk("[firewall] log device file reg' fail");
		clean();
		return -1;
	}
        if((rules_file = device_create_file(rule_dev, (const struct device_attribute*)&dev_attr_rules.attr))){
                printk("[firewall] rules device file reg' fail");
                clean();
		return -1;
        }
	// log dev setup
	log_major_number = register_chrdev(0,CLASS_NAME "_" DEVICE_NAME_LOG, &logps);
	if(log_major_number < 0){
		clean();
		return -1;
	}
	log_class = class_create(THIS_MODULE, CLASS_NAME "_" DEVICE_NAME_LOG);
	if(IS_ERR(log_class)){
		printk("[firewall] log class reg' fail");
		clean();
		return -1;
	}
	
	log_dev = device_create(log_class, NULL, MKDEV(log_major_number, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);	
	if (IS_ERR(log_dev)){
		printk("[firewall] log device reg' fail");
		clean();
		return -1;
	}
	conn_dev = device_create(fw_class, NULL, MKDEV(major_number, MINOR_CONN), NULL, CONN_NAME);
	if(IS_ERR(conn_dev)){
                printk("[firewall] conn device reg' fail\n");
                clean();
		return -1;
        }
	if((conn_file = device_create_file(conn_dev, (const struct device_attribute*)&dev_attr_conns.attr))){
                printk("[firewall] conn device file reg' fail\n");
                clean();
		return -1;
        }
	ftp_dev = device_create(fw_class, NULL, MKDEV(major_number, MINOR_FTP), NULL, DEVICE_NAME_FTP);
	if(IS_ERR(conn_dev)){
		clean();
                printk("[firewall] ftp device reg' fail\n");
		return -1;
	}
	if((ftp_file = device_create_file(ftp_dev, (const struct device_attribute*)&dev_attr_ftp.attr))){
                printk("[firewall] ftp device file reg' fail\n");
                clean();
                return -1;
        }

	//register the hook
	conn_setup();
	add_new_connection(0,0,0,0,SYN_RCVD);
	add_new_connection(0,0,0,0,SYN_SENT);
	nf_register_hook(&fo_ops);
	//init DS's
	log_reset(NULL, NULL, NULL, 0);
	printk("[Firewall] Registerd with majors %d and %d", major_number, log_major_number);
	return 0;
	
}

void basic_fw_exit(void){
	//cleanup
	conn_clear();
	log_reset(NULL, NULL, NULL,0);
	kfree(log_list);
	dec();
	for(int i = 0; i< rule_num; i++){
		kfree(&rule_list[i]);
	}
	clean();
	nf_unregister_hook(&fo_ops);
	return;
}

module_init(basic_fw_init);
module_exit(basic_fw_exit);
