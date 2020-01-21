#include "fw.h"
#include "ruler.h"
#include "logging.h"
#include "conn.h"
#include "netfilter.h"

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
struct nf_hook_ops lo_ops;

int major_number;
int log_major_number;

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

static __init int basic_fw_init(void){
        //hooks setup
        fo_ops.hook = forward_hook;
	lo_ops.hook = local_out_hook;
	
	fo_ops.hooknum = NF_INET_PRE_ROUTING;
	lo_ops.hooknum = NF_INET_LOCAL_OUT;
	
	fo_ops.pf = PF_INET;
	lo_ops.pf = PF_INET;
        
	fo_ops.priority = NF_IP_PRI_FIRST;
        lo_ops.priority = NF_IP_PRI_FIRST;
	
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
	nf_register_hook(&fo_ops);
	nf_register_hook(&lo_ops);
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
	nf_unregister_hook(&lo_ops);
	return;
}

module_init(basic_fw_init);
module_exit(basic_fw_exit);
