#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
//general perpuse includes

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
//netfilter API
#define ACC "*** Packet Accepted ***"
#define REJ "*** Packet Dropped ***"

MODULE_LICENSE("GPL");

struct nf_hook_ops fo_ops;
struct nf_hook_ops in_ops;
struct nf_hook_ops out_ops;
int acc_count = 0;
int drop_count = 0;

//start of sysfs code from moodle

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u,%u,%u\n", acc_count, drop_count, acc_count + drop_count);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int tmp;
	if (sscanf(buf, "%u", &tmp) == 1 && tmp == 0)
		acc_count = 0;
		drop_count = 0;
	return count;	
}

static DEVICE_ATTR(sysfs_att, S_IRWXO , display, modify);

 int sysfs_init(void){
	//create char device
	major_number = register_chrdev(0, "Sysfs_Device", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "Sysfs_class");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "sysfs_class" "_" "sysfs_Device");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	return 0;
}

void sysfs_exit(void){
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "Sysfs_Device");
}

//end of sysfs code


//for in-out packets - we accept
unsigned int in_out_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	printk(KERN_INFO ACC);
	acc_count++;
	return NF_ACCEPT;
}


//for forward packets - we drop
unsigned int forward_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	printk(KERN_INFO REJ);
	drop_count++;
	return NF_DROP;
}


int basic_fw_init(void){
	//setup
	in_ops.hook = in_out_hook;
	out_ops.hook = in_out_hook;
	fo_ops.hook = forward_hook;	

	in_ops.hooknum = NF_INET_LOCAL_IN;
	out_ops.hooknum = NF_INET_LOCAL_OUT;
	fo_ops.hooknum = NF_INET_FORWARD;
	
	in_ops.pf = PF_INET;
	out_ops.pf = PF_INET;
	fo_ops.pf = PF_INET;

	in_ops.priority = NF_IP_PRI_FIRST;
	out_ops.priority = NF_IP_PRI_FIRST;
	fo_ops.priority = NF_IP_PRI_FIRST;
	//register
	nf_register_hook(&in_ops);
	nf_register_hook(&out_ops);
	nf_register_hook(&fo_ops);
		
	return sysfs_init();
}


void basic_fw_exit(void){
	nf_unregister_hook(&in_ops);
	nf_unregister_hook(&out_ops);
	nf_unregister_hook(&fo_ops);
	sysfs_exit(); 
}

module_init(basic_fw_init);
module_exit(basic_fw_exit);




