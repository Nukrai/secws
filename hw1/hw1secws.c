#include <linux/kernel.h>
#include <linux/module.h>
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

//for in-out packets - we accept
unsigned int in_out_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	printk(KERN_INFO ACC);
	return NF_ACCEPT;
}


//for forward packets - we drop
unsigned int forward_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	printk(KERN_INFO REJ);
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

	return 0;
}


void basic_fw_exit(void){
	nf_unregister_hook(&in_ops);
	nf_unregister_hook(&out_ops);
	nf_unregister_hook(&fo_ops);
}

module_init(basic_fw_init);
module_exit(basic_fw_exit);




