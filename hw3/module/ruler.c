#include "fw.h"
#include "ruler.h"
#include "logging.h"
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
rule_t* get(int idx){ //get rule_list[idx] if present, else NULL
	if(idx >= 0 && idx < rule_num){
		return &rule_list[idx];
	}
	return NULL;
}
// rules device modify (store) function
ssize_t ruler_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
	char*  str = kmalloc(count, GFP_ATOMIC);
	char* free_str = str;
	inc();
	char* l;
	int i = 0;
	rule_num = 0;
	rule_t* r = kcalloc(1, sizeof(rule_t), GFP_ATOMIC);
	inc();
	strncpy(str, buf, count); 
	//run for each line
	while( (l = strsep(&str,"\n")) != NULL && i >= 0){
		//parse arguments
		i = sscanf(l,"%20s %hhu %u %hhu %u %hhu %hhu %hu %hu %hhu %hhu",
		(r -> rule_name),
		(char*)&(r -> direction),
		&(r -> src_ip),
		&(r -> src_prefix_size),
		&(r ->dst_ip),
		&(r -> dst_prefix_size),
		&(r -> protocol),
		&(r->src_port),
		&(r->dst_port),
		(char *)&(r -> ack),	
		&(r -> action));
		if(i < 11 && i >= 0){ // erros
			return count;		
		}
		if(r){ // checking for errors
                	rule_list[rule_num] = (*r);
                	rule_num ++;
		}
		if(rule_num == MAX_RULES || i < 0){ //if more than 50 rules - take the first 50
			break;
		}
	}
	kfree(free_str);
	dec();	
	return count;
}
// rules device display (read) function
ssize_t ruler_display(struct device *dev, struct device_attribute *attr, char *buf){
	char ret[rule_num * MAX_LINE];
	char l[MAX_LINE];
	l[0] = '\0';
	ret[0] = '\0';
	// for each rule
	for(int i = 0; i < rule_num;i++){
		rule_t* r = &rule_list[i];
		//format repr.
		sprintf(l,"%20s %hhu %u %hhu %u %hhu %hhu %hu %hu %hhu %hhu",
		(r -> rule_name),
                (r -> direction),
                (r -> src_ip),
                (r -> src_prefix_size),
                (r ->dst_ip),
                (r -> dst_prefix_size),
		(r -> protocol),
                (r->src_port),
                (r->dst_port),
                (r -> ack),
                (r -> action));
		strcat(ret, l);
		strcat(ret, "\n");
	}
	// copy to supplied buffer
	strncpy(buf, ret, strlen(ret));
	return strlen(ret);
}
// check if the 2 ip's match (when under mask)
int compare_ip(unsigned int ip1, unsigned int ip2, int mask){
	unsigned int real_mask = ~(0xffffffff << mask);
	if(mask == 32){
		real_mask = 0xffffffff;
	}
	//printk("ip1=%x, ip2=%x, mask=%d\n", ip1, ip2, mask);
	int ret = !((ip1 ^ ip2) & real_mask);
	//printk("ret=%d, mask=%u\n", ret, real_mask);
	return ret;
}
// search for rule with these parameters. -1 if not found
int search_rule(int direction, unsigned int src_ip, unsigned int dst_ip, int src_port, int dst_port, int protocol, int ack){
	printk("[search_rule] %x %x\n", src_ip, dst_ip);
	for(int i = 0; i < rule_num;i++){
		if(rule_list[i].direction != direction && rule_list[i].direction != DIRECTION_ANY){
			continue;
		}		
		if(!compare_ip(rule_list[i].src_ip,src_ip,rule_list[i].src_prefix_size) && (rule_list[i].src_ip != 0)){
			continue;
		}
                if(!compare_ip(rule_list[i].dst_ip, dst_ip, rule_list[i].dst_prefix_size) && (rule_list[i].dst_ip != 0)){
                        continue;
                }
		printk("rule src %d dst %d packet src %d dst %d\n", rule_list[i].src_port, rule_list[i].dst_port,src_port,dst_port);
                if((rule_list[i].src_port != src_port) &&
			 (rule_list[i].src_port < 1023 || src_port < 1023) &&
			 (rule_list[i].src_port != PORT_ANY)){
                        continue;
                }
                if((rule_list[i].dst_port != dst_port) &&
			 (rule_list[i].dst_port < 1023 || dst_port < 1023) &&
			 (rule_list[i].dst_port != PORT_ANY)){
                        continue;
                }
                if((rule_list[i].protocol != protocol) && (rule_list[i].protocol != PROT_ANY)){
                        continue;
                }
		printk("[ack is %d]", rule_list[i].ack);
                if(!(rule_list[i].ack & (ack + 1)) && rule_list[i].ack != ACK_ANY && ack != ACK_ANY){ //(rule_list[i].ack != ack) && (rule_list[i].ack != ACK_ANY)){
                        continue;
                }
		return i;
	}
	return -1;

}

