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



unsigned int local_out_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
 	skb_linearize(skb);
	struct tcphdr* tcp_header = NULL;
	struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
	unsigned int src_ip = ip_header -> saddr;
	unsigned int dst_ip = ip_header -> daddr;
	if(!(ip_header -> protocol == PROT_TCP)){
		return NF_ACCEPT;
	}
	tcp_header = (struct tcphdr *)(skb -> data + ip_header->ihl * 4);
	int src_port = htons(tcp_header -> source);
	int dst_port = htons(tcp_header -> dest);
	int proxy_port = enforce_proxy(tcp_header, ip_header, skb, 0, src_port, dst_port, 2); // change src ip, etc...	
        src_ip = ip_header -> saddr;
        dst_ip = ip_header -> daddr;
	src_port = htons(tcp_header -> source);
	dst_port = htons(tcp_header -> dest);
	int syn =  tcp_header -> syn;
	int ack =  tcp_header -> ack;
	int fin =  tcp_header -> fin;
	int rst =  tcp_header -> rst;
	if(proxy_port > 0){
		update_proxy_port(dst_ip, dst_port, src_ip, 0, proxy_port);
	// reversed because the packet that tells us the proxy port is from the
	// proxy port and when we want to override it, its when we need it as dest port.
	}
	if(tcp_header -> rst){ // if rst we want to close the conns in conn table
		tcp_enforce(src_ip, src_port, dst_ip, dst_port, syn, ack, fin, rst);
	}
	if(ack){ // if last ack in connection
		last_ack_cleanup(dst_ip, dst_port, src_ip, src_port);		
	}
	return NF_ACCEPT;
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
	int syn = 0;
	direction_t direction;
	log_piece* p;
	unsigned char protocol = ip_header -> protocol;
	if(compare_ip(src_ip, LOOPBACK, 8) || compare_ip(dst_ip, LOOPBACK, 8)){ //loopback packets
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
		syn = tcp_header -> syn;
		ack = tcp_header -> ack; 
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
		if( !(strlen(in -> name) == 4)){// && strlen(out -> name) == 4)){
                        //c
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

	int is_ftp20 = 0; // if this port was manually opened by ftp PORT command
	if(syn == 1 && ack == 0 && protocol ==  PROT_TCP){
		syn = tcp_header -> syn;
		int fin = tcp_header -> fin;
		int rst = tcp_header -> rst;
		is_ftp20 = is_matching(src_ip, src_port, dst_ip, dst_port, syn, fin, rst, get_ftp20());
		if(is_ftp20){ // add new connection
			add_new_connection(src_ip, src_port, dst_ip, dst_port, SYN_SENT);	
			add_new_connection(dst_ip, dst_port, src_ip, src_port, SYN_RCVD);
			return NF_ACCEPT;	
		}
	}

	// search rule for the packet if it's syn
	if((syn == 1 && ack == 0 && is_ftp20 == 0) || protocol != PROT_TCP){
		
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
			if(ret == NF_ACCEPT && protocol == PROT_TCP){
				add_new_connection(src_ip, src_port, dst_ip, dst_port, SYN_SENT);
				add_new_connection(dst_ip, dst_port, src_ip, src_port, SYN_RCVD);
				enforce_proxy(tcp_header, ip_header, skb, 1, src_port, dst_port,
                                get_proxy_port(src_ip, src_port, dst_ip, dst_port));
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
		int syn = tcp_header -> syn;
                int fin = tcp_header -> fin;
                int rst = tcp_header -> rst;
                unsigned int ret = tcp_enforce(src_ip, src_port, dst_ip, dst_port, syn, ack, fin, rst);
		if(ret == NF_ACCEPT){ // if accepted - we may need proxy stuff
			enforce_proxy(tcp_header, ip_header, skb, 1, src_port, dst_port,
				get_proxy_port(src_ip, src_port, dst_ip, dst_port));
		}
		return ret;
	}	
}

// do the proxy stuff
int enforce_proxy(struct tcphdr* tcp_header, struct iphdr* ip_header, struct sk_buff* skb, int is_pre, int src_port, int dst_port, int proxy_port){

	if(!tcp_header)
		return -1;
	if(is_pre == 1){
		if(dst_port == (80) || dst_port == (21)){ // I hijack packet to server to my proxy
			//changing of routing
			ip_header->daddr = MY_IP_IN;//change to my ip
			tcp_header->dest = ntohs((tcp_header->dest == htons(80) ?
			 HTTP_PROXY_PORT : FTP_PROXY_PORT)); // to proxy port
			//here start the fix of checksum for both IP and TCP
			int tcplen = (skb->len - ((ip_header->ihl) << 2));
			tcp_header -> check = 0;
			tcp_header -> check = tcp_v4_check(tcplen, ip_header->saddr, ip_header -> daddr, csum_partial((char*)tcp_header, tcplen, 0));
			skb->ip_summed = CHECKSUM_NONE; //stop offloading
			ip_header->check = 0;
			ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
			return -1;
		}
		if(src_port == (80) || src_port  == (21)){ // I take response that should go to host1 to my proxy
       		    //changing of routing

			ip_header->daddr = MY_IP_OUT; //change to my ip
			//here start the fix of checksum for both IP and TCP
			int tcplen = (skb->len - ((ip_header->ihl) << 2));
			tcp_header -> check = 0;
	                tcp_header -> check = tcp_v4_check(tcplen, ip_header->saddr, ip_header -> daddr, csum_partial((char*)tcp_header, tcplen, 0));
			skb->ip_summed = CHECKSUM_NONE; //stop offloading
			ip_header->check = 0;
			ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
	                return -1;
		}
	}
	else{
		if(dst_port == (80) || dst_port == (21)){// i send to server- need to look like client
	                    //changing of routing
			int ret = ntohs(tcp_header -> source); 
                        ip_header->saddr = HOST1_IP; //change to client ip
                        //here start the fix of checksum for both IP and TCP
                        int tcplen = (skb->len - ((ip_header->ihl) << 2));
                        tcp_header -> check = 0;
                        tcp_header -> check = tcp_v4_check(tcplen, ip_header->saddr, ip_header -> daddr, csum_partial((char*)tcp_header, tcplen, 0));
                        skb->ip_summed = CHECKSUM_NONE; //stop offloading
                        ip_header->check = 0;
                        ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
			return src_port;
                }
		if(src_port == HTTP_PROXY_PORT || src_port == FTP_PROXY_PORT){ /// i send to client - need to look like server
                            //changing of routing
                        ip_header->saddr = HOST2_IP; //change to client ip
			tcp_header->source = ntohs((src_port == HTTP_PROXY_PORT ? 80 : 21)); // to source port
                        //here start the fix of checksum for both IP and TCP
                        int tcplen = (skb->len - ((ip_header->ihl) << 2));
                        tcp_header -> check = 0;
                        tcp_header -> check = tcp_v4_check(tcplen, ip_header->saddr, ip_header -> daddr, csum_partial((char*)tcp_header, tcplen, 0));
                        skb->ip_summed = CHECKSUM_NONE; //stop offloading
                        ip_header->check = 0;
                        ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
                        return -1;
                }

	}
	return -1;
}
	

