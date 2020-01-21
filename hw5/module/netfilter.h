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

#ifndef HOOKS_H
#define HOOKS_H

#define LOOPBACK (16777343)

unsigned int forward_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

unsigned int local_out_hook(unsigned int num, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));


int enforce_proxy(struct tcphdr* tcp_header, struct iphdr* ip_header, struct sk_buff* skb, int is_pre, int src_port, int dst_port, int proxy_port);
#endif /* HOOKS_H */
