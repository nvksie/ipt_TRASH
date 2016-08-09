/*
 * This is a module which is used for rejecting packets.
 */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#include <linux/netfilter_bridge.h>
#endif

#include "trash.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dyluck <cz@de3eb.cn>");
MODULE_DESCRIPTION("Xtables: packet \"TRASH\" target for IPv4. save port resources under DDoS attack.");

#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr) \
  ((unsigned char *)&addr)[0],                  \
    ((unsigned char *)&addr)[1],                \
    ((unsigned char *)&addr)[2],                \
    ((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr)                            \
  ((unsigned char *)&addr)[3],                  \
    ((unsigned char *)&addr)[2],                \
    ((unsigned char *)&addr)[1],                \
    ((unsigned char *)&addr)[0]
#endif

static unsigned int
trash_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr*)(((void*)iph) + (iph->ihl << 2));

	const struct ipt_trash_info *info = par->targinfo;

	pr_info("%u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", IPQUAD(iph->saddr), ntohs(tcph->source), IPQUAD(iph->daddr), ntohs(tcph->dest));

	//return NF_DROP;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->ack = 0;
	tcph->urg = 0;

	iph->tot_len = htons((iph->ihl << 2) + (tcph->doff << 2));
	
	// updating checksum is not necessary
	//iph->check = 0;
	//tcph->check = 0;

	if (info->action == O_CONTINUE)
		return XT_CONTINUE;
	return NF_ACCEPT;
}

static int trash_tg_check(const struct xt_tgchk_param *par)
{
	const struct ipt_entry *e = par->entryinfo;
	if (e->ip.proto != IPPROTO_TCP ||
		(e->ip.invflags & XT_INV_PROTO)) {
			pr_info("TRASH invalid for non-tcp\n");
			return -EINVAL;
	}
	return 0;
}

static struct xt_target trash_tg_reg __read_mostly = {
	.name		= "TRASH",
	.family		= NFPROTO_IPV4,
	.target		= trash_tg,
	.targetsize	= sizeof(struct ipt_trash_info),
	.table		= "filter",
	.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_LOCAL_OUT),
	.checkentry	= trash_tg_check,
	.me		= THIS_MODULE,
};

static int __init trash_tg_init(void)
{
	return xt_register_target(&trash_tg_reg);
}

static void __exit trash_tg_exit(void)
{
	xt_unregister_target(&trash_tg_reg);
}

module_init(trash_tg_init);
module_exit(trash_tg_exit);
