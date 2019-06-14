/*
 * TCP window modification target for IP tables
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru>
 * (C) 2017 fixes by Vadim Fedorenko <junjunk@fromru.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/checksum.h>

#include <linux/netfilter/x_tables.h>
#include "ipt_TWIN.h"

MODULE_AUTHOR("Harald Welte <laforge@netfilter.org>");
MODULE_AUTHOR("Vadim Fedorenko <junjunk@fromru.com>");
MODULE_DESCRIPTION("Xtables: TCPWIN field modification target");
MODULE_LICENSE("GPL");

static unsigned int
twin_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
        struct tcphdr *tcph;
        struct iphdr *iph;
        const struct ipt_TWIN_info *info = par->targinfo;
        int offset, len;

        if (!skb_make_writable(skb, skb->len))
                return NF_DROP;
        if (skb_linearize(skb))
                return NF_DROP;
        iph = ip_hdr(skb);
        if (iph && (iph->protocol == IPPROTO_TCP))
        {
                offset = iph->ihl << 2;
                tcph = (struct tcphdr*)(skb->data + offset);
                tcph->window = htons(info->win);
                len = skb->len - offset;
                tcph->check = 0;
                tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len, iph->protocol, csum_partial((char*)tcph, len, 0));
                skb->ip_summed = CHECKSUM_UNNECESSARY;
        }
        return XT_CONTINUE;
}

static int twin_tg_check(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target hl_tg_reg[] __read_mostly = {
	{
		.name       = "TCPWIN",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = twin_tg,
		.targetsize = sizeof(struct ipt_TWIN_info),
		.table      = "mangle",
		.checkentry = twin_tg_check,
		.me         = THIS_MODULE,
	},
};

static int __init hl_tg_init(void)
{
	return xt_register_targets(hl_tg_reg, ARRAY_SIZE(hl_tg_reg));
}

static void __exit hl_tg_exit(void)
{
	xt_unregister_targets(hl_tg_reg, ARRAY_SIZE(hl_tg_reg));
}

module_init(hl_tg_init);
module_exit(hl_tg_exit);
MODULE_ALIAS("ipt_TCPWIN");
