/* Shared library add-on to iptables for the TCP window target
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <xtables.h>
#include "../kernel/ipt_TWIN.h"

static const struct xt_option_entry TWIN_opts[] = {
	{.name = "tcpwin-set", .type = XTTYPE_UINT16, .id = 1,
	 .excl = 0, .flags = XTOPT_PUT, XTOPT_POINTER(struct ipt_TWIN_info, win)},
	XTOPT_TABLEEND,
};

static void TWIN_help(void)
{
	printf("TCP window target options\n"
		"  --tcpwin-set value		Set TCP window to <value 0-65535>\n");
}

static void TWIN_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
}

static void TWIN_check(struct xt_fcheck_call *cb)
{
}

static void TWIN_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_TWIN_info *info = 
		(struct ipt_TWIN_info *) target->data;
	printf(" --tcpwin-set %u", info->win);
}

static void TWIN_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	const struct ipt_TWIN_info *info =
		(struct ipt_TWIN_info *) target->data;
	printf(" TCP window set to %u", info->win);
}

static struct xtables_target twin_tg_reg = {
	.name		= "TCPWIN",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct ipt_TWIN_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_TWIN_info)),
	.help		= TWIN_help,
	.print		= TWIN_print,
	.save		= TWIN_save,
	.x6_parse	= TWIN_parse,
	.x6_fcheck	= TWIN_check,
	.x6_options	= TWIN_opts,
};

void _init(void)
{
	xtables_register_target(&twin_tg_reg);
}
