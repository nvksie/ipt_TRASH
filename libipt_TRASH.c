/* Shared library add-on to iptables to add customized REJECT support.
 *
 * (C) 2000 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 */
#include <stdio.h>
#include <string.h>
#include <xtables.h>

#include "trash.h"

static void TRASH_help(void)
{
        printf(
"TRASH target options:\n"
" --action      [ accept | continue ]\n"
"		accept this packet or continue matching next rule.");
}

static void TRASH_parse(struct xt_option_call *cb)
{
        struct ipt_trash_info *info = cb->data;
        xtables_option_parse(cb);
        if(info && 0 == strncasecmp("continue", cb->arg, strlen(cb->arg))) {
                info->action = O_CONTINUE;
        }
}

static void TRASH_print(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
        const struct ipt_trash_info *info = (const struct ipt_trash_info *)target->data;
		printf(" action:");
		if (info->action == O_CONTINUE)
				printf("continue");
		else
				printf("accept");
}

static void TRASH_save(const void *ip, const struct xt_entry_target *target)
{
        const struct ipt_trash_info *info = (const struct ipt_trash_info *)target->data;
		printf(" --action");
		if (info->action == O_CONTINUE)
				printf(" continue");
		else
				printf(" accept");
}

static const struct xt_option_entry TRASH_opts[] = {
        {.name = "action", .id = O_CONTINUE, .type = XTTYPE_STRING},
        XTOPT_TABLEEND,
};

static void TRASH_init(struct xt_entry_target *t)
{
        struct ipt_trash_info *info = (struct ipt_trash_info *)t->data;

        /* default */
        info->action = O_ACCEPT;
}

static struct xtables_target reject_tg_reg = {
	.name		= "TRASH",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct ipt_trash_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_trash_info)),
	.help		= TRASH_help,
	.init		= TRASH_init,
	.x6_parse	= TRASH_parse,
	.print		= TRASH_print,
	.save		= TRASH_save,
	.x6_options	= TRASH_opts,
};

void _init(void)
{
	xtables_register_target(&reject_tg_reg);
}
