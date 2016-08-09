enum trash_action {
        O_ACCEPT = 0,
	O_CONTINUE,
};

struct ipt_trash_info
{
        enum trash_action action;
};
