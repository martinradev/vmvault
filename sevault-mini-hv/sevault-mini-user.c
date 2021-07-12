#include "sevault-mini-user.h"
#include "sevault-mini.h"
#include "sevault-mini-user-ioctl.h"
#include "sevault-mini-debug.h"

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/io.h>

static int sevault_mini_user_open(struct inode *node, struct file *f) {
	return 0;
}

static int sevault_mini_user_release(struct inode *node, struct file *f) {
	return 0;
}

static long sevault_mini_user_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	return -EINVAL;
}

static const struct file_operations sevault_mini_user_ops = {
	.owner          = THIS_MODULE,
	.release        = sevault_mini_user_release,
	.open           = sevault_mini_user_open,
	.unlocked_ioctl = sevault_mini_user_ioctl,
};

static struct miscdevice sevault_mini_user_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sevault_mini_user",
	.fops = &sevault_mini_user_ops,
};

int sevault_mini_register_user_node(void) {
	int r;

	r = misc_register(&sevault_mini_user_misc);
	if (r) {
		return r;
	}

	return 0;
}

void sevault_mini_deregister_user_node(void) {
	misc_deregister(&sevault_mini_user_misc);
}
