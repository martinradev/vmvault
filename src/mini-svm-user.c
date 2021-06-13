#include "mini-svm-user.h"
#include "mini-svm.h"
#include "mini-svm-user-ioctl.h"

#include <linux/miscdevice.h>
#include <linux/fs.h>

static int mini_svm_user_open(struct inode *node, struct file *f) {
	return 0;
}

static int mini_svm_user_release(struct inode *node, struct file *f) {
	return 0;
}

static long mini_svm_user_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	if (cmd == MINI_SVM_IOCTL_START) {
		mini_svm_init_and_run();
	} else if (cmd == MINI_SVM_IOCTL_STOP) {
		mini_svm_stop();
	} else {
		printk("Invalid cmd: %x\n", cmd);
		return -EINVAL;
	}
	return 0;
}

static const struct file_operations mini_svm_user_ops = {
	.owner          = THIS_MODULE,
	.release        = mini_svm_user_release,
	.open           = mini_svm_user_open,
	.unlocked_ioctl = mini_svm_user_ioctl,
};

static struct miscdevice mini_svm_user_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mini_svm",
	.fops = &mini_svm_user_ops,
};

int mini_svm_register_user_node(void) {
	int r;

	r = misc_register(&mini_svm_user_misc);
	if (r) {
		return r;
	}

	return 0;
}

void mini_svm_deregister_user_node(void) {
	misc_deregister(&mini_svm_user_misc);
}
