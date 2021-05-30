#include "mini-svm.h"
#include "mini-svm-vmcb.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/init.h>

static int mini_svm_init(void) {
	pr_debug("SVM init module\n");
	if (!boot_cpu_has(X86_FEATURE_SVM)) {
		printk("SVM not supported\n");
		return -EINVAL;
	}
	return 0;
}

static void __exit mini_svm_exit(void) {
	pr_debug("SVM exit module\n");
}

module_init(mini_svm_init);
module_exit(mini_svm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Radev");
