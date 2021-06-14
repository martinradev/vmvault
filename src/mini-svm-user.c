#include "mini-svm-user.h"
#include "mini-svm.h"
#include "mini-svm-user-ioctl.h"

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/io.h>

static int mini_svm_user_open(struct inode *node, struct file *f) {
	return 0;
}

static int mini_svm_user_release(struct inode *node, struct file *f) {
	return 0;
}

int mini_svm_user_mmap_regions(struct file *f, struct vm_area_struct *vma) {
	int r;
	unsigned long vmcb_pfn = (virt_to_phys(global_ctx->vcpu.vmcb) >> 12U);
	unsigned long state_pfn = (virt_to_phys(global_ctx->vcpu.state) >> 12U);

	if ((vma->vm_end - vma->vm_start) != 0x2000UL) {
		return -EINVAL;
	}

	r = remap_pfn_range(vma, vma->vm_start, vmcb_pfn, PAGE_SIZE, vma->vm_page_prot);
	if (r) {
		printk("Failed to map vmcb pfn\n");
		return r;
	}

	r = remap_pfn_range(vma, vma->vm_start + PAGE_SIZE, state_pfn, PAGE_SIZE, vma->vm_page_prot);
	if (r) {
		printk("Failed to map state pfn\n");
		return r;
	}

	return 0;

	// TODO: handle failure
}

static long mini_svm_user_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	long r = 0;
	switch(cmd) {
	case MINI_SVM_IOCTL_START:
		mini_svm_init_and_run();
		break;
	case MINI_SVM_IOCTL_RESUME:
		mini_svm_resume();
		break;
	case MINI_SVM_IOCTL_STOP:
		mini_svm_stop();
		break;
	default:
		printk("Invalid cmd: %x\n", cmd);
		return -EINVAL;
	}
	return r;
}

static const struct file_operations mini_svm_user_ops = {
	.owner          = THIS_MODULE,
	.release        = mini_svm_user_release,
	.open           = mini_svm_user_open,
	.unlocked_ioctl = mini_svm_user_ioctl,
	.mmap           = mini_svm_user_mmap_regions,
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
