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

static void phys_mem_vma_close(struct vm_area_struct *vma) {
	mini_svm_destroy_nested_table(global_ctx->mm);
}

static const struct vm_operations_struct mini_svm_vma_ops = {
	.close = phys_mem_vma_close,
};

static int mini_svm_user_mmap_regions(struct file *f, struct vm_area_struct *vma) {
	int r;
	size_t i;
	const unsigned long vmcb_pfn = (virt_to_phys(global_ctx->vcpu.vmcb) >> 12U);
	const unsigned long state_pfn = (virt_to_phys(global_ctx->vcpu.state) >> 12U);
	const unsigned long cmd = (vma->vm_pgoff << 12);

	vma->vm_pgoff = 0;
	switch (cmd) {
	case MINI_SVM_MMAP_VM_STATE:
		if ((vma->vm_end - vma->vm_start) != PAGE_SIZE) {
			return -EINVAL;
		}
		r = remap_pfn_range(vma, vma->vm_start, state_pfn, PAGE_SIZE, vma->vm_page_prot);
		if (r) {
			printk("Failed to map vmcb pfn\n");
			return r;
		}
		break;
	case MINI_SVM_MMAP_VM_VMCB:
		if ((vma->vm_end - vma->vm_start) != PAGE_SIZE) {
			return -EINVAL;
		}
		r = remap_pfn_range(vma, vma->vm_start, vmcb_pfn, PAGE_SIZE, vma->vm_page_prot);
		if (r) {
			printk("Failed to map vmcb pfn\n");
			return r;
		}
		break;
	case MINI_SVM_MMAP_VM_PHYS_MEM:
		{
			// TODO: Handle failure
			const size_t phys_as_size = (vma->vm_end - vma->vm_start);
			const size_t num_pages = (phys_as_size / PAGE_SIZE);
			if (phys_as_size > MINI_SVM_MAX_PHYS_SIZE) {
				return -ENOMEM;
			}

			// Destroy old stuff.
			if (global_ctx->mm->phys_memory_pages) {
				mini_svm_destroy_nested_table(global_ctx->mm);
			}

			global_ctx->mm->phys_as_size = phys_as_size;
			r = mini_svm_construct_nested_table(global_ctx->mm);
			if (r) {
				return r;
			}
			for (i = 0; i < num_pages; ++i) {
				const u64 page_pfn = page_to_phys(global_ctx->mm->phys_memory_pages[i]) >> 12U;
				r = remap_pfn_range(vma, vma->vm_start + i * PAGE_SIZE, page_pfn, PAGE_SIZE, vma->vm_page_prot);
				if (r) {
					return r;
				}
			}
			global_ctx->vcpu.vmcb->control.ncr3 = global_ctx->mm->pml4.pa;
			vma->vm_ops = &mini_svm_vma_ops;
			break;
		}
	case MINI_SVM_MMAP_VM_PT:
		{

		}
		return -ENOENT;
	default:
		printk("Unknown cmd: %lx\n", cmd);
		return -ENOENT;
	}

	return 0;
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
