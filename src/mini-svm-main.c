#include "mini-svm.h"
#include "mini-svm-vmcb.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <asm/io.h>

struct mini_svm_context *global_ctx = NULL;

void hello_world(void *vmcb);

static int mini_svm_allocate_ctx(struct mini_svm_context **out_ctx) {
	int r = 0;
	struct mini_svm_context *ctx;
	struct mini_svm_vmcb *vmcb = NULL;
	unsigned long host_save_va = 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		pr_debug("Failed to allocate ctx\n");
		r = -ENOMEM;
		goto fail;
	}

	vmcb = (struct mini_svm_vmcb *)get_zeroed_page(GFP_KERNEL);
	if (!vmcb) {
		pr_debug("Failed to allocate vmcb\n");
		r = -ENOMEM;
		goto fail;
	}

	host_save_va = get_zeroed_page(GFP_KERNEL);
	ctx->host_save_va = host_save_va;

	ctx->vmcb = vmcb;

	*out_ctx = ctx;
	return 0;

fail:
	if (ctx) {
		kfree(ctx);
	}
	if (vmcb) {
		free_page((unsigned long)vmcb);
	}
	if (host_save_va) {
		free_page((unsigned long)host_save_va);
	}
	return r;
}

static void run_vm(struct mini_svm_context *ctx) {
	unsigned long vmcb_phys = virt_to_phys(ctx->vmcb);
	printk("hello world: %lx %lx\n", ctx->vmcb, vmcb_phys);
	hello_world(vmcb_phys);
}

static int enable_svm(struct mini_svm_context *ctx) {
	u64 efer;

	// Check if svm is supported.
	if (!boot_cpu_has(X86_FEATURE_SVM)) {
		printk("SVM not supported\n");
		return -EINVAL;
	}

	// Check if already enabled.
	rdmsrl(MSR_EFER, efer);
	if (efer & EFER_SVME) {
		return 0;
	}

	// Enable SVM.
	wrmsrl(MSR_EFER, efer | EFER_SVME);

	wrmsrl(MSR_VM_HSAVE_PA, virt_to_phys((void*)ctx->host_save_va));

	return 0;
}

static int mini_svm_init(void) {
	int r;

	r = mini_svm_allocate_ctx(&global_ctx);
	if (r) {
		return r;
	}

	r = enable_svm(global_ctx);
	if (r != 0) {
		return r;
	}

	// We have to enable SVM and set VM_HSAVE_PA MSR

	run_vm(global_ctx);

	pr_debug("svm initialized\n");

	return 0;
}

static void __exit mini_svm_exit(void) {
	pr_debug("SVM exit module\n");
}

module_init(mini_svm_init);
module_exit(mini_svm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Radev");
