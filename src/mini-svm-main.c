#include "mini-svm.h"
#include "mini-svm-exit-codes.h"
#include "mini-svm-mm.h"
#include "mini-svm-common-structures.h"
#include "mini-svm-debug.h"
#include "mini-svm-user.h"

#include <linux/build_bug.h>
#include "mini-svm-vmcb.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/context_tracking.h>
#include <asm/io.h>

struct mini_svm_context *global_ctx = NULL;

void __mini_svm_run(u64 vmcb_phys, void *regs);

static void mini_svm_setup_ctrl(struct mini_svm_vmcb_control *ctrl) {
	// Necessary to be intercepted.
	ctrl->vec4.vmrun_intercept = 1;
	ctrl->vec4.vmload_intercept = 1;
	ctrl->vec4.vmsave_intercept = 1;

	ctrl->guest_asid = 1;
	ctrl->np_enable = 1;
	ctrl->nRIP = 1;
	ctrl->tlb_control = 0x1;
}

static void mini_svm_run(struct mini_svm_vmcb *vmcb, struct mini_svm_vm_regs *regs) {
	u64 vmcb_phys = virt_to_phys(vmcb);

	// Load the special registers into vmcb from the regs context
	vmcb->save.rip = regs->rip;
	vmcb->save.rax = regs->rax;
	vmcb->save.rsp = regs->rsp;

	__mini_svm_run(vmcb_phys, regs);

	// Save registers from vmcb to the regs context
	regs->rip = vmcb->save.rip;
	regs->rax = vmcb->save.rax;
	regs->rsp = vmcb->save.rsp;
}

static int mini_svm_allocate_ctx(struct mini_svm_context **out_ctx) {
	int r = 0;
	struct mini_svm_context *ctx;
	struct mini_svm_vmcb *vmcb = NULL;
	struct mini_svm_mm *mm = NULL;
	unsigned long host_save_va = 0;
	struct mini_svm_vm_state *vm_state = NULL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		printk("Failed to allocate ctx\n");
		r = -ENOMEM;
		goto fail;
	}

	vmcb = (struct mini_svm_vmcb *)get_zeroed_page(GFP_KERNEL);
	if (!vmcb) {
		printk("Failed to allocate vmcb\n");
		r = -ENOMEM;
		goto fail;
	}

	host_save_va = get_zeroed_page(GFP_KERNEL);
	if (!host_save_va) {
		printk("Failed to allocate host_save\n");
		r = -ENOMEM;
		goto fail;
	}

	vm_state = (struct mini_svm_vm_state *)get_zeroed_page(GFP_KERNEL);
	if (!vm_state) {
		r = -ENOMEM;
		goto fail;
	}

	if (mini_svm_create_mm(&mm)) {
		printk("Failed to allocate mm\n");
		r = -ENOMEM;
		goto fail;
	}

	ctx->vcpu.host_save_va = host_save_va;
	ctx->vcpu.vmcb = vmcb;
	ctx->vcpu.state = vm_state;
	ctx->mm = mm;

	*out_ctx = ctx;

	return 0;

fail:
	if (ctx) {
		kfree(ctx);
	}
	if (mm) {
		mini_svm_destroy_mm(mm);
	}
	if (vm_state) {
		free_page((unsigned long)vm_state);
	}
	if (vmcb) {
		free_page((unsigned long)vmcb);
	}
	if (host_save_va) {
		free_page((unsigned long)host_save_va);
	}
	return r;
}

static void mini_svm_free_ctx(struct mini_svm_context *ctx) {
	free_page((unsigned long)ctx->vcpu.host_save_va);
	free_page((unsigned long)ctx->vcpu.vmcb);
	free_page((unsigned long)ctx->vcpu.state);
	mini_svm_destroy_mm(ctx->mm);
	kfree(ctx);
}

static void run_vm(struct mini_svm_context *ctx) {
#if 0
	mini_svm_dump_vmcb(ctx->vcpu.vmcb);
#endif

	mini_svm_run(ctx->vcpu.vmcb, &ctx->vcpu.state->regs);

#if 0
	mini_svm_dump_vmcb(ctx->vcpu.vmcb);
#endif
}

static int enable_svm(struct mini_svm_context *ctx) {
	u64 efer;
	u64 hsave_pa;
	u64 hsave_pa_read;

	// Check if svm is supported.
	if (!boot_cpu_has(X86_FEATURE_SVM)) {
		printk("SVM not supported\n");
		return -EINVAL;
	}

	// Enable SVM.
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer | EFER_SVME);

	// Read efer again and check if truly enabled.
	rdmsrl(MSR_EFER, efer);
	if ((efer & EFER_SVME) == 0) {
		return -EINVAL;
	}

	hsave_pa = virt_to_phys((void *)ctx->vcpu.host_save_va);
	wrmsrl(MSR_VM_HSAVE_PA, hsave_pa);

	rdmsrl(MSR_VM_HSAVE_PA, hsave_pa_read);
	if (hsave_pa_read != hsave_pa) {
		printk("Written hsave value was unexpected\n");
		return -EINVAL;
	}

	return 0;
}

static atomic_t mini_svm_global_should_run;

void mini_svm_init_and_run(void) {
	run_vm(global_ctx);
}

void mini_svm_resume(void) {
	global_ctx->vcpu.state->regs.rip = global_ctx->vcpu.vmcb->control.nRIP;
	run_vm(global_ctx);
}

void mini_svm_stop(void) {
	atomic_set(&mini_svm_global_should_run, 0);
	mini_svm_destroy_nested_table(global_ctx->mm);
}

static int mini_svm_init(void) {
	int r;

	r = mini_svm_allocate_ctx(&global_ctx);
	if (r) {
		return r;
	}

	r = enable_svm(global_ctx);
	if (r != 0) {
		printk("Enabling svm failed\n");
		return r;
	}

	{
		global_ctx->vcpu.vmcb->control.ncr3 = global_ctx->mm->pml4.pa;
		mini_svm_setup_ctrl(&global_ctx->vcpu.vmcb->control);
	}

	r = mini_svm_register_user_node();
	if (r < 0) {
		printk("Failed to allocate user node\n");
		return r;
	}

	return 0;
}

static void __exit mini_svm_exit(void) {
	u64 efer;

	printk("SVM exit module\n");

	// Disable SVME.
	// Otherwise, KVM would whine.
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer & ~EFER_SVME);

	mini_svm_free_ctx(global_ctx);
	mini_svm_deregister_user_node();
}

module_init(mini_svm_init);
module_exit(mini_svm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Radev");
