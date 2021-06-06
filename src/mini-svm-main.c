#include "mini-svm.h"
#include "mini-svm-vmcb.h"
#include "mini-svm-exit-codes.h"
#include "mini-svm-mm.h"
#include "mini-svm-debug.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/context_tracking.h>
#include <asm/io.h>

struct mini_svm_context *global_ctx = NULL;

void hello_world(void *vmcb);

static void mini_svm_setup_ctrl(struct mini_svm_vmcb_control *ctrl) {
	// TODO: don't use memset
	memset(&ctrl->excp_vec_intercepts, 0xFF, sizeof(ctrl->excp_vec_intercepts));
	ctrl->vec3.hlt_intercept = 1;
	ctrl->vec4.vmrun_intercept = 1;
	ctrl->guest_asid = 1;
	ctrl->np_enable = 1;
	ctrl->nRIP = 1;
	ctrl->tlb_control = 0x1;
}

static void mini_svm_setup_save(struct mini_svm_vmcb_save_area *save) {
	save->efer |= EFER_SVME | EFER_LME | EFER_LMA;
	save->rip = 0x202;

	save->cr0 = (0x1U);

	save->reg_cs.base = 0;
	save->reg_cs.limit = -1;
	save->reg_cs.selector = 1<<3;
}

static void mini_svm_handle_exception(const enum MINI_SVM_EXCEPTION excp) {
	printk("Received exception. # = %x. Name: %s\n", (unsigned)excp, translate_mini_svm_exception_number_to_str(excp));
	switch(excp) {
		case MINI_SVM_EXCEPTION_DF:
		{
			break;
		}
	}
}

static void mini_svm_handle_exit(struct mini_svm_context *ctx) {
	struct mini_svm_vmcb *vmcb = ctx->vmcb;
	u64 exitcode = get_exitcode(&vmcb->control);

	// TODO: Doing this through function pointers for the respective handlers is
	// probably better.
	printk("exitcode: %llx. Name: %s\n", exitcode, translate_mini_svm_exitcode_to_str(exitcode));
	if (exitcode >= MINI_SVM_EXITCODE_VMEXIT_EXCP_0 && exitcode <= MINI_SVM_EXITCODE_VMEXIT_EXCP_15) {
		const enum MINI_SVM_EXCEPTION excp =
			(enum MINI_SVM_EXCEPTION)(exitcode - MINI_SVM_EXITCODE_VMEXIT_EXCP_0);
		mini_svm_handle_exception(excp);
	}
}

static int mini_svm_allocate_ctx(struct mini_svm_context **out_ctx) {
	int r = 0;
	struct mini_svm_context *ctx;
	struct mini_svm_vmcb *vmcb = NULL;
	struct mini_svm_mm *mm = NULL;
	unsigned long host_save_va = 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		printk("Failed to allocate ctx\n");
		r = -ENOMEM;
		goto fail;
	}

	vmcb = (struct mini_svm_vmcb *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!vmcb) {
		printk("Failed to allocate vmcb\n");
		r = -ENOMEM;
		goto fail;
	}

	host_save_va = get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!host_save_va) {
		printk("Failed to allocate host_save\n");
		r = -ENOMEM;
		goto fail;
	}

	if (mini_svm_create_mm(&mm)) {
		printk("Failed to allocate mm\n");
		r = -ENOMEM;
		goto fail;
	}

	ctx->host_save_va = host_save_va;
	ctx->vmcb = vmcb;
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

	unsigned long cr3 = 0;
	asm volatile(
		"mov %%cr3, %0"
		: "=r"(cr3)
		:
		:
	);

	printk("host cr3 = %lx\n", cr3);

	mini_svm_dump_vmcb(global_ctx->vmcb);

	hello_world(vmcb_phys);

	mini_svm_dump_vmcb(global_ctx->vmcb);
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

	// Check if already enabled.
	rdmsrl(MSR_EFER, efer);
	if (efer & EFER_SVME) {
		return 0;
	}

	// Enable SVM.
	wrmsrl(MSR_EFER, efer | EFER_SVME);

	// Read efer again and check if truly enabled.
	rdmsrl(MSR_EFER, efer);
	if ((efer & EFER_SVME) == 0) {
		return -EINVAL;
	}

	hsave_pa = virt_to_phys((void *)ctx->host_save_va);
	printk("Use VM_HSAVE_PA: %lx\n", hsave_pa);
	wrmsrl(MSR_VM_HSAVE_PA, hsave_pa);

	rdmsrl(MSR_VM_HSAVE_PA, hsave_pa_read);
	if (hsave_pa_read != hsave_pa) {
		printk("Written hsave value was unexpected\n");
		return -EINVAL;
	}

	return 0;
}

static int mini_svm_init(void) {
	int r;
	size_t i;

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
		void *vm_code_page = get_zeroed_page(GFP_KERNEL_ACCOUNT);
		if (!vm_code_page) {
			printk("Failed to allocate vm page\n");
			return -ENOMEM;
		}

		u16 *vm_code_page_word = (u16 *)vm_code_page;
		for (i = 0; i < 0x1000 / 2; ++i) {
			vm_code_page_word[i] = 0xf4U;
		}
		r = mini_svm_construct_debug_mm_one_page(global_ctx->mm);
		if (r) {
			printk("Failed to allocate vm page table\n");
			return r;
		}

		unsigned char bytes[1] = {0xf4};
		mini_svm_mm_write_phys_memory(global_ctx->mm, 0x202, bytes, sizeof(bytes));

		global_ctx->vmcb->control.ncr3 = global_ctx->mm->pml4.pa;
		mini_svm_setup_ctrl(&global_ctx->vmcb->control);
		mini_svm_setup_save(&global_ctx->vmcb->save);

		run_vm(global_ctx);

		mini_svm_handle_exit(global_ctx);
	}

	printk("svm initialized\n");

	return 0;
}

static void __exit mini_svm_exit(void) {
	printk("SVM exit module\n");
}

module_init(mini_svm_init);
module_exit(mini_svm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Radev");
