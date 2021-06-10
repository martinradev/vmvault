#include "mini-svm.h"
#include "mini-svm-vmcb.h"
#include "mini-svm-exit-codes.h"
#include "mini-svm-mm.h"
#include "mini-svm-debug.h"

#include "vm-program.h"
#include "vm-config.h"

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
	// TODO: don't use memset
	memset(&ctrl->excp_vec_intercepts, 0xFF, sizeof(ctrl->excp_vec_intercepts));
	ctrl->vec3.hlt_intercept = 1;
	ctrl->vec4.vmrun_intercept = 1;
	ctrl->vec4.vmmcall_intercept = 1;
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

static void mini_svm_setup_regs_context(struct mini_svm_vm_regs *regs) {
	// Setup general-purpose guest registers
	regs->rip = VM_CONFIG_RIP;
	regs->rax = VM_CONFIG_RAX;
	regs->rbx = VM_CONFIG_RBX;
	regs->rcx = VM_CONFIG_RCX;
	regs->rdx = VM_CONFIG_RDX;
	regs->rdi = VM_CONFIG_RDI;
	regs->rsi = VM_CONFIG_RSI;
	regs->rbp = VM_CONFIG_RBP;
	regs->rsp = VM_CONFIG_RSP;
	regs->r8 =  VM_CONFIG_R8;
	regs->r9 =  VM_CONFIG_R9;
	regs->r10 = VM_CONFIG_R10;
	regs->r11 = VM_CONFIG_R11;
	regs->r12 = VM_CONFIG_R12;
	regs->r13 = VM_CONFIG_R13;
	regs->r14 = VM_CONFIG_R14;
	regs->r15 = VM_CONFIG_R15;
}

static void mini_svm_setup_save(struct mini_svm_vmcb_save_area *save) {
	// Setup long mode.
	save->efer = EFER_SVME | EFER_LME | EFER_LMA;
	save->cr0 = (X86_CR0_PE | X86_CR0_PG);
	save->cr3 = (0x0U);
	save->cr4 = (X86_CR4_PAE | X86_CR4_PGE);

	// Setup gdt
	save->reg_gdtr.base = 0x0;
	save->reg_gdtr.limit = 0xffff;

	// Setup segments
	save->reg_cs.base = 0x0;
	save->reg_cs.limit = -1;
	save->reg_cs.attribute = 0x029b;
	save->reg_cs.selector = 0x8;

	save->reg_ss.base = 0;
	save->reg_ss.limit = -1;
	save->reg_ss.attribute = 0x0a93;
	save->reg_ss.selector = 0x10;

	memcpy(&save->reg_ds, &save->reg_ss, sizeof(save->reg_ss));
	memcpy(&save->reg_ss, &save->reg_ss, sizeof(save->reg_ss));
	memcpy(&save->reg_fs, &save->reg_ss, sizeof(save->reg_ss));
	memcpy(&save->reg_gs, &save->reg_ss, sizeof(save->reg_ss));
}

static void mini_svm_handle_exception(const enum MINI_SVM_EXCEPTION excp) {
	printk("Received exception. # = %x. Name: %s\n", (unsigned)excp, translate_mini_svm_exception_number_to_str(excp));
}

static void mini_svm_handle_exit(struct mini_svm_context *ctx) {
	struct mini_svm_vmcb *vmcb = ctx->vmcb;
	u64 exitcode = get_exitcode(&vmcb->control);

	// TODO: Doing this through function pointers for the respective handlers is probably better.
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
	mini_svm_dump_vmcb(ctx->vmcb);

	mini_svm_run(ctx->vmcb, &ctx->regs);

	mini_svm_dump_vmcb(ctx->vmcb);
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
		r = mini_svm_construct_debug_mm_one_page(global_ctx->mm);
		if (r) {
			printk("Failed to allocate vm page table\n");
			return r;
		}

		mini_svm_construct_1gb_gpt(global_ctx->mm);

		mini_svm_mm_write_virt_memory(global_ctx->mm, VM_CONFIG_IMAGE_ADDRESS, vm_program, vm_program_len);

		global_ctx->vmcb->control.ncr3 = global_ctx->mm->pml4.pa;
		mini_svm_setup_ctrl(&global_ctx->vmcb->control);
		mini_svm_setup_save(&global_ctx->vmcb->save);
		mini_svm_setup_regs_context(&global_ctx->regs);

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
