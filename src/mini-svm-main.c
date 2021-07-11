#include "mini-svm.h"
#include "mini-svm-exit-codes.h"
#include "mini-svm-mm.h"
#include "mini-svm-debug.h"
#include "mini-svm-user.h"
#include "mini-svm-crypto.h"
#include "vm-program.h"

#include <linux/build_bug.h>
#include "mini-svm-vmcb.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/context_tracking.h>
#include <asm/io.h>
#include <asm/string.h>

// FIXME
#include "../uapi/mini-svm-communication-block.h"

static cpumask_var_t svm_enabled;

struct mini_svm_context *global_ctx = NULL;

#define IMAGE_START 0x8000UL
#define CR0_PE (1UL << 0U)
#define CR0_ET (1UL << 4U)
#define CR0_ET (1UL << 4U)
#define CR0_NW (1UL << 29U)
#define CR0_CD (1UL << 30U)
#define CR0_PG (1UL << 31U)
#define CR4_PAE (1UL << 5U)
#define CR4_PGE (1UL << 7U)
#define CR4_OSFXSR (1UL << 9U)
#define CR4_OSXMMEXCPT (1UL << 10U)

void __mini_svm_run(u64 vmcb_phys, void *regs);

int mini_svm_intercept_vmmcall(const MiniSvmCommunicationBlock *commBlock, const struct mini_svm_vm_state *state) {
	const unsigned long cmd = state->regs.rax;
	const unsigned long arg1 = state->regs.rdi;
	const unsigned long arg2 = state->regs.rsi;
	const unsigned long arg3 = state->regs.rdx;

	if ((VmmCall)cmd == VmmCall_DebugPrint) {
		printk("VM send debug msg: %s\n", getDebugMessage(commBlock));
		printk("args: %lx %lx %lx\n", arg1, arg2, arg3);
	}

	return 0;
}

static int mini_svm_intercept_npf(struct mini_svm_vmcb *vmcb, struct mini_svm_vm_state *state) {
	__u64 fault_phys_address = vmcb->control.exitinfo_v2;
	printk("Received NPF at phys addr: 0x%llx\n", vmcb->control.exitinfo_v2);
	dump_regs(state);
	if (fault_phys_address >= MINI_SVM_MAX_PHYS_SIZE) {
		return 1;
	}
	return 1;
}

static void mini_svm_handle_exception(const enum MINI_SVM_EXCEPTION excp, const struct mini_svm_vm_state *state) {
	printk("Received exception. # = %x. Name: %s\n", (unsigned)excp, translate_mini_svm_exception_number_to_str(excp));
	dump_regs(state);
}

static int mini_svm_handle_exit(struct mini_svm_vcpu *vcpu) {
	const MiniSvmCommunicationBlock *commBlock = vcpu->commBlock;
	struct mini_svm_vmcb *vmcb = vcpu->vmcb;
	struct mini_svm_vm_state *state = vcpu->state;
	__u64 exitcode = get_exitcode(&vmcb->control);
	int should_exit = 0;

	printk("Exitcode: %s\n", translate_mini_svm_exitcode_to_str((enum MINI_SVM_EXITCODE)exitcode));
	//dump_regs(state);

	// TODO: Doing this through function pointers for the respective handlers is probably better.
	switch((enum MINI_SVM_EXITCODE)exitcode) {
		case MINI_SVM_EXITCODE_VMEXIT_EXCP_0 ... MINI_SVM_EXITCODE_VMEXIT_EXCP_15:
			mini_svm_handle_exception((enum MINI_SVM_EXCEPTION)(exitcode - MINI_SVM_EXITCODE_VMEXIT_EXCP_0), state);
		case MINI_SVM_EXITCODE_VMEXIT_INVALID:
		case MINI_SVM_EXITCODE_VMEXIT_HLT:
		case MINI_SVM_EXITCODE_VMEXIT_SHUTDOWN:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_NPF:
			should_exit = mini_svm_intercept_npf(vmcb, state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_VMMCALL:
			should_exit = mini_svm_intercept_vmmcall(commBlock, state);
			break;
		default:
			printk("Unkown exit code\n");
			should_exit = 1;
			break;
	}

	return should_exit;
}

static void mini_svm_setup_regs(struct mini_svm_vm_regs *regs, unsigned int vcpu_id) {
	regs->rip = IMAGE_START;
	regs->rsp = IMAGE_START - 0x8;
	regs->rax = 0;
	regs->rbx = 0;
	regs->rcx = 0;
	regs->rdx = 0;

	// The VM expects to receive the vcpu id as the first parameter (rdi)
	regs->rdi = vcpu_id;

	regs->rsi = 0;
	regs->rbp = 0;
	regs->r8 = 0;
	regs->r9 = 0;
	regs->r10 = 0;
	regs->r11 = 0;
	regs->r12 = 0;
	regs->r13 = 0;
	regs->r14 = 0;
	regs->r15 = 0;
}

static void dump_communication_block(const MiniSvmCommunicationBlock *block) {
#define p(X) \
	printk("%s: %x\n", #X, (unsigned)(X))
	p(block->result);
	p(block->operationType);
	p(block->cipherType);
	p(block->sourceHpa);
	p(block->destinationHpa);
#undef p
}

static void mini_svm_setup_vmcb(struct mini_svm_vmcb *vmcb, u64 ncr3) {
	struct mini_svm_vmcb_save_area *save = &vmcb->save;
	struct mini_svm_vmcb_control *ctrl = &vmcb->control;
	memset(&ctrl->excp_vec_intercepts, 0xFF, sizeof(ctrl->excp_vec_intercepts));
	ctrl->vec3.hlt_intercept = 1;
	ctrl->vec4.vmrun_intercept = 1;
	ctrl->vec4.vmmcall_intercept = 1;
	ctrl->vec4.vmload_intercept = 1;
	ctrl->vec4.vmsave_intercept = 1;
	ctrl->tlb_control = 1;
	ctrl->guest_asid = 1;
	ctrl->np_enable = 1;
	ctrl->tlb_control = 1;
	ctrl->ncr3 = ncr3;

	// Setup long mode.
	save->efer = EFER_SVME | EFER_LME | EFER_LMA;
	save->cr0 = (CR0_PE | CR0_PG);
	save->cr3 = 0x0;
	save->cr4 = (CR4_PAE | CR4_PGE | CR4_OSXMMEXCPT | CR4_OSFXSR);

	// Setup gdt
	save->reg_gdtr.base = 0x0;
	save->reg_gdtr.limit = -1;

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

	// Every index is cacheable.
	save->g_pat = 0x0606060606060606ULL;
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

static void enable_svm(struct mini_svm_vcpu *vcpu) {
	u64 hsave_pa;
	u64 hsave_pa_read;
	u64 efer;

	// Enable SVM.
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer | EFER_SVME);

	hsave_pa = virt_to_phys((void *)vcpu->host_save_va);
	wrmsrl(MSR_VM_HSAVE_PA, hsave_pa);
}

static void run_vm(struct mini_svm_vcpu *vcpu) {
#if 0
	mini_svm_dump_vmcb(ctx->vcpu.vmcb);
#endif
	const int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, svm_enabled)) {
		enable_svm(vcpu);
		cpumask_set_cpu(cpu, svm_enabled);
	}

	mini_svm_run(vcpu->vmcb, &vcpu->state->regs);

#if 0
	mini_svm_dump_vmcb(ctx->vcpu.vmcb);
#endif
}

static int mini_svm_init_and_run(void) {
	unsigned int cpu_index;
	struct mini_svm_vcpu *vcpu;
	int r;

	// Load image.
	mini_svm_mm_write_phys_memory(global_ctx->mm, IMAGE_START, __vm_program, __vm_program_len);

	cpu_index = get_cpu();
	vcpu = &global_ctx->vcpus[cpu_index];

	setOperationType(vcpu->commBlock, MiniSvmOperation_Init);
	run_vm(vcpu);

	put_cpu();

	r = mini_svm_handle_exit(vcpu);
	if (r < 0) {
		return r;
	}

	if (getResult(vcpu->commBlock) != MiniSvmReturnResult_Ok) {
		return -EFAULT;
	}

	return 0;
}

static void mini_svm_resume(struct mini_svm_vcpu *vcpu) {
	vcpu->state->regs.rip = vcpu->vmcb->control.nRIP;
	run_vm(vcpu);
}

MiniSvmReturnResult checkResult(MiniSvmCommunicationBlock *commBlock) {
	const MiniSvmReturnResult result = getResult(commBlock);
	const bool failed = result != MiniSvmReturnResult_Ok;
	if (failed) {
		printk("Return result was not ok\n");
	}
	if (buildFlavor == MiniSvmBuildFlavor_Debug) {
		printk("Debug message: %s\n", getDebugMessage(commBlock));
		clearDebugMessage(commBlock);
	}
	return result;
}

MiniSvmReturnResult registerContext(
	const uint64_t array,
	size_t size,
	const uint64_t iv,
	size_t ivSize,
	uint16_t *keyId) {
	MiniSvmReturnResult result;

	const unsigned cpu_id = get_cpu();

	struct mini_svm_vcpu *vcpu = &global_ctx->vcpus[cpu_id];
	MiniSvmCommunicationBlock *commBlock = vcpu->commBlock;
	setOperationType(commBlock, MiniSvmOperation_RegisterContext);
	setSourceHpa(commBlock, array);
	setSourceSize(commBlock, size);
	setIv(commBlock, iv, ivSize);

	// TODO
	mini_svm_resume(vcpu);
	if (mini_svm_handle_exit(vcpu)) {
		printk("Svm exitted with a weird error\n");
		// TODO
		result = MiniSvmReturnResult_Fail;
		goto exit;
	}
	result = checkResult(commBlock);

	if (result == MiniSvmReturnResult_Ok) {
		*keyId = getContextId(commBlock);
	}

exit:
	put_cpu();

	return result;
}

MiniSvmReturnResult removeContext(uint16_t contextId) {

	const unsigned cpu_id = get_cpu();
	struct mini_svm_vcpu *vcpu = &global_ctx->vcpus[cpu_id];

	MiniSvmReturnResult result;
	MiniSvmCommunicationBlock *commBlock = vcpu->commBlock;
	setOperationType(commBlock, MiniSvmOperation_RemoveContext);
	setContextId(commBlock, contextId);

	mini_svm_resume(vcpu);
	if (mini_svm_handle_exit(vcpu)) {
		printk("Svm exitted with a weird error\n");
		// TODO
		result = MiniSvmReturnResult_Fail;
		goto exit;
	}

	result = checkResult(commBlock);

exit:
	put_cpu();
	return result;
}

static MiniSvmReturnResult performEncDecOp(uint16_t keyId, MiniSvmCipher cipherType, MiniSvmOperation opType, MiniSvmSgList *sgList) {
	size_t i;
	MiniSvmReturnResult result;
	const unsigned cpu_id = get_cpu();
	struct mini_svm_vcpu *vcpu = &global_ctx->vcpus[cpu_id];
	MiniSvmCommunicationBlock *commBlock = vcpu->commBlock;
	setOperationType(commBlock, opType);
	clearSgList(&commBlock->opSgList);
	for (i = 0; i < sgList->numRanges; ++i) {
		MiniSvmDataRange *entry = &sgList->ranges[i];
		if (!addSgListEntry(&commBlock->opSgList, entry->srcPhysAddr, entry->dstPhysAddr, entry->length)) {
			return MiniSvmReturnResult_Fail;
		}
	}
	setCipherType(commBlock, cipherType);

	mini_svm_resume(vcpu);
	if (mini_svm_handle_exit(vcpu)) {
		printk("Svm exitted with a weird error\n");
		// TODO
		result = MiniSvmReturnResult_Fail;
		goto exit;
	}

	result = checkResult(commBlock);

exit:
	put_cpu();
	return result;
}

static MiniSvmReturnResult performEncDecOpSingleSgEntry(uint16_t keyId, MiniSvmCipher cipherType, MiniSvmOperation opType, const uint64_t input, size_t size, uint64_t output) {
	MiniSvmSgList sgList;
	sgList.numRanges = 1;
	sgList.ranges[0].srcPhysAddr = input;
	sgList.ranges[0].dstPhysAddr = output;
	sgList.ranges[0].length = size;
	return performEncDecOp(keyId, cipherType, opType, &sgList);
}

MiniSvmReturnResult encryptDataSingleSgEntry(uint16_t keyId, MiniSvmCipher cipherType, const uint64_t input, size_t size, uint64_t output) {
	return performEncDecOpSingleSgEntry(keyId, cipherType, MiniSvmOperation_EncryptData, input, size, output);
}

MiniSvmReturnResult decryptDataSingleSgEntry(uint16_t keyId, MiniSvmCipher cipherType, const uint64_t input, size_t size, uint64_t output) {
	return performEncDecOpSingleSgEntry(keyId, cipherType, MiniSvmOperation_DecryptData, input, size, output);
}

MiniSvmReturnResult encryptData(uint16_t keyId, MiniSvmCipher cipherType, MiniSvmSgList *sgList) {
	return performEncDecOp(keyId, cipherType, MiniSvmOperation_EncryptData, sgList);
}

MiniSvmReturnResult decryptData(uint16_t keyId, MiniSvmCipher cipherType, MiniSvmSgList *sgList) {
	return performEncDecOp(keyId, cipherType, MiniSvmOperation_DecryptData, sgList);
}

static int mini_svm_create_vcpu(struct mini_svm_vcpu *vcpu, const struct mini_svm_mm *mm, const unsigned int id) {
	struct mini_svm_vmcb *vmcb = NULL;
	void *host_save_va = NULL;
	struct mini_svm_vm_state *vm_state = NULL;
	int r = 0;

	vmcb = (struct mini_svm_vmcb *)get_zeroed_page(GFP_KERNEL);
	if (!vmcb) {
		printk("Failed to allocate vmcb\n");
		r = -ENOMEM;
		goto exit;
	}

	host_save_va = get_zeroed_page(GFP_KERNEL);
	if (!host_save_va) {
		printk("Failed to allocate host_save\n");
		r = -ENOMEM;
		goto exit;
	}

	vm_state = (struct mini_svm_vm_state *)get_zeroed_page(GFP_KERNEL);
	if (!vm_state) {
		r = -ENOMEM;
		goto exit;
	}

	vcpu->host_save_va = host_save_va;
	vcpu->vmcb = vmcb;
	vcpu->state = vm_state;
	vcpu->commBlock = (MiniSvmCommunicationBlock *)((u8 *)mm->phys_map + kMiniSvmCommunicationBlockGpa + id * 0x1000UL);
	vcpu->vcpu_id = id;

exit:
	return r;
}

static void mini_svm_destroy_vcpu(struct mini_svm_vcpu *vcpu) {
	free_page(vcpu->vmcb);
	free_page(vcpu->state);
	free_page(vcpu->host_save_va);
}

static int mini_svm_allocate_ctx(struct mini_svm_context **out_ctx) {
	int r = 0;
	struct mini_svm_context *ctx;
	struct mini_svm_vmcb *vmcb = NULL;
	struct mini_svm_mm *mm = NULL;
	unsigned long host_save_va = 0;
	struct mini_svm_vm_state *vm_state = NULL;
	struct mini_svm_vcpu *vcpus = NULL;
	unsigned i = 0;

	if (!zalloc_cpumask_var(&svm_enabled, GFP_KERNEL)) {
		printk("Failed to allocate cpu mask for svm tracking\n");
		r = -ENOMEM;
		goto fail;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		printk("Failed to allocate ctx\n");
		r = -ENOMEM;
		goto fail;
	}

	if (mini_svm_create_mm(&mm)) {
		printk("Failed to allocate mm\n");
		r = -ENOMEM;
		goto fail;
	}

	vcpus = kzalloc(NR_CPUS * sizeof(struct mini_svm_vcpu), GFP_KERNEL);
	if (!vcpus) {
		printk("Failed to allocate vcpu structures\n");
		r = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < NR_CPUS; ++i) {
		r = mini_svm_create_vcpu(&vcpus[i], mm, i);
		if (r < 0) {
			goto fail;
		}
	}

	ctx->mm = mm;
	ctx->vcpus = vcpus;

	for (i = 0; i < NR_CPUS; ++i) {
		struct mini_svm_vcpu *vcpu = &vcpus[i];
		mini_svm_setup_vmcb(vcpu->vmcb, mm->pml4.pa);
		mini_svm_setup_regs(&vcpu->state->regs, i);
	}

	*out_ctx = ctx;

	return 0;

fail:
	if (vcpus) {
		for (; i != 0;) {
			--i;
			mini_svm_destroy_vcpu(&vcpus[i]);
		}
		kfree(vcpus);
	}
	if (mm) {
		mini_svm_destroy_mm(mm);
	}
	if (ctx) {
		kfree(ctx);
	}
	return r;
}

static void mini_svm_free_ctx(struct mini_svm_context *ctx) {
	u64 efer;
	unsigned i;

	for (i = 0; i < NR_CPUS; ++i) {
		mini_svm_destroy_vcpu(&ctx->vcpus[i]);
	}
	kfree(ctx->vcpus);
	mini_svm_destroy_mm(ctx->mm);
	kfree(ctx);

	// Disable SVME.
	// Otherwise, KVM would whine.
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer & ~EFER_SVME);
}

static int mini_svm_init(void) {
	int r;

	// Check if svm is supported.
	if (!boot_cpu_has(X86_FEATURE_SVM)) {
		printk("SVM not supported\n");
		return -EINVAL;
	}

	r = mini_svm_allocate_ctx(&global_ctx);
	if (r) {
		return r;
	}

	r = mini_svm_register_user_node();
	if (r < 0) {
		printk("Failed to allocate user node\n");
		return r;
	}

	// Run the vm to init the state.
	// Check that no failure happened when doing init.
	if (mini_svm_init_and_run()) {
		mini_svm_deregister_user_node();
		mini_svm_free_ctx(global_ctx);
		return -EINVAL;
	}

	mini_svm_run_tests(global_ctx);

	r = mini_svm_register_cipher();
	if (r) {
		mini_svm_deregister_user_node();
		mini_svm_free_ctx(global_ctx);
		return r;
	}

	return 0;
}

static void __exit mini_svm_exit(void) {
	u64 efer;

	printk("SVM exit module\n");

	mini_svm_free_ctx(global_ctx);
	mini_svm_deregister_user_node();
}

module_init(mini_svm_init);
module_exit(mini_svm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Radev");
