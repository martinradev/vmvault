// Copyright (C) 2021 Martin Radev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "sevault-mini.h"
#include "sevault-mini-exit-codes.h"
#include "sevault-mini-mm.h"
#include "sevault-mini-debug.h"
#include "sevault-mini-user.h"
#include "sevault-mini-crypto.h"
#include "vm-program.h"

#include <linux/build_bug.h>
#include "sevault-mini-vmcb.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/context_tracking.h>
#include <asm/io.h>
#include <asm/string.h>

// FIXME
#include "../uapi/sevault-mini-communication-block.h"

static inline u64 xgetbv(u32 index)
{
	u32 eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));
	return eax + ((u64)edx << 32);
}

static inline void xsetbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	asm volatile(".byte 0x0f,0x01,0xd1" /* xsetbv */
		     : : "a" (eax), "d" (edx), "c" (index));
}

static cpumask_var_t svm_enabled;

bool sevault_debug_enable_logging = false;
module_param(sevault_debug_enable_logging, bool, 0);

struct sevault_mini_context *global_ctx = NULL;

#define IMAGE_START 0x4000UL
#define STACK_START 0x10000UL
#define STACK_SIZE_PER_CPU 0x400
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
#define CR4_OSXSAVE (1UL << 18U)

void __sevault_mini_run(u64 vmcb_phys, void *regs);

int sevault_mini_intercept_vmmcall(const SevaultMiniCommunicationBlock *commBlock, const struct sevault_mini_vm_state *state) {
	const unsigned long cmd = state->regs.rax;
	const unsigned long arg1 = state->regs.rdi;
	const unsigned long arg2 = state->regs.rsi;
	const unsigned long arg3 = state->regs.rdx;

	if ((VmmCall)cmd == VmmCall_DebugPrint) {
		sevault_log_msg("VM send debug msg: %s\n", getDebugMessage(commBlock));
		sevault_log_msg("args: %lx %lx %lx\n", arg1, arg2, arg3);
	}

	return 0;
}

static int sevault_mini_intercept_npf(struct sevault_mini_vmcb *vmcb, struct sevault_mini_vm_state *state) {
	__u64 fault_phys_address = vmcb->control.exitinfo_v2;
	sevault_log_msg("Received NPF at phys addr: 0x%llx\n", vmcb->control.exitinfo_v2);
	dump_regs(state);
	if (fault_phys_address >= MINI_SVM_MAX_PHYS_SIZE) {
		return 1;
	}
	return 1;
}

static void sevault_mini_handle_exception(const enum MINI_SVM_EXCEPTION excp, const struct sevault_mini_vm_state *state) {
	sevault_log_msg("Received exception. # = %x. Name: %s\n", (unsigned)excp, translate_sevault_mini_exception_number_to_str(excp));
	dump_regs(state);
}

static int sevault_mini_handle_exit(struct sevault_mini_vcpu *vcpu) {
	const SevaultMiniCommunicationBlock *commBlock = vcpu->commBlock;
	struct sevault_mini_vmcb *vmcb = vcpu->vmcb;
	struct sevault_mini_vm_state *state = vcpu->state;
	__u64 exitcode = get_exitcode(&vmcb->control);
	int should_exit = 0;

	sevault_log_msg("Exitcode: %s\n", translate_sevault_mini_exitcode_to_str((enum MINI_SVM_EXITCODE)exitcode));
	//dump_regs(state);

	// TODO: Doing this through function pointers for the respective handlers is probably better.
	switch((enum MINI_SVM_EXITCODE)exitcode) {
		case MINI_SVM_EXITCODE_VMEXIT_EXCP_0 ... MINI_SVM_EXITCODE_VMEXIT_EXCP_15:
			sevault_mini_handle_exception((enum MINI_SVM_EXCEPTION)(exitcode - MINI_SVM_EXITCODE_VMEXIT_EXCP_0), state);
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_INVALID:
		case MINI_SVM_EXITCODE_VMEXIT_HLT:
		case MINI_SVM_EXITCODE_VMEXIT_SHUTDOWN:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_NPF:
			should_exit = sevault_mini_intercept_npf(vmcb, state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_VMMCALL:
			should_exit = sevault_mini_intercept_vmmcall(commBlock, state);
			break;
		default:
			sevault_log_msg("Unkown exit code\n");
			should_exit = 1;
			break;
	}

	return should_exit;
}

static void sevault_mini_setup_regs(struct sevault_mini_vm_regs *regs, unsigned int vcpu_id) {
	regs->rip = IMAGE_START;
	regs->rsp = STACK_START + (vcpu_id * STACK_SIZE_PER_CPU) + STACK_SIZE_PER_CPU - 0x8UL;
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

static void sevault_mini_setup_vmcb(struct sevault_mini_vmcb *vmcb, u64 ncr3) {
	struct sevault_mini_vmcb_save_area *save = &vmcb->save;
	struct sevault_mini_vmcb_control *ctrl = &vmcb->control;
	memset(&ctrl->excp_vec_intercepts, 0xFF, sizeof(ctrl->excp_vec_intercepts));
	ctrl->vec3.hlt_intercept = 1;
	ctrl->vec4.vmrun_intercept = 1;
	ctrl->vec4.vmmcall_intercept = 1;
	ctrl->vec4.vmload_intercept = 1;
	ctrl->vec4.vmsave_intercept = 1;
	ctrl->tlb_control = 0;
	ctrl->guest_asid = 1;
	ctrl->np_enable = 1;
	ctrl->ncr3 = ncr3;

	// Setup long mode.
	save->efer = EFER_SVME | EFER_LME | EFER_LMA;
	save->cr0 = (CR0_PE | CR0_PG);
	save->cr3 = 0x0;
	save->cr4 = (CR4_PAE | CR4_PGE | CR4_OSXMMEXCPT | CR4_OSFXSR | CR4_OSXSAVE);

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

static void sevault_mini_run(struct sevault_mini_vmcb *vmcb, struct sevault_mini_vm_regs *regs) {
	u64 vmcb_phys = virt_to_phys(vmcb);

	// Load the special registers into vmcb from the regs context
	vmcb->save.rip = regs->rip;
	vmcb->save.rax = regs->rax;
	vmcb->save.rsp = regs->rsp;

	__sevault_mini_run(vmcb_phys, regs);

	// Save registers from vmcb to the regs context
	regs->rip = vmcb->save.rip;
	regs->rax = vmcb->save.rax;
	regs->rsp = vmcb->save.rsp;
}

static void enable_svm(struct sevault_mini_vcpu *vcpu) {
	u64 hsave_pa;
	u64 efer;

	// Enable SVM.
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer | EFER_SVME);

	hsave_pa = virt_to_phys((void *)vcpu->host_save_va);
	wrmsrl(MSR_VM_HSAVE_PA, hsave_pa);
}

static void run_vm(struct sevault_mini_vcpu *vcpu) {
#if 0
	sevault_mini_dump_vmcb(ctx->vcpu.vmcb);
#endif
	const int cpu = raw_smp_processor_id();

	// Save host xcr0
	const u64 host_xcr0 = xgetbv(0x0);
	const u64 guest_xcr0 = host_xcr0 | 0x7UL; // Enable avx, sse, x87

	if (!cpumask_test_cpu(cpu, svm_enabled)) {
		enable_svm(vcpu);
		cpumask_set_cpu(cpu, svm_enabled);
	}

	// Load guest xcr0
	xsetbv(0x0, guest_xcr0);

	sevault_mini_run(vcpu->vmcb, &vcpu->state->regs);

	// Restore host xcr0
	xsetbv(0x0, host_xcr0);

#if 0
	sevault_mini_dump_vmcb(ctx->vcpu.vmcb);
#endif
}

static int sevault_mini_init_and_run(void) {
	unsigned int cpu_index;
	struct sevault_mini_vcpu *vcpu;
	int r;

	cpu_index = get_cpu();
	vcpu = &global_ctx->vcpus[cpu_index];

	setOperationType(vcpu->commBlock, SevaultMiniOperation_Init);
	run_vm(vcpu);

	put_cpu();

	r = sevault_mini_handle_exit(vcpu);
	if (r < 0) {
		return r;
	}

	if (getResult(vcpu->commBlock) != SevaultMiniReturnResult_Ok) {
		return -EFAULT;
	}

	vcpu->state->regs.rip = vcpu->vmcb->control.nRIP;

	return 0;
}

static void sevault_mini_resume(struct sevault_mini_vcpu *vcpu) {
	// We do not expect any changes, so mark all vmcb bits as clean.
	vcpu->vmcb->control.vmcb_clean = ((1U << 13) - 1U);
	run_vm(vcpu);
	vcpu->state->regs.rip = vcpu->vmcb->control.nRIP;
}

SevaultMiniReturnResult checkResult(SevaultMiniCommunicationBlock *commBlock) {
	const SevaultMiniReturnResult result = getResult(commBlock);
	const bool failed = result != SevaultMiniReturnResult_Ok;
	if (failed) {
		sevault_log_msg("Return result was not ok\n");
	}
	if (buildFlavor == SevaultMiniBuildFlavor_Debug) {
		sevault_log_msg("Debug message: %s\n", getDebugMessage(commBlock));
		clearDebugMessage(commBlock);
	}
	return result;
}

SevaultMiniReturnResult registerContext(
	const uint64_t array,
	size_t size,
	const uint64_t iv,
	size_t ivSize,
	uint16_t *keyId) {
	SevaultMiniReturnResult result;

	const unsigned cpu_id = get_cpu();

	struct sevault_mini_vcpu *vcpu = &global_ctx->vcpus[cpu_id];
	SevaultMiniCommunicationBlock *commBlock = vcpu->commBlock;
	setOperationType(commBlock, SevaultMiniOperation_RegisterContext);
	setSourceHpa(commBlock, array);
	setSourceSize(commBlock, size);
	setIv(commBlock, iv, ivSize);

	// TODO
	sevault_mini_resume(vcpu);
	if (sevault_mini_handle_exit(vcpu)) {
		sevault_log_msg("Svm exitted with a weird error\n");
		// TODO
		result = SevaultMiniReturnResult_Fail;
		goto exit;
	}
	result = checkResult(commBlock);

	if (result == SevaultMiniReturnResult_Ok) {
		*keyId = getContextId(commBlock);
	}

exit:
	put_cpu();
	return result;
}

SevaultMiniReturnResult removeContext(uint16_t contextId) {

	const unsigned cpu_id = get_cpu();
	struct sevault_mini_vcpu *vcpu = &global_ctx->vcpus[cpu_id];

	SevaultMiniReturnResult result;
	SevaultMiniCommunicationBlock *commBlock = vcpu->commBlock;
	setOperationType(commBlock, SevaultMiniOperation_RemoveContext);
	setContextId(commBlock, contextId);

	sevault_mini_resume(vcpu);
	if (sevault_mini_handle_exit(vcpu)) {
		sevault_log_msg("Svm exitted with a weird error\n");
		// TODO
		result = SevaultMiniReturnResult_Fail;
		goto exit;
	}

	result = checkResult(commBlock);

exit:
	put_cpu();
	return result;
}

static SevaultMiniReturnResult performEncDecOp(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniOperation opType, SevaultMiniSgList *sgList, const u64 iv, unsigned int ivlen) {
	size_t i;
	SevaultMiniReturnResult result;
	const unsigned cpu_id = get_cpu();
	struct sevault_mini_vcpu *vcpu = &global_ctx->vcpus[cpu_id];
	SevaultMiniCommunicationBlock *commBlock = vcpu->commBlock;
	setOperationType(commBlock, opType);
	clearSgList(&commBlock->opSgList);
	setIv(commBlock, iv, ivlen);
	for (i = 0; i < sgList->numRanges; ++i) {
		SevaultMiniDataRange *entry = &sgList->ranges[i];
		if (!addSgListEntry(&commBlock->opSgList, entry->srcPhysAddr, entry->dstPhysAddr, entry->length)) {
			return SevaultMiniReturnResult_Fail;
		}
	}
	setCipherType(commBlock, cipherType);
	setContextId(commBlock, keyId);

	sevault_mini_resume(vcpu);
	if (sevault_mini_handle_exit(vcpu)) {
		sevault_log_msg("Svm exitted with a weird error\n");
		// TODO
		result = SevaultMiniReturnResult_Fail;
		goto exit;
	}

	result = checkResult(commBlock);

exit:
	put_cpu();
	return result;
}

static SevaultMiniReturnResult performEncDecOpSingleSgEntry(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniOperation opType, const uint64_t input, size_t size, uint64_t output) {
	SevaultMiniSgList sgList;
	sgList.numRanges = 1;
	sgList.ranges[0].srcPhysAddr = input;
	sgList.ranges[0].dstPhysAddr = output;
	sgList.ranges[0].length = size;
	return performEncDecOp(keyId, cipherType, opType, &sgList, 0, 0);
}

SevaultMiniReturnResult encryptDataSingleSgEntry(uint16_t keyId, SevaultMiniCipher cipherType, const uint64_t input, size_t size, uint64_t output) {
	return performEncDecOpSingleSgEntry(keyId, cipherType, SevaultMiniOperation_EncryptData, input, size, output);
}

SevaultMiniReturnResult decryptDataSingleSgEntry(uint16_t keyId, SevaultMiniCipher cipherType, const uint64_t input, size_t size, uint64_t output) {
	return performEncDecOpSingleSgEntry(keyId, cipherType, SevaultMiniOperation_DecryptData, input, size, output);
}

SevaultMiniReturnResult encryptDataWithIv(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList, const u64 iv, const unsigned int iv_length) {
	return performEncDecOp(keyId, cipherType, SevaultMiniOperation_EncryptData, sgList, iv, iv_length);
}

SevaultMiniReturnResult decryptDataWithIv(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList, const u64 iv, const unsigned int iv_length) {
	return performEncDecOp(keyId, cipherType, SevaultMiniOperation_DecryptData, sgList, iv, iv_length);
}

SevaultMiniReturnResult encryptData(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList) {
	return performEncDecOp(keyId, cipherType, SevaultMiniOperation_EncryptData, sgList, 0, 0);
}

SevaultMiniReturnResult decryptData(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList) {
	return performEncDecOp(keyId, cipherType, SevaultMiniOperation_DecryptData, sgList, 0, 0);
}

static int sevault_mini_create_vcpu(struct sevault_mini_vcpu *vcpu, const struct sevault_mini_mm *mm, const unsigned int id) {
	struct sevault_mini_vmcb *vmcb = NULL;
	unsigned long host_save_va = 0;
	struct sevault_mini_vm_state *vm_state = NULL;
	int r = 0;

	vmcb = (struct sevault_mini_vmcb *)get_zeroed_page(GFP_KERNEL);
	if (!vmcb) {
		sevault_log_msg("Failed to allocate vmcb\n");
		r = -ENOMEM;
		goto exit;
	}

	host_save_va = get_zeroed_page(GFP_KERNEL);
	if (!host_save_va) {
		sevault_log_msg("Failed to allocate host_save\n");
		r = -ENOMEM;
		goto exit;
	}

	vm_state = (struct sevault_mini_vm_state *)get_zeroed_page(GFP_KERNEL);
	if (!vm_state) {
		r = -ENOMEM;
		goto exit;
	}

	vcpu->host_save_va = host_save_va;
	vcpu->vmcb = vmcb;
	vcpu->state = vm_state;
	vcpu->commBlock = (SevaultMiniCommunicationBlock *)((u8 *)mm->comm_block_memory + id * 0x1000UL);
	vcpu->vcpu_id = id;

exit:
	return r;
}

static void sevault_mini_destroy_vcpu(struct sevault_mini_vcpu *vcpu) {
	free_page((unsigned long)vcpu->vmcb);
	free_page((unsigned long)vcpu->state);
	free_page(vcpu->host_save_va);
}

static int sevault_mini_allocate_ctx(struct sevault_mini_context **out_ctx) {
	int r = 0;
	struct sevault_mini_context *ctx;
	struct sevault_mini_mm *mm = NULL;
	struct sevault_mini_vcpu *vcpus = NULL;
	unsigned i = 0;

	if (!zalloc_cpumask_var(&svm_enabled, GFP_KERNEL)) {
		sevault_log_msg("Failed to allocate cpu mask for svm tracking\n");
		r = -ENOMEM;
		goto fail;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		sevault_log_msg("Failed to allocate ctx\n");
		r = -ENOMEM;
		goto fail;
	}

	if (sevault_mini_create_mm(&mm)) {
		sevault_log_msg("Failed to allocate mm\n");
		r = -ENOMEM;
		goto fail;
	}

	vcpus = kzalloc(nr_cpu_ids * sizeof(struct sevault_mini_vcpu), GFP_KERNEL);
	if (!vcpus) {
		sevault_log_msg("Failed to allocate vcpu structures\n");
		r = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < nr_cpu_ids; ++i) {
		r = sevault_mini_create_vcpu(&vcpus[i], mm, i);
		if (r < 0) {
			goto fail;
		}
	}

	// Load image.
	r = sevault_mini_mm_write_phys_memory(mm, IMAGE_START, __vm_program, __vm_program_len);
	if (r < 0) {
		goto fail;
	}

	// Mark memory as inaccessible to the kernel.
	// This is a solution until SEV support is added:
	// Check https://github.com/martinradev/sevault-mini-svm/issues/3 and 4
	r = sevault_mini_mm_mark_vm_memory_inaccessible(mm);
	if (r < 0) {
		goto fail;
	}

	ctx->mm = mm;
	ctx->vcpus = vcpus;

	for (i = 0; i < nr_cpu_ids; ++i) {
		struct sevault_mini_vcpu *vcpu = &vcpus[i];
		sevault_mini_setup_vmcb(vcpu->vmcb, mm->pml4.pa);
		sevault_mini_setup_regs(&vcpu->state->regs, i);
	}

	*out_ctx = ctx;

	return 0;

fail:
	if (vcpus) {
		for (; i != 0;) {
			--i;
			sevault_mini_destroy_vcpu(&vcpus[i]);
		}
		kfree(vcpus);
	}
	if (mm) {
		sevault_mini_destroy_mm(mm);
	}
	if (ctx) {
		kfree(ctx);
	}
	return r;
}

static void sevault_mini_free_ctx(struct sevault_mini_context *ctx) {
	u64 efer;
	unsigned i;

	for (i = 0; i < nr_cpu_ids; ++i) {
		sevault_mini_destroy_vcpu(&ctx->vcpus[i]);
	}
	kfree(ctx->vcpus);
	sevault_mini_destroy_mm(ctx->mm);
	kfree(ctx);

	// Disable SVME.
	// Otherwise, KVM would whine.
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer & ~EFER_SVME);
}

static int sevault_mini_init(void) {
	int r;

	// Check if svm is supported.
	if (!boot_cpu_has(X86_FEATURE_SVM)) {
		sevault_log_msg("SVM not supported\n");
		return -EINVAL;
	}

	r = sevault_mini_allocate_ctx(&global_ctx);
	if (r) {
		return r;
	}

	r = sevault_mini_register_user_node();
	if (r < 0) {
		sevault_log_msg("Failed to allocate user node\n");
		return r;
	}

	// Run the vm to init the state.
	// Check that no failure happened when doing init.
	if (sevault_mini_init_and_run()) {
		sevault_mini_deregister_user_node();
		sevault_mini_free_ctx(global_ctx);
		return -EINVAL;
	}

	sevault_mini_run_tests(global_ctx);

	r = sevault_mini_register_cipher();
	if (r) {
		sevault_mini_deregister_user_node();
		sevault_mini_free_ctx(global_ctx);
		return r;
	}

	return 0;
}

static void __exit sevault_mini_exit(void) {
	sevault_log_msg("SVM exit module\n");

	sevault_mini_free_ctx(global_ctx);
	sevault_mini_deregister_cipher();
	sevault_mini_deregister_user_node();
}

module_init(sevault_mini_init);
module_exit(sevault_mini_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Radev");
