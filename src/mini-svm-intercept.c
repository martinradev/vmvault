#include "mini-svm-intercept.h"
#include "mini-svm-mm.h"

#include <linux/kernel.h>

void mini_svm_intercept_rdtsc(struct mini_svm_vcpu *vcpu) {
	vcpu->state->regs.rax = (vcpu->state->clock & 0xFFFFFFFFUL);
	vcpu->state->regs.rdx = ((vcpu->state->clock >> 32U) & 0xFFFFFFFFUL);
	vcpu->state->clock++;
}

void mini_svm_intercept_rdtscp(struct mini_svm_vcpu *vcpu) {
	vcpu->state->regs.rcx = 0x1337UL;
	mini_svm_intercept_rdtsc(vcpu);
}

int mini_svm_intercept_npf(struct mini_svm_context *ctx) {
	u64 fault_phys_address = ctx->vcpu.vmcb->control.exitinfo_v2;
	printk("Received NPF at phys addr: 0x%llx\n", ctx->vcpu.vmcb->control.exitinfo_v2);
	if (fault_phys_address >= MINI_SVM_MAX_PHYS_SIZE) {
		return 1;
	}
	return 1;
}

int mini_svm_intercept_cpuid(struct mini_svm_context *ctx) {
	return 0;
}

int mini_svm_intercept_vmmcall(struct mini_svm_context *ctx) {
	return 0;
}
