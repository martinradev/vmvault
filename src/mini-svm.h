#ifndef MINI_SVM_H
#define MINI_SVM_H

#include "mini-svm-mm.h"

#include <linux/build_bug.h>
#include "mini-svm-vmcb.h"

struct mini_svm_vm_regs {
	u64 rbx;
	u64 rcx;
	u64 rdx;
	u64 rdi;
	u64 rsi;
	u64 rbp;

	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;

	u64 rip;
	u64 rax;
	u64 rsp;
};

struct mini_svm_vcpu {
	struct mini_svm_vmcb *vmcb;
	struct mini_svm_vm_regs regs;
	unsigned long host_save_va;
	u64 clock;
};

struct mini_svm_context {
	struct mini_svm_mm *mm;
	struct mini_svm_vcpu vcpu;
};

void mini_svm_init_and_run(void);
void mini_svm_stop(void);

#endif // MINI_SVM_H
