#ifndef MINI_SVM_H
#define MINI_SVM_H

#include "mini-svm-mm.h"

#include <linux/build_bug.h>
#include "mini-svm-vmcb.h"
#include "mini-svm-user-ioctl.h"

extern struct mini_svm_context *global_ctx;

struct mini_svm_vcpu {
	struct mini_svm_vmcb *vmcb;
	struct mini_svm_vm_state *state;
	unsigned long host_save_va;
};

struct mini_svm_context {
	struct mini_svm_mm *mm;
	struct mini_svm_vcpu vcpu;
};

void mini_svm_init_and_run(void);
void mini_svm_stop(void);

#endif // MINI_SVM_H
