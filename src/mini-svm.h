#ifndef MINI_SVM_H
#define MINI_SVM_H

#include "mini-svm-vmcb.h"
#include "mini-svm-mm.h"

struct mini_svm_context {
	struct mini_svm_vmcb *vmcb;
	struct mini_svm_mm *mm;
	unsigned long host_save_va;
};

#endif // MINI_SVM_H
