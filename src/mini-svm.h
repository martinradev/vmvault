#ifndef MINI_SVM_H
#define MINI_SVM_H

#include "mini-svm-vmcb.h"

struct mini_svm_context {
	struct mini_svm_vmcb *vmcb;
	unsigned long host_save_va;
};

#endif // MINI_SVM_H
