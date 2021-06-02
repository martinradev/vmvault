#include "mini-svm-exit-codes.h"

#include <linux/kernel.h>
#include <asm/bug.h>

const char *translate_mini_svm_exitcode_to_str(const enum MINI_SVM_EXITCODE exitcode) {
#define p(X) \
	case X: \
		return #X

	switch (exitcode) {
	p(MINI_SVM_EXITCODE_VMEXIT_INVALID);
	default:
		BUG();
		return NULL;
	};

#undef p
}
