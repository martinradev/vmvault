#include "mini-svm-exit-codes.h"

#include <linux/kernel.h>
#include <asm/bug.h>

const char *translate_mini_svm_exitcode_to_str(const enum MINI_SVM_EXITCODE exitcode) {
#define p(X) \
	case X: \
		return #X

	switch (exitcode) {
	p(MINI_SVM_EXITCODE_VMEXIT_INVALID);
	p(MINI_SVM_EXITCODE_VMEXIT_BUSY);
	p(MINI_SVM_EXITCODE_VMEXIT_SHUTDOWN);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_0);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_1);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_2);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_3);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_4);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_5);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_6);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_7);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_8);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_9);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_10);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_11);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_12);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_13);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_14);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_15);
	p(MINI_SVM_EXITCODE_VMEXIT_HLT);
	p(MINI_SVM_EXITCODE_VMEXIT_VMMCALL);
	p(MINI_SVM_EXITCODE_VMEXIT_NPF);
	default:
		BUG();
		return NULL;
	};

#undef p
}

const char *translate_mini_svm_exception_number_to_str(const enum MINI_SVM_EXCEPTION excp) {
#define p(X) \
	case MINI_SVM_EXCEPTION_ ## X: \
		return #X " exception"
	switch(excp) {
	p(DE);
	p(DB);
	p(NMI);
	p(BP);
	p(OF);
	p(BR);
	p(UD);
	p(NM);
	p(DF);
	p(CSO);
	p(TS);
	p(NP);
	p(SS);
	p(GP);
	p(PF);
	p(MF);
	p(AC);
	p(MC);
	p(XF);
	p(VE);
	p(SX);
	default:
		printk("Invalid exception: %x\n", excp);
		BUG();
		return "";
	}
#undef p
}
