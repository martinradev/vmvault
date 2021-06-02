#ifndef MINI_SVM_EXIT_CODES_H
#define MINI_SVM_EXIT_CODES_H

enum MINI_SVM_EXITCODE {
	MINI_SVM_EXITCODE_VMEXIT_INVALID = -1,
	MINI_SVM_EXITCODE_VMEXIT_BUSY = -2,
};

const char *translate_mini_svm_exitcode_to_str(const enum MINI_SVM_EXITCODE exitcode);

#endif // MINI_SVM_EXIT_CODES_H
