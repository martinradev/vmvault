#ifndef MINI_SVM_INTERCEPT_H
#define MINI_SVM_INTERCEPT_H

#include "mini-svm.h"

void mini_svm_intercept_rdtsc(struct mini_svm_vcpu *vcpu);

void mini_svm_intercept_rdtscp(struct mini_svm_vcpu *vcpu);

int mini_svm_intercept_npf(struct mini_svm_context *ctx);

int mini_svm_intercept_cpuid(struct mini_svm_context *ctx);

int mini_svm_intercept_vmmcall(struct mini_svm_context *ctx);

#endif // MINI_SVM_INTERCEPT_H
