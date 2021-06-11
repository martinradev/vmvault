#ifndef MINI_SVM_INTERCEPT_H
#define MINI_SVM_INTERCEPT_H

static inline void mini_svm_intercept_rdtsc(struct mini_svm_vcpu *vcpu) {
	vcpu->regs.rax = (vcpu->clock & 0xFFFFFFFFUL);
	vcpu->regs.rdx = ((vcpu->clock >> 32U) & 0xFFFFFFFFUL);
	vcpu->clock++;
}

static inline void mini_svm_intercept_rdtscp(struct mini_svm_vcpu *vcpu) {
	mini_svm_intercept_rdtsc(vcpu);
}

#endif // MINI_SVM_INTERCEPT_H
