#ifndef MINI_SVM_DEBUG_H
#define MINI_SVM_DEBUG_H

void mini_svm_dump_vmcb(struct mini_svm_vmcb *vmcb);

void mini_svm_run_tests(struct mini_svm_context *ctx);

void dump_regs(const struct mini_svm_vm_state *state);

#endif // MINI_SVM_DEBUG_H
