#ifndef MINI_SVM_DEBUG_H
#define MINI_SVM_DEBUG_H

void sevault_log_msg(const char *format, ...);

void sevault_mini_dump_vmcb(struct sevault_mini_vmcb *vmcb);

void sevault_mini_run_tests(struct sevault_mini_context *ctx);

void dump_regs(const struct sevault_mini_vm_state *state);

#endif // MINI_SVM_DEBUG_H
