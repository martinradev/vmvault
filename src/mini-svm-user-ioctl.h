#ifndef MINI_SVM_USER_IOCTL_H
#define MINI_SVM_USER_IOCTL_H

#define MINI_SVM_IOCTL_START 0x1337U
#define MINI_SVM_IOCTL_STOP  0x1338U

struct mini_svm_vm_regs {
	__u64 rbx;
	__u64 rcx;
	__u64 rdx;
	__u64 rdi;
	__u64 rsi;
	__u64 rbp;
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 rip;
	__u64 rax;
	__u64 rsp;
};

struct mini_svm_vm_state {
	struct mini_svm_vm_regs regs;
	__u64 clock;
};

#endif // MINI_SVM_USER_IOCTL_H
