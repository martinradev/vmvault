#ifndef MINI_SVM_COMMON_STRUCTURES_H
#define MINI_SVM_COMMON_STRUCTURES_H

static const __u64 MINI_SVM_PRESENT_MASK = 0x1UL;
static const __u64 MINI_SVM_WRITEABLE_MASK = 0x2UL;
static const __u64 MINI_SVM_USER_MASK = 0x4UL;
static const __u64 MINI_SVM_LEAF_MASK = (1UL << 7U);

#define MINI_SVM_4KB (4096UL)
#define MINI_SVM_2MB (512UL * MINI_SVM_4KB)
#define MINI_SVM_1GB (512UL * MINI_SVM_2MB)
#define MINI_SVM_512GB (512UL * MINI_SVM_1GB)

static inline __u64 mini_svm_create_entry(__u64 pa, __u64 mask) {
	return pa | mask;
}

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

#endif // MINI_SVM_COMMON_STRUCTURES_H
