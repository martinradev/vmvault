#ifndef MINI_SVM_H
#define MINI_SVM_H

#include "mini-svm-mm.h"

#include <linux/build_bug.h>
#include "mini-svm-vmcb.h"
#include "mini-svm-user-ioctl.h"

#include <asm/string.h>
#include "../uapi/mini-svm-communication-block.h"

extern struct mini_svm_context *global_ctx;

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

struct mini_svm_vcpu {
	struct mini_svm_vmcb *vmcb;
	struct mini_svm_vm_state *state;
	MiniSvmCommunicationBlock *commBlock;
	unsigned long host_save_va;
	unsigned long host_save_pa;
	unsigned vcpu_id;
};

struct mini_svm_context {
	struct mini_svm_mm *mm;
	struct mini_svm_vcpu *vcpus;
	unsigned num_vcpus;
};

MiniSvmReturnResult checkResult(MiniSvmCommunicationBlock *commBlock);

MiniSvmReturnResult registerContext(
		const uint64_t data,
		size_t size,
		const uint64_t iv,
		size_t ivSize,
		uint16_t *keyId);

MiniSvmReturnResult removeContext(uint16_t contextId);

MiniSvmReturnResult encryptDataSingleSgEntry(uint16_t keyId, MiniSvmCipher cipherType, const uint64_t input, size_t size, uint64_t output);
MiniSvmReturnResult decryptDataSingleSgEntry(uint16_t keyId, MiniSvmCipher cipherType, const uint64_t input, size_t size, uint64_t output);

// For these functions, the caller must update the sg list
MiniSvmReturnResult encryptData(uint16_t keyId, MiniSvmCipher cipherType);
MiniSvmReturnResult decryptData(uint16_t keyId, MiniSvmCipher cipherType);

#endif // MINI_SVM_H
