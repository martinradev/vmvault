// Copyright (C) 2021 Martin Radev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#ifndef MINI_SVM_H
#define MINI_SVM_H

#include "sevault-mini-mm.h"

#include <linux/build_bug.h>
#include "sevault-mini-vmcb.h"
#include "sevault-mini-user-ioctl.h"

#include <asm/string.h>
#include "../uapi/sevault-mini-communication-block.h"

extern struct sevault_mini_context *global_ctx;
extern bool sevault_debug_enable_logging;

static const __u64 MINI_SVM_PRESENT_MASK = 0x1UL;
static const __u64 MINI_SVM_WRITEABLE_MASK = 0x2UL;
static const __u64 MINI_SVM_USER_MASK = 0x4UL;
static const __u64 MINI_SVM_LEAF_MASK = (1UL << 7U);

#define MINI_SVM_4KB (4096UL)
#define MINI_SVM_2MB (512UL * MINI_SVM_4KB)
#define MINI_SVM_1GB (512UL * MINI_SVM_2MB)
#define MINI_SVM_512GB (512UL * MINI_SVM_1GB)

static inline __u64 sevault_mini_create_entry(__u64 pa, __u64 mask) {
	return pa | mask;
}

struct sevault_mini_vm_regs {
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

struct sevault_mini_vm_state {
	struct sevault_mini_vm_regs regs;
	__u64 clock;
};

struct sevault_mini_vcpu {
	struct sevault_mini_vmcb *vmcb;
	struct sevault_mini_vm_state *state;
	SevaultMiniCommunicationBlock *commBlock;
	unsigned long host_save_va;
	unsigned long host_save_pa;
	unsigned vcpu_id;
};

struct sevault_mini_context {
	struct sevault_mini_mm *mm;
	struct sevault_mini_vcpu *vcpus;
	unsigned num_vcpus;
};

SevaultMiniReturnResult checkResult(SevaultMiniCommunicationBlock *commBlock);

SevaultMiniReturnResult registerContext(
		const uint64_t data,
		size_t size,
		const uint64_t iv,
		size_t ivSize,
		uint16_t *keyId);

SevaultMiniReturnResult removeContext(uint16_t contextId);

SevaultMiniReturnResult encryptDataSingleSgEntry(uint16_t keyId, SevaultMiniCipher cipherType, const uint64_t input, size_t size, uint64_t output);
SevaultMiniReturnResult decryptDataSingleSgEntry(uint16_t keyId, SevaultMiniCipher cipherType, const uint64_t input, size_t size, uint64_t output);

SevaultMiniReturnResult encryptData(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList);
SevaultMiniReturnResult decryptData(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList);

SevaultMiniReturnResult encryptDataWithIv(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList, const u64 iv, const unsigned int iv_length);
SevaultMiniReturnResult decryptDataWithIv(uint16_t keyId, SevaultMiniCipher cipherType, SevaultMiniSgList *sgList, const u64 iv, const unsigned int iv_length);

#endif // MINI_SVM_H
