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

#ifndef VMVAULT_H
#define VMVAULT_H

#include "vmvault-mm.h"

#include <linux/build_bug.h>
#include "vmvault-vmcb.h"
#include "vmvault-user-ioctl.h"

#include <asm/string.h>
#include "../uapi/vmvault-communication-block.h"

extern struct vmvault_context *global_ctx;
extern bool vmvault_debug_enable_logging;

static const __u64 VMVAULT_PRESENT_MASK = 0x1UL;
static const __u64 VMVAULT_WRITEABLE_MASK = 0x2UL;
static const __u64 VMVAULT_USER_MASK = 0x4UL;
static const __u64 VMVAULT_LEAF_MASK = (1UL << 7U);

#define VMVAULT_4KB (4096UL)
#define VMVAULT_2MB (512UL * VMVAULT_4KB)
#define VMVAULT_1GB (512UL * VMVAULT_2MB)
#define VMVAULT_512GB (512UL * VMVAULT_1GB)

static inline __u64 vmvault_create_entry(__u64 pa, __u64 mask) {
	return pa | mask;
}

struct vmvault_vm_regs {
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

struct vmvault_vm_state {
	struct vmvault_vm_regs regs;
	__u64 clock;
};

struct vmvault_vcpu {
	struct vmvault_vmcb *vmcb;
	struct vmvault_vm_state *state;
	VmVaultCommunicationBlock *commBlock;
	unsigned long host_save_va;
	unsigned long host_save_pa;
	unsigned vcpu_id;
};

struct vmvault_context {
	struct vmvault_mm *mm;
	struct vmvault_vcpu *vcpus;
	unsigned num_vcpus;
};

VmVaultReturnResult checkResult(VmVaultCommunicationBlock *commBlock);

VmVaultReturnResult registerContext(
		const uint64_t data,
		size_t size,
		const uint64_t iv,
		size_t ivSize,
		uint16_t *keyId);

VmVaultReturnResult removeContext(uint16_t contextId);

VmVaultReturnResult encryptDataSingleSgEntry(uint16_t keyId, VmVaultCipher cipherType, const uint64_t input, size_t size, uint64_t output);
VmVaultReturnResult decryptDataSingleSgEntry(uint16_t keyId, VmVaultCipher cipherType, const uint64_t input, size_t size, uint64_t output);

VmVaultReturnResult encryptData(uint16_t keyId, VmVaultCipher cipherType, VmVaultSgList *sgList);
VmVaultReturnResult decryptData(uint16_t keyId, VmVaultCipher cipherType, VmVaultSgList *sgList);

VmVaultReturnResult encryptDataWithIv(uint16_t keyId, VmVaultCipher cipherType, VmVaultSgList *sgList, const u64 iv, const unsigned int iv_length);
VmVaultReturnResult decryptDataWithIv(uint16_t keyId, VmVaultCipher cipherType, VmVaultSgList *sgList, const u64 iv, const unsigned int iv_length);

#endif // VMVAULT_H
