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

#ifndef VMVAULT_DEBUG_H
#define VMVAULT_DEBUG_H

#include "vmvault-debug.h"
#include "vmvault.h"

#include <linux/build_bug.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include "vmvault-vmcb.h"

#define gva_to_gpa(X) ((u64)slow_virt_to_phys(X))

void vmvault_log_msg(const char *format, ...) {
	if (vmvault_debug_enable_logging) {
		va_list args;
		va_start(args, format);
		vprintk(format, args);
		va_end(args);
	}
}

void vmvault_dump_regs(const struct vmvault_vm_state *state) {
	vmvault_log_msg("rax = %llx\n", state->regs.rax);
	vmvault_log_msg("rbx = %llx\n", state->regs.rbx);
	vmvault_log_msg("rcx = %llx\n", state->regs.rcx);
	vmvault_log_msg("rdx = %llx\n", state->regs.rdx);
	vmvault_log_msg("rsi = %llx\n", state->regs.rsi);
	vmvault_log_msg("rdi = %llx\n", state->regs.rdi);
	vmvault_log_msg("rip = %llx\n", state->regs.rip);
	vmvault_log_msg("rsp = %llx\n", state->regs.rsp);
	vmvault_log_msg("rbp = %llx\n", state->regs.rbp);
	vmvault_log_msg("r8 = %llx\n", state->regs.r8);
	vmvault_log_msg("r9 = %llx\n", state->regs.r9);
	vmvault_log_msg("r10 = %llx\n", state->regs.r10);
	vmvault_log_msg("r11 = %llx\n", state->regs.r11);
	vmvault_log_msg("r12 = %llx\n", state->regs.r12);
	vmvault_log_msg("r13 = %llx\n", state->regs.r13);
	vmvault_log_msg("r14 = %llx\n", state->regs.r14);
	vmvault_log_msg("r15 = %llx\n", state->regs.r15);
}

void vmvault_dump_vmcb(struct vmvault_vmcb *vmcb) {
	vmvault_log_msg("=============\n");
	vmvault_log_msg("Control:\n");
	vmvault_log_msg("CR read: %.16llx\n", *(__u64 *)&vmcb->control.cr_rd_intercepts);
	vmvault_log_msg("CR write: %.16llx\n", *(__u64 *)&vmcb->control.cr_wr_intercepts);
	vmvault_log_msg("exitcode: %.16llx\n", *(__u64 *)&vmcb->control.exitcode);
	vmvault_log_msg("exitinfo_v1: %.16llx\n", *(__u64 *)&vmcb->control.exitinfo_v1);
	vmvault_log_msg("exitinfo_v2: %.16llx\n", *(__u64 *)&vmcb->control.exitinfo_v2);
	vmvault_log_msg("exitintinfo: %.16llx\n", *(__u64 *)&vmcb->control.exitintinfo);
	vmvault_log_msg("nRIP: %.16llx\n", *(__u64 *)&vmcb->control.nRIP);
	vmvault_log_msg("ncr3: %.16llx\n", *(__u64 *)&vmcb->control.ncr3);
	vmvault_log_msg("num bytes fetched: %.16llx\n", *(__u64 *)&vmcb->control.num_bytes_fetched);
	vmvault_log_msg("\nSave:\n");
	vmvault_log_msg("cr0: %.16llx\n", *(__u64 *)&vmcb->save.cr0);
	vmvault_log_msg("cr2: %.16llx\n", *(__u64 *)&vmcb->save.cr2);
	vmvault_log_msg("cr3: %.16llx\n", *(__u64 *)&vmcb->save.cr3);
	vmvault_log_msg("cr4: %.16llx\n", *(__u64 *)&vmcb->save.cr4);
	vmvault_log_msg("rax: %.16llx\n", *(__u64 *)&vmcb->save.rax);
	vmvault_log_msg("rip: %.16llx\n", *(__u64 *)&vmcb->save.rip);
	vmvault_log_msg("rsp: %.16llx\n", *(__u64 *)&vmcb->save.rsp);
	vmvault_log_msg("=============\n");
}

void vmvault_run_tests(struct vmvault_context *ctx) {
	uint8_t *iv_page;
	uint8_t *key_page;
	uint8_t *data_page;
	uint8_t *output_page;
	size_t i;
	uint16_t contextId;
	VmVaultReturnResult ret;

	key_page = kzalloc(0x1000, GFP_KERNEL);
	BUG_ON(!key_page);
	iv_page = kzalloc(0x1000, GFP_KERNEL);
	BUG_ON(!iv_page);
	data_page = kzalloc(0x1000, GFP_KERNEL);
	BUG_ON(!data_page);
	output_page = kzalloc(0x1000, GFP_KERNEL);
	BUG_ON(!output_page);

	{
		// Send valid keys.
		uint16_t contextIdCounter = 0;
		const uint16_t all_key_sizes[] = {16, 24, 32};
		for (i = 0; i < sizeof(all_key_sizes) / sizeof(all_key_sizes[0]); ++i) {
			const size_t keylen = all_key_sizes[i];
			ret = registerContext(gva_to_gpa(&key_page[0]), keylen, 0, 0, &contextId);
			BUG_ON(ret != VmVaultReturnResult_Ok);
			BUG_ON(contextIdCounter != contextId);
			++contextIdCounter;
		}

		// Destroy the keys.
		ret = removeContext(0);
		BUG_ON(ret != VmVaultReturnResult_Ok);
		ret = removeContext(1);
		BUG_ON(ret != VmVaultReturnResult_Ok);
		ret = removeContext(2);
		BUG_ON(ret != VmVaultReturnResult_Ok);
	}

	// Send an invalid key
	{
		ret = registerContext(gva_to_gpa(&key_page[0]), 100, 0, 0, &contextId);
		BUG_ON(ret == VmVaultReturnResult_Ok);
		ret = registerContext(gva_to_gpa(&key_page[0]), (uint16_t)-1, 0, 0, &contextId);
		BUG_ON(ret == VmVaultReturnResult_Ok);
		ret = registerContext(gva_to_gpa(&key_page[0]), 0, 0, 0, &contextId);
		BUG_ON(ret == VmVaultReturnResult_Ok);
	}

	// Check iv
	{
		ret = registerContext(gva_to_gpa(&key_page[0]), 16, gva_to_gpa(&iv_page[0]), 32, &contextId);
		BUG_ON(ret == VmVaultReturnResult_Ok);

		ret = registerContext(gva_to_gpa(&key_page[0]), 16, gva_to_gpa(&iv_page[0]), 16, &contextId);
		BUG_ON(ret != VmVaultReturnResult_Ok);
		ret = removeContext(contextId);
		BUG_ON(ret != VmVaultReturnResult_Ok);

		ret = registerContext(gva_to_gpa(&key_page[0]), 16, gva_to_gpa(&iv_page[0]), 4U, &contextId);
		BUG_ON(ret == VmVaultReturnResult_Ok);
	}

	{
		// Try to delete unexisting keys.
		ret = removeContext(1337);
		BUG_ON(ret == VmVaultReturnResult_Ok);
		ret = removeContext(13);
		BUG_ON(ret == VmVaultReturnResult_Ok);

		// Try to fill up keys.
		for (i = 0; true; ++i) {
			ret = registerContext(gva_to_gpa(&key_page[0]), 16, 0, 0, &contextId);
			if (ret != VmVaultReturnResult_Ok) {
				break;
			}
		}
		ret = registerContext(gva_to_gpa(&key_page[0]), 16, 0, 0, &contextId);
		BUG_ON(ret == VmVaultReturnResult_Ok);

		for (i = 0; true; ++i) {
			ret = removeContext(i);
			if (ret != VmVaultReturnResult_Ok) {
				break;
			}
		}
	}

	{
		/* EBC tests */
		// Small block
		{
			uint8_t expected[] =
				{ 0x31U, 0xe3U, 0x3aU, 0x6eU, 0x52U, 0x50U, 0x90U, 0x9aU, 0x7eU, 0x51U, 0x8cU, 0xe7U, 0x6dU, 0x2cU, 0x9fU, 0x79U };
			for (i = 0; i < 16; ++i) {
				key_page[i] = 0x41U;
			}
			ret = registerContext(gva_to_gpa(key_page), 16, 0, 0, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));

			for (i = 0; i < 16; ++i) {
				data_page[i] = 0x42U;
			}
			ret = encryptDataSingleSgEntry(contextId, VmVaultCipher_AesEcb, gva_to_gpa(data_page), 16, gva_to_gpa(output_page));
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(memcmp(output_page, expected, 16) == 0));

			for (i = 0; i < 16; ++i) {
				key_page[i] = 0x41U;
			}
			ret = registerContext(gva_to_gpa(key_page), 16, 0, 0, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));

			ret = decryptDataSingleSgEntry(contextId, VmVaultCipher_AesEcb, gva_to_gpa(data_page), 16, gva_to_gpa(&output_page[16]));
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(memcmp(output_page, &output_page[0], 16) == 0));
		}

		// Multiple blocks
		{
			uint8_t expected[] = { 0x5bU, 0xe8U, 0x7eU, 0x2eU, 0x5bU, 0x44U, 0x7cU, 0x94U, 0x4bU, 0x21U, 0xc9U, 0xafU, 0x77U, 0x56U, 0xc0U, 0xd8U, 0x3U, 0xf2U, 0xc3U, 0xbdU, 0xcaU, 0x82U, 0x6bU, 0xf0U, 0x82U, 0xd7U, 0xcfU, 0xb0U, 0x35U, 0xcdU, 0xb8U, 0xc1U, 0xd5U, 0x33U, 0xe5U, 0x9bU, 0x45U, 0xa1U, 0x53U, 0xedU, 0x7eU, 0x5eU, 0x9cU, 0x5dU, 0xfcU, 0xfdU, 0x4aU, 0xaaU, 0x3eU, 0xf0U, 0xb1U, 0xa5U, 0xe3U, 0x5U, 0x9dU, 0xabU, 0x21U, 0xfcU, 0xe2U, 0x3aU, 0x7bU, 0x61U, 0xc4U, 0xcaU, 0xadU, 0xdeU, 0x68U, 0xf7U, 0xadU, 0x49U, 0x72U, 0x68U, 0xd3U, 0x1aU, 0xdU, 0xddU, 0x5cU, 0x74U, 0xb0U, 0x8fU, 0x3dU, 0x2dU, 0x90U, 0xdcU, 0xefU, 0x49U, 0xd3U, 0x28U, 0x22U, 0x29U, 0x8bU, 0x87U, 0x8fU, 0x81U, 0x55U, 0x81U };
			for (i = 0; i < 16; ++i) {
				key_page[i] = i;
			}
			for (i = 0; i < 96; ++i) {
				data_page[i] = i + 32;
			}

			ret = registerContext(gva_to_gpa(key_page), 16, 0, 0, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));
			ret = encryptDataSingleSgEntry(contextId, VmVaultCipher_AesEcb, gva_to_gpa(data_page), 96, gva_to_gpa(output_page));
			BUG_ON(!(memcmp(output_page, expected, 96) == 0));

			for (i = 0; i < 16; ++i) {
				key_page[i] = i;
			}
			ret = registerContext(gva_to_gpa(key_page), 16, 0, 0, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));
			ret = decryptDataSingleSgEntry(contextId, VmVaultCipher_AesEcb, gva_to_gpa(output_page), 96, gva_to_gpa(&output_page[96]));
			BUG_ON(!(memcmp(data_page, &output_page[96], 96) == 0));
		}
	}

		// Invalid block size
		{
			ret = registerContext(gva_to_gpa(key_page), 16, 0, 0, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));
			ret = encryptDataSingleSgEntry(contextId, VmVaultCipher_AesEcb, gva_to_gpa(data_page), 44, gva_to_gpa(output_page));
			BUG_ON(!(ret != VmVaultReturnResult_Ok));

			ret = decryptDataSingleSgEntry(contextId, VmVaultCipher_AesEcb, gva_to_gpa(data_page), 44, gva_to_gpa(output_page));
			BUG_ON(!(ret != VmVaultReturnResult_Ok));
		}

		/* CBC tests */
		// Single block
		{
			const uint8_t expected[] = { 0xaaU, 0x1aU, 0x18U, 0xffU, 0x55U, 0x61U, 0x5fU, 0x61U, 0x22U, 0xf2U, 0x87U, 0x48U, 0x65U, 0xc8U, 0x1bU, 0xfcU };
			memset(key_page, 0x41, 16);
			memset(iv_page, 0x42, 16);
			memset(data_page, 0x43, 16);
			ret = registerContext(gva_to_gpa(key_page), 16, gva_to_gpa(iv_page), 16, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));
			ret = encryptDataSingleSgEntry(contextId, VmVaultCipher_AesCbc, gva_to_gpa(data_page), 16, gva_to_gpa(output_page));
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(memcmp(output_page, expected, 16) == 0));

			ret = registerContext(gva_to_gpa(key_page), 16, gva_to_gpa(iv_page), 16, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			ret = decryptDataSingleSgEntry(contextId, VmVaultCipher_AesCbc, gva_to_gpa(output_page), 16, gva_to_gpa(&output_page[16]));
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(memcmp(&output_page[16], data_page, 16) == 0));
		}

		// Multiple blocks
		{
			const uint8_t expected[] =
			{ 0xaaU, 0x1aU, 0x18U, 0xffU, 0x55U, 0x61U, 0x5fU, 0x61U, 0x22U, 0xf2U, 0x87U, 0x48U, 0x65U, 0xc8U, 0x1bU, 0xfcU, 0xf9U, 0xcbU, 0x40U, 0xedU, 0xf6U, 0x4eU, 0xd0U, 0x2dU, 0x9dU, 0x31U, 0x72U, 0x42U, 0xd1U, 0xf2U, 0x5aU, 0x0U, 0x9bU, 0x94U, 0xd5U, 0x38U, 0xeeU, 0x37U, 0x46U, 0x51U, 0xf3U, 0x69U, 0x53U, 0x98U, 0x10U, 0xeeU, 0xe4U, 0xa9U, 0x5bU, 0xc8U, 0xa3U, 0xfdU, 0x98U, 0xdbU, 0x29U, 0x15U, 0x55U, 0xd3U, 0xa8U, 0x7aU, 0x4bU, 0xadU, 0x5U, 0x49U, 0x22U, 0xdU, 0x84U, 0x7U, 0x7cU, 0x59U, 0xeeU, 0xeaU, 0x20U, 0x2U, 0xdeU, 0x79U, 0x6bU, 0x34U, 0xaaU, 0x7dU, 0xeU, 0xafU, 0x57U, 0x3eU, 0x9bU, 0x11U, 0x98U, 0xb1U, 0xf8U, 0xb7U, 0x84U, 0x81U, 0x16U, 0xefU, 0xbcU, 0x32U };
			memset(key_page, 0x41, 16);
			memset(iv_page, 0x42, 16);
			memset(data_page, 0x43, 96);
			ret = registerContext(gva_to_gpa(key_page), 16, gva_to_gpa(iv_page), 16, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));
			ret = encryptDataSingleSgEntry(contextId, VmVaultCipher_AesCbc, gva_to_gpa(data_page), 96, gva_to_gpa(output_page));
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(memcmp(output_page, expected, 96) == 0));

			ret = registerContext(gva_to_gpa(key_page), 16, gva_to_gpa(iv_page), 16, &contextId);
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(contextId >= 0));
			ret = decryptDataSingleSgEntry(contextId, VmVaultCipher_AesCbc, gva_to_gpa(output_page), 96, gva_to_gpa(&output_page[96]));
			BUG_ON(!(ret == VmVaultReturnResult_Ok));
			BUG_ON(!(memcmp(&output_page[96], data_page, 96) == 0));
		}
}

#endif // VMVAULT_DEBUG_H
