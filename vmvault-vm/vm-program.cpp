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

#include "aes.h"

#include <cstring>
#include <limits>

#include "vmvault-communication-block.h"
#include "util.h"

static const ContextIdDataType MaxKeyLengthInBytes { 32U };
static u8 *host_memory { reinterpret_cast<u8 *>(1024UL * 1024UL * 1024UL) };

class CipherContext {
public:
	void reset(const u8 *key,
			   ContextIdDataType keyLength,
			   const u8 *iv,
			   uint16_t ivLength) {
		if (keyLength > MaxKeyLengthInBytes || ivLength > MaxKeyLengthInBytes) {
			// This should never be reached with proper sanitization.
			hard_failure();
		}
		mAesContext.initContext(key, keyLength, iv);
		mKeyLen = keyLength;
		mIvLen = ivLength;
		mState = KeyState::Active;
	}

	void updateIv(const u8 *iv, uint16_t ivLength) {
		if (ivLength > MaxKeyLengthInBytes) {
			// This should never be reached with proper sanitization.
			hard_failure();
		}
		mAesContext.updateIv(iv, ivLength);
		mIvLen = ivLength;
	}

	const ContextIdDataType getKeyLen() const {
		return mKeyLen;
	}

	const uint16_t getIvLen() const {
		return mIvLen;
	}

	void invalidate() {
		mState = KeyState::Inactive;
		mKeyLen = 0;
		mIvLen = 0;
		mAesContext.invalidate();
	}

	bool isActive() const {
		return mState == KeyState::Active;
	}

	AesContext &getAesContext() {
		return mAesContext;
	}

private:
	enum class KeyState {
		Inactive,
		Active,
	};

private:
	AesContext mAesContext;
	ContextIdDataType mKeyLen;
	uint16_t mIvLen;
	KeyState mState;
};

static void read_host_memory(const u64 hpa, void *out, size_t sz) {
	memcpy(out, &host_memory[hpa], sz);
}

template<typename T>
static void read_host_memory(const u64 hpa, T &out) {
	read_host_memory(hpa, (void *)&out, sizeof(T));
}

template<size_t size>
static inline void reportResult(VmVaultCommunicationBlock &commBlock, VmVaultReturnResult result, const char (&message)[size]) {
	if constexpr (buildFlavor == VmVaultBuildFlavor_Debug) {
		writeDebugMessage(&commBlock, message, size);
	}
	setResult(&commBlock, result);
	vmgexit();
}

static const u16 kMaxNumCipherContexts { 0xF000UL / sizeof(CipherContext) };
static CipherContext *const cipherContexts { reinterpret_cast<CipherContext *>(0x20000UL) };
static RWLock contextKeyLock;
static u16 numCipherContexts;
static u16 initDone;

static inline VmVaultReturnResult removeContext(VmVaultCommunicationBlock &commBlock) {
	ScopedRWLock scopedLock { contextKeyLock };

	const auto &removeContextView { retrieveRemoveCipherContextView(&commBlock) };
	if (removeContextView.contextId >= kMaxNumCipherContexts) {
		return VmVaultReturnResult_InvalidContextId;
	}

	CipherContext &cipherContext { cipherContexts[removeContextView.contextId] };
	if (!cipherContext.isActive()) {
		return VmVaultReturnResult_KeyAlreadyRemoved;
	}
	cipherContext.invalidate();
	--numCipherContexts;

	return VmVaultReturnResult_Ok;
}

static inline VmVaultReturnResult registerContext(VmVaultCommunicationBlock &commBlock) {
	ScopedRWLock scopedLock { contextKeyLock };

	if (numCipherContexts >= kMaxNumCipherContexts) {
		return VmVaultReturnResult_KeyStoreOutOfSpace;
	}
	const auto &contextView { retrieveSetCipherContextView(&commBlock) };
	if (contextView.keyLenInBytes != 16UL &&
		contextView.keyLenInBytes != 24UL &&
		contextView.keyLenInBytes != 32UL) {
		return VmVaultReturnResult_InvalidSourceSize;
	}

	if (contextView.ivLenInBytes > 0U && contextView.ivLenInBytes != contextView.keyLenInBytes) {
		return VmVaultReturnResult_InvalidIvLen;
	}

	// Find free key
	for (u16 i {} ; i < kMaxNumCipherContexts; ++i) {
		auto &cipherContext { cipherContexts[i] };
		if (!cipherContext.isActive()) {
			cipherContext.reset(
				&host_memory[contextView.keyHpa],
				contextView.keyLenInBytes,
				&host_memory[contextView.ivHpa],
				contextView.ivLenInBytes);
			setContextId(&commBlock, i);
			++numCipherContexts;
			return VmVaultReturnResult_Ok;
		}
	}

	return VmVaultReturnResult_NoFreeKeySlot;
}

template<VmVaultOperation op>
static inline VmVaultReturnResult encDecData(VmVaultCommunicationBlock &commBlock) {
	const auto &encryptView { retrieveEncryptDataView(&commBlock) };
	if (encryptView.contextId >= kMaxNumCipherContexts) {
		return VmVaultReturnResult_InvalidContextId;
	}

	if (encryptView.encDecSgList.numRanges == 0) {
		return VmVaultReturnResult_InvalidNumRanges;
	}

	// Get key for the operation.
	auto &context { cipherContexts[encryptView.contextId] };

	if (!context.isActive()) {
		return VmVaultReturnResult_ContextNotActive;
	}

	if (encryptView.ivLenInBytes > 0) {
		context.updateIv(&host_memory[encryptView.ivHpa], encryptView.ivLenInBytes);
	}

	for (size_t i {}; i < encryptView.encDecSgList.numRanges; ++i) {
		const auto &range { encryptView.encDecSgList.ranges[i] };
		const u64 inputGva { reinterpret_cast<u64>(&host_memory[range.srcPhysAddr]) };
		const u64 outputGva { reinterpret_cast<u64>(&host_memory[range.dstPhysAddr]) };
		const u32 length { range.length };

		if (length == 0) {
			return VmVaultReturnResult_InvalidLength;
		}
		const u8 *input { reinterpret_cast<const u8 *>(inputGva) };
		u8 *output { reinterpret_cast<u8 *>(outputGva) };
		if (outputGva + length < outputGva) {
			return VmVaultReturnResult_InvalidEncDecSize;
		}
		if (inputGva + length < inputGva) {
			return VmVaultReturnResult_InvalidEncDecSize;
		}
		if (length % context.getKeyLen() != 0U) {
			return VmVaultReturnResult_InvalidEncDecSize;
		}

		switch (encryptView.cipherType) {
			case VmVaultCipher_AesEcb:
				if constexpr (op == VmVaultOperation_EncryptData) {
					aesEncrypt<VmVaultCipher_AesEcb>(input, output, length, context.getAesContext());
				}
				else if constexpr (op == VmVaultOperation_DecryptData) {
					aesDecrypt<VmVaultCipher_AesEcb>(input, output, length, context.getAesContext());
				}
				break;
			case VmVaultCipher_AesCbc:
				if constexpr (op == VmVaultOperation_EncryptData) {
					aesEncrypt<VmVaultCipher_AesCbc>(input, output, length, context.getAesContext());
				}
				else if constexpr (op == VmVaultOperation_DecryptData) {
					aesDecrypt<VmVaultCipher_AesCbc>(input, output, length, context.getAesContext());
				}
				break;
			default:
				return VmVaultReturnResult_InvalidCipher;
		}
	}

	return VmVaultReturnResult_Ok;
}

void entry(unsigned long vcpu_id) {
	VmVaultCommunicationBlock &commBlock
	{ *reinterpret_cast<VmVaultCommunicationBlock *>(kVmVaultCommunicationBlockGpa + 0x1000UL * vcpu_id) };

	if (!initDone) {
		if (getOperationType(&commBlock) != VmVaultOperation_Init) {
			reportResult(commBlock, VmVaultReturnResult_InitFail, "Init failed");
			hard_failure();
		}
		numCipherContexts = 0;
		contextKeyLock.init();
		for (size_t i {}; i < kMaxNumCipherContexts; ++i) {
			cipherContexts[i].invalidate();
		}
		initDone = true;
		reportResult(commBlock, VmVaultReturnResult_Ok, "Init done");
	}

	VmVaultReturnResult returnValue;
	while (1) {
		switch(getOperationType(&commBlock)) {
			case VmVaultOperation_RegisterContext:
				returnValue = registerContext(commBlock);
				break;
			case VmVaultOperation_RemoveContext:
				returnValue = removeContext(commBlock);
				break;
			case VmVaultOperation_EncryptData:
				returnValue = encDecData<VmVaultOperation_EncryptData>(commBlock);
				break;
			case VmVaultOperation_DecryptData:
				returnValue = encDecData<VmVaultOperation_DecryptData>(commBlock);
				break;
			default:
				returnValue = VmVaultReturnResult_Fail;
				break;
		}
		reportResult(commBlock, returnValue, "");
	}
}

extern "C"
void _start(uint16_t vcpu_id) {
	entry(vcpu_id);
	hard_failure();
}
