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

#include "sevault-mini-communication-block.h"
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
static inline void reportResult(SevaultMiniCommunicationBlock &commBlock, SevaultMiniReturnResult result, const char (&message)[size]) {
	if constexpr (buildFlavor == SevaultMiniBuildFlavor_Debug) {
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

static inline SevaultMiniReturnResult removeContext(SevaultMiniCommunicationBlock &commBlock) {
	ScopedRWLock scopedLock { contextKeyLock };

	const auto &removeContextView { retrieveRemoveCipherContextView(&commBlock) };
	if (removeContextView.contextId >= kMaxNumCipherContexts) {
		return SevaultMiniReturnResult_InvalidContextId;
	}

	CipherContext &cipherContext { cipherContexts[removeContextView.contextId] };
	if (!cipherContext.isActive()) {
		return SevaultMiniReturnResult_KeyAlreadyRemoved;
	}
	cipherContext.invalidate();
	--numCipherContexts;

	return SevaultMiniReturnResult_Ok;
}

static inline SevaultMiniReturnResult registerContext(SevaultMiniCommunicationBlock &commBlock) {
	ScopedRWLock scopedLock { contextKeyLock };

	if (numCipherContexts >= kMaxNumCipherContexts) {
		return SevaultMiniReturnResult_KeyStoreOutOfSpace;
	}
	const auto &contextView { retrieveSetCipherContextView(&commBlock) };
	if (contextView.keyLenInBytes != 16UL &&
		contextView.keyLenInBytes != 24UL &&
		contextView.keyLenInBytes != 32UL) {
		return SevaultMiniReturnResult_InvalidSourceSize;
	}

	if (contextView.ivLenInBytes > 0U && contextView.ivLenInBytes != contextView.keyLenInBytes) {
		return SevaultMiniReturnResult_InvalidIvLen;
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
			return SevaultMiniReturnResult_Ok;
		}
	}

	return SevaultMiniReturnResult_NoFreeKeySlot;
}

template<SevaultMiniOperation op>
static inline SevaultMiniReturnResult encDecData(SevaultMiniCommunicationBlock &commBlock) {
	const auto &encryptView { retrieveEncryptDataView(&commBlock) };
	if (encryptView.contextId >= kMaxNumCipherContexts) {
		return SevaultMiniReturnResult_InvalidContextId;
	}

	if (encryptView.encDecSgList.numRanges == 0) {
		return SevaultMiniReturnResult_InvalidNumRanges;
	}

	// Get key for the operation.
	auto &context { cipherContexts[encryptView.contextId] };

	if (!context.isActive()) {
		return SevaultMiniReturnResult_ContextNotActive;
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
			return SevaultMiniReturnResult_InvalidLength;
		}
		const u8 *input { reinterpret_cast<const u8 *>(inputGva) };
		u8 *output { reinterpret_cast<u8 *>(outputGva) };
		if (outputGva + length < outputGva) {
			return SevaultMiniReturnResult_InvalidEncDecSize;
		}
		if (inputGva + length < inputGva) {
			return SevaultMiniReturnResult_InvalidEncDecSize;
		}
		if (length % context.getKeyLen() != 0U) {
			return SevaultMiniReturnResult_InvalidEncDecSize;
		}

		switch (encryptView.cipherType) {
			case SevaultMiniCipher_AesEcb:
				if constexpr (op == SevaultMiniOperation_EncryptData) {
					aesEncrypt<SevaultMiniCipher_AesEcb>(input, output, length, context.getAesContext());
				}
				else if constexpr (op == SevaultMiniOperation_DecryptData) {
					aesDecrypt<SevaultMiniCipher_AesEcb>(input, output, length, context.getAesContext());
				}
				break;
			case SevaultMiniCipher_AesCbc:
				if constexpr (op == SevaultMiniOperation_EncryptData) {
					aesEncrypt<SevaultMiniCipher_AesCbc>(input, output, length, context.getAesContext());
				}
				else if constexpr (op == SevaultMiniOperation_DecryptData) {
					aesDecrypt<SevaultMiniCipher_AesCbc>(input, output, length, context.getAesContext());
				}
				break;
			default:
				return SevaultMiniReturnResult_InvalidCipher;
		}
	}

	return SevaultMiniReturnResult_Ok;
}

void entry(unsigned long vcpu_id) {
	SevaultMiniCommunicationBlock &commBlock
	{ *reinterpret_cast<SevaultMiniCommunicationBlock *>(kSevaultMiniCommunicationBlockGpa + 0x1000UL * vcpu_id) };

	if (!initDone) {
		if (getOperationType(&commBlock) != SevaultMiniOperation_Init) {
			reportResult(commBlock, SevaultMiniReturnResult_InitFail, "Init failed");
			hard_failure();
		}
		numCipherContexts = 0;
		contextKeyLock.init();
		for (size_t i {}; i < kMaxNumCipherContexts; ++i) {
			cipherContexts[i].invalidate();
		}
		initDone = true;
		reportResult(commBlock, SevaultMiniReturnResult_Ok, "Init done");
	}

	SevaultMiniReturnResult returnValue;
	while (1) {
		switch(getOperationType(&commBlock)) {
			case SevaultMiniOperation_RegisterContext:
				returnValue = registerContext(commBlock);
				break;
			case SevaultMiniOperation_RemoveContext:
				returnValue = removeContext(commBlock);
				break;
			case SevaultMiniOperation_EncryptData:
				returnValue = encDecData<SevaultMiniOperation_EncryptData>(commBlock);
				break;
			case SevaultMiniOperation_DecryptData:
				returnValue = encDecData<SevaultMiniOperation_DecryptData>(commBlock);
				break;
			default:
				returnValue = SevaultMiniReturnResult_Fail;
				break;
		}
		reportResult(commBlock, returnValue, "");
	}
}

extern "C"
void _start(uint16_t vcpu_id) {
	entry(vcpu_id);
	hlt();
}
