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
			hlt();
		}
		mAesContext.initContext(key, keyLength, iv);
		mKeyLen = keyLength;
		mIvLen = ivLength;
		mState = KeyState::Active;
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
	AesContext mAesContext { };
	ContextIdDataType mKeyLen { };
	uint16_t mIvLen { };
	KeyState mState { KeyState::Inactive };
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
static RWLock contextKeyLock {};
static CipherContext *const cipherContexts { reinterpret_cast<CipherContext *>(0x20000UL) };
static u16 numCipherContexts { };
static u16 initDone { std::numeric_limits<u16>::max() };

static inline void removeContext(SevaultMiniCommunicationBlock &commBlock) {
	ScopedRWLock scopedLock { contextKeyLock };

	const auto &removeContextView { retrieveRemoveCipherContextView(&commBlock) };
	if (removeContextView.contextId >= kMaxNumCipherContexts) {
		reportResult(commBlock, SevaultMiniReturnResult_InvalidContextId, "Invalid context id");
		return;
	}

	auto &cipherContext { cipherContexts[removeContextView.contextId] };
	if (!cipherContext.isActive()) {
		reportResult(commBlock, SevaultMiniReturnResult_KeyAlreadyRemoved, "Key was already removed");
		return;
	}
	cipherContext.invalidate();
	--numCipherContexts;

	reportResult(commBlock, SevaultMiniReturnResult_Ok, "Key was removed");
}

static inline void registerContext(SevaultMiniCommunicationBlock &commBlock) {
	ScopedRWLock scopedLock { contextKeyLock };

	if (numCipherContexts >= kMaxNumCipherContexts) {
		reportResult(commBlock, SevaultMiniReturnResult_KeyStoreOutOfSpace, "No available key slots");
		return;
	}
	const auto &contextView { retrieveSetCipherContextView(&commBlock) };
	if (contextView.keyLenInBytes != 16UL &&
		contextView.keyLenInBytes != 24UL &&
		contextView.keyLenInBytes != 32UL) {
		reportResult(commBlock, SevaultMiniReturnResult_InvalidSourceSize, "Keylen is invalid");
		return;
	}

	if (contextView.ivLenInBytes > 0U && contextView.ivLenInBytes != contextView.keyLenInBytes) {
		reportResult(commBlock, SevaultMiniReturnResult_InvalidIvLen, "iv len is greater than key len");
		return;
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
			reportResult(commBlock, SevaultMiniReturnResult_Ok, "Key registered");
			return;
		}
	}

	reportResult(commBlock, SevaultMiniReturnResult_NoFreeKeySlot, "Could not find a free key slot");
}

template<SevaultMiniOperation op>
static inline void encDecData(SevaultMiniCommunicationBlock &commBlock) {
	const auto &encryptView { retrieveEncryptDataView(&commBlock) };
	if (encryptView.contextId >= numCipherContexts) {
		reportResult(commBlock, SevaultMiniReturnResult_InvalidContextId, "Invalid context id");
		return;
	}

	if (encryptView.encDecSgList.numRanges == 0) {
		reportResult(commBlock, SevaultMiniReturnResult_Fail, "Invalid num ranges");
		return;
	}

	// Get key for the operation.
	auto &context { cipherContexts[encryptView.contextId] };

	for (size_t i {}; i < encryptView.encDecSgList.numRanges; ++i) {
		const auto &range { encryptView.encDecSgList.ranges[i] };
		const u64 inputGva { reinterpret_cast<u64>(&host_memory[range.srcPhysAddr]) };
		const u64 outputGva { reinterpret_cast<u64>(&host_memory[range.dstPhysAddr]) };
		const u32 length { range.length };

		if (length == 0) {
			reportResult(commBlock, SevaultMiniReturnResult_Fail, "Invalid length");
			return;
		}
		const u8 *input { reinterpret_cast<const u8 *>(inputGva) };
		u8 *output { reinterpret_cast<u8 *>(outputGva) };
		if (outputGva + length < outputGva) {
			reportResult(commBlock, SevaultMiniReturnResult_InvalidEncDecSize, "Invalid output gva");
			return;
		}
		if (inputGva + length < inputGva) {
			reportResult(commBlock, SevaultMiniReturnResult_InvalidEncDecSize, "Invalid input gva");
			return;
		}
		if (length % context.getKeyLen() != 0U) {
			reportResult(commBlock, SevaultMiniReturnResult_InvalidEncDecSize, "Input size is not multiple of block size");
			return;
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
				reportResult(commBlock, SevaultMiniReturnResult_InvalidCipher, "Unknown cipher");
				return;
		}
	}

	reportResult(commBlock, SevaultMiniReturnResult_Ok, "Enc/dec done");
}

void entry(unsigned long vcpu_id) {
	SevaultMiniCommunicationBlock &commBlock
	{ *reinterpret_cast<SevaultMiniCommunicationBlock *>(kSevaultMiniCommunicationBlockGpa + 0x1000UL * vcpu_id) };

	// FIXME: again another hack for when initDone would be put in .bss
	if (initDone == std::numeric_limits<u16>::max()) {
		// FIXME: We have to manually zero it out. Does it get placed in bss?
		numCipherContexts = 0;
		contextKeyLock.init();
		for (size_t i {}; i < kMaxNumCipherContexts; ++i) {
			cipherContexts[i].invalidate();
		}
		initDone = 0;
		if (getOperationType(&commBlock) != SevaultMiniOperation_Init) {
			reportResult(commBlock, SevaultMiniReturnResult_Fail, "Init failed");
			while(1) {
				hlt();
			}
		} else {
			reportResult(commBlock, SevaultMiniReturnResult_Ok, "Init done");
		}
	}

	while (1) {
		switch(getOperationType(&commBlock)) {
			case SevaultMiniOperation_RegisterContext:
				registerContext(commBlock);
				break;
			case SevaultMiniOperation_RemoveContext:
				removeContext(commBlock);
				break;
			case SevaultMiniOperation_EncryptData:
				encDecData<SevaultMiniOperation_EncryptData>(commBlock);
				break;
			case SevaultMiniOperation_DecryptData:
				encDecData<SevaultMiniOperation_DecryptData>(commBlock);
				break;
			default:
				hlt();
				break;
		}
	}
}

extern "C"
void _start(uint16_t vcpu_id) {
	entry(vcpu_id);
	hlt();
}
