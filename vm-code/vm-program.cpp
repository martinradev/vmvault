#include "aes.h"

#include "mini-svm-communication-block.h"
#include "hv-microbench-structures.h"

#include <cstring>

#include "util.h"

static const ContextIdDataType MaxKeyLengthInBytes { 32U };
static u8 *host_memory { reinterpret_cast<u8 *>(1024UL * 1024UL * 1024UL) };

static MiniSvmCommunicationBlock &commBlock
	{ *reinterpret_cast<MiniSvmCommunicationBlock *>(kMiniSvmCommunicationBlockGpa) };

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
static inline void reportResult(MiniSvmReturnResult result, const char (&message)[size]) {
	if constexpr (buildFlavor == MiniSvmBuildFlavor_Debug) {
		writeDebugMessage(&commBlock, message, size);
	}
	setResult(&commBlock, result);
	vmgexit();
}

static const u16 kMaxNumCipherContexts { 0xF000UL / sizeof(CipherContext) };
CipherContext *const cipherContexts { reinterpret_cast<CipherContext *>(0x20000UL) };
static u16 numCipherContexts { };

static inline void removeContext() {
	const auto &removeContextView { retrieveRemoveCipherContextView(&commBlock) };
	if (removeContextView.contextId >= kMaxNumCipherContexts) {
		reportResult(MiniSvmReturnResult_InvalidContextId, "Invalid context id");
		return;
	}

	auto &cipherContext { cipherContexts[removeContextView.contextId] };
	if (!cipherContext.isActive()) {
		reportResult(MiniSvmReturnResult_KeyAlreadyRemoved, "Key was already removed");
		return;
	}
	cipherContext.invalidate();
	--numCipherContexts;

	reportResult(MiniSvmReturnResult_Ok, "Key was removed");
}

static inline void registerContext() {
	if (numCipherContexts >= kMaxNumCipherContexts) {
		reportResult(MiniSvmReturnResult_KeyStoreOutOfSpace, "No available key slots");
		return;
	}
	const auto &contextView { retrieveSetCipherContextView(&commBlock) };
	if (contextView.keyLenInBytes != 16UL &&
		contextView.keyLenInBytes != 24UL &&
		contextView.keyLenInBytes != 32UL) {
		reportResult(MiniSvmReturnResult_InvalidSourceSize, "Keylen is invalid");
		return;
	}

	if (contextView.ivLenInBytes > 0U && contextView.ivLenInBytes != contextView.keyLenInBytes) {
		reportResult(MiniSvmReturnResult_InvalidIvLen, "iv len is greater than key len");
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
			reportResult(MiniSvmReturnResult_Ok, "Key registered");
			return;
		}
	}

	reportResult(MiniSvmReturnResult_NoFreeKeySlot, "Could not find a free key slot");
}

template<MiniSvmOperation op>
static inline void encDecData() {
	const auto &encryptView { retrieveEncryptDataView(&commBlock) };
	if (encryptView.contextId >= numCipherContexts) {
		reportResult(MiniSvmReturnResult_InvalidContextId, "Invalid context id");
		return;
	}

	// Get key for the operation.
	auto &context { cipherContexts[encryptView.contextId] };

	const u64 inputGva { reinterpret_cast<u64>(&host_memory[encryptView.inputHpa]) };
	const u64 outputGva { reinterpret_cast<u64>(&host_memory[encryptView.outputHpa]) };
	const u8 *input { reinterpret_cast<const u8 *>(inputGva) };
	u8 *output { reinterpret_cast<u8 *>(outputGva) };
	if (outputGva + encryptView.inputSize < outputGva) {
		reportResult(MiniSvmReturnResult_InvalidEncDecSize, "Invalid output gva");
		return;
	}
	if (inputGva + encryptView.inputSize < inputGva) {
		reportResult(MiniSvmReturnResult_InvalidEncDecSize, "Invalid input gva");
		return;
	}
	if (encryptView.inputSize % context.getKeyLen() != 0U) {
		reportResult(MiniSvmReturnResult_InvalidEncDecSize, "Input size is not multiple of block size");
		return;
	}

	switch (encryptView.cipherType) {
		case MiniSvmCipher_AesEcb:
			if constexpr (op == MiniSvmOperation_EncryptData) {
				aesEncrypt<MiniSvmCipher_AesEcb>(input, output, encryptView.inputSize, context.getAesContext());
			}
			else if constexpr (op == MiniSvmOperation_DecryptData) {
				aesDecrypt<MiniSvmCipher_AesEcb>(input, output, encryptView.inputSize, context.getAesContext());
			}
			break;
		case MiniSvmCipher_AesCbc:
			if constexpr (op == MiniSvmOperation_EncryptData) {
				aesEncrypt<MiniSvmCipher_AesCbc>(input, output, encryptView.inputSize, context.getAesContext());
			}
			else if constexpr (op == MiniSvmOperation_DecryptData) {
				aesDecrypt<MiniSvmCipher_AesCbc>(input, output, encryptView.inputSize, context.getAesContext());
			}
			break;
		default:
			reportResult(MiniSvmReturnResult_InvalidCipher, "Unknown cipher");
			return;
	}

	reportResult(MiniSvmReturnResult_Ok, "Enc/dec done");
}

void entry() {
	if (getOperationType(&commBlock) != MiniSvmOperation_Init) {
		reportResult(MiniSvmReturnResult_Fail, "Init failed");
	} else {
		reportResult(MiniSvmReturnResult_Ok, "Init done");
	}

	while (1) {
		switch(getOperationType(&commBlock)) {
			case MiniSvmOperation_RegisterContext:
				registerContext();
				break;
			case MiniSvmOperation_RemoveContext:
				removeContext();
				break;
			case MiniSvmOperation_EncryptData:
				encDecData<MiniSvmOperation_EncryptData>();
				break;
			case MiniSvmOperation_DecryptData:
				encDecData<MiniSvmOperation_DecryptData>();
				break;
			default:
				hlt();
				break;
		}
	}
}

extern "C"
void _start() {
	entry();
	hlt();
}
