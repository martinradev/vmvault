#include "aes.h"

#include "mini-svm-communication-block.h"
#include "hv-microbench-structures.h"

#include <cstring>

#include "util.h"

static const MiniSvmCommunicationBlock::ContextIdDataType MaxKeyLengthInBytes { 32U };
static u8 *host_memory { reinterpret_cast<u8 *>(1024UL * 1024UL * 1024UL) };

static MiniSvmCommunicationBlock &commBlock
	{ *reinterpret_cast<MiniSvmCommunicationBlock *>(kMiniSvmCommunicationBlockGpa) };

class CipherContext {
public:
	void reset(const u8 *key,
			   MiniSvmCommunicationBlock::ContextIdDataType keyLength,
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

	const MiniSvmCommunicationBlock::ContextIdDataType getKeyLen() const {
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
	MiniSvmCommunicationBlock::ContextIdDataType mKeyLen { };
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

template<size_t Size>
static inline void reportResult(MiniSvmReturnResult result, const char (&message)[Size]) {
	if constexpr (buildFlavor == MiniSvmBuildFlavor::Debug) {
		commBlock.writeDebugMessage<Size>(message);
	}
	commBlock.setResult(result);
	vmgexit();
}

static const u16 kMaxNumCipherContexts { 0xF000UL / sizeof(CipherContext) };
CipherContext *const cipherContexts { reinterpret_cast<CipherContext *>(0x20000UL) };
static u16 numCipherContexts { };

static inline void removeContext() {
	const auto &removeContextView { commBlock.retrieveRemoveCipherContextView() };
	if (removeContextView.contextId >= kMaxNumCipherContexts) {
		reportResult(MiniSvmReturnResult::InvalidContextId, "Invalid context id");
		return;
	}

	auto &cipherContext { cipherContexts[removeContextView.contextId] };
	if (!cipherContext.isActive()) {
		reportResult(MiniSvmReturnResult::KeyAlreadyRemoved, "Key was already removed");
		return;
	}
	cipherContext.invalidate();
	--numCipherContexts;

	reportResult(MiniSvmReturnResult::Ok, "Key was removed");
}

static inline void registerContext() {
	if (numCipherContexts >= kMaxNumCipherContexts) {
		reportResult(MiniSvmReturnResult::KeyStoreOutOfSpace, "No available key slots");
		return;
	}
	const auto &contextView { commBlock.retrieveSetCipherContextView() };
	if (contextView.keyLenInBytes != 16UL &&
		contextView.keyLenInBytes != 24UL &&
		contextView.keyLenInBytes != 32UL) {
		reportResult(MiniSvmReturnResult::InvalidSourceSize, "Keylen is invalid");
		return;
	}

	if (contextView.ivLenInBytes > 0U && contextView.ivLenInBytes != contextView.keyLenInBytes) {
		reportResult(MiniSvmReturnResult::InvalidIvLen, "iv len is greater than key len");
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
			commBlock.setContextId(i);
			++numCipherContexts;
			reportResult(MiniSvmReturnResult::Ok, "Key registered");
			return;
		}
	}

	reportResult(MiniSvmReturnResult::NoFreeKeySlot, "Could not find a free key slot");
}

static inline void encryptData() {
	const auto &encryptView { commBlock.retrieveEncryptDataView() };
	if (encryptView.contextId >= numCipherContexts) {
		reportResult(MiniSvmReturnResult::InvalidContextId, "Invalid context id");
		return;
	}

	// Get key for the operation.
	auto &context { cipherContexts[encryptView.contextId] };

	const u64 inputGva { reinterpret_cast<u64>(&host_memory[encryptView.inputHpa]) };
	const u64 outputGva { reinterpret_cast<u64>(&host_memory[encryptView.outputHpa]) };
	const u8 *input { reinterpret_cast<const u8 *>(inputGva) };
	u8 *output { reinterpret_cast<u8 *>(outputGva) };
	if (outputGva + encryptView.inputSize < outputGva) {
		reportResult(MiniSvmReturnResult::InvalidEncDecSize, "Invalid output gva");
		return;
	}
	if (inputGva + encryptView.inputSize < inputGva) {
		reportResult(MiniSvmReturnResult::InvalidEncDecSize, "Invalid input gva");
		return;
	}
	if (encryptView.inputSize % context.getKeyLen() != 0U) {
		reportResult(MiniSvmReturnResult::InvalidEncDecSize, "Input size is not multiple of block size");
		return;
	}

	switch (encryptView.cipherType) {
		case MiniSvmCipher::AesEcb:
			aesEncrypt<MiniSvmCipher::AesEcb>(input, output, encryptView.inputSize, context.getAesContext());
			break;
		case MiniSvmCipher::AesCbc:
			aesEncrypt<MiniSvmCipher::AesCbc>(input, output, encryptView.inputSize, context.getAesContext());
			break;
		default:
			reportResult(MiniSvmReturnResult::InvalidCipher, "Unknown cipher");
			return;
	}

	reportResult(MiniSvmReturnResult::Ok, "Enc/dec done");
}

void entry() {
	if (commBlock.getOperationType() != MiniSvmOperation::Init) {
		hlt();
	}
	reportResult(MiniSvmReturnResult::Ok, "Init done");

	while (1) {
		switch(commBlock.getOperationType()) {
			case MiniSvmOperation::RegisterContext:
				registerContext();
				break;
			case MiniSvmOperation::RemoveContext:
				removeContext();
				break;
			case MiniSvmOperation::EncryptData:
				encryptData();
				break;
			case MiniSvmOperation::DecryptData:
				hlt();
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
