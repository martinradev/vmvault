#include "aes.h"

#include "mini-svm-communication-block.h"
#include "hv-microbench-structures.h"

#include <cstring>

#include "util.h"

static const MiniSvmCommunicationBlock::KeyDataType MaxKeyLengthInBytes { 32U };
static u8 *host_memory { reinterpret_cast<u8 *>(1024UL * 1024UL * 1024UL) };

static MiniSvmCommunicationBlock &commBlock
	{ *reinterpret_cast<MiniSvmCommunicationBlock *>(kMiniSvmCommunicationBlockGpa) };

class Key {
public:
	void reset(const u8 *key, MiniSvmCommunicationBlock::KeyDataType keyLength) {
		if (keyLength > MaxKeyLengthInBytes) {
			hlt();
		}
		memcpy(mKey.data(), key, keyLength);
		mKeyLen = keyLength;
		mState = KeyState::Active;
	}

	const u8* getKey() const {
		return mKey.data();
	}

	const MiniSvmCommunicationBlock::KeyDataType getKeyLen() const {
		return mKeyLen;
	}

	void invalidate() {
		memset(mKey.data(), 0, mKeyLen);
		mState = KeyState::Inactive;
		mKeyLen = 0;
	}

	bool isActive() const {
		return mState == KeyState::Active;
	}

private:
	enum class KeyState {
		Inactive,
		Active,
	};

private:
	std::array<u8, MaxKeyLengthInBytes> mKey;
	MiniSvmCommunicationBlock::KeyDataType mKeyLen { };
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

static const u16 kMaxKeys { 0xF000UL / sizeof(Key) };
Key *const keys { reinterpret_cast<Key *>(0x20000UL) };
static u16 numKeys { };

static inline void removeKey() {
	const auto &removeKeyView { commBlock.retrieveRemoveKeyView() };
	if (removeKeyView.keyId >= kMaxKeys) {
		reportResult(MiniSvmReturnResult::InvalidKeyId, "Invalid key id");
		return;
	}

	auto &key { keys[removeKeyView.keyId] };
	if (!key.isActive()) {
		reportResult(MiniSvmReturnResult::KeyAlreadyRemoved, "Key was already removed");
		return;
	}
	key.invalidate();
	--numKeys;

	reportResult(MiniSvmReturnResult::Ok, "Key was removed");
}

static inline void registerKey() {
	if (numKeys >= kMaxKeys) {
		reportResult(MiniSvmReturnResult::KeyStoreOutOfSpace, "No available key slots");
		return;
	}
	const auto &keyView { commBlock.retrieveSetKeyView() };
	if (keyView.keyLenInBytes != 16UL &&
		keyView.keyLenInBytes != 24UL &&
		keyView.keyLenInBytes != 32UL) {
		reportResult(MiniSvmReturnResult::InvalidSourceSize, "Keylen is invalid");
		return;
	}

	// Find free key
	for (u16 i {} ; i < kMaxKeys; ++i) {
		auto &key { keys[i] };
		if (!key.isActive()) {
			key.reset(&host_memory[keyView.keyHpa], keyView.keyLenInBytes);
			commBlock.setKeyId(i);
			++numKeys;
			reportResult(MiniSvmReturnResult::Ok, "Key registered");
			return;
		}
	}

	reportResult(MiniSvmReturnResult::NoFreeKeySlot, "Could not find a free key slot");
}

static inline void encryptData() {
	const auto &encryptView { commBlock.retrieveEncryptDataView() };
	if (encryptView.keyId >= numKeys) {
		reportResult(MiniSvmReturnResult::InvalidKeyId, "Invalid key id");
		return;
	}

	// Get key for the operation.
	const Key &key { keys[encryptView.keyId] }; 

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
	if (encryptView.inputSize % key.getKeyLen() != 0U) {
		reportResult(MiniSvmReturnResult::InvalidEncDecSize, "Input size is not multiple of block size");
		return;
	}

	switch (encryptView.cipherType) {
		case MiniSvmCipher::AesEcb:
			_encAesEcb(input, output, encryptView.inputSize, key.getKey(), key.getKeyLen());
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
			case MiniSvmOperation::RegisterKey:
				registerKey();
				break;
			case MiniSvmOperation::RemoveKey:
				removeKey();
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
