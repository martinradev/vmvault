#include "aes.h"

#include "mini-svm-communication-block.h"
#include "hv-microbench-structures.h"

#include <cstring>

#include "util.h"

static const u16 MaxKeyLengthInBytes { 32U };
static const u64 HPA_OFFSET { 1024UL * 1024UL * 1024UL };
static inline u64 hpa_to_gva(u64 hpa) {
	return HPA_OFFSET + hpa;
}
static inline void *hpa_to_gva_ptr(u64 hpa) {
	return reinterpret_cast<void *>(hpa_to_gva(hpa));
}

static struct MiniSvmCommunicationBlock &commBlock
	{ *reinterpret_cast<MiniSvmCommunicationBlock *>(kMiniSvmCommunicationBlockGpa) };

class Key {
public:
	void reset(const void *key, u16 keyLength) {
		if (keyLength > MaxKeyLengthInBytes) {
			hlt();
		}
		memcpy(mKey.data(), key, keyLength);
		mKeyLen = keyLength;
	}

	const u8* getKey() const {
		return mKey.data();
	}

	const uint16_t getKeyLen() const {
		return mKeyLen;
	}

private:
	std::array<u8, MaxKeyLengthInBytes> mKey;
	uint16_t mKeyLen;
};

static Result save_key(u64 hpa, u16 keylen) {
	return Result::Ok;
}

static void read_host_memory(const u64 hpa, void *out, size_t sz) {
	const void *gva { reinterpret_cast<const void *>(hpa_to_gva(hpa)) };
	memcpy(out, gva, sz);
}

template<typename T>
static void read_host_memory(const u64 hpa, T &out) {
	read_host_memory(hpa, (void *)&out, sizeof(T));
}

static void reportResult(MiniSvmReturnResult result) {
	commBlock.setResult(result);
	vmgexit();
}

static const u64 kMaxKeys { 16UL };
Key *keys { reinterpret_cast<Key *>(0x6000UL) };
static u64 numKeys { };

static inline void registerKey() {
	if (numKeys >= kMaxKeys) {
		reportResult(MiniSvmReturnResult::KeyStoreOutOfSpace);
		return;
	}
	const auto &keyView { commBlock.retrieveSetKeyView() };
	if (keyView.keyLenInBytes != 16UL &&
		keyView.keyLenInBytes != 24UL &&
		keyView.keyLenInBytes != 32UL) {
		reportResult(MiniSvmReturnResult::InvalidSourceSize);
		return;
	}

	keys[numKeys++].reset(hpa_to_gva_ptr(keyView.keyHpa), keyView.keyLenInBytes);

	reportResult(MiniSvmReturnResult::Ok);
}

static inline void encryptData() {
	const auto &encryptView { commBlock.retrieveEncryptDataView() };
	if (encryptView.keyId >= numKeys) {
		reportResult(MiniSvmReturnResult::InvalidKeyId);
		return;
	}
	const u64 inputGva { hpa_to_gva(encryptView.inputHpa) };
	const u64 outputGva { hpa_to_gva(encryptView.outputHpa) };
	const u8 *input { reinterpret_cast<const u8 *>(inputGva) };
	u8 *output { reinterpret_cast<u8 *>(outputGva) };
	if (outputGva + encryptView.inputSize < outputGva) {
		reportResult(MiniSvmReturnResult::InvalidEncDecSize);
		return;
	}

	// Get key for the operation.
	const Key &key { keys[encryptView.keyId] }; 

	switch (encryptView.cipherType) {
		case MiniSvmCipher::AesEcb:
			_encAesEcb(input, output, key.getKey(), key.getKeyLen());
			break;
		default:
			reportResult(MiniSvmReturnResult::InvalidCipher);
			return;
	}

	reportResult(MiniSvmReturnResult::Ok);
}

void _start() {
	if (commBlock.getOperationType() != MiniSvmOperation::Init) {
		hlt();
	}
	reportResult(MiniSvmReturnResult::Ok);

	while (1) {
		switch(commBlock.getOperationType()) {
			case MiniSvmOperation::RegisterKey:
				registerKey();
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

	const u64 hpa { 0x1000000UL };
	u64 value;
	read_host_memory(hpa, value);
	vmmcall(hpa, value, 0, 0);

	vmgexit();
	// Exit.
	hlt();
}
