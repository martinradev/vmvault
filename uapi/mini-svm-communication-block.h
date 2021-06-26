#ifndef MINI_SVM_COMMUNICATION_BLOCK_H
#define MINI_SVM_COMMUNICATION_BLOCK_H

#include <cstdint>

enum class MiniSvmOperation : uint8_t {
	RegisterKey,
	RemoveKey,
	EncryptData,
	DecryptData,
	Init,
};

enum class MiniSvmCipher : uint8_t {
	AesEcb,
	AesCbc,
	AesCtr
};

enum class MiniSvmReturnResult : uint8_t {
	Ok,
	Fail,

	InvalidSourceSize,
	KeyStoreOutOfSpace,
	InvalidKeyId,
	InvalidEncDecSize,
	InvalidCipher
};

class __attribute__((packed)) MiniSvmCommunicationBlock {
public:

	struct SetKeyView {
		MiniSvmOperation operationType;
		uint64_t keyHpa;
		uint64_t keyLenInBytes;
	};

	struct EncryptDataView {
		MiniSvmOperation operationType;
		MiniSvmCipher cipherType;
		uint64_t inputHpa;
		uint64_t outputHpa;
		uint64_t inputSize;
		uint16_t keyId;
	};

private:
	MiniSvmReturnResult result;
	MiniSvmOperation operationType;
	MiniSvmCipher cipherType;
	uint64_t sourceHpa;
	uint64_t destinationHpa;
	uint64_t sourceSize;
	uint16_t keyId_InOut;

public:
	void setResult(const MiniSvmReturnResult &resultIn) {
		result = resultIn;
	}

	void setOperationType(const MiniSvmOperation &operationIn) {
		operationType = operationIn;
	}

	void setCipherType(const MiniSvmCipher &cipherIn) {
		cipherType = cipherIn;
	}

	void setSourceHpa(const uint64_t sourceHpaIn) {
		sourceHpa = sourceHpaIn;
	}

	void setDestinationHpa(const uint64_t destinationHpaIn) {
		destinationHpa = destinationHpaIn;
	}

	void setSourceSize(const uint64_t sourceSizeIn) {
		sourceSize = sourceSizeIn;
	}

	const MiniSvmReturnResult &getResult() const {
		return result;
	}

	const MiniSvmOperation &getOperationType() const {
		return operationType;
	}

	const SetKeyView retrieveSetKeyView() const {
		struct SetKeyView keyView {
			__atomic_load_n(&operationType, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceHpa, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceSize, __ATOMIC_RELAXED) };
		return keyView;
	}

	const EncryptDataView retrieveEncryptDataView() const {
		struct EncryptDataView encryptDataView {
			__atomic_load_n(&operationType, __ATOMIC_RELAXED),
			__atomic_load_n(&cipherType, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceHpa, __ATOMIC_RELAXED),
			__atomic_load_n(&destinationHpa, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceSize, __ATOMIC_RELAXED),
			__atomic_load_n(&keyId_InOut, __ATOMIC_RELAXED) };
		return encryptDataView;
	}

public:
	friend void dump_communication_block();
};

const uint64_t kMiniSvmCommunicationBlockGpa { 0x3000UL };

#endif // MINI_SVM_COMMUNICATION_BLOCK_H
