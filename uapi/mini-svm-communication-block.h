#ifndef MINI_SVM_COMMUNICATION_BLOCK_H
#define MINI_SVM_COMMUNICATION_BLOCK_H

#include <cstdint>

// Debug is for developvment,
// Release is for testing
enum class MiniSvmBuildFlavor {
	Debug,
	Release
};

static constexpr MiniSvmBuildFlavor buildFlavor { MiniSvmBuildFlavor::Debug };

enum class MiniSvmOperation : uint8_t {
	RegisterContext,
	RemoveContext,
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
	InvalidContextId,
	InvalidEncDecSize,
	InvalidCipher,
	KeyAlreadyRemoved,
	NoFreeKeySlot
};

class __attribute__((packed)) MiniSvmCommunicationBlock {
public:

	using ContextIdDataType = uint16_t;

	struct SetCipherContextView {
		MiniSvmOperation operationType;
		uint64_t keyHpa;
		uint64_t keyLenInBytes;
	};

	struct RemoveCipherContextView {
		MiniSvmOperation operationType;
		ContextIdDataType contextId;
	};

	struct EncryptDataView {
		MiniSvmOperation operationType;
		MiniSvmCipher cipherType;
		uint64_t inputHpa;
		uint64_t outputHpa;
		uint64_t inputSize;
		ContextIdDataType contextId;
	};

private:
	MiniSvmReturnResult result;
	MiniSvmOperation operationType;
	MiniSvmCipher cipherType;
	uint64_t sourceHpa;
	uint64_t destinationHpa;
	uint64_t sourceSize;
	ContextIdDataType contextId_InOut;

	char debugMessage[64];

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

	void setContextId(const ContextIdDataType contextId) {
		contextId_InOut = contextId;
	}

	const MiniSvmReturnResult &getResult() const {
		return result;
	}

	const MiniSvmOperation &getOperationType() const {
		return operationType;
	}

	const char *getDebugMessage() const {
		return debugMessage;
	}

	const ContextIdDataType getContextId() const {
		return contextId_InOut;
	}

	const SetCipherContextView retrieveSetCipherContextView() const {
		SetCipherContextView contextView {
			__atomic_load_n(&operationType, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceHpa, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceSize, __ATOMIC_RELAXED) };
		return contextView;
	}

	const RemoveCipherContextView retrieveRemoveCipherContextView() const {
		RemoveCipherContextView removeContextView {
			__atomic_load_n(&operationType, __ATOMIC_RELAXED),
			__atomic_load_n(&contextId_InOut, __ATOMIC_RELAXED), };
		return removeContextView;
	}

	const EncryptDataView retrieveEncryptDataView() const {
		struct EncryptDataView encryptDataView {
			__atomic_load_n(&operationType, __ATOMIC_RELAXED),
			__atomic_load_n(&cipherType, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceHpa, __ATOMIC_RELAXED),
			__atomic_load_n(&destinationHpa, __ATOMIC_RELAXED),
			__atomic_load_n(&sourceSize, __ATOMIC_RELAXED),
			__atomic_load_n(&contextId_InOut, __ATOMIC_RELAXED) };
		return encryptDataView;
	}

	template<size_t Size>
	void writeDebugMessage(const char (&message)[Size]) {
		static_assert(Size <= sizeof(debugMessage));
		memcpy(debugMessage, message, Size);
	}

	void clearDebugMessage() {
		memset(debugMessage, 0, sizeof(debugMessage));
	}

public:
	friend void dump_communication_block();
};

static_assert(sizeof(MiniSvmCommunicationBlock) <= 0x1000UL);

const uint64_t kMiniSvmCommunicationBlockGpa { 0x30000UL };

#endif // MINI_SVM_COMMUNICATION_BLOCK_H
