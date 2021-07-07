#ifndef MINI_SVM_COMMUNICATION_BLOCK_H
#define MINI_SVM_COMMUNICATION_BLOCK_H

typedef enum VmmCall_t {
        VmmCall_DebugPrint = 0x9000,
} VmmCall;

// Debug is for developvment,
// Release is for testing
typedef enum MiniSvmBuildFlavor_t {
	MiniSvmBuildFlavor_Debug,
	MiniSvmBuildFlavor_Release
} MiniSvmBuildFlavor;

static const MiniSvmBuildFlavor buildFlavor = MiniSvmBuildFlavor_Debug;

typedef enum MiniSvmOperation_t {
	MiniSvmOperation_RegisterContext,
	MiniSvmOperation_RemoveContext,
	MiniSvmOperation_EncryptData,
	MiniSvmOperation_DecryptData,
	MiniSvmOperation_Init,
} MiniSvmOperation;

typedef enum MiniSvmCipher_t {
	MiniSvmCipher_AesEcb,
	MiniSvmCipher_AesCbc,
	MiniSvmCipher_AesCtr
} MiniSvmCipher;

typedef enum MiniSvmReturnResult_t {
	MiniSvmReturnResult_Ok,
	MiniSvmReturnResult_Fail,

	MiniSvmReturnResult_InvalidSourceSize,
	MiniSvmReturnResult_KeyStoreOutOfSpace,
	MiniSvmReturnResult_InvalidContextId,
	MiniSvmReturnResult_InvalidEncDecSize,
	MiniSvmReturnResult_InvalidCipher,
	MiniSvmReturnResult_KeyAlreadyRemoved,
	MiniSvmReturnResult_NoFreeKeySlot,
	MiniSvmReturnResult_InvalidIvLen
} MiniSvmReturnResult;

typedef uint16_t ContextIdDataType;

typedef struct __attribute__((packed)) MiniSvmCommunicationBlock_t {
	uint16_t vcpuId;
	MiniSvmReturnResult result;
	MiniSvmOperation operationType;
	MiniSvmCipher cipherType;
	uint64_t sourceHpa;
	uint64_t destinationHpa;
	uint64_t sourceSize;
	uint64_t ivHpa;
	uint16_t ivSize;
	ContextIdDataType contextId_InOut;

	char debugMessage[64];
} MiniSvmCommunicationBlock;

static inline void setResult(MiniSvmCommunicationBlock *commBlock, MiniSvmReturnResult resultIn) {
	commBlock->result = resultIn;
}

static inline void setOperationType(MiniSvmCommunicationBlock *commBlock, MiniSvmOperation operationIn) {
	commBlock->operationType = operationIn;
}

static inline void setCipherType(MiniSvmCommunicationBlock *commBlock, MiniSvmCipher cipherIn) {
	commBlock->cipherType = cipherIn;
}

static inline void setSourceHpa(MiniSvmCommunicationBlock *commBlock, uint64_t sourceHpaIn) {
	commBlock->sourceHpa = sourceHpaIn;
}

static inline void setDestinationHpa(MiniSvmCommunicationBlock *commBlock, uint64_t destinationHpaIn) {
	commBlock->destinationHpa = destinationHpaIn;
}

static inline void setSourceSize(MiniSvmCommunicationBlock *commBlock, uint64_t sourceSizeIn) {
	commBlock->sourceSize = sourceSizeIn;
}

static inline void setContextId(MiniSvmCommunicationBlock *commBlock, ContextIdDataType contextId) {
	commBlock->contextId_InOut = contextId;
}

static inline void setIv(MiniSvmCommunicationBlock *commBlock, uint64_t ivHpaIn, uint64_t ivSizeIn) {
	commBlock->ivHpa = ivHpaIn;
	commBlock->ivSize = ivSizeIn;
}

static inline const MiniSvmReturnResult getResult(MiniSvmCommunicationBlock *commBlock) {
	return commBlock->result;
}

static inline const MiniSvmOperation getOperationType(MiniSvmCommunicationBlock *commBlock) {
	return commBlock->operationType;
}

static inline const char *getDebugMessage(const MiniSvmCommunicationBlock *commBlock) {
	return commBlock->debugMessage;
}

static inline const ContextIdDataType getContextId(MiniSvmCommunicationBlock *commBlock) {
	return commBlock->contextId_InOut;
}

typedef struct SetCipherContextView_t {
	MiniSvmOperation operationType;
	uint64_t keyHpa;
	uint64_t keyLenInBytes;
	uint64_t ivHpa;
	uint64_t ivLenInBytes;
} SetCipherContextView;

static inline const SetCipherContextView retrieveSetCipherContextView(MiniSvmCommunicationBlock *commBlock) {
	SetCipherContextView contextView = {
		.operationType = __atomic_load_n(&commBlock->operationType, __ATOMIC_RELAXED),
		.keyHpa = __atomic_load_n(&commBlock->sourceHpa, __ATOMIC_RELAXED),
		.keyLenInBytes = __atomic_load_n(&commBlock->sourceSize, __ATOMIC_RELAXED),
		.ivHpa = __atomic_load_n(&commBlock->ivHpa, __ATOMIC_RELAXED),
		.ivLenInBytes = __atomic_load_n(&commBlock->ivSize, __ATOMIC_RELAXED)
	};
	return contextView;
}

typedef struct RemoveCipherContextView_t {
	MiniSvmOperation operationType;
	ContextIdDataType contextId;
} RemoveCipherContextView;

static inline const RemoveCipherContextView retrieveRemoveCipherContextView(MiniSvmCommunicationBlock *commBlock) {
	RemoveCipherContextView removeContextView = {
		.operationType =__atomic_load_n(&commBlock->operationType, __ATOMIC_RELAXED),
		.contextId = __atomic_load_n(&commBlock->contextId_InOut, __ATOMIC_RELAXED), };
	return removeContextView;
}

typedef struct EncryptDataView_t {
	MiniSvmOperation operationType;
	MiniSvmCipher cipherType;
	uint64_t inputHpa;
	uint64_t outputHpa;
	uint64_t inputSize;
	ContextIdDataType contextId;
} EncryptDataView;

static inline const EncryptDataView retrieveEncryptDataView(MiniSvmCommunicationBlock *commBlock) {
	EncryptDataView encryptDataView = {
		.operationType = __atomic_load_n(&commBlock->operationType, __ATOMIC_RELAXED),
		.cipherType = __atomic_load_n(&commBlock->cipherType, __ATOMIC_RELAXED),
		.inputHpa = __atomic_load_n(&commBlock->sourceHpa, __ATOMIC_RELAXED),
		.outputHpa = __atomic_load_n(&commBlock->destinationHpa, __ATOMIC_RELAXED),
		.inputSize = __atomic_load_n(&commBlock->sourceSize, __ATOMIC_RELAXED),
		.contextId = __atomic_load_n(&commBlock->contextId_InOut, __ATOMIC_RELAXED) };
	return encryptDataView;
}

static inline void writeDebugMessage(MiniSvmCommunicationBlock *commBlock, const char *message, size_t size) {
	if (size > sizeof(commBlock->debugMessage)) {
		size = sizeof(commBlock->debugMessage);
	}
	memcpy(commBlock->debugMessage, message, size);
}

static inline void clearDebugMessage(MiniSvmCommunicationBlock *commBlock) {
	memset(commBlock->debugMessage, 0, sizeof(commBlock->debugMessage));
}

static_assert(sizeof(MiniSvmCommunicationBlock) <= 0x1000UL);

// FIXME
#define kMiniSvmCommunicationBlockGpa 0x30000UL

#endif // MINI_SVM_COMMUNICATION_BLOCK_H
