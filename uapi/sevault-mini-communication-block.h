#ifndef MINI_SVM_COMMUNICATION_BLOCK_H
#define MINI_SVM_COMMUNICATION_BLOCK_H

typedef enum VmmCall_t {
        VmmCall_DebugPrint = 0x9000,
} VmmCall;

// Debug is for developvment,
// Release is for testing
typedef enum SevaultMiniBuildFlavor_t {
	SevaultMiniBuildFlavor_Debug,
	SevaultMiniBuildFlavor_Release
} SevaultMiniBuildFlavor;

static const SevaultMiniBuildFlavor buildFlavor = SevaultMiniBuildFlavor_Debug;

typedef struct SevaultMiniDataRange_t {
	uint64_t srcPhysAddr;
	uint64_t dstPhysAddr;
	uint32_t length;
} SevaultMiniDataRange;

#define SevaultMiniSgList_Max_Entries 16

typedef struct SevaultMiniSgList_t {
	SevaultMiniDataRange ranges[SevaultMiniSgList_Max_Entries];
	uint8_t numRanges;
} SevaultMiniSgList;

typedef enum SevaultMiniOperation_t {
	SevaultMiniOperation_RegisterContext,
	SevaultMiniOperation_RemoveContext,
	SevaultMiniOperation_EncryptData,
	SevaultMiniOperation_DecryptData,
	SevaultMiniOperation_Init,
} SevaultMiniOperation;

typedef enum SevaultMiniCipher_t {
	SevaultMiniCipher_AesEcb,
	SevaultMiniCipher_AesCbc,
	SevaultMiniCipher_AesCtr
} SevaultMiniCipher;

typedef enum SevaultMiniReturnResult_t {
	SevaultMiniReturnResult_Ok,
	SevaultMiniReturnResult_Fail,
	SevaultMiniReturnResult_InitFail,
	SevaultMiniReturnResult_InvalidSourceSize,
	SevaultMiniReturnResult_KeyStoreOutOfSpace,
	SevaultMiniReturnResult_InvalidContextId,
	SevaultMiniReturnResult_ContextNotActive,
	SevaultMiniReturnResult_InvalidEncDecSize,
	SevaultMiniReturnResult_InvalidCipher,
	SevaultMiniReturnResult_KeyAlreadyRemoved,
	SevaultMiniReturnResult_NoFreeKeySlot,
	SevaultMiniReturnResult_InvalidIvLen,
	SevaultMiniReturnResult_InvalidNumRanges,
	SevaultMiniReturnResult_InvalidLength,
} SevaultMiniReturnResult;

typedef uint16_t ContextIdDataType;

typedef struct __attribute__((packed)) SevaultMiniCommunicationBlock_t {
	uint16_t vcpuId;
	SevaultMiniReturnResult result;
	SevaultMiniOperation operationType;
	SevaultMiniCipher cipherType;
	uint64_t sourceHpa;
	uint64_t destinationHpa;
	uint64_t sourceSize;
	uint64_t ivHpa;
	uint16_t ivSize;
	ContextIdDataType contextId_InOut;
	SevaultMiniSgList opSgList;

	char debugMessage[64];
} SevaultMiniCommunicationBlock;

static inline void clearSgList(SevaultMiniSgList *sgList) {
	sgList->numRanges = 0;
}

static inline int addSgListEntry(SevaultMiniSgList *opSgList, uint64_t srcPhysAddr, uint64_t dstPhysAddr, uint32_t length) {
	unsigned int index = opSgList->numRanges;
	if (index + 1 >= SevaultMiniSgList_Max_Entries) {
		return 0;
	}
	opSgList->ranges[index].srcPhysAddr = srcPhysAddr;
	opSgList->ranges[index].dstPhysAddr = dstPhysAddr;
	opSgList->ranges[index].length = length;
	opSgList->numRanges++;
	return 1;
}

static inline int isSgListFull(SevaultMiniSgList *opSgList) {
	return opSgList->numRanges + 1 == SevaultMiniSgList_Max_Entries;
}

static inline int isSgListEmpty(SevaultMiniSgList *opSgList) {
	return opSgList->numRanges == 0;
}

static inline void setResult(SevaultMiniCommunicationBlock *commBlock, SevaultMiniReturnResult resultIn) {
	commBlock->result = resultIn;
}

static inline void setOperationType(SevaultMiniCommunicationBlock *commBlock, SevaultMiniOperation operationIn) {
	commBlock->operationType = operationIn;
}

static inline void setCipherType(SevaultMiniCommunicationBlock *commBlock, SevaultMiniCipher cipherIn) {
	commBlock->cipherType = cipherIn;
}

static inline void setSourceHpa(SevaultMiniCommunicationBlock *commBlock, uint64_t sourceHpaIn) {
	commBlock->sourceHpa = sourceHpaIn;
}

static inline void setDestinationHpa(SevaultMiniCommunicationBlock *commBlock, uint64_t destinationHpaIn) {
	commBlock->destinationHpa = destinationHpaIn;
}

static inline void setSourceSize(SevaultMiniCommunicationBlock *commBlock, uint64_t sourceSizeIn) {
	commBlock->sourceSize = sourceSizeIn;
}

static inline void setContextId(SevaultMiniCommunicationBlock *commBlock, ContextIdDataType contextId) {
	commBlock->contextId_InOut = contextId;
}

static inline void setIv(SevaultMiniCommunicationBlock *commBlock, uint64_t ivHpaIn, uint64_t ivSizeIn) {
	commBlock->ivHpa = ivHpaIn;
	commBlock->ivSize = ivSizeIn;
}

static inline const SevaultMiniReturnResult getResult(SevaultMiniCommunicationBlock *commBlock) {
	return commBlock->result;
}

static inline const SevaultMiniOperation getOperationType(SevaultMiniCommunicationBlock *commBlock) {
	return commBlock->operationType;
}

static inline const char *getDebugMessage(const SevaultMiniCommunicationBlock *commBlock) {
	return commBlock->debugMessage;
}

static inline const ContextIdDataType getContextId(SevaultMiniCommunicationBlock *commBlock) {
	return commBlock->contextId_InOut;
}

typedef struct SetCipherContextView_t {
	SevaultMiniOperation operationType;
	uint64_t keyHpa;
	uint64_t keyLenInBytes;
	uint64_t ivHpa;
	uint64_t ivLenInBytes;
} SetCipherContextView;

static inline const SetCipherContextView retrieveSetCipherContextView(SevaultMiniCommunicationBlock *commBlock) {
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
	SevaultMiniOperation operationType;
	ContextIdDataType contextId;
} RemoveCipherContextView;

static inline const RemoveCipherContextView retrieveRemoveCipherContextView(SevaultMiniCommunicationBlock *commBlock) {
	RemoveCipherContextView removeContextView = {
		.operationType =__atomic_load_n(&commBlock->operationType, __ATOMIC_RELAXED),
		.contextId = __atomic_load_n(&commBlock->contextId_InOut, __ATOMIC_RELAXED), };
	return removeContextView;
}

typedef struct EncryptDataView_t {
	SevaultMiniOperation operationType;
	SevaultMiniCipher cipherType;
	ContextIdDataType contextId;
	SevaultMiniSgList encDecSgList;
} EncryptDataView;

static inline const EncryptDataView retrieveEncryptDataView(SevaultMiniCommunicationBlock *commBlock) {
	EncryptDataView encryptDataView = {
		.operationType = __atomic_load_n(&commBlock->operationType, __ATOMIC_RELAXED),
		.cipherType = __atomic_load_n(&commBlock->cipherType, __ATOMIC_RELAXED),
		.contextId = __atomic_load_n(&commBlock->contextId_InOut, __ATOMIC_RELAXED),
		.encDecSgList = { .numRanges = __atomic_load_n(&commBlock->opSgList.numRanges, __ATOMIC_RELAXED) } };
	memcpy(&encryptDataView.encDecSgList.ranges, &commBlock->opSgList.ranges, sizeof(SevaultMiniDataRange) * encryptDataView.encDecSgList.numRanges);
	return encryptDataView;
}

static inline void writeDebugMessage(SevaultMiniCommunicationBlock *commBlock, const char *message, size_t size) {
	if (size > sizeof(commBlock->debugMessage)) {
		size = sizeof(commBlock->debugMessage);
	}
	memcpy(commBlock->debugMessage, message, size);
}

static inline void clearDebugMessage(SevaultMiniCommunicationBlock *commBlock) {
	memset(commBlock->debugMessage, 0, sizeof(commBlock->debugMessage));
}

static_assert(sizeof(SevaultMiniCommunicationBlock) <= 0x1000UL);

// FIXME
#define kSevaultMiniCommunicationBlockGpa 0x30000UL

#endif // MINI_SVM_COMMUNICATION_BLOCK_H
