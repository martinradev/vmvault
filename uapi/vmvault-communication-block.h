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

#ifndef VMVAULT_COMMUNICATION_BLOCK_H
#define VMVAULT_COMMUNICATION_BLOCK_H

typedef enum VmmCall_t {
        VmmCall_DebugPrint = 0x9000,
} VmmCall;

// Debug is for developvment,
// Release is for testing
typedef enum VmVaultBuildFlavor_t {
	VmVaultBuildFlavor_Debug,
	VmVaultBuildFlavor_Release
} VmVaultBuildFlavor;

static const VmVaultBuildFlavor buildFlavor = VmVaultBuildFlavor_Debug;

typedef struct VmVaultDataRange_t {
	uint64_t srcPhysAddr;
	uint64_t dstPhysAddr;
	uint32_t length;
} VmVaultDataRange;

#define VmVaultSgList_Max_Entries 16

typedef struct VmVaultSgList_t {
	VmVaultDataRange ranges[VmVaultSgList_Max_Entries];
	uint8_t numRanges;
} VmVaultSgList;

typedef enum VmVaultOperation_t {
	VmVaultOperation_RegisterContext,
	VmVaultOperation_RemoveContext,
	VmVaultOperation_EncryptData,
	VmVaultOperation_DecryptData,
	VmVaultOperation_Init,
} VmVaultOperation;

typedef enum VmVaultCipher_t {
	VmVaultCipher_AesEcb,
	VmVaultCipher_AesCbc,
	VmVaultCipher_AesCtr
} VmVaultCipher;

typedef enum VmVaultReturnResult_t {
	VmVaultReturnResult_Ok,
	VmVaultReturnResult_Fail,
	VmVaultReturnResult_InitFail,
	VmVaultReturnResult_InvalidSourceSize,
	VmVaultReturnResult_KeyStoreOutOfSpace,
	VmVaultReturnResult_InvalidContextId,
	VmVaultReturnResult_ContextNotActive,
	VmVaultReturnResult_InvalidEncDecSize,
	VmVaultReturnResult_InvalidCipher,
	VmVaultReturnResult_KeyAlreadyRemoved,
	VmVaultReturnResult_NoFreeKeySlot,
	VmVaultReturnResult_InvalidIvLen,
	VmVaultReturnResult_InvalidNumRanges,
	VmVaultReturnResult_InvalidLength,
} VmVaultReturnResult;

typedef uint16_t ContextIdDataType;

typedef struct __attribute__((packed)) VmVaultCommunicationBlock_t {
	uint16_t vcpuId;
	VmVaultReturnResult result;
	VmVaultOperation operationType;
	VmVaultCipher cipherType;
	uint64_t sourceHpa;
	uint64_t destinationHpa;
	uint64_t sourceSize;
	uint64_t ivHpa;
	uint16_t ivSize;
	ContextIdDataType contextId_InOut;
	VmVaultSgList opSgList;

	char debugMessage[64];
} VmVaultCommunicationBlock;

static inline void clearSgList(VmVaultSgList *sgList) {
	sgList->numRanges = 0;
}

static inline int addSgListEntry(VmVaultSgList *opSgList, uint64_t srcPhysAddr, uint64_t dstPhysAddr, uint32_t length) {
	unsigned int index = opSgList->numRanges;
	if (index + 1 >= VmVaultSgList_Max_Entries) {
		return 0;
	}
	opSgList->ranges[index].srcPhysAddr = srcPhysAddr;
	opSgList->ranges[index].dstPhysAddr = dstPhysAddr;
	opSgList->ranges[index].length = length;
	opSgList->numRanges++;
	return 1;
}

static inline int isSgListFull(VmVaultSgList *opSgList) {
	return opSgList->numRanges + 1 == VmVaultSgList_Max_Entries;
}

static inline int isSgListEmpty(VmVaultSgList *opSgList) {
	return opSgList->numRanges == 0;
}

static inline void setResult(VmVaultCommunicationBlock *commBlock, VmVaultReturnResult resultIn) {
	commBlock->result = resultIn;
}

static inline void setOperationType(VmVaultCommunicationBlock *commBlock, VmVaultOperation operationIn) {
	commBlock->operationType = operationIn;
}

static inline void setCipherType(VmVaultCommunicationBlock *commBlock, VmVaultCipher cipherIn) {
	commBlock->cipherType = cipherIn;
}

static inline void setSourceHpa(VmVaultCommunicationBlock *commBlock, uint64_t sourceHpaIn) {
	commBlock->sourceHpa = sourceHpaIn;
}

static inline void setDestinationHpa(VmVaultCommunicationBlock *commBlock, uint64_t destinationHpaIn) {
	commBlock->destinationHpa = destinationHpaIn;
}

static inline void setSourceSize(VmVaultCommunicationBlock *commBlock, uint64_t sourceSizeIn) {
	commBlock->sourceSize = sourceSizeIn;
}

static inline void setContextId(VmVaultCommunicationBlock *commBlock, ContextIdDataType contextId) {
	commBlock->contextId_InOut = contextId;
}

static inline void setIv(VmVaultCommunicationBlock *commBlock, uint64_t ivHpaIn, uint64_t ivSizeIn) {
	commBlock->ivHpa = ivHpaIn;
	commBlock->ivSize = ivSizeIn;
}

static inline const VmVaultReturnResult getResult(VmVaultCommunicationBlock *commBlock) {
	return commBlock->result;
}

static inline const VmVaultOperation getOperationType(VmVaultCommunicationBlock *commBlock) {
	return commBlock->operationType;
}

static inline const char *getDebugMessage(const VmVaultCommunicationBlock *commBlock) {
	return commBlock->debugMessage;
}

static inline const ContextIdDataType getContextId(VmVaultCommunicationBlock *commBlock) {
	return commBlock->contextId_InOut;
}

typedef struct SetCipherContextView_t {
	VmVaultOperation operationType;
	uint64_t keyHpa;
	uint64_t keyLenInBytes;
	uint64_t ivHpa;
	uint64_t ivLenInBytes;
} SetCipherContextView;

static inline const SetCipherContextView retrieveSetCipherContextView(VmVaultCommunicationBlock *commBlock) {
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
	VmVaultOperation operationType;
	ContextIdDataType contextId;
} RemoveCipherContextView;

static inline const RemoveCipherContextView retrieveRemoveCipherContextView(VmVaultCommunicationBlock *commBlock) {
	RemoveCipherContextView removeContextView = {
		.operationType =__atomic_load_n(&commBlock->operationType, __ATOMIC_RELAXED),
		.contextId = __atomic_load_n(&commBlock->contextId_InOut, __ATOMIC_RELAXED), };
	return removeContextView;
}

typedef struct EncryptDataView_t {
	VmVaultOperation operationType;
	VmVaultCipher cipherType;
	ContextIdDataType contextId;
	VmVaultSgList encDecSgList;
	uint64_t ivHpa;
	uint64_t ivLenInBytes;
} EncryptDataView;

static inline const EncryptDataView retrieveEncryptDataView(VmVaultCommunicationBlock *commBlock) {
	EncryptDataView encryptDataView = {
		.operationType = __atomic_load_n(&commBlock->operationType, __ATOMIC_RELAXED),
		.cipherType = __atomic_load_n(&commBlock->cipherType, __ATOMIC_RELAXED),
		.contextId = __atomic_load_n(&commBlock->contextId_InOut, __ATOMIC_RELAXED),
		.encDecSgList = { .numRanges = __atomic_load_n(&commBlock->opSgList.numRanges, __ATOMIC_RELAXED) },
		.ivHpa = __atomic_load_n(&commBlock->ivHpa, __ATOMIC_RELAXED),
		.ivLenInBytes = __atomic_load_n(&commBlock->ivSize, __ATOMIC_RELAXED)
	};
	memcpy(&encryptDataView.encDecSgList.ranges, &commBlock->opSgList.ranges, sizeof(VmVaultDataRange) * encryptDataView.encDecSgList.numRanges);
	return encryptDataView;
}

static inline void writeDebugMessage(VmVaultCommunicationBlock *commBlock, const char *message, size_t size) {
	if (size > sizeof(commBlock->debugMessage)) {
		size = sizeof(commBlock->debugMessage);
	}
	memcpy(commBlock->debugMessage, message, size);
}

static inline void clearDebugMessage(VmVaultCommunicationBlock *commBlock) {
	memset(commBlock->debugMessage, 0, sizeof(commBlock->debugMessage));
}

static_assert(sizeof(VmVaultCommunicationBlock) <= 0x1000UL);

// FIXME
#define kVmVaultCommunicationBlockGpa 0x30000UL

#endif // VMVAULT_COMMUNICATION_BLOCK_H
