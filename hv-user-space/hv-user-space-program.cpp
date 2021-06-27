#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <array>
#include <cassert>
#include <limits>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>

#include "mini-svm-user-ioctl.h"
#include "mini-svm-exit-codes.h"
#include "mini-svm-common-structures.h"
#include "mini-svm-vmcb.h"
#include "mini-svm-communication-block.h"

#include "hv-util.h"
#include "hv-microbench-structures.h"

#include "phys_addr_util.h"

#define MINI_SVM_MAX_PHYS_SIZE (64UL * 1024UL * 1024UL)
#define IMAGE_START 0x8000UL

#define EFER_SVME (1UL << 12U)
#define EFER_LME (1UL << 8U)
#define EFER_LMA (1UL << 10)
#define CR0_PE (1UL << 0U)
#define CR0_ET (1UL << 4U)
#define CR0_NW (1UL << 29U)
#define CR0_CD (1UL << 30U)
#define CR0_PG (1UL << 31U)
#define CR4_PAE (1UL << 5U)
#define CR4_PGE (1UL << 7U)
#define CR4_OSFXSR (1UL << 9U)
#define CR4_OSXMMEXCPT (1UL << 10U)

// The start of guest physical memory is for the GPT which currently just takes two physical pages
// Writes to memory at an address lower than this one should be forbidden when they go via write_virt_memory.
#define PHYS_BASE_OFFSET 0x3000U

static void *guest_memory = NULL;

int mini_svm_mm_write_phys_memory(void *phys_base, __u64 phys_address, void *bytes, __u64 num_bytes) {
	if (phys_address + num_bytes > MINI_SVM_MAX_PHYS_SIZE) {
		return false;
	}

	printf("write phys: %lx\n", phys_address);
	memcpy((unsigned char *)phys_base + phys_address, bytes, num_bytes);

	return true;
}

bool mini_svm_mm_write_virt_memory(void *phys_base, __u64 virt_address, void *bytes, __u64 num_bytes) {
	if (virt_address < PHYS_BASE_OFFSET) {
		return false;
	}
	return mini_svm_mm_write_phys_memory(phys_base, virt_address, bytes, num_bytes);
}

size_t get_phys_memory_size() {
	return (size_t)sysconf(_SC_PHYS_PAGES) * (size_t)sysconf(_SC_PAGE_SIZE);
}

int mini_svm_construct_1gb_gpt(void *phys_base) {
	// We just need 2 pages for the page table, which will start at physical address 0 and will have length of 1gig.
	const __u64 pml4e = mini_svm_create_entry(0x1000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	if (!mini_svm_mm_write_phys_memory(phys_base, 0x0, (void *)&pml4e, sizeof(pml4e))) {
		return false;
	}
	const __u64 pdpe = mini_svm_create_entry(0x2000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	if (!mini_svm_mm_write_phys_memory(phys_base, 0x1000, (void *)&pdpe, sizeof(pdpe))) {
		return false;
	}
	const __u64 pde = mini_svm_create_entry(0x3000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	if (!mini_svm_mm_write_phys_memory(phys_base, 0x2000, (void *)&pde, sizeof(pde))) {
		return false;
	}

	// Write stack pte
	const __u64 stack_pte = mini_svm_create_entry(0x7000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	if (!mini_svm_mm_write_phys_memory(phys_base, 0x3000 + 8UL * 7UL, (void *)&stack_pte, sizeof(stack_pte))) {
		return false;
	}

	// Create image ptes
	for (size_t i = 0; i < 8UL; ++i) {
		const __u64 image_pte = mini_svm_create_entry(0x8000 + 0x1000 * i, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
		if (!mini_svm_mm_write_phys_memory(phys_base, 0x3000 + 8UL * (8UL + i), (void *)&image_pte, sizeof(image_pte))) {
			return false;
		}
	}

	// Create keys ptes
	for (size_t i = 0; i < 2UL; ++i) {
		const __u64 keys_pte = mini_svm_create_entry(0x20000 + 0x1000 * i, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
		if (!mini_svm_mm_write_phys_memory(phys_base, 0x3000 + 8UL * (32 + i), (void *)&keys_pte, sizeof(keys_pte))) {
			return false;
		}
	}

	// Create comm block ptes
	const __u64 comm_block_pte = mini_svm_create_entry(0x30000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	if (!mini_svm_mm_write_phys_memory(phys_base, 0x3000 + 8UL * (48), (void *)&comm_block_pte, sizeof(comm_block_pte))) {
		return false;
	}

	// Direct-map host pages.
	const size_t one_gig { 1024UL * 1024UL * 1024UL };
	const size_t num_one_gig_pages { (get_phys_memory_size() + one_gig - 1UL) / one_gig };
	for (size_t i = 0; i < num_one_gig_pages; ++i) {
		const __u64 pdpe = mini_svm_create_entry(one_gig * (i + 1UL), MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_LEAF_MASK);
		if (!mini_svm_mm_write_phys_memory(phys_base, 0x1000UL + 0x8UL * (i + 1UL), (void *)&pdpe, sizeof(pdpe))) {
			return false;
		}
	}
	return true;
}

bool load_vm_program(const char *filename, void *phys_base) {
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		printf("Failed to open file: %s\n", filename);
		return false;
	}

	size_t sz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	void *buffer = malloc(sz);
	if (!buffer) {
		printf("Failed to allocate buffer for the image\n");
		return false;
	}
	ssize_t nread = read(fd, buffer, sz);
	if (nread < 0 || nread != sz) {
		printf("Failed to read file. Read: %zd. Expected: %zu\n", nread, sz);
		return false;
	}
	close(fd);

	const __u64 image_base = IMAGE_START;
	if (!mini_svm_mm_write_virt_memory(phys_base, image_base, buffer, nread)) {
		return false;
	}

	return true;
}

static void setup_ctrl(struct mini_svm_vmcb_control *ctrl) {
	memset(&ctrl->excp_vec_intercepts, 0xFF, sizeof(ctrl->excp_vec_intercepts));
	ctrl->vec3.hlt_intercept = 1;
	ctrl->vec3.cpuid_intercept = 1;
	ctrl->vec4.vmrun_intercept = 1;
	ctrl->vec4.vmmcall_intercept = 1;
	ctrl->tlb_control = 1;
}

static void setup_save(struct mini_svm_vmcb_save_area *save) {
	// Setup long mode.
	save->efer = EFER_SVME | EFER_LME | EFER_LMA;
	save->cr0 = (CR0_PE | CR0_PG);
	save->cr3 = 0x0;
	save->cr4 = (CR4_PAE | CR4_PGE | CR4_OSXMMEXCPT | CR4_OSFXSR);

	// Setup gdt
	save->reg_gdtr.base = 0x0;
	save->reg_gdtr.limit = -1;

	// Setup segments
	save->reg_cs.base = 0x0;
	save->reg_cs.limit = -1;
	save->reg_cs.attribute = 0x029b;
	save->reg_cs.selector = 0x8;

	save->reg_ss.base = 0;
	save->reg_ss.limit = -1;
	save->reg_ss.attribute = 0x0a93;
	save->reg_ss.selector = 0x10;

	memcpy(&save->reg_ds, &save->reg_ss, sizeof(save->reg_ss));
	memcpy(&save->reg_ss, &save->reg_ss, sizeof(save->reg_ss));
	memcpy(&save->reg_fs, &save->reg_ss, sizeof(save->reg_ss));
	memcpy(&save->reg_gs, &save->reg_ss, sizeof(save->reg_ss));

	// Everything index is cacheable.
	save->g_pat = 0x0606060606060606ULL;
}

static void dump_regs(const struct mini_svm_vm_state *state) {
	printf("rax = %llx\n", state->regs.rax);
	printf("rbx = %llx\n", state->regs.rbx);
	printf("rcx = %llx\n", state->regs.rcx);
	printf("rdx = %llx\n", state->regs.rdx);
	printf("rsi = %llx\n", state->regs.rsi);
	printf("rdi = %llx\n", state->regs.rdi);
	printf("rip = %llx\n", state->regs.rip);
	printf("rsp = %llx\n", state->regs.rsp);
	printf("rbp = %llx\n", state->regs.rbp);
	printf("r8 = %llx\n", state->regs.r8);
	printf("r9 = %llx\n", state->regs.r9);
	printf("r10 = %llx\n", state->regs.r10);
	printf("r11 = %llx\n", state->regs.r11);
	printf("r12 = %llx\n", state->regs.r12);
	printf("r13 = %llx\n", state->regs.r13);
	printf("r14 = %llx\n", state->regs.r14);
	printf("r15 = %llx\n", state->regs.r15);
}

static void mini_svm_handle_exception(const enum MINI_SVM_EXCEPTION excp, const struct mini_svm_vm_state *state) {
	printf("Received exception. # = %x. Name: %s\n", (unsigned)excp, translate_mini_svm_exception_number_to_str(excp));
	dump_regs(state);
}

void mini_svm_intercept_rdtsc(struct mini_svm_vm_state *state) {
	state->regs.rax = (state->clock & 0xFFFFFFFFUL);
	state->regs.rdx = ((state->clock >> 32U) & 0xFFFFFFFFUL);
	state->clock++;
}

void mini_svm_intercept_rdtscp(struct mini_svm_vm_state *state) {
	state->regs.rcx = 0x1337UL;
	mini_svm_intercept_rdtsc(state);
}

int mini_svm_intercept_npf(struct mini_svm_vmcb *vmcb, struct mini_svm_vm_state *state) {
	__u64 fault_phys_address = vmcb->control.exitinfo_v2;
	printf("Received NPF at phys addr: 0x%llx\n", vmcb->control.exitinfo_v2);
	dump_regs(state);
	if (fault_phys_address >= MINI_SVM_MAX_PHYS_SIZE) {
		return 1;
	}
	return 1;
}

int mini_svm_intercept_cpuid(struct mini_svm_vm_state *state) {
	return 0;
}

int mini_svm_intercept_vmmcall(struct MiniSvmCommunicationBlock &commBlock, struct mini_svm_vm_state *state) {
	const unsigned long cmd = state->regs.rax;
	const unsigned long arg1 = state->regs.rdi;
	const unsigned long arg2 = state->regs.rsi;
	const unsigned long arg3 = state->regs.rdx;

	if ((VmmCall)cmd == VmmCall::DebugPrint) {
		printf("VM send debug msg: %s\n", commBlock.getDebugMessage());
	}

	return 0;
}

static int mini_svm_handle_exit(struct MiniSvmCommunicationBlock &commBlock, struct mini_svm_vmcb *vmcb, struct mini_svm_vm_state *state) {
	__u64 exitcode = get_exitcode(&vmcb->control);
	int should_exit = 0;

	printf("Exitcode: %s\n", translate_mini_svm_exitcode_to_str((enum MINI_SVM_EXITCODE)exitcode));

	// TODO: Doing this through function pointers for the respective handlers is probably better.
	switch((enum MINI_SVM_EXITCODE)exitcode) {
		case MINI_SVM_EXITCODE_VMEXIT_EXCP_0 ... MINI_SVM_EXITCODE_VMEXIT_EXCP_15:
			mini_svm_handle_exception((enum MINI_SVM_EXCEPTION)(exitcode - MINI_SVM_EXITCODE_VMEXIT_EXCP_0), state);
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_RDTSC:
			mini_svm_intercept_rdtsc(state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_RDTSCP:
			mini_svm_intercept_rdtscp(state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_INVALID:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_HLT:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_SHUTDOWN:
			should_exit = 1;
			break;
		case MINI_SVM_EXITCODE_VMEXIT_NPF:
			should_exit = mini_svm_intercept_npf(vmcb, state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_CPUID:
			should_exit = mini_svm_intercept_cpuid(state);
			break;
		case MINI_SVM_EXITCODE_VMEXIT_VMMCALL:
			should_exit = mini_svm_intercept_vmmcall(commBlock, state);
			break;
		default:
			printf("Unkown exit code\n");
			should_exit = 1;
			break;
	}

	return should_exit;
}

void mini_svm_setup_regs(struct mini_svm_vm_regs *regs) {
	regs->rip = IMAGE_START;
	regs->rax = 0x0;
	regs->rbx = 0;
	regs->rcx = 0xdeadbeefUL;
	regs->rdx = 0x484848UL;
	regs->rdi = 0;
	regs->rsi = 0;
	regs->rbp = 0;
	regs->rsp = IMAGE_START - 0x8;
	regs->r8 = 0;
	regs->r9 = 0;
	regs->r10 = 0;
	regs->r11 = 0;
	regs->r12 = 0;
	regs->r13 = 0;
	regs->r14 = 0;
	regs->r15 = 0;
}

void dump_communication_block() {
#define p(X) \
	printf("%s: %x\n", #X, static_cast<unsigned>(X))

	const uint64_t commBlockHva = kMiniSvmCommunicationBlockGpa + reinterpret_cast<uint64_t>(guest_memory);
	const struct MiniSvmCommunicationBlock &block =
		*reinterpret_cast<const struct MiniSvmCommunicationBlock *>(commBlockHva);

	p(block.result);
	p(block.operationType);
	p(block.cipherType);
	p(block.sourceHpa);
	p(block.destinationHpa);

#undef p
}

static int mini_svm_fd {};
static struct mini_svm_vmcb *vmcb {};
static struct mini_svm_vm_state *state {};

static MiniSvmReturnResult checkResult(MiniSvmCommunicationBlock &commBlock) {
	const MiniSvmReturnResult result { commBlock.getResult() };
	const bool failed {result != MiniSvmReturnResult::Ok };
	if (failed) {
		printf("Return result was not ok\n");
	}
	if constexpr (buildFlavor == MiniSvmBuildFlavor::Debug) {
		printf("Debug message: %s\n", commBlock.getDebugMessage());
		commBlock.clearDebugMessage();
	}
	return result;
}

static MiniSvmReturnResult setKey(MiniSvmCommunicationBlock &commBlock, const uint8_t *array, size_t size, uint16_t *keyId) {
	const uint64_t pa { gva_to_gpa( reinterpret_cast<const void *>(&array[0])) };
	commBlock.setOperationType(MiniSvmOperation::RegisterKey);
	commBlock.setSourceHpa(pa);
	commBlock.setSourceSize(size);

	if (ioctl(mini_svm_fd, MINI_SVM_IOCTL_RESUME, 0) < 0) {
		printf("Failed to ioctl mini-svm\n");
		exit(-1);
	}
	if (mini_svm_handle_exit(commBlock, vmcb, state)) {
		printf("Svm exitted with a weird error\n");
		exit(-1);
	}
	const MiniSvmReturnResult result { checkResult(commBlock) };

	if (result == MiniSvmReturnResult::Ok) {
		*keyId = commBlock.getKeyId();
	}
	return result;
}

template<size_t Size>
static MiniSvmReturnResult setKey(MiniSvmCommunicationBlock &commBlock, const std::array<uint8_t, Size> &array, uint16_t *keyId) {
	static_assert(Size == 16 || Size == 24 || Size == 32);
	return setKey(commBlock, array.data(), Size, keyId);
}

static void encryptData(MiniSvmCommunicationBlock &commBlock, uint16_t keyId, MiniSvmCipher cipherType, const void *input, size_t size, void *output) {
	const uint64_t paInput { gva_to_gpa(input) };
	const uint64_t paOutput { gva_to_gpa(output) };
	commBlock.setOperationType(MiniSvmOperation::EncryptData);
	commBlock.setSourceHpa(paInput);
	commBlock.setDestinationHpa(paOutput);
	commBlock.setSourceSize(size);
	commBlock.setCipherType(MiniSvmCipher::AesEcb);

	if (ioctl(mini_svm_fd, MINI_SVM_IOCTL_RESUME, 0) < 0) {
		printf("Failed to ioctl mini-svm\n");
		exit(-1);
	}
	if (mini_svm_handle_exit(commBlock, vmcb, state)) {
		printf("Svm exitted with a weird error\n");
		exit(-1);
	}
	checkResult(commBlock);
}

static void runSetKeyTests(MiniSvmCommunicationBlock &commBlock) {
	// Send valid keys.
	uint16_t keyIdCounter {};
	for (auto keylen : {16, 24, 32}) {
		uint8_t key[keylen] {};
		uint16_t keyId;
		const auto result { setKey(commBlock, &key[0], keylen, &keyId) };
		assert(result == MiniSvmReturnResult::Ok);
		assert(keyIdCounter == keyId);
		++keyIdCounter;
	}

	// Send an invalid key
	const uint8_t key[100] {};
	uint16_t keyId;
	const auto result1 { setKey(commBlock, &key[0], sizeof(key), &keyId) };
	assert(result1 != MiniSvmReturnResult::Ok);
	const auto result2 { setKey(commBlock, &key[0], std::numeric_limits<uint16_t>::max(), &keyId) };
	assert(result2 != MiniSvmReturnResult::Ok);
	const auto result3 { setKey(commBlock, &key[0], 0, &keyId) };
	assert(result3 != MiniSvmReturnResult::Ok);
}

static void runEncDecTests(MiniSvmCommunicationBlock &commBlock) {
	// Set key
	std::array<uint8_t, 16> key {};
	key.fill(0x41U);
	uint16_t keyId;
	const auto result { setKey(commBlock, key, &keyId) };
	assert(result == MiniSvmReturnResult::Ok);
	assert(keyId >= 0);

	std::array<uint8_t, 32> data {};
	data.fill(0x42U);
	std::array<uint8_t, 32> output {};
	encryptData(commBlock, keyId, MiniSvmCipher::AesEcb, data.data(), data.size(), output.data());
}

int main(int argc, char *argv[]) {
	mini_svm_fd = open("/dev/mini_svm", O_RDWR);
	if (mini_svm_fd < 0) {
		printf("Failed to open mini-svm\n");
		return -1;
	}

	void *pages = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mini_svm_fd, MINI_SVM_MMAP_VM_VMCB);
	if (pages == MAP_FAILED) {
		printf("Failed to mmap vmcb\n");
		return -1;
	}
	vmcb = (struct mini_svm_vmcb *)pages;

	pages = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mini_svm_fd, MINI_SVM_MMAP_VM_STATE);
	if (pages == MAP_FAILED) {
		printf("Failed to mmap vm state\n");
		return -1;
	}
	state = (struct mini_svm_vm_state *)pages;

	guest_memory = mmap(0, MINI_SVM_MAX_PHYS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mini_svm_fd, MINI_SVM_MMAP_VM_PHYS_MEM);
	if (guest_memory == MAP_FAILED) {
		printf("Failed to retrieve guest memory\n");
		return -1;
	}

	if (!mini_svm_construct_1gb_gpt(guest_memory)) {
		printf("Failed to create GPT\n");
		return -1;
	}

	if (argc != 2) {
		printf("Unkown args.\n");
		return -1;
	}
	if (!load_vm_program(argv[1], guest_memory)) {
		printf("Failed to laod vm\n");
		return -1;
	}

	setup_ctrl(&vmcb->control);
	setup_save(&vmcb->save);
	mini_svm_setup_regs(&state->regs);

	const uint64_t commBlockHva = kMiniSvmCommunicationBlockGpa + reinterpret_cast<uint64_t>(guest_memory);
	struct MiniSvmCommunicationBlock &commBlock =
		*reinterpret_cast<struct MiniSvmCommunicationBlock *>(commBlockHva);
	bool should_exit;

	// Init
	commBlock.setOperationType(MiniSvmOperation::Init);
	int r = ioctl(mini_svm_fd, MINI_SVM_IOCTL_START, 0);
	if (r < 0) {
		printf("Failed to ioctl mini-svm\n");
		return -1;
	}
	should_exit = mini_svm_handle_exit(commBlock, vmcb, state);
	if (should_exit) {
		printf("Failed to init\n");
		exit(-1);
	}
	checkResult(commBlock);

	runSetKeyTests(commBlock);
	runEncDecTests(commBlock);

	return 0;
}
