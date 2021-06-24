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

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>

#include "mini-svm-user-ioctl.h"
#include "mini-svm-exit-codes.h"
#include "mini-svm-common-structures.h"
#include "mini-svm-vmcb.h"

#include "hv-util.h"
#include "hv-microbench-structures.h"

#define MINI_SVM_MAX_PHYS_SIZE (64UL * 1024UL * 1024UL)
#define IMAGE_START 0x18000UL

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

// The start of guest physical memory is for the GPT which currently just takes two physical pages
// Writes to memory at an address lower than this one should be forbidden when they go via write_virt_memory.
#define PHYS_BASE_OFFSET 0x3000U

enum class MicrobenchExperiment {
	ICacheSize,
	DCacheSize,
	DTLBSize,
	ITLBSize,

	Unknown
};

static void *guest_memory = NULL;
MicrobenchExperiment experimentType;
static FILE *data_access_results_file;
static FILE *page_access_results_file;
static FILE *instruction_fetch_results_file;
static FILE *instruction_fetch_page_results_file;


static void report_experiment_result(unsigned long size, unsigned long ncycles) {
	switch(experimentType) {
		case MicrobenchExperiment::ICacheSize:
			fprintf(instruction_fetch_results_file, "%.16lu bytes: %.16lu cycles\n", size * 64UL, ncycles);
			break;
		case MicrobenchExperiment::DCacheSize:
			fprintf(data_access_results_file, "%.16lu bytes: %.16lu cycles\n", size * 64UL, ncycles);
			break;
		case MicrobenchExperiment::DTLBSize:
			fprintf(page_access_results_file, "%.16lu pages: %.16lu cycles\n", size, ncycles);
			break;
		case MicrobenchExperiment::ITLBSize:
			fprintf(instruction_fetch_page_results_file, "%.16lu pages: %.16lu cycles\n", size, ncycles);
			break;
		default:
			fprintf(stderr, "Unknown option\n");
			exit(1);
	}
}

int mini_svm_mm_write_phys_memory(void *phys_base, __u64 phys_address, void *bytes, __u64 num_bytes) {
	if (phys_address + num_bytes > MINI_SVM_MAX_PHYS_SIZE) {
		return false;
	}

	memcpy((unsigned char *)phys_base + phys_address, bytes, num_bytes);

	return true;
}

bool mini_svm_mm_write_virt_memory(void *phys_base, __u64 virt_address, void *bytes, __u64 num_bytes) {
	if (virt_address < PHYS_BASE_OFFSET) {
		return false;
	}
	return mini_svm_mm_write_phys_memory(phys_base, virt_address, bytes, num_bytes);
}

int mini_svm_construct_1gb_gpt(void *phys_base) {
	// We just need 2 pages for the page table, which will start at physical address 0 and will have length of 1gig.
	const __u64 pml4e = mini_svm_create_entry(0x1000, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK);
	const __u64 pdpe = mini_svm_create_entry(0x0, MINI_SVM_PRESENT_MASK | MINI_SVM_USER_MASK | MINI_SVM_WRITEABLE_MASK | MINI_SVM_LEAF_MASK);
	if (!mini_svm_mm_write_phys_memory(phys_base, 0x0, (void *)&pml4e, sizeof(pml4e))) {
		return false;
	}
	if (!mini_svm_mm_write_phys_memory(phys_base, 0x1000, (void *)&pdpe, sizeof(pdpe))) {
		return false;
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
	//ctrl->vec3.rdtsc_intercept = 1;
	//ctrl->vec4.rdtscp_intercept = 1;
}

static void setup_save(struct mini_svm_vmcb_save_area *save) {
	// Setup long mode.
	save->efer = EFER_SVME | EFER_LME | EFER_LMA;
	save->cr0 = (CR0_PE | CR0_PG);
	save->cr3 = 0x0;
	save->cr4 = (CR4_PAE | CR4_PGE);

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

int mini_svm_intercept_vmmcall(struct mini_svm_vm_state *state) {
	const VmmCall cmd = (const VmmCall)state->regs.rax;
	const unsigned long arg1 = state->regs.rdi;
	const unsigned long arg2 = state->regs.rsi;
	const unsigned long arg3 = state->regs.rdx;

	const unsigned long cache_line_size = 64UL;
	const unsigned long page_size = 0x1000UL;

	switch(cmd) {
		case VmmCall::RequestRandomPageAccessSeq:
		case VmmCall::RequestRandomDataAccessSeq:
		{
			const size_t granularity_size = (cmd == VmmCall::RequestRandomDataAccessSeq) ? cache_line_size : page_size;
			const unsigned long start_phys_addr = arg1;
			const unsigned long start_rand_va = arg2;
			const unsigned long num_elements = arg3;
			std::vector<unsigned long> seq, seq2;
			generate_random_unique_sequence(num_elements, seq);
			generate_random_unique_sequence(granularity_size / cache_line_size, seq2);
			unsigned long prev_index = 0;
			for (unsigned long i = 0; i < num_elements; ++i) {
				unsigned long next_index = seq[i] * granularity_size;
				if (cmd == VmmCall::RequestRandomPageAccessSeq && i != num_elements - 1) {
					// Additionally, we have to access a random cache line within the page to ensure that we do not thrash
					// the cache but the TLB instead.
					next_index += cache_line_size * seq2[i % seq2.size()];
				}
				const unsigned long next_va = next_index + start_rand_va;
				if (!mini_svm_mm_write_virt_memory(guest_memory, start_phys_addr + prev_index, (void *)&next_va, sizeof(next_va))) {
					printf("Failed to write index\n");
					return -1;
				}
				prev_index = next_index;
			}
			break;
		}
		case VmmCall::RequestRandomJmpAccessSeq:
		case VmmCall::RequestRandomJmpPageSeq:
		{
			const size_t granularity_size = (cmd == VmmCall::RequestRandomJmpAccessSeq) ? cache_line_size : page_size;
			const unsigned long start_phys_addr = arg1;
			const unsigned long start_rand_va = arg2;
			const unsigned long num_elements = arg3;
			std::vector<unsigned long> seq, seq2;
			generate_random_unique_sequence(num_elements, seq);
			generate_random_unique_sequence(granularity_size / cache_line_size, seq2);
			unsigned long prev_index = 0;
			for (unsigned long i = 0; i < num_elements - 1; ++i) {
				unsigned long next_index = seq[i] * granularity_size;
				if (cmd == VmmCall::RequestRandomJmpPageSeq && i != num_elements - 2) {
					// Additionally, we have to access a random cache line within the page to ensure that we do not thrash
					// the cache but the TLB instead.
					next_index += cache_line_size * seq2[i % seq2.size()];
				}
				unsigned next_gpa = next_index + start_phys_addr;
				unsigned next_gva = next_index + start_rand_va;
				unsigned prev_gpa = prev_index + start_phys_addr;
				unsigned prev_gva = prev_index + start_rand_va;
				unsigned rel_addr = next_gva - (prev_gva + 0x5UL);
				unsigned char jmp_rel_machine_code[5];
				jmp_rel_machine_code[0] = 0xE9UL;
				memcpy(&jmp_rel_machine_code[1], &rel_addr, sizeof(rel_addr));
				if (!mini_svm_mm_write_virt_memory(guest_memory, prev_gpa, jmp_rel_machine_code, sizeof(jmp_rel_machine_code))) {
					printf("Failed to write index\n");
					return -1;
				}
				prev_index = next_index;
			}
			unsigned prev_gpa = start_phys_addr + prev_index;
			const unsigned char jmp_rbx[2] = {0xffU, 0xe3U};
			if (!mini_svm_mm_write_virt_memory(guest_memory, prev_gpa, (void *)jmp_rbx, sizeof(jmp_rbx))) {
				printf("Failed to write index\n");
				return -1;
			}
			break;
		}
		case VmmCall::ReportResult:
		{
			const unsigned long ncycles = arg1;
			const unsigned long num_accesses = arg2;
			printf("Result is: %lx\n", arg1);
			report_experiment_result(num_accesses, ncycles);
			break;
		}
		case VmmCall::StartRandomAccess:
			experimentType = MicrobenchExperiment::DCacheSize;
			break;
		case VmmCall::StartRandomPageAccess:
			experimentType = MicrobenchExperiment::DTLBSize;
			break;
		case VmmCall::StartRandomJmp:
			experimentType = MicrobenchExperiment::ICacheSize;
			break;
		case VmmCall::StartRandomPageJmp:
			experimentType = MicrobenchExperiment::ITLBSize;
			break;
		case VmmCall::DoneTest:
			experimentType = MicrobenchExperiment::Unknown;
			break;
		default:
		{
			printf("Unknown cmd: %lx %lx %lx %lx\n", cmd, arg1, arg2, arg3);
			break;
		}
	}

	return 0;
}

static int mini_svm_handle_exit(struct mini_svm_vmcb *vmcb, struct mini_svm_vm_state *state) {
	__u64 exitcode = get_exitcode(&vmcb->control);
	int should_exit = 0;

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
			should_exit = mini_svm_intercept_vmmcall(state);
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
	regs->rsp = IMAGE_START;
	regs->r8 = 0;
	regs->r9 = 0;
	regs->r10 = 0;
	regs->r11 = 0;
	regs->r12 = 0;
	regs->r13 = 0;
	regs->r14 = 0;
	regs->r15 = 0;
}

int main(int argc, char *argv[]) {
	int fd = open("/dev/mini_svm", O_RDWR);
	if (fd < 0) {
		printf("Failed to open mini-svm\n");
		return -1;
	}

	struct mini_svm_vmcb *vmcb = NULL;
	struct mini_svm_vm_state *state = NULL;

	void *pages = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MINI_SVM_MMAP_VM_VMCB);
	if (pages == MAP_FAILED) {
		printf("Failed to mmap vmcb\n");
		return -1;
	}
	vmcb = (struct mini_svm_vmcb *)pages;

	pages = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MINI_SVM_MMAP_VM_STATE);
	if (pages == MAP_FAILED) {
		printf("Failed to mmap vm state\n");
		return -1;
	}
	state = (struct mini_svm_vm_state *)pages;

	guest_memory = mmap(0, MINI_SVM_MAX_PHYS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MINI_SVM_MMAP_VM_PHYS_MEM);
	if (guest_memory == MAP_FAILED) {
		printf("Failed to retrieve guest memory\n");
		return -1;
	}

	if (!mini_svm_construct_1gb_gpt(guest_memory)) {
		printf("Failed to create GPT\n");
		return -1;
	}

	// Try to get VM image
	if (argc != 6) {
		printf("Unexpected args. Expected: vm-image-file data-access-results-file page-access-results-file instruction-fetch-results-file instruction-fetch-page-results-file\n");
		return -1;
	}

	if (!load_vm_program(argv[1], guest_memory)) {
		printf("Failed to load vm image\n");
		return -1;
	}

	data_access_results_file = fopen(argv[2], "w+");
	if (data_access_results_file == NULL) {
		printf("Failed to open data access file: %s\n", argv[2]);
		return -1;
	}

	page_access_results_file = fopen(argv[3], "w+");
	if (page_access_results_file == NULL) {
		printf("Failed to open page access file: %s\n", argv[3]);
		return -1;
	}

	instruction_fetch_results_file = fopen(argv[4], "w+");
	if (instruction_fetch_results_file == NULL) {
		printf("Failed to open instruction fetch file: %s\n", argv[4]);
		return -1;
	}

	instruction_fetch_page_results_file = fopen(argv[5], "w+");
	if (instruction_fetch_page_results_file == NULL) {
		printf("Failed to open instruction fetch page file: %s\n", argv[5]);
		return -1;
	}

	setup_ctrl(&vmcb->control);
	setup_save(&vmcb->save);
	mini_svm_setup_regs(&state->regs);

	int r = ioctl(fd, MINI_SVM_IOCTL_START, 0);
	if (r < 0) {
		printf("Failed to ioctl mini-svm\n");
		return -1;
	}

	vmcb->control.vmcb_clean = -1;

	int should_exit;
	do {
		should_exit = mini_svm_handle_exit(vmcb, state);
		if (should_exit) {
			break;
		}
		vmcb->control.vmcb_clean = -1;
		int r = ioctl(fd, MINI_SVM_IOCTL_RESUME, 0);
		if (r < 0) {
			printf("Failed to ioctl mini-svm\n");
			return -1;
		}
	} while(1);

	return 0;
}
