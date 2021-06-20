#include "util.h"

#include "hv-microbench-structures.h"

#include <cstddef>

using SequenceAccessFunction = void (*)(unsigned long*);

static void access_sequence(unsigned long *start_seq_va) {
	asm volatile(
		"mov %0, %%rax\n\t"
		"mov %0, %%rbx\n\t"
		".loop%=:\n\t"
		"mov (%%rax), %%rax\n\t"
		"cmp %%rax, %%rbx\n\t"
		"je .done%=\n\t"
		"jmp .loop%=\n\t"
		".done%=:\n\t"
		:
		: "r"(start_seq_va)
		: "%rax", "%rbx"
	);
}

static void jmp_sequence(unsigned long *start_seq_va) {
	asm volatile(
		"mov %0, %%rax\n\t"
		"lea 0x2(%%rip), %%rbx\n\t" // jmp rax is just 2 bytes
		"jmp %%rax\n\t" // the last element in the sequence would do a 'jmp rbx'
		:
		: "r"(start_seq_va)
		: "%rax", "%rbx"
	);
}

constexpr SequenceAccessFunction select_function(unsigned sequence_type) {
	switch(sequence_type) {
	case VMMCALL_REQUEST_RANDOM_JMP_SEQUENCE:
		return jmp_sequence;
	case VMMCALL_REQUEST_RANDOM_DATA_ACCESS_SEQUENCE:
		return access_sequence;
	default:
		hlt();
		// Unreacable.
	}
}

template<unsigned sequence_type>
void sample_random_access(const size_t size, const unsigned long num_iterations) {
	constexpr SequenceAccessFunction func = select_function(sequence_type);
	unsigned long *start_seq_va = (unsigned long *)0x20000;
	for (size_t i = 64; i < size; i += 64) {
		const unsigned long sequence_length = i;
		vmmcall(sequence_type, (unsigned long)start_seq_va, sequence_length);
		unsigned long ta, te;
		while (1) {
			ta = rdtsc_and_bar();
			for (unsigned long i = 0; i < num_iterations; ++i) {
				func(start_seq_va);
			}
			te = bar_and_rdtsc();
			if (te > ta) {
				break;
			}
		}
		const unsigned long total_accesses = num_iterations * sequence_length;
		const unsigned long delta = (te - ta) / total_accesses;
		vmmcall(VMMCALL_REPORT_RESULT, delta, sequence_length);
	}
}

void _start() {
	//determine_data_cache_sizes();
	//sample_random_access<VMMCALL_REQUEST_RANDOM_DATA_ACCESS_SEQUENCE>(1 * 1024 * 1024 / 64, 8192);
	sample_random_access<VMMCALL_REQUEST_RANDOM_JMP_SEQUENCE>(512 * 1024 / 64, 4096);
	//determine_instruction_cache_sizes();
	hlt();
}
