#include "util.h"

#include "hv-microbench-structures.h"

#include <cstddef>

static void determine_cache_sizes(void);

void _start() {
	determine_cache_sizes();
	hlt();
}

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

void determine_cache_sizes(void) {
	unsigned long *start_seq_va = (unsigned long *)0x20000;

	for (size_t i = 64; i < 1024 * 1024 / 64; i += 64) {
		const unsigned long num_iterations = 4096;
		const unsigned long sequence_length = i;
		vmmcall(VMMCALL_REQUEST_RANDOM_DATA_ACCESS_SEQUENCE, (unsigned long)start_seq_va, sequence_length);
		const unsigned long ta = rdtsc_and_bar();
		for (unsigned long i = 0; i < num_iterations; ++i) {
			access_sequence(start_seq_va);
		}
		const unsigned long te = bar_and_rdtsc();
		const unsigned long total_accesses = num_iterations * sequence_length;
		const unsigned long delta = (te - ta) / total_accesses;
		vmmcall(VMMCALL_REPORT_RESULT, delta, sequence_length);
	}
}
