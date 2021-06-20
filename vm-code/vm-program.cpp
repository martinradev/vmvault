#include "util.h"

#include "hv-microbench-structures.h"

#include <cstddef>
#include <tuple>

using SequenceAccessFunction = void (*)(const unsigned long*);

static void access_sequence(const unsigned long *start_seq_va) {
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

static void jmp_sequence(const unsigned long *start_seq_va) {
	asm volatile(
		"mov %0, %%rax\n\t"
		"lea 0x2(%%rip), %%rbx\n\t" // jmp rax is just 2 bytes
		"jmp %%rax\n\t" // the last element in the sequence would do a 'jmp rbx'
		:
		: "r"(start_seq_va)
		: "%rax", "%rbx"
	);
}

enum class CacheSizeSamplingType {
	DataAccess,
	Jmp
};

constexpr std::tuple<VmmCall, VmmCall, SequenceAccessFunction> translate(CacheSizeSamplingType samplingType) {
	switch(samplingType) {
	case CacheSizeSamplingType::DataAccess:
		return std::make_tuple(VmmCall::StartRandomAccess, VmmCall::RequestRandomDataAccessSeq, access_sequence);
	case CacheSizeSamplingType::Jmp:
		return std::make_tuple(VmmCall::StartRandomJmp, VmmCall::RequestRandomJmpAccessSeq, jmp_sequence);
	default:
		hlt();
		// Unreachable
	}
}

template<CacheSizeSamplingType samplingType>
void sample_random_access(const size_t size, const unsigned long num_iterations) {
	const unsigned long *start_seq_va = (unsigned long *)0x20000;
	VmmCall startVmmCall, requestSeqVmmCall;
	SequenceAccessFunction func;
	std::tie (startVmmCall, requestSeqVmmCall, func) = translate(samplingType);

	vmmcall(startVmmCall);
	for (size_t i = 64; i < size; i += 64) {
		const unsigned long sequence_length = i;
		vmmcall(requestSeqVmmCall, (unsigned long)start_seq_va, sequence_length);
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
		vmmcall(VmmCall::ReportResult, delta, sequence_length);
	}
	vmmcall(VmmCall::DoneTest);
}

void _start() {
	sample_random_access<CacheSizeSamplingType::DataAccess>(2 * 1024 * 1024 / 64, 4096);
	sample_random_access<CacheSizeSamplingType::Jmp>(2 * 1024 * 1024 / 64, 4096);
	hlt();
}
