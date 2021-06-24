#include "util.h"

#include "hv-microbench-structures.h"

#include <cstddef>
#include <tuple>
#include <algorithm>
#include <string.h>

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
		"jmp *%%rax\n\t" // the last element in the sequence would do a 'jmp rbx'
		:
		: "r"(start_seq_va)
		: "%rax", "%rbx"
	);
}

enum class CacheSizeSamplingType {
	DataAccess,
	Jmp,
	PageAccess,
	PageJmp,
};

constexpr std::tuple<VmmCall, VmmCall, SequenceAccessFunction> translate(CacheSizeSamplingType samplingType) {
	switch(samplingType) {
	case CacheSizeSamplingType::PageAccess:
		return std::make_tuple(VmmCall::StartRandomPageAccess, VmmCall::RequestRandomPageAccessSeq, access_sequence);
	case CacheSizeSamplingType::DataAccess:
		return std::make_tuple(VmmCall::StartRandomAccess, VmmCall::RequestRandomDataAccessSeq, access_sequence);
	case CacheSizeSamplingType::Jmp:
		return std::make_tuple(VmmCall::StartRandomJmp, VmmCall::RequestRandomJmpAccessSeq, jmp_sequence);
	case CacheSizeSamplingType::PageJmp:
		return std::make_tuple(VmmCall::StartRandomPageJmp, VmmCall::RequestRandomJmpPageSeq, jmp_sequence);
	default:
		hlt();
		// Unreachable
	}
}

template<CacheSizeSamplingType samplingType>
static inline void sample_random_access(const unsigned long start_phys_addr, const unsigned long *start_seq_va, const size_t start, const size_t size, const size_t step, const unsigned long num_iterations) {
	VmmCall startVmmCall, requestSeqVmmCall;
	SequenceAccessFunction func;
	std::tie (startVmmCall, requestSeqVmmCall, func) = translate(samplingType);

	vmmcall(startVmmCall);
	for (size_t i = start; i <= size; i += step) {
		const unsigned long sequence_length = i;
		auto smallest = std::numeric_limits<unsigned long>::max();
		for (unsigned long j = 0; j < num_iterations; ++j) {
			vmmcall(requestSeqVmmCall, start_phys_addr, (unsigned long)start_seq_va, sequence_length);
			unsigned long ta, te;
			const unsigned long ntimes = 64;
			while (1) {
				func((unsigned long *)(start_seq_va));
				ta = rdtsc_and_bar();
				for (size_t q = 0; q < ntimes; ++q) {
					func((unsigned long *)(start_seq_va));
				}
				te = bar_and_rdtsc();
				if (te > ta) {
					break;
				}
			}
			const unsigned long total_accesses = ntimes * sequence_length;
			const unsigned long delta = (te - ta) / total_accesses;
			smallest = std::min(smallest, delta);
		}
		vmmcall(VmmCall::ReportResult, smallest, sequence_length);
	}
	vmmcall(VmmCall::DoneTest);
}

static inline void construct_4k_tables() {
	volatile unsigned long *pdp = (volatile unsigned long *)0x1000UL;
	volatile unsigned long *pd = (volatile unsigned long *)0x2000UL;
	pdp[1] = ((unsigned long)pd | 0x7UL);

	for (unsigned long j = 0; j < 16; ++j) {
		volatile unsigned long *pt = (volatile unsigned long *)(0x3000UL + j * 0x1000UL);
		pd[j] = ((unsigned long)pt | 0x7UL);
		for (unsigned long i = 0; i < 512; ++i) {
			pt[i] = ((j * 1024UL * 1024UL * 2UL) + (i * 0x1000UL)) | 0x7UL; // Not writeable, not executable
		}
	}
	// Flush TLBs
	asm volatile(
		"movq %0, %%cr3\n\t"
		:
		: "r"(0x0UL)
		:
	);
}

void _start() {
	construct_4k_tables();

	// Check data cache size and access latency.
	sample_random_access<CacheSizeSamplingType::DataAccess>(0x20000UL, (unsigned long *)0x20000, 128, 2 * 1024 * 1024 / 64, 128, 16);

	// Check instruction cache size and access latency.
	sample_random_access<CacheSizeSamplingType::Jmp>(0x20000UL, (unsigned long *)0x20000, 128, 2 * 1024 * 1024 / 64, 128, 16);

	// Check dTLB size and latency.
	sample_random_access<CacheSizeSamplingType::PageAccess>(
		0x20000UL, (unsigned long *)(0x20000UL), 4, 4096, 4, 32);

	// Check iTLB size and latency.
	sample_random_access<CacheSizeSamplingType::PageJmp>(
		0x20000UL, (unsigned long *)(0x20000UL), 4, 1024, 4, 32);

	// Exit.
	hlt();
}
