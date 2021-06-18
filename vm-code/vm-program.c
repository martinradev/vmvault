#include "util.h"

void _start() {
#if 0
	const char msg[] = "ooooello World!";
	for (unsigned i = 0; i < sizeof(msg); ++i) {
		asm volatile(
			"movq %0, %%rax\n\t"
			"vmmcall\n\t"
			:
			: "r"(rdtsc())
			: "%rax", "%rbx", "%rcx", "%rdx"
		);
	}
#endif
	#define N 1024
#if 0
	unsigned long tsc[N];
	for (int i = 0; i < N; ++i) {
		tsc[i] = rdtsc();
	}
	for (int i = 1; i < N; ++i) {
		vmmcall(tsc[i] - tsc[i - 1]);
	}
#endif
	unsigned long perf[N];
	for (int i = 0; i < N; ++i) {
		perf[i] = rd_aperf();
	}

#if 0
	for (int i = 1; i < N; ++i) {
		vmmcall(perf[i] - perf[i - 1]);
	}
#endif

	unsigned long average;
	const unsigned long num = 1024 * 1024 * 16;

	MEASURE_AVERAGE(average, "", num);
	vmmcall(average);

	MEASURE_AVERAGE(average, "mov 0x0, %%rax\n\t", num);
	vmmcall(average);

#if 1
	MEASURE_AVERAGE(average, "mov 0x0, %%rax\n\tmov 0x40, %%rcx\n\t", num);
	vmmcall(average);

	MEASURE_AVERAGE(average, "nop\n\tnop\n\tnop\n\t", num);
	vmmcall(average);

	MEASURE_AVERAGE(average, "nop\n\t", num);
	vmmcall(average);
#endif

	asm volatile(
		"hlt\n\t"
	);
}

