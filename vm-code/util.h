#ifndef UTIL_H
#define UTIL_H

static inline unsigned long rdtsc_and_bar(void) {
	unsigned long tsc;
	asm volatile(
		"rdtsc\n\t"
		"mfence\n\t"
		"shl $32, %%rdx\n\t"
		"or %%rdx, %%rax\n\t"
		"mov %%rax, %0\n\t"
		: "=r"(tsc)
		:
		: "%rax", "%rdx"
	);
	return tsc;
}

static inline unsigned long bar_and_rdtsc(void) {
	unsigned long tsc;
	asm volatile(
		"mfence\n\t"
		"rdtsc\n\t"
		"shl $32, %%rdx\n\t"
		"or %%rdx, %%rax\n\t"
		"mov %%rax, %0\n\t"
		: "=r"(tsc)
		:
		: "%rax", "%rdx"
	);
	return tsc;
}

static inline unsigned long rdtsc(void) {
	unsigned long tsc;
	asm volatile(
		"rdtsc\n\t"
		"shl $32, %%rdx\n\t"
		"or %%rdx, %%rax\n\t"
		"mov %%rax, %0\n\t"
		: "=r"(tsc)
		:
		: "%rax", "%rdx"
	);
	return tsc;
}

static inline unsigned long rdtscp(void) {
	unsigned long tsc;
	asm volatile(
		"rdtscp\n\t"
		"shl $32, %%rdx\n\t"
		"or %%rdx, %%rax\n\t"
		"mov %%rax, %0\n\t"
		: "=r"(tsc)
		:
		: "%rax", "%rdx"
	);
	return tsc;
}

static inline unsigned long rd_aperf(void) {
	unsigned long clock;
	asm volatile(
		"mov $0xe8, %%rcx\n\t"
		"rdmsr\n\t"
		"shl $32, %%rdx\n\t"
		"or %%rdx, %%rax\n\t"
		"mov %%rax, %0\n\t"
		: "=r"(clock)
		:
		: "%rax", "%rdx", "%rcx"
	);
	return clock;
}

static inline void vmmcall(
		unsigned long cmd,
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3) {
	asm volatile(
		"movq %0, %%rax\n\t"
		"movq %1, %%rdi\n\t"
		"movq %2, %%rsi\n\t"
		"movq %3, %%rdx\n\t"
		"vmmcall\n\t"
		:
		: "r"(cmd), "r"(arg1), "r"(arg2), "r"(arg3)
		: "%rax", "%rdi", "%rsi", "%rdx"
	);
}

static inline void vmmcall(unsigned long cmd) {
	vmmcall(cmd, 0, 0, 0);
}

static inline void vmmcall(unsigned long cmd, unsigned long arg1) {
	vmmcall(cmd, arg1, 0, 0);
}

static inline void vmmcall(unsigned long cmd, unsigned long arg1, unsigned long arg2) {
	vmmcall(cmd, arg1, arg2, 0);
}

#define MEASURE(OPS) \
	{ \
		asm volatile( \
			"mov $0xe8, %%rcx\n\t" \
			"rdmsr\n\t" \
			/* "rdtsc\n\t" */ \
			"shl $32, %%rdx\n\t" \
			"or %%rdx, %%rax\n\t" \
			"mov %%rax, %%r8\n\t" \
			OPS \
			"mov $0xe8, %%rcx\n\t" \
			"rdmsr\n\t" \
			/* "rdtsc\n\t" */ \
			"shl $32, %%rdx\n\t" \
			"or %%rdx, %%rax\n\t" \
			"sub %%r8, %%rax\n\t" \
			"mov %%rax, %0\n\t" \
			: "=r"(delta_result) \
			: \
			: "%rax", "%rdx", "%rcx", "%r8", "%rbx" \
		); \
	}

#define MEASURE_AVERAGE(OUT, OPS, NUM) \
{ \
		unsigned long total = 0; \
		for (unsigned long i = 0; i < NUM; ++i) { \
				unsigned long delta_result = 0; \
				MEASURE( \
					OPS \
				); \
				total += delta_result; \
		} \
		OUT = total / (unsigned long)NUM; \
}

void measure_random_access_linked_list(const unsigned long *start, unsigned long *out);

#endif
