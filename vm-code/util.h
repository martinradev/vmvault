#ifndef UTIL_H
#define UTIL_H

#include "hv-microbench-structures.h"
#include "mini-svm-communication-block.h"

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
		: "r"((unsigned long)cmd), "r"(arg1), "r"(arg2), "r"(arg3)
		: "%rax", "%rdi", "%rsi", "%rdx"
	);
}

static inline void vmmcall(VmmCall cmd, unsigned long arg1, unsigned long arg2) {
	vmmcall((unsigned long)cmd, arg1, arg2, 0);
}

static inline void vmmcall(VmmCall cmd, unsigned long arg1) {
	vmmcall(cmd, arg1, 0);
}

static inline void vmmcall(VmmCall cmd) {
	vmmcall(cmd, 0);
}

static inline void hlt() {
	asm volatile("hlt\n\t");
}

static inline void vmgexit() {
	asm volatile("rep; vmmcall");
}

#endif
