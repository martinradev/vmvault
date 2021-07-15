#ifndef UTIL_H
#define UTIL_H

#include <array>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <atomic>

#include "sevault-mini-communication-block.h"

using u64 = uint64_t;
using u32 = uint64_t;
using u16 = uint16_t;
using u8  = uint8_t;

enum class Result {
	Ok,
	Fail
};

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
	asm volatile("hlt\n\t" : : : "memory");
}

static inline void vmgexit() {
	asm volatile("rep; vmmcall" : : : "memory");
}

extern "C"
void *memcpy(void *dest, const void *src, size_t size) noexcept {
	u8 *destAsU8 { static_cast<u8 *>(dest) };
	const u8 *srcAsU8 { static_cast<const u8 *>(src) };
	for (size_t i {}; i < size; ++i) {
		destAsU8[i] = srcAsU8[i];
	}
	return dest;
}

extern "C"
void *memset(void *dest, int value, size_t size) noexcept {
	u8 *destAsU8 { static_cast<u8 *>(dest) };
	const u8 valueAsU8 { static_cast<const u8>(value) };
	for (size_t i {}; i < size; ++i) {
		destAsU8[i] = valueAsU8;
	}
	return dest;
}

class RWLock {
public:
	void takeLock() {
		while(flag.test_and_set()) {
			asm volatile ("pause\n\t");
		}
	}
	void releaseLock() {
		flag.clear();
	}
private:
	std::atomic_flag flag {};
};

class ScopedRWLock {
public:
	ScopedRWLock(RWLock &lockIn) : lock(lockIn) {
		lock.takeLock();
	}
	~ScopedRWLock() {
		lock.releaseLock();
	}
private:
	RWLock &lock;
};

#endif
