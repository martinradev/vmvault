#ifndef AES_H
#define AES_H

#include "util.h"
#include "mini-svm-communication-block.h"

#include <wmmintrin.h>

static const uint8_t bk[] {1U, 2U, 4U, 8U, 16U, 32U, 64U, 128U, 27U, 54U};

struct AesContext {
	__m128i encRounds[13];
	__m128i decRounds[13];
	__m128i iv;

	void initContext(const u8 *key, u16 keyLen, const u8 *ivIn) {
		const __m128i xmm1 { _mm_loadu_si128(reinterpret_cast<const __m128i *>(key)) };
		encRounds[0] = xmm1;
		#pragma GCC unroll 32
		for (uint8_t i = 1; i <= 10; ++i) {
			__m128i key { encRounds[i - 1] };
			__m128i tmp { _mm_aeskeygenassist_si128(key, bk[i - 1]) };
			tmp = _mm_shuffle_epi32(tmp, 255U);
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
			encRounds[i] = _mm_xor_si128(key, tmp);
		}
		decRounds[0] = encRounds[10];
		#pragma GCC unroll 32
		for (uint8_t i = 1; i < 10; ++i) {
			decRounds[i] = _mm_aesimc_si128(encRounds[10 - i]);
		}
		decRounds[10] = encRounds[0];
		iv = _mm_loadu_si128(reinterpret_cast<const __m128i *>(ivIn));
	}

	void invalidate() {
		memset(encRounds, 0, sizeof(encRounds));
		memset(decRounds, 0, sizeof(decRounds));
		memset(&iv, 0, sizeof(iv));
	}
};

template<MiniSvmCipher cipher>
static void inline aesEncrypt(const u8 *input, u8 *output, size_t inputSize, AesContext &ctx) {
	for (size_t i = 0; i < inputSize; i += 16UL) {
		__m128i data { _mm_loadu_si128(reinterpret_cast<const __m128i *>(&input[i])) };
		if constexpr (cipher == MiniSvmCipher_AesCbc) {
			data = _mm_xor_si128(data, ctx.iv);
		}
		data = _mm_xor_si128(data, ctx.encRounds[0]);
		#pragma GCC unroll 32
		for (size_t j = 1; j < 10; ++j) {
			data = _mm_aesenc_si128(data, ctx.encRounds[j]);
		}
		data = _mm_aesenclast_si128(data, ctx.encRounds[10]);
		_mm_storeu_si128(reinterpret_cast<__m128i *>(&output[i]), data);
		if constexpr (cipher == MiniSvmCipher_AesCbc) {
			ctx.iv = data;
		}
	}
}

template<MiniSvmCipher cipher>
static void inline aesDecrypt(const u8 *input, u8 *output, size_t inputSize, AesContext &ctx) {
	for (size_t i = 0; i < inputSize; i += 16UL) {
		__m128i encrypted_data { _mm_loadu_si128(reinterpret_cast<const __m128i *>(&input[i])) };
		__m128i data = _mm_xor_si128(encrypted_data, ctx.decRounds[0]);
		#pragma GCC unroll 32
		for (size_t j = 1; j < 10; ++j) {
			data = _mm_aesdec_si128(data, ctx.decRounds[j]);
		}
		data = _mm_aesdeclast_si128(data, ctx.decRounds[10]);
		if constexpr (cipher == MiniSvmCipher_AesCbc) {
			data = _mm_xor_si128(data, ctx.iv);
			ctx.iv = encrypted_data;
		}
		_mm_storeu_si128(reinterpret_cast<__m128i *>(&output[i]), data);
	}
}

#endif
