#ifndef AES_H
#define AES_H

#include "util.h"

#include <wmmintrin.h>

extern "C" {
#include "tiny-aes/tiny-aes.h"
}

static const uint8_t bk[] {1U, 2U, 4U, 8U, 16U, 32U, 64U, 128U, 27U, 54U};

static void inline _encAesEcb(const u8 *input, u8 *output, size_t inputSize, const u8 *key, u16 keyLen) {
	// Generate round keys.
	// TODO: do before
	__m128i round[11];
	const __m128i xmm1 { _mm_loadu_si128(reinterpret_cast<const __m128i *>(key)) };
	round[0] = xmm1;
	for (uint8_t i = 1; i <= 10; ++i) {
		__m128i key { round[i - 1] };
		__m128i tmp { _mm_aeskeygenassist_si128(key, bk[i - 1]) };
		tmp = _mm_shuffle_epi32(tmp, 255U);
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		round[i] = _mm_xor_si128(key, tmp);
	}

	// Do the encryption
	for (size_t i = 0; i < inputSize; i += 16UL) {
		__m128i data { _mm_loadu_si128(reinterpret_cast<const __m128i *>(&input[i])) };
		data = _mm_xor_si128(data, round[0]);
		for (size_t j = 1; j < 10; ++j) {
			data = _mm_aesenc_si128(data, round[j]);
		}
		data = _mm_aesenclast_si128(data, round[10]);
		_mm_storeu_si128(reinterpret_cast<__m128i *>(&output[i]), data);
	}
}

static void _encAesCbc(const u8 *input, u8 *output, size_t inputSize, const u8 *key, u16 keyLen, const u8 *iv, u16 ivLen) {
	// Generate round keys.
	// TODO: do before
	__m128i round[11];
	const __m128i xmm1 { _mm_loadu_si128(reinterpret_cast<const __m128i *>(key)) };
	round[0] = xmm1;
	for (uint8_t i = 1; i <= 10; ++i) {
		__m128i key { round[i - 1] };
		__m128i tmp { _mm_aeskeygenassist_si128(key, bk[i - 1]) };
		tmp = _mm_shuffle_epi32(tmp, 255U);
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		round[i] = _mm_xor_si128(key, tmp);
	}

	// Do the encryption
	__m128i iv128 { _mm_loadu_si128(reinterpret_cast<const __m128i *>(iv)) };
	for (size_t i = 0; i < inputSize; i += 16UL) {
		__m128i data { _mm_loadu_si128(reinterpret_cast<const __m128i *>(&input[i])) };
		data = _mm_xor_si128(data, iv128);
		data = _mm_xor_si128(data, round[0]);
		for (size_t j = 1; j < 10; ++j) {
			data = _mm_aesenc_si128(data, round[j]);
		}
		data = _mm_aesenclast_si128(data, round[10]);
		_mm_storeu_si128(reinterpret_cast<__m128i *>(&output[i]), data);
		iv128 = data;
	}
}

#endif
