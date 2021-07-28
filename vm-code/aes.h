// Copyright (C) 2021 Martin Radev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#ifndef AES_H
#define AES_H

#include "util.h"
#include "sevault-mini-communication-block.h"

#include <wmmintrin.h>
#include <immintrin.h>

static const uint8_t bk[] {1U, 2U, 4U, 8U, 16U, 32U, 64U, 128U, 27U, 54U};

struct AesContext {
	__m128i encRounds[13];
	__m128i decRounds[13];
	__m128i iv;

	void initContext(const u8 *key, u16 keyLen, const u8 *ivIn) {
		const __m128i xmm1 { _mm_loadu_si128(reinterpret_cast<const __m128i *>(key)) };
		encRounds[0] = xmm1;
		#pragma GCC unroll 32
		for (uint8_t i { 1 }; i <= 10; ++i) {
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

	void updateIv(const u8 *ivIn, u16 ivLen) {
		iv = _mm_loadu_si128(reinterpret_cast<const __m128i *>(ivIn));
	}

	void invalidate() {
		memset(encRounds, 0, sizeof(encRounds));
		memset(decRounds, 0, sizeof(decRounds));
		memset(&iv, 0, sizeof(iv));
	}
};

template<SevaultMiniCipher cipher>
static void inline aesEncrypt(const u8 *input, u8 *output, size_t inputSize, AesContext &ctx) {
	const __m128i round0 = ctx.encRounds[0];
	const __m128i round1 = ctx.encRounds[1];
	const __m128i round2 = ctx.encRounds[2];
	const __m128i round3 = ctx.encRounds[3];
	const __m128i round4 = ctx.encRounds[4];
	const __m128i round5 = ctx.encRounds[5];
	const __m128i round6 = ctx.encRounds[6];
	const __m128i round7 = ctx.encRounds[7];
	const __m128i round8 = ctx.encRounds[8];
	const __m128i round9 = ctx.encRounds[9];
	const __m128i round10 = ctx.encRounds[10];

	size_t i {};
	for (; i < inputSize; i += 16UL) {
		__m128i data { _mm_loadu_si128(reinterpret_cast<const __m128i *>(&input[i])) };
		if constexpr (cipher == SevaultMiniCipher_AesCbc) {
			data = _mm_xor_si128(data, ctx.iv);
		}
		data = _mm_xor_si128(data, round0);
		data = _mm_aesenc_si128(data, round1);
		data = _mm_aesenc_si128(data, round2);
		data = _mm_aesenc_si128(data, round3);
		data = _mm_aesenc_si128(data, round4);
		data = _mm_aesenc_si128(data, round5);
		data = _mm_aesenc_si128(data, round6);
		data = _mm_aesenc_si128(data, round7);
		data = _mm_aesenc_si128(data, round8);
		data = _mm_aesenc_si128(data, round9);
		data = _mm_aesenclast_si128(data, round10);
		_mm_storeu_si128(reinterpret_cast<__m128i *>(&output[i]), data);
		if constexpr (cipher == SevaultMiniCipher_AesCbc) {
			ctx.iv = data;
		}
	}
}

template<SevaultMiniCipher cipher>
static void inline aesDecrypt(const u8 *input, u8 *output, size_t inputSize, AesContext &ctx) {
	size_t i {};
	for (; i < inputSize; i += 16UL) {
		__m128i encrypted_data { _mm_loadu_si128(reinterpret_cast<const __m128i *>(&input[i])) };
		__m128i data = _mm_xor_si128(encrypted_data, ctx.decRounds[0]);
		#pragma GCC unroll 32
		for (size_t j = 1; j < 10; ++j) {
			data = _mm_aesdec_si128(data, ctx.decRounds[j]);
		}
		data = _mm_aesdeclast_si128(data, ctx.decRounds[10]);
		if constexpr (cipher == SevaultMiniCipher_AesCbc) {
			data = _mm_xor_si128(data, ctx.iv);
			ctx.iv = encrypted_data;
		}
		_mm_storeu_si128(reinterpret_cast<__m128i *>(&output[i]), data);
	}
}

#endif
