#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include "sm4_opt_avx2.h"

static inline void xor_block_avx2(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i;
    for (i = 0; i + 32 <= len; i += 32) {
        __m256i a = _mm256_loadu_si256((__m256i *)(dst + i));
        __m256i b = _mm256_loadu_si256((__m256i *)(src + i));
        _mm256_storeu_si256((__m256i *)(dst + i), _mm256_xor_si256(a, b));
    }
    for (; i < len; i++) dst[i] ^= src[i];
}

static inline void ghash_avx2(uint8_t *Y, const uint8_t *blocks, size_t nblocks, const uint8_t *H) {
    __m128i y = _mm_loadu_si128((__m128i *)Y);
    for (size_t i = 0; i < nblocks; i++) {
        __m128i x = _mm_loadu_si128((__m128i *)(blocks + i * 16));
        y = _mm_xor_si128(y, x);
        y = gf128_mul_avx2(y, H);
    }
    _mm_storeu_si128((__m128i *)Y, y);
}

void sm4_gcm_encrypt_avx2(
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *plaintext, uint8_t *ciphertext, size_t len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *tag
) {
    uint8_t H[16] = {0};
    sm4_encrypt_block_avx2(key, H, H);

    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    size_t nblocks = (len + 15) / 16;
    for (size_t i = 0; i < nblocks; i += 2) {
        uint8_t ctr[32];
        for (int j = 0; j < 2; j++) {
            if (i + j >= nblocks) break;
            memcpy(ctr + j * 16, J0, 16);
            uint32_t ctr_val = 1 + i + j;
            ctr[j * 16 + 12] = (ctr_val >> 24) & 0xff;
            ctr[j * 16 + 13] = (ctr_val >> 16) & 0xff;
            ctr[j * 16 + 14] = (ctr_val >> 8) & 0xff;
            ctr[j * 16 + 15] = (ctr_val) & 0xff;
        }
        uint8_t stream[32];
        sm4_encrypt_block2_avx2(key, ctr, stream);

        size_t block_len = (i == nblocks - 1) ? (len % 16 == 0 ? 16 : len % 16) : 16 * 2;
        xor_block_avx2(ciphertext + i * 16, stream, block_len);
    }

    size_t total_ghash_len = ((aad_len + 15) / 16 + nblocks + 2) * 16;
    uint8_t ghash_in[total_ghash_len];
    size_t pos = 0;

    memcpy(ghash_in + pos, aad, aad_len);
    pos += aad_len;
    while (pos % 16 != 0) ghash_in[pos++] = 0;

    memcpy(ghash_in + pos, ciphertext, len);
    pos += len;
    while (pos % 16 != 0) ghash_in[pos++] = 0;

    uint64_t aad_bits = aad_len * 8;
    uint64_t c_bits = len * 8;
    for (int i = 0; i < 8; i++) ghash_in[pos++] = (aad_bits >> (56 - i * 8)) & 0xff;
    for (int i = 0; i < 8; i++) ghash_in[pos++] = (c_bits >> (56 - i * 8)) & 0xff;

    uint8_t Y[16] = {0};
    size_t gblocks = pos / 16;
    ghash_avx2(Y, ghash_in, gblocks, H);

    uint8_t EKJ0[16];
    sm4_encrypt_block_avx2(key, J0, EKJ0);
    xor_block_avx2(tag, Y, 16);
    xor_block_avx2(tag, EKJ0, 16);
}