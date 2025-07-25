// Written by Grok, 2025-Jul-25
// gcc -o pippip_hash_arm pippip_hash_arm.c -march=armv8-a+aes -O2

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arm_neon.h>

#define HashInBITS 32 // default 26 i.e. 2^26 i.e. 64MS(Mega Slots); slots contain 8bytes pointers or 512MB
#define MASK ((1ULL << HashInBITS) - 1)
#define _PADr_KAZE(x, n) (((x) << (n)) >> (n))
#define _PAD_KAZE(x, n) (((x) << (n)))

typedef struct {
    uint64_t low;
    uint64_t high;
} hashPippip128_t;

static inline uint64_t fold64(uint64_t A, uint64_t B) {
    #if defined(__GNUC__) || defined(__clang__)
        // Use 64-bit multiply and high multiply for 128-bit result
        uint64_t low = A * B; // Low 64 bits
        uint64_t high;
        // UMULH equivalent: get high 64 bits of 128-bit product
        #ifdef __aarch64__
            high = __builtin_aarch64_umulh(A, B);
        #else
            // Fallback for non-AArch64 or older compilers
            uint64_t a_low = A & 0xFFFFFFFF;
            uint64_t a_high = A >> 32;
            uint64_t b_low = B & 0xFFFFFFFF;
            uint64_t b_high = B >> 32;
            uint64_t mid = a_low * b_high + a_high * b_low;
            low = (a_low * b_low) + (mid << 32);
            high = (a_high * b_high) + (mid >> 32) + (low < (mid << 32));
        #endif
        return low ^ high;
    #else
        uint64_t hash64 = A ^ B;
        hash64 *= 1099511628211;
        return hash64;
    #endif
}

static inline uint32_t fold32(uint32_t A, uint32_t B) {
    #if defined(__GNUC__) || defined(__clang__)
        uint64_t r = (uint64_t)A * (uint64_t)B;
        return (uint32_t)r ^ (uint32_t)(r >> 32);
    #else
        uint32_t hash32 = A ^ B;
        hash32 *= 591798841;
        return hash32;
    #endif
}

void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ARM(const char *str, size_t wrdlen, uint32_t seed, void *output) {
    uint8x16_t chunkA;
    uint8x16_t chunkB;
    uint8x16_t stateMIX;
    uint64_t hashLH;
    uint64_t hashRH;

    // Initialize stateMIX with seed XOR wrdlen
    stateMIX = vreinterpretq_u8_u32(vdupq_n_u32((uint32_t)wrdlen ^ seed));

    if (wrdlen > 8) {
        uint8x16_t stateA = vreinterpretq_u8_u64(vdupq_n_u64(0x9e3779b97f4a7c15));
        stateA = vsetq_lane_u64(0x6c62272e07bb0142, vreinterpretq_u64_u8(stateA), 1);
        uint8x16_t stateB = vreinterpretq_u8_u64(vdupq_n_u64(0x9e3779b97f4a7c15));
        stateB = vsetq_lane_u64(0x6c62272e07bb0142, vreinterpretq_u64_u8(stateB), 1);
        uint8x16_t stateC = vreinterpretq_u8_u64(vdupq_n_u64(0x9e3779b97f4a7c15));
        stateC = vsetq_lane_u64(0x6c62272e07bb0142, vreinterpretq_u64_u8(stateC), 1);

        size_t Cycles, NDhead;
        if (wrdlen > 16) {
            Cycles = ((wrdlen - 1) >> 5) + 1;
            NDhead = wrdlen - (Cycles << 4);
            if (NDhead < 0 || NDhead + 16 > wrdlen) {
                // Fallback to single-chunk processing for safety
                Cycles = wrdlen >> 4; // Process 16-byte chunks
                for (; Cycles--; str += 16) {
                    chunkA = vld1q_u8((const uint8_t *)str);
                    stateA = vaeseq_u8(stateA, chunkA);
                    stateC = vaeseq_u8(stateC, chunkA);
                    stateB = vaeseq_u8(stateB, chunkA);
                    stateC = vaeseq_u8(stateC, chunkA);
                }
            } else if (Cycles & 1) {
                #pragma nounroll
                for (; Cycles--; str += 16) {
                    chunkA = vld1q_u8((const uint8_t *)str);
                    stateA = vaeseq_u8(stateA, chunkA);
                    chunkB = vld1q_u8((const uint8_t *)(str + NDhead));
                    stateC = vaeseq_u8(stateC, chunkA);
                    stateB = vaeseq_u8(stateB, chunkB);
                    stateC = vaeseq_u8(stateC, chunkB);
                }
            } else {
                Cycles = Cycles >> 1;
                uint8x16_t stateA2 = vreinterpretq_u8_u64(vdupq_n_u64(0x9e3779b97f4a7c15));
                stateA2 = vsetq_lane_u64(0x6c62272e07bb0142, vreinterpretq_u64_u8(stateA2), 1);
                uint8x16_t stateB2 = vreinterpretq_u8_u64(vdupq_n_u64(0x9e3779b97f4a7c15));
                stateB2 = vsetq_lane_u64(0x6c62272e07bb0142, vreinterpretq_u64_u8(stateB2), 1);
                uint8x16_t stateC2 = vreinterpretq_u8_u64(vdupq_n_u64(0x9e3779b97f4a7c15));
                stateC2 = vsetq_lane_u64(0x6c62272e07bb0142, vreinterpretq_u64_u8(stateC2), 1);
                #pragma nounroll
                for (; Cycles--; str += 32) {
                    chunkA = vld1q_u8((const uint8_t *)str);
                    uint8x16_t chunkA2 = vld1q_u8((const uint8_t *)(str + 16));
                    stateA = vaeseq_u8(stateA, chunkA);
                    stateA2 = vaeseq_u8(stateA2, chunkA2);
                    chunkB = vld1q_u8((const uint8_t *)(str + NDhead));
                    uint8x16_t chunkB2 = vld1q_u8((const uint8_t *)(str + NDhead + 16));
                    stateC = vaeseq_u8(stateC, chunkA);
                    stateB = vaeseq_u8(stateB, chunkB);
                    stateC = vaeseq_u8(stateC, chunkB);
                    stateC2 = vaeseq_u8(stateC2, chunkA2);
                    stateB2 = vaeseq_u8(stateB2, chunkB2);
                    stateC2 = vaeseq_u8(stateC2, chunkB2);
                    stateMIX = vaeseq_u8(stateMIX, stateA2);
                    stateMIX = vaeseq_u8(stateMIX, stateB2);
                    stateMIX = vaeseq_u8(stateMIX, stateC2);
                }
            }
        } else { // 9..16 bytes
            NDhead = wrdlen - (1 << 3);
            hashLH = (*(uint64_t *)(str));
            hashRH = (*(uint64_t *)(str + NDhead));
            chunkA = vreinterpretq_u8_u64(vdupq_n_u64(hashLH));
            stateA = vaeseq_u8(stateA, chunkA);
            chunkB = vreinterpretq_u8_u64(vdupq_n_u64(hashRH));
            stateC = vaeseq_u8(stateC, chunkA);
            stateB = vaeseq_u8(stateB, chunkB);
            stateC = vaeseq_u8(stateC, chunkB);
        }
        stateMIX = vaeseq_u8(stateMIX, stateA);
        stateMIX = vaeseq_u8(stateMIX, stateB);
        stateMIX = vaeseq_u8(stateMIX, stateC);
    } else {
        hashLH = _PADr_KAZE(*(uint64_t *)(str + 0), (8 - wrdlen) << 3);
        hashRH = _PAD_KAZE(*(uint64_t *)(str + 0), (8 - wrdlen) << 3);
        chunkA = vreinterpretq_u8_u64(vdupq_n_u64(hashLH));
        chunkB = vreinterpretq_u8_u64(vdupq_n_u64(hashRH));
        stateMIX = vaeseq_u8(stateMIX, chunkA);
        stateMIX = vaeseq_u8(stateMIX, chunkB);
    }

    #ifdef eXdupe
        vst1q_u8((uint8_t *)output, stateMIX); // Store full 128-bit state
    #else
        uint64_t result[2];
        vst1q_u8((uint8_t *)result, stateMIX);
        uint64_t hash64 = fold64(result[0], result[1]);
        *(uint32_t *)output = (uint32_t)hash64 ^ wrdlen;
    #endif
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];
    size_t len = strlen(input);
    uint32_t seed = 42;

    // Test 32-bit hash
    uint32_t hash32;
    FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ARM(input, len, seed, &hash32);
    printf("32-bit hash: 0x%08x\n", hash32);

    // Test 128-bit hash (eXdupe mode)
    #ifdef eXdupe
        hashPippip128_t hash128;
        FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ARM(input, len, seed, &hash128);
        printf("128-bit hash: 0x%016llx%016llx\n",
               (unsigned long long)hash128.high, (unsigned long long)hash128.low);
    #endif

    return 0;
}
