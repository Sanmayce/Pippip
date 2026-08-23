// FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_4HEADS 'VierKöpfe': the 100% FREE lookuper, last update: 2026-Aug-21, Kaze (sanmayce@sanmayce.com). [
// This latest revision was written when Mikayla "saveafox" left this world.

// "There it now stands for ever. Black on white.
// I can't get away from it. Ahoy, Yorikke, ahoy, hoy, ho!
// Go to hell now if you wish. What do I care? It's all the same now to me.
// I am part of you now. Where you go I go, where you leave I leave, when you go to the devil I go. Married.
// Vanished from the living. Damned and doomed. Of me there is not left a breath in all the vast world.
// Ahoy, Yorikke! Ahoy, hoy, ho!
// I am not buried in the sea,
// The death ship is now part of me
// So far from sunny New Orleans
// So far from lovely Louisiana."
// /An excerpt from 'THE DEATH SHIP - THE STORY OF AN AMERICAN SAILOR' by B.TRAVEN/
// 
// "Walking home to our good old Yorikke, I could not help thinking of this beautiful ship, with a crew on board that had faces as if they were seeing ghosts by day and by night.
// Compared to that gilded Empress, the Yorikke was an honorable old lady with lavender sachets in her drawers.
// Yorikke did not pretend to anything she was not. She lived up to her looks. Honest to her lowest ribs and to the leaks in her bilge.
// Now, what is this? I find myself falling in love with that old jane.
// All right, I cannot pass by you, Yorikke; I have to tell you I love you. Honest, baby, I love you.
// I have six black finger-nails, and four black and green-blue nails on my toes, which you, honey, gave me when necking you.
// Grate-bars have crushed some of my toes. And each finger-nail has its own painful story to tell.
// My chest, my back, my arms, my legs are covered with scars of burns and scorchings.
// Each scar, when it was being created, caused me pains which I shall surely never forget.
// But every outcry of pain was a love-cry for you, honey.
// You are no hypocrite. Your heart does not bleed tears when you do not feel heart-aches deeply and truly.
// You do not dance on the water if you do not feel like being jolly and kicking chasers in the pants.
// Your heart never lies. It is fine and clean like polished gold. Never mind the rags, honey dear.
// When you laugh, your whole soul and all your body is laughing.
// And when you weep, sweety, then you weep so that even the reefs you pass feel like weeping with you.
// I never want to leave you again, honey. I mean it. Not for all the rich and elegant buckets in the world.
// I love you, my gypsy of the sea!"
// /An excerpt from 'THE DEATH SHIP - THE STORY OF AN AMERICAN SAILOR' by B.TRAVEN/
//
// Dedicated to Pippip, the main character in the 'Das Totenschiff' roman, actually the B.Traven himself, his real name was Hermann Albert Otto Maksymilian Feige.
// CAUTION: Add 8 more bytes to the buffer being hashed, usually malloc(...+8) - to prevent out of boundary reads!
// Many thanks go to Yurii 'Hordi' Hordiienko, he lessened with 3 instructions the original 'Pippip', thus:
// 

#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>
#define HashInBITS 32 // default 26 i.e. 2^26 i.e. 64MS(Mega Slots); slots contain 8bytes pointers or 512MB, because many netbooks have 512MB free (1GB in total)!
#define MASK ((1ULL << HashInBITS) - 1)
#define _PADr_KAZE(x, n) ( ((x) << (n))>>(n) )
#define _PAD_KAZE(x, n) ( ((x) << (n)) )

typedef struct {
	uint64_t low;
	uint64_t high;
} hashPippip128_t;

static inline uint64_t fold64(uint64_t A, uint64_t B) {
	#if defined(__GNUC__) || defined(__clang__)
		__uint128_t r = (__uint128_t)A * B;
		return (uint64_t)r ^ (uint64_t)(r >> 64);
	#else
		uint64_t hash64 = A ^ B;
		hash64 *= 1099511628211; //591798841;
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

// ### 1. `0x6C62272E07BB0142` (The FNV-128 Offset Basis)
// 
// * **Origin:** This is the upper 64 bits of the **128-bit FNV offset basis**.
// * **Derivation:** The full 128-bit FNV offset basis is a massive, mathematically derived integer (`144066263297769815596495629667062367629`), which in hexadecimal is `0x6C62272E07BB014262B821756295C58D`. The first half is `0x6C62272E07BB0142`.
// * **Use Case:** It acts as the seed/starting state for Fowler-Noll-Vo (FNV) 128-bit non-cryptographic hashes.
// ### 2. `0x9E3779B97F4A7C15` (The Golden Ratio Constant)
// * **Origin:** This is derived from the **Golden Ratio** ($\phi$).
// * **Derivation:** It represents the fractional part of $\phi \times 2^{64}$. Specifically, $2^{64} / \phi \approx 11400714819323198485$, which translates directly to `0x9E3779B97F4A7C15` in 64-bit hexadecimal.
// * **Name/Use Case:** Widely known as the **RC5 Magic Constant** ($Q_{64}$), the **Golden Gamma**, or `pow64_over_phi`. It is incredibly popular for scattering bits cleanly, featuring heavily in SplitMix64 pseudo-random number generators, the Tiny Encryption Algorithm (TEA), and SpookyHash.

#define MGK_64_01 0x6c62272e07bb0142ULL
#define MGK_64_02 0x9e3779b97f4a7c15ULL

// Actually 'FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_4HEADS'
static inline void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla (const char *str, size_t wrdlen, uint32_t seed, void *output) {
	__m128i chunkA;
	__m128i chunkB;
	__m128i stateMIX;
	uint64_t hashLH;
	uint64_t hashRH;

	stateMIX = _mm_set1_epi32( (uint32_t)wrdlen ^ seed );
		__m128i stateA = _mm_set_epi64x(MGK_64_01, MGK_64_02);
		__m128i stateB = _mm_set_epi64x(MGK_64_01, MGK_64_02);

	if (wrdlen > 16) {
		__m128i stateC = _mm_set_epi64x(MGK_64_01, MGK_64_02);
		__m128i stateD = _mm_set_epi64x(MGK_64_01, MGK_64_02);

		const __m128i BSWAP_MASK = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
			
		size_t num_blocks = ((wrdlen - 1) >> 5) + 1;
		size_t stride_bytes = num_blocks << 4;
		size_t NDhead = wrdlen - stride_bytes;

		const uint8_t *p_h1 = (const uint8_t *)str;
		const uint8_t *p_h2 = (const uint8_t *)str + NDhead;
		const uint8_t *p_h3 = (const uint8_t *)str + wrdlen - 16;
		const uint8_t *p_h4 = (const uint8_t *)str + stride_bytes - 16;

		for (size_t i = 0; i < num_blocks; i++) {
		    __m128i v1 = _mm_loadu_si128((const __m128i *)p_h1);
		    __m128i v2 = _mm_loadu_si128((const __m128i *)p_h2);
		    __m128i v3 = _mm_loadu_si128((const __m128i *)p_h3);
		    __m128i v4 = _mm_loadu_si128((const __m128i *)p_h4);

		    stateA = _mm_aesenc_si128(stateA, v1);
		    stateB = _mm_aesenc_si128(stateB, v2);
		    stateC = _mm_aesenc_si128(stateC, v3);
		    stateD = _mm_aesenc_si128(stateD, v4);

		stateMIX = _mm_aesenc_si128(stateMIX, stateA);
		stateMIX = _mm_aesenc_si128(stateMIX, stateB);
		stateMIX = _mm_aesenc_si128(stateMIX, stateC);
		stateMIX = _mm_aesenc_si128(stateMIX, stateD);

		    v1 = _mm_shuffle_epi8(v1, BSWAP_MASK);
		    v2 = _mm_shuffle_epi8(v2, BSWAP_MASK);
		    v3 = _mm_shuffle_epi8(v3, BSWAP_MASK);
		    v4 = _mm_shuffle_epi8(v4, BSWAP_MASK);

		    stateA = _mm_aesenc_si128(stateA, v3);
		    stateB = _mm_aesenc_si128(stateB, v4);
		    stateC = _mm_aesenc_si128(stateC, v1);
		    stateD = _mm_aesenc_si128(stateD, v2);

		stateMIX = _mm_aesenc_si128(stateMIX, stateA);
		stateMIX = _mm_aesenc_si128(stateMIX, stateB);
		stateMIX = _mm_aesenc_si128(stateMIX, stateC);
		stateMIX = _mm_aesenc_si128(stateMIX, stateD);

		    p_h1 += 16;
		    p_h2 += 16;
		    p_h3 -= 16;
		    p_h4 -= 16;
		}
	} else { // 1..16

	        hashLH = (*(uint64_t *)(str));
			if (wrdlen > 8) {
		        hashRH = (*(uint64_t *)(str+ wrdlen-(1<<3) ));
			} else {
				hashLH = _PADr_KAZE(hashLH, (8-wrdlen)<<3); // wrdlen == 0 is not handled since <<64 is undefined
				hashRH = _PAD_KAZE(hashLH, (8-wrdlen)<<3);
			}
				chunkA = _mm_set_epi64x(hashLH, hashLH);
				chunkB = _mm_set_epi64x(hashRH, hashRH);

				stateMIX = _mm_aesenc_si128(stateMIX, _mm_aesenc_si128(stateA, chunkA));
				stateMIX = _mm_aesenc_si128(stateMIX, chunkA);
				stateMIX = _mm_aesenc_si128(stateMIX, _mm_aesenc_si128(stateB, chunkB));
				stateMIX = _mm_aesenc_si128(stateMIX, chunkB);
	}

    #ifdef eXdupe
	    _mm_storeu_si128((__m128i *)output, stateMIX); // For eXdupe
    #else
		uint64_t result[2];
		_mm_storeu_si128((__m128i *)result, stateMIX);
		uint64_t hash64 = fold64(result[0], result[1]);
		*(uint32_t*)output = (uint32_t)hash64 ^ wrdlen;
    #endif
}

// Actually 'FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_FOX'
static inline void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_FOX (const char *str, size_t wrdlen, uint32_t seed, void *output) {
	__m128i chunkA;
	__m128i chunkB;
	__m128i stateMIX;
	uint64_t hashLH;
	uint64_t hashRH;
    //__m128i InterleaveMask = _mm_set_epi8(15,7,14,6,13,5,12,4,11,3,10,2,9,1,8,0);

	stateMIX = _mm_set1_epi32( (uint32_t)wrdlen ^ seed );
		__m128i stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
		__m128i stateB = _mm_set_epi64x(0x6A09E667F3BCC908, 0xBB67AE8584CAA73B);
		__m128i stateC = _mm_set_epi64x(0x3C6EF372FE94F82B, 0x428A2F98D728AE22);
	if (wrdlen > 8) {
		size_t Cycles, NDhead;
		if (wrdlen > 16) {
			Cycles = ((wrdlen - 1)>>5) + 1;
			NDhead = wrdlen - (Cycles<<4);
			if (Cycles & 1) {
				#pragma nounroll
				for(; Cycles--; str += 16) {
					//_mm_prefetch(str+512, _MM_HINT_T0);
					//_mm_prefetch(str+NDhead+512, _MM_HINT_T0);

					chunkA = _mm_loadu_si128((__m128i *)(str));
					chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
					stateA = _mm_aesenc_si128(stateA, chunkA);
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateC = _mm_aesenc_si128(stateC, chunkB);
					//stateC = _mm_aesenc_si128(stateC, stateMIX);
				}
			} else {
				Cycles = Cycles>>1;
				__m128i stateA2 = _mm_set_epi64x(0x9e3779b97f4a7c15, 0x6c62272e07bb0142);
				__m128i stateB2 = _mm_set_epi64x(0xBB67AE8584CAA73B, 0x6A09E667F3BCC908);
				__m128i stateC2 = _mm_set_epi64x(0x428A2F98D728AE22, 0x3C6EF372FE94F82B);
				#pragma nounroll
				for(; Cycles--; str += 32) {
					_mm_prefetch(str, _MM_HINT_T0);
					_mm_prefetch(str+NDhead, _MM_HINT_T0);

					chunkA = _mm_loadu_si128((__m128i *)(str));
					__m128i chunkA2 = _mm_loadu_si128((__m128i *)(str+16));
					stateA = _mm_aesenc_si128(stateA, chunkA);
					stateA2 = _mm_aesenc_si128(stateA2, chunkA2);
					chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
					__m128i chunkB2 = _mm_loadu_si128((__m128i *)(str+NDhead+16));
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateB2 = _mm_aesenc_si128(stateB2, chunkB2);

					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateC2 = _mm_aesenc_si128(stateC2, chunkA2);

					stateC = _mm_aesenc_si128(stateC, chunkB);
					stateC2 = _mm_aesenc_si128(stateC2, chunkB2);
				}
				stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
				stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
				stateMIX = _mm_aesenc_si128(stateMIX, stateC2);
			}
		} else { // 9..16
            NDhead = wrdlen - (1<<3);
            hashLH = (*(uint64_t *)(str));
            hashRH = (*(uint64_t *)(str+NDhead));

            chunkA = _mm_set_epi64x(hashLH, hashLH);
            chunkB = _mm_set_epi64x(hashRH, hashRH);

            chunkA = _mm_xor_si128(chunkA, stateMIX);
            chunkB = _mm_xor_si128(chunkB, stateMIX);

            stateA = _mm_aesenc_si128(stateA, chunkA);
            stateB = _mm_aesenc_si128(stateB, chunkB);

		}
	} else {
		hashLH = _PADr_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3); // wrdlen == 0 is not handled since <<64 is undefined
		hashRH = _PAD_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3);
	    chunkA = _mm_set_epi64x(hashLH, hashRH);
	    chunkB = _mm_set_epi64x(hashRH, hashLH);
					stateA = _mm_aesenc_si128(stateA, chunkA);
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateC = _mm_aesenc_si128(stateC, chunkB);
	}

		stateMIX = _mm_aesenc_si128(stateMIX, stateA);
		stateMIX = _mm_aesenc_si128(stateMIX, stateB);
		stateMIX = _mm_aesenc_si128(stateMIX, stateC);

    #ifdef eXdupe
	    _mm_storeu_si128((__m128i *)output, stateMIX); // For eXdupe
    #else
		uint64_t result[2];
		_mm_storeu_si128((__m128i *)result, stateMIX);
		uint64_t hash64 = fold64(result[0], result[1]);
		*(uint32_t*)output = (uint32_t)hash64 ^ wrdlen;
    #endif
}

//	Cycles = ((wrdlen - 1)>>5) + 1;
//	NDhead = wrdlen - (Cycles<<4);
// And some visualization for XMM-WORD:
/*
kl= 33..64 Cycles= (kl-1)/32+1=2; MARGINAL CASES:
                                 2nd head starts at 33-2*16=1 or:
                                        0123456789012345 0123456789012345 0
                                 Head1: [XMM-WORD      ] [XMM-WORD      ]
                                 Head2:  [XMM-WORD      ] [XMM-WORD      ]

                                 2nd head starts at 64-2*16=32 or:
                                        0123456789012345 0123456789012345 0123456789012345 0123456789012345
                                 Head1: [XMM-WORD      ] [XMM-WORD      ]
                                 Head2:                                   [XMM-WORD      ] [XMM-WORD      ]

kl=65..96 Cycles= (kl-1)/32+1=3; MARGINAL CASES:
                                 2nd head starts at 65-3*16=17 or:
                                        0123456789012345 0123456789012345 0123456789012345 0123456789012345 0
                                 Head1: [XMM-WORD      ] [XMM-WORD      ] [XMM-WORD      ]
                                 Head2:                   [XMM-WORD      ] [XMM-WORD      ] [XMM-WORD      ]

                                 2nd head starts at 96-3*16=48 or:
                                        0123456789012345 0123456789012345 0123456789012345 0123456789012345 0123456789012345 0123456789012345
                                 Head1: [XMM-WORD      ] [XMM-WORD      ] [XMM-WORD      ]
                                 Head2:                                                    [XMM-WORD      ] [XMM-WORD      ] [XMM-WORD      ]
*/

// And some visualization for Q-WORD:
/*
kl= 9..16 Cycles= (kl-1)/16+1=1; MARGINAL CASES:
                                 2nd head starts at 9-1*8=1 or:
                                        012345678
                                 Head1: [Q-WORD]
                                 Head2:  [Q-WORD]

                                 2nd head starts at 16-1*8=8 or:
                                        0123456789012345
                                 Head1: [Q-WORD]
                                 Head2:         [Q-WORD]

kl=17..24 Cycles= (kl-1)/16+1=2; MARGINAL CASES:
                                 2nd head starts at 17-2*8=1 or:
                                        01234567890123456
                                 Head1: [Q-WORD][Q-WORD]
                                 Head2:  [Q-WORD][Q-WORD]

                                 2nd head starts at 24-2*8=8 or:
                                        012345678901234567890123
                                 Head1: [Q-WORD][Q-WORD]
                                 Head2:         [Q-WORD][Q-WORD]

kl=25..32 Cycles= (kl-1)/16+1=2; MARGINAL CASES:
                                 2nd head starts at 25-2*8=9 or:
                                        0123456789012345678901234
                                 Head1: [Q-WORD][Q-WORD]
                                 Head2:          [Q-WORD][Q-WORD]

                                 2nd head starts at 32-2*8=16 or:
                                        01234567890123456789012345678901
                                 Head1: [Q-WORD][Q-WORD]
                                 Head2:                 [Q-WORD][Q-WORD]

kl=33..40 Cycles= (kl-1)/16+1=3; MARGINAL CASES:
                                 2nd head starts at 33-3*8=9 or:
                                        012345678901234567890123456789012
                                 Head1: [Q-WORD][Q-WORD][Q-WORD]
                                 Head2:          [Q-WORD][Q-WORD][Q-WORD]

                                 2nd head starts at 40-3*8=16 or:
                                        0123456789012345678901234567890123456789
                                 Head1: [Q-WORD][Q-WORD][Q-WORD]
                                 Head2:                 [Q-WORD][Q-WORD][Q-WORD]

kl=41..48 Cycles= (kl-1)/16+1=3; MARGINAL CASES:
                                 2nd head starts at 41-3*8=17 or:
                                        01234567890123456789012345678901234567890
                                 Head1: [Q-WORD][Q-WORD][Q-WORD]
                                 Head2:                  [Q-WORD][Q-WORD][Q-WORD]

                                 2nd head starts at 48-3*8=24 or:
                                        012345678901234567890123456789012345678901234567
                                 Head1: [Q-WORD][Q-WORD][Q-WORD]
                                 Head2:                         [Q-WORD][Q-WORD][Q-WORD]
*/

// The more the merrier, therefore I added the 10,000 GitHub stars performer xxhash also:
// https://github.com/Cyan4973/xxHash/issues/1029
// 
// Pippip is not an extremely fast hash, it is the spirit of the author materialized disregarding anything outside the "staying true to oneself", or as one bona fide man Otto/Pippip once said:
// 
// Translate as verbatim as possible:
// In 1926, Traven wrote that the only biography of a writer should be his
// works: «Die Biographie eines schöpferischen Menschen ist ganz und gar unwichtig.
// Wenn der Mensch in seinen Werken nicht zu erkennen ist, dann ist entweder der
// Mensch nichts wert oder seine Werke sind nichts wert. Darum sollte der schöpferische
// Mensch keine andere Biographie haben als seine Werke» (Hauschild, B. Traven: Die
// unbekannten Jahre, op. cit., p. 31.)
// 
// In 1926, Traven wrote that the only biography of a writer should be his works:
// “The biography of a creative person is completely and utterly unimportant.
// If the person is not recognizable in his works, then either the person is worthless or his works are worthless.
// Therefore, the creative person should have no other biography than his works” (Hauschild, B. Traven: Die unbekannten Jahre, op. cit., p. 31.) 

// https://godbolt.org/z/4Y9rr6K6K
// x86-64 clang 22.1.0
// -O3 -maes -msse4.2
/*
.LCPI0_0:
        .quad   -7046029254386353131
        .quad   7809847782465536322
.LCPI0_1:
        .byte   15
        .byte   14
        .byte   13
        .byte   12
        .byte   11
        .byte   10
        .byte   9
        .byte   8
        .byte   7
        .byte   6
        .byte   5
        .byte   4
        .byte   3
        .byte   2
        .byte   1
        .byte   0
FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla(char const*, unsigned long, unsigned int, void*):
        mov     eax, esi
        xor     eax, edx
        movd    xmm0, eax
        pshufd  xmm0, xmm0, 0
        cmp     rsi, 17
        jb      .LBB0_3
        lea     rax, [rsi - 1]
        shr     rax
        and     rax, -16
        lea     rdx, [rdi + rax]
        neg     rax
        lea     r8, [rsi + rdi]
        add     r8, -16
        movdqa  xmm1, xmmword ptr [rip + .LCPI0_0]
        xor     r9d, r9d
        movdqa  xmm2, xmmword ptr [rip + .LCPI0_1]
        movdqa  xmm3, xmm1
        movdqa  xmm4, xmm1
        movdqa  xmm5, xmm1
.LBB0_2:
        movdqu  xmm7, xmmword ptr [rdi]
        movdqu  xmm6, xmmword ptr [r8 + rax]
        movdqu  xmm8, xmmword ptr [r8 + r9]
        movdqu  xmm9, xmmword ptr [rdx + r9]
        aesenc  xmm1, xmm7
        aesenc  xmm3, xmm6
        aesenc  xmm4, xmm8
        aesenc  xmm5, xmm9
        aesenc  xmm0, xmm1
        aesenc  xmm0, xmm3
        aesenc  xmm0, xmm4
        aesenc  xmm0, xmm5
        pshufb  xmm7, xmm2
        pshufb  xmm6, xmm2
        pshufb  xmm8, xmm2
        pshufb  xmm9, xmm2
        aesenc  xmm1, xmm8
        aesenc  xmm3, xmm9
        aesenc  xmm4, xmm7
        aesenc  xmm5, xmm6
        aesenc  xmm0, xmm1
        aesenc  xmm0, xmm3
        aesenc  xmm0, xmm4
        aesenc  xmm0, xmm5
        add     rdi, 16
        add     rax, 16
        add     r9, -16
        cmp     rax, 16
        jne     .LBB0_2
        jmp     .LBB0_7
.LBB0_3:
        mov     rdx, qword ptr [rdi]
        cmp     rsi, 9
        jb      .LBB0_5
        mov     rdi, qword ptr [rdi + rsi - 8]
        jmp     .LBB0_6
.LBB0_5:
        lea     eax, [8*rsi]
        neg     al
        mov     r8, rcx
        mov     ecx, eax
        shl     rdx, cl
        mov     rdi, rdx
        shr     rdx, cl
        mov     rcx, r8
.LBB0_6:
        movq    xmm1, rdx
        pshufd  xmm1, xmm1, 68
        movq    xmm2, rdi
        pshufd  xmm2, xmm2, 68
        movdqa  xmm3, xmmword ptr [rip + .LCPI0_0]
        movdqa  xmm4, xmm3
        aesenc  xmm4, xmm1
        aesenc  xmm0, xmm4
        aesenc  xmm0, xmm1
        aesenc  xmm3, xmm2
        aesenc  xmm0, xmm3
        aesenc  xmm0, xmm2
.LBB0_7:
        movq    rdx, xmm0
        pextrq  rax, xmm0, 1
        mul     rdx
        xor     esi, edx
        xor     esi, eax
        mov     dword ptr [rcx], esi
        ret
*/

/*
[sanmayce@djudjeto build]$ cmake ..
CMake Deprecation Warning at CMakeLists.txt:1 (cmake_minimum_required):
  Compatibility with CMake < 3.10 will be removed from a future version of
  CMake.

  Update the VERSION argument <min> value.  Or, use the <min>...<max> syntax
  to tell CMake that the project requires at least <min> but has been updated
  to work with policies introduced by <max> or earlier.


-- The C compiler identification is GNU 15.2.1
-- The CXX compiler identification is GNU 15.2.1
-- The ASM compiler identification is GNU
-- Found assembler: /usr/bin/cc
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Looking for sys/types.h
-- Looking for sys/types.h - found
-- Looking for stdint.h
-- Looking for stdint.h - found
-- Looking for stddef.h
-- Looking for stddef.h - found
-- Check size of __int64
-- Check size of __int64 - failed
-- Check size of int64_t
-- Check size of int64_t - done
-- Check size of __uint128_t
-- Check size of __uint128_t - done
-- CMAKE_SYSTEM_PROCESSOR: x86_64
-- AES-NI available
-- CLMUL available
-- SHA-NI available
-- AVX2 available
-- AVX512F available
-- AVX512VL available
-- Performing Test ALLOW_ALIGNED_ACCESS
-- Performing Test ALLOW_ALIGNED_ACCESS - Success
-- HAVE_ALIGNED_ACCESS_REQUIRED not required
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD
-- Performing Test CMAKE_HAVE_LIBC_PTHREAD - Success
-- Found Threads: TRUE
-- IPO / LTO enabled
-- Configuring done (2.2s)
-- Generating done (0.0s)
-- Build files have been written to: /home/sanmayce/Downloads/smhasher3_mybuild_2026-Aug-17/smhasher/build
[sanmayce@djudjeto build]$ make
[  1%] Building CXX object CMakeFiles/SMHasherSupport.dir/AvalancheTest.cpp.o
[  2%] Building CXX object CMakeFiles/SMHasherSupport.dir/Bitslice.cpp.o
[  3%] Building CXX object CMakeFiles/SMHasherSupport.dir/Bitvec.cpp.o
[  4%] Building C object CMakeFiles/SMHasherSupport.dir/chaskey.c.o
[  5%] Building CXX object CMakeFiles/SMHasherSupport.dir/CityTest.cpp.o
[  6%] Building CXX object CMakeFiles/SMHasherSupport.dir/City.cpp.o
[  7%] Building CXX object CMakeFiles/SMHasherSupport.dir/crc.cpp.o
[  8%] Building CXX object CMakeFiles/SMHasherSupport.dir/DifferentialTest.cpp.o
[  9%] Building CXX object CMakeFiles/SMHasherSupport.dir/HashMapTest.cpp.o
[ 10%] Building CXX object CMakeFiles/SMHasherSupport.dir/Hashes.cpp.o
[ 11%] Building C object CMakeFiles/SMHasherSupport.dir/hasshe2.c.o
[ 12%] Building C object CMakeFiles/SMHasherSupport.dir/crc32_hw.c.o
[ 13%] Building CXX object CMakeFiles/SMHasherSupport.dir/KeysetTest.cpp.o
[ 14%] Building CXX object CMakeFiles/SMHasherSupport.dir/lookup3.cpp.o
[ 15%] Building CXX object CMakeFiles/SMHasherSupport.dir/md5.cpp.o
[ 16%] Building CXX object CMakeFiles/SMHasherSupport.dir/MurmurHash1.cpp.o
[ 17%] Building CXX object CMakeFiles/SMHasherSupport.dir/MurmurHash2.cpp.o
[ 18%] Building CXX object CMakeFiles/SMHasherSupport.dir/MurmurHash3.cpp.o
[ 19%] Building CXX object CMakeFiles/SMHasherSupport.dir/Platform.cpp.o
[ 20%] Building CXX object CMakeFiles/SMHasherSupport.dir/Random.cpp.o
[ 21%] Building CXX object CMakeFiles/SMHasherSupport.dir/sha1.cpp.o
[ 22%] Building C object CMakeFiles/SMHasherSupport.dir/siphash_ssse3.c.o
[ 23%] Building CXX object CMakeFiles/SMHasherSupport.dir/SpeedTest.cpp.o
[ 24%] Building CXX object CMakeFiles/SMHasherSupport.dir/Spooky.cpp.o
[ 25%] Building CXX object CMakeFiles/SMHasherSupport.dir/SpookyTest.cpp.o
[ 26%] Building CXX object CMakeFiles/SMHasherSupport.dir/SpookyV2.cpp.o
[ 27%] Building CXX object CMakeFiles/SMHasherSupport.dir/SpookyTestV2.cpp.o
[ 28%] Building CXX object CMakeFiles/SMHasherSupport.dir/Stats.cpp.o
[ 29%] Building CXX object CMakeFiles/SMHasherSupport.dir/SuperFastHash.cpp.o
[ 30%] Building CXX object CMakeFiles/SMHasherSupport.dir/Types.cpp.o
[ 31%] Building C object CMakeFiles/SMHasherSupport.dir/PMurHash.c.o
[ 32%] Building CXX object CMakeFiles/SMHasherSupport.dir/tifuhash.cpp.o
[ 33%] Building CXX object CMakeFiles/SMHasherSupport.dir/floppsyhash.cpp.o
[ 34%] Building CXX object CMakeFiles/SMHasherSupport.dir/fasthash.cpp.o
[ 35%] Building CXX object CMakeFiles/SMHasherSupport.dir/beamsplitter.cpp.o
[ 36%] Building CXX object CMakeFiles/SMHasherSupport.dir/discohash_512.cpp.o
[ 37%] Building C object CMakeFiles/SMHasherSupport.dir/xxhash.c.o
[ 38%] Building CXX object CMakeFiles/SMHasherSupport.dir/metrohash/metrohash64.cpp.o
[ 39%] Building CXX object CMakeFiles/SMHasherSupport.dir/metrohash/metrohash128.cpp.o
[ 40%] Building C object CMakeFiles/SMHasherSupport.dir/cmetrohash64.c.o
[ 41%] Building C object CMakeFiles/SMHasherSupport.dir/opt_cmetrohash64_1.c.o
[ 42%] Building CXX object CMakeFiles/SMHasherSupport.dir/farmhash.cc.o
[ 43%] Building CXX object CMakeFiles/SMHasherSupport.dir/FarmTest.cc.o
[ 44%] Building C object CMakeFiles/SMHasherSupport.dir/pearson_hash/pearson.c.o
[ 45%] Building C object CMakeFiles/SMHasherSupport.dir/t1ha/t1ha0.c.o
[ 46%] Building C object CMakeFiles/SMHasherSupport.dir/t1ha/t1ha1.c.o
[ 47%] Building C object CMakeFiles/SMHasherSupport.dir/t1ha/t1ha2.c.o
[ 48%] Building C object CMakeFiles/SMHasherSupport.dir/t1ha/t1ha0_ia32aes_noavx.c.o
[ 49%] Building C object CMakeFiles/SMHasherSupport.dir/t1ha/t1ha0_ia32aes_avx.c.o
[ 50%] Building C object CMakeFiles/SMHasherSupport.dir/t1ha/t1ha0_ia32aes_avx2.c.o
[ 51%] Building C object CMakeFiles/SMHasherSupport.dir/SHA-Intrinsics/sha1-x86.c.o
[ 52%] Building C object CMakeFiles/SMHasherSupport.dir/SHA-Intrinsics/sha256-x86.c.o
[ 53%] Building C object CMakeFiles/SMHasherSupport.dir/gxhash.c.o
[ 54%] Building CXX object CMakeFiles/SMHasherSupport.dir/mum.cc.o
[ 55%] Building CXX object CMakeFiles/SMHasherSupport.dir/mum_v3.cc.o
[ 56%] Building C object CMakeFiles/SMHasherSupport.dir/jody_hash32.c.o
[ 57%] Building C object CMakeFiles/SMHasherSupport.dir/jody_hash64.c.o
[ 58%] Building C object CMakeFiles/SMHasherSupport.dir/tsip.c.o
[ 59%] Building C object CMakeFiles/SMHasherSupport.dir/seahash.c.o
[ 60%] Building C object CMakeFiles/SMHasherSupport.dir/farmhash-c.c.o
[ 61%] Building CXX object CMakeFiles/SMHasherSupport.dir/farmhash-c-test.cc.o
[ 62%] Building C object CMakeFiles/SMHasherSupport.dir/clhash.c.o
[ 63%] Building CXX object CMakeFiles/SMHasherSupport.dir/metrohash/metrohash64crc.cpp.o
[ 64%] Building CXX object CMakeFiles/SMHasherSupport.dir/metrohash/metrohash128crc.cpp.o
[ 65%] Building C object CMakeFiles/SMHasherSupport.dir/crc32_hw1.c.o
[ 66%] Building ASM object CMakeFiles/SMHasherSupport.dir/crc32-pclmul_asm.S.o
[ 67%] Building C object CMakeFiles/SMHasherSupport.dir/blake2b.c.o
[ 68%] Building C object CMakeFiles/SMHasherSupport.dir/blake2s.c.o
[ 69%] Building C object CMakeFiles/SMHasherSupport.dir/rmd128.c.o
[ 70%] Building C object CMakeFiles/SMHasherSupport.dir/rmd160.c.o
[ 71%] Building C object CMakeFiles/SMHasherSupport.dir/rmd256.c.o
[ 72%] Building C object CMakeFiles/SMHasherSupport.dir/sha2/sha224.c.o
[ 73%] Building C object CMakeFiles/SMHasherSupport.dir/sha2/sha256.c.o
[ 74%] Building C object CMakeFiles/SMHasherSupport.dir/sha2/sha512_224.c.o
[ 75%] Building C object CMakeFiles/SMHasherSupport.dir/sha2/sha512_256.c.o
[ 76%] Building C object CMakeFiles/SMHasherSupport.dir/sha3.c.o
[ 77%] Building CXX object CMakeFiles/SMHasherSupport.dir/PMP_Multilinear.cpp.o
[ 78%] Building CXX object CMakeFiles/SMHasherSupport.dir/PMP_Multilinear_64.cpp.o
[ 79%] Building CXX object CMakeFiles/SMHasherSupport.dir/PMP_Multilinear_test.cpp.o
[ 80%] Building CXX object CMakeFiles/SMHasherSupport.dir/vmac.cpp.o
[ 81%] Building C object CMakeFiles/SMHasherSupport.dir/rijndael-alg-fst.c.o
[ 82%] Building C object CMakeFiles/SMHasherSupport.dir/blake3/blake3.c.o
[ 83%] Building C object CMakeFiles/SMHasherSupport.dir/blake3/blake3_dispatch.c.o
[ 84%] Building C object CMakeFiles/SMHasherSupport.dir/blake3/blake3_portable.c.o
[ 85%] Building C object CMakeFiles/SMHasherSupport.dir/blake3/blake3_sse41.c.o
[ 86%] Building C object CMakeFiles/SMHasherSupport.dir/blake3/blake3_avx2.c.o
[ 87%] Building C object CMakeFiles/SMHasherSupport.dir/blake3/blake3_avx512.c.o
[ 88%] Building C object CMakeFiles/SMHasherSupport.dir/pengyhash.c.o
[ 89%] Building C object CMakeFiles/SMHasherSupport.dir/pearson_hash/pearsonb.c.o
[ 90%] Building C object CMakeFiles/SMHasherSupport.dir/edonr.c.o
[ 91%] Building C object CMakeFiles/SMHasherSupport.dir/asconhashv12/hash.c.o
[ 92%] Building C object CMakeFiles/SMHasherSupport.dir/umash.c.o
[ 93%] Building C object CMakeFiles/SMHasherSupport.dir/xmsx.c.o
[ 94%] Building C object CMakeFiles/SMHasherSupport.dir/crc64.c.o
[ 95%] Building C object CMakeFiles/SMHasherSupport.dir/crcspeed.c.o
[ 96%] Building C object CMakeFiles/SMHasherSupport.dir/crccombine.c.o
[ 97%] Building CXX object CMakeFiles/SMHasherSupport.dir/rainbow_test.cpp.o
[ 98%] Building CXX object CMakeFiles/SMHasherSupport.dir/rainstorm_test.cpp.o
[ 99%] Linking CXX static library libSMHasherSupport.a
[ 99%] Built target SMHasherSupport
[ 99%] Building CXX object CMakeFiles/SMHasher.dir/main.cpp.o
[100%] Linking CXX executable SMHasher
[100%] Built target SMHasher
[sanmayce@djudjeto build]$ ./SMHasher FNV1A_Pippip_Yurii
-------------------------------------------------------------------------------
--- Testing FNV1A_Pippip_Yurii "FNV1A-Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla 32-bit sanmayce" POOR

[[[ Sanity Tests ]]]

Verification value 0x39862F71 ....... FAIL! (Expected 0xF56905A8)
Running sanity check 1       .......... PASS
Running AppendedZeroesTest .......... PASS

[[[ Speed Tests ]]]

Bulk speed test - 262144-byte keys
Alignment  7 -  2.283 bytes/cycle - 3930.76 MiB/sec @ 1805 MHz
Alignment  6 -  2.283 bytes/cycle - 3930.71 MiB/sec @ 1805 MHz
Alignment  5 -  2.283 bytes/cycle - 3930.75 MiB/sec @ 1805 MHz
Alignment  4 -  2.283 bytes/cycle - 3930.69 MiB/sec @ 1805 MHz
Alignment  3 -  2.283 bytes/cycle - 3930.67 MiB/sec @ 1805 MHz
Alignment  2 -  2.283 bytes/cycle - 3930.68 MiB/sec @ 1805 MHz
Alignment  1 -  2.283 bytes/cycle - 3930.55 MiB/sec @ 1805 MHz
Alignment  0 -  2.283 bytes/cycle - 3930.74 MiB/sec @ 1805 MHz
Average      -  2.283 bytes/cycle - 3930.70 MiB/sec @ 1805 MHz

Small key speed test -    1-byte keys -    29.00 cycles/hash
Small key speed test -    2-byte keys -    29.59 cycles/hash
Small key speed test -    3-byte keys -    29.66 cycles/hash
Small key speed test -    4-byte keys -    29.55 cycles/hash
Small key speed test -    5-byte keys -    29.64 cycles/hash
Small key speed test -    6-byte keys -    29.00 cycles/hash
Small key speed test -    7-byte keys -    29.28 cycles/hash
Small key speed test -    8-byte keys -    29.61 cycles/hash
Small key speed test -    9-byte keys -    28.64 cycles/hash
Small key speed test -   10-byte keys -    28.53 cycles/hash
Small key speed test -   11-byte keys -    28.50 cycles/hash
Small key speed test -   12-byte keys -    28.45 cycles/hash
Small key speed test -   13-byte keys -    28.49 cycles/hash
Small key speed test -   14-byte keys -    28.68 cycles/hash
Small key speed test -   15-byte keys -    28.60 cycles/hash
Small key speed test -   16-byte keys -    28.54 cycles/hash
Small key speed test -   17-byte keys -    32.68 cycles/hash
Small key speed test -   18-byte keys -    32.63 cycles/hash
Small key speed test -   19-byte keys -    32.54 cycles/hash
Small key speed test -   20-byte keys -    32.41 cycles/hash
Small key speed test -   21-byte keys -    33.80 cycles/hash
Small key speed test -   22-byte keys -    33.72 cycles/hash
Small key speed test -   23-byte keys -    33.77 cycles/hash
Small key speed test -   24-byte keys -    34.16 cycles/hash
Small key speed test -   25-byte keys -    34.12 cycles/hash
Small key speed test -   26-byte keys -    33.95 cycles/hash
Small key speed test -   27-byte keys -    34.08 cycles/hash
Small key speed test -   28-byte keys -    33.00 cycles/hash
Small key speed test -   29-byte keys -    33.95 cycles/hash
Small key speed test -   30-byte keys -    33.94 cycles/hash
Small key speed test -   31-byte keys -    33.94 cycles/hash
Small key speed test -   32-byte keys -    33.01 cycles/hash
Average                                    31.234 cycles/hash
Average, weighted by key length freq.      30.633 cycles/hash (using 93.0% of top-7m Tranco DNS names dataset)
Average, weighted by key length freq.      28.725 cycles/hash (using 27.1% of startup-1M UMASH trace dataset)

[[[ 'Hashmap' Speed Tests ]]]

std::unordered_map
Init std HashMapTest:     414.579 cycles/op (479823 inserts, 1% deletions)
Running std HashMapTest:  477.898 cycles/op (67.4 stdv)

greg7mdp/parallel-hashmap
Init fast HashMapTest:    460.100 cycles/op (479823 inserts, 1% deletions)
Running fast HashMapTest: 331.284 cycles/op (2.8 stdv)  ....... PASS

[[[ Avalanche Tests ]]]

Testing   24-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.599333%
Testing   32-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.596000%
Testing   40-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.630000%
Testing   48-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.610000%
Testing   56-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.662667%
Testing   64-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.772667%
Testing   72-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.707333%
Testing   80-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.711333%
Testing   96-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.618667%
Testing  112-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.665333%
Testing  128-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.712000%
Testing  160-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.678000%
Testing  512-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.761333%
Testing 1024-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.784667%

[[[ Keyset 'Sparse' Tests ]]]

Keyset 'Sparse' - 16-bit keys with up to 9 bits set - 50643 keys
Testing collisions ( 32-bit) - Expected    0.3, actual      0 (0.00x)
Testing collisions (high 19-25 bits) - Worst is 22 bits: 300/304 (0.99x)
Testing collisions (low  19-25 bits) - Worst is 23 bits: 163/152 (1.07x)
Testing distribution - Worst bias is the 13-bit window at bit  3 - 0.614%

Keyset 'Sparse' - 24-bit keys with up to 8 bits set - 1271626 keys
Testing collisions ( 32-bit) - Expected  188.2, actual    196 (1.04x) (8)
Testing distribution - Worst bias is the 17-bit window at bit  3 - 0.073%

Keyset 'Sparse' - 32-bit keys with up to 7 bits set - 4514873 keys
Testing collisions ( 32-bit) - Expected 2372.2, actual   2383 (1.00x) (11)
Testing distribution - Worst bias is the 19-bit window at bit 22 - 0.051%

Keyset 'Sparse' - 40-bit keys with up to 6 bits set - 4598479 keys
Testing collisions ( 32-bit) - Expected 2460.8, actual   2466 (1.00x) (6)
Testing distribution - Worst bias is the 19-bit window at bit 31 - 0.025%

Keyset 'Sparse' - 48-bit keys with up to 6 bits set - 14196869 keys
Testing collisions ( 32-bit) - Expected 23437.8, actual  23556 (1.01x) (119)
Testing distribution - Worst bias is the 20-bit window at bit 18 - 0.028%

Keyset 'Sparse' - 56-bit keys with up to 5 bits set - 4216423 keys
Testing collisions ( 32-bit) - Expected 2069.0, actual   2099 (1.01x) (31)
Testing distribution - Worst bias is the 19-bit window at bit 31 - 0.035%

Keyset 'Sparse' - 64-bit keys with up to 5 bits set - 8303633 keys
Testing collisions ( 32-bit) - Expected 8021.7, actual   8056 (1.00x) (35)
Testing distribution - Worst bias is the 20-bit window at bit 17 - 0.040%

Keyset 'Sparse' - 72-bit keys with up to 5 bits set - 15082603 keys
Testing collisions ( 32-bit) - Expected 26451.8, actual  26487 (1.00x) (36)
Testing distribution - Worst bias is the 20-bit window at bit 22 - 0.017%

Keyset 'Sparse' - 96-bit keys with up to 4 bits set - 3469497 keys
Testing collisions ( 32-bit) - Expected 1401.0, actual   1321 (0.94x)
Testing distribution - Worst bias is the 19-bit window at bit 23 - 0.073%

Keyset 'Sparse' - 160-bit keys with up to 4 bits set - 26977161 keys
Testing collisions ( 32-bit) - Expected 84546.1, actual  84733 (1.00x) (187)
Testing distribution - Worst bias is the 20-bit window at bit 18 - 0.014%

Keyset 'Sparse' - 256-bit keys with up to 3 bits set - 2796417 keys
Testing collisions ( 32-bit) - Expected  910.2, actual    960 (1.05x) (50)
Testing distribution - Worst bias is the 19-bit window at bit 23 - 0.074%

Keyset 'Sparse' - 512-bit keys with up to 3 bits set - 22370049 keys
Testing collisions ( 32-bit) - Expected 58155.4, actual  58136 (1.00x) (-19)
Testing distribution - Worst bias is the 20-bit window at bit 31 - 0.012%

Keyset 'Sparse' - 1024-bit keys with up to 2 bits set - 524801 keys
Testing collisions ( 32-bit) - Expected   32.1, actual     32 (1.00x)
Testing distribution - Worst bias is the 16-bit window at bit 23 - 0.116%

Keyset 'Sparse' - 2048-bit keys with up to 2 bits set - 2098177 keys
Testing collisions ( 32-bit) - Expected  512.4, actual    537 (1.05x) (25)
Testing distribution - Worst bias is the 18-bit window at bit 27 - 0.066%


[[[ Keyset 'Permutation' Tests ]]]

Combination Lowbits Tests:
Keyset 'Combination' - up to 7 blocks from a set of 8 - 2396744 keys
Testing collisions ( 32-bit) - Expected  668.6, actual    674 (1.01x) (6)
Testing distribution - Worst bias is the 17-bit window at bit  2 - 0.047%


Combination Highbits Tests
Keyset 'Combination' - up to 7 blocks from a set of 8 - 2396744 keys
Testing collisions ( 32-bit) - Expected  668.6, actual    689 (1.03x) (21)
Testing distribution - Worst bias is the 18-bit window at bit 21 - 0.070%


Combination Hi-Lo Tests:
Keyset 'Combination' - up to 6 blocks from a set of 15 - 12204240 keys
Testing collisions ( 32-bit) - Expected 17322.9, actual  17416 (1.01x) (94)
Testing distribution - Worst bias is the 20-bit window at bit  5 - 0.030%


Combination 0x80000000 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8324 (1.02x) (138)
Testing distribution - Worst bias is the 19-bit window at bit  4 - 0.028%


Combination 0x00000001 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8157 (1.00x) (-29)
Testing distribution - Worst bias is the 20-bit window at bit 10 - 0.035%


Combination 0x8000000000000000 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8102 (0.99x) (-84)
Testing distribution - Worst bias is the 20-bit window at bit 10 - 0.041%


Combination 0x0000000000000001 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8171 (1.00x) (-15)
Testing distribution - Worst bias is the 20-bit window at bit  5 - 0.028%


Combination 16-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8212 (1.00x) (26)
Testing distribution - Worst bias is the 20-bit window at bit 13 - 0.033%


Combination 16-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8241 (1.01x) (55)
Testing distribution - Worst bias is the 20-bit window at bit 10 - 0.036%


Combination 32-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8233 (1.01x) (47)
Testing distribution - Worst bias is the 20-bit window at bit  4 - 0.035%


Combination 32-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8067 (0.99x) (-119)
Testing distribution - Worst bias is the 20-bit window at bit 12 - 0.034%


Combination 64-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8234 (1.01x) (48)
Testing distribution - Worst bias is the 20-bit window at bit 14 - 0.057%


Combination 64-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8107 (0.99x) (-79)
Testing distribution - Worst bias is the 19-bit window at bit  5 - 0.012%


Combination 128-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8076 (0.99x) (-110)
Testing distribution - Worst bias is the 19-bit window at bit 17 - 0.018%


Combination 128-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8113 (0.99x) (-73)
Testing distribution - Worst bias is the 20-bit window at bit 27 - 0.026%


[[[ Keyset 'Window' Tests ]]]

Keyset 'Window' -  72-bit key,  20-bit window - 72 tests, 1048576 keys per test
Window at   0 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at   1 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at   2 - Testing collisions ( 32-bit) - Expected  128.0, actual    123 (0.96x)
Window at   3 - Testing collisions ( 32-bit) - Expected  128.0, actual    116 (0.91x)
Window at   4 - Testing collisions ( 32-bit) - Expected  128.0, actual    123 (0.96x)
Window at   5 - Testing collisions ( 32-bit) - Expected  128.0, actual    112 (0.88x)
Window at   6 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at   7 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at   8 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at   9 - Testing collisions ( 32-bit) - Expected  128.0, actual    135 (1.05x) (8)
Window at  10 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at  11 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  12 - Testing collisions ( 32-bit) - Expected  128.0, actual    137 (1.07x) (10)
Window at  13 - Testing collisions ( 32-bit) - Expected  128.0, actual    122 (0.95x)
Window at  14 - Testing collisions ( 32-bit) - Expected  128.0, actual    141 (1.10x) (14)
Window at  15 - Testing collisions ( 32-bit) - Expected  128.0, actual    160 (1.25x) (33)
Window at  16 - Testing collisions ( 32-bit) - Expected  128.0, actual    127 (0.99x)
Window at  17 - Testing collisions ( 32-bit) - Expected  128.0, actual    116 (0.91x)
Window at  18 - Testing collisions ( 32-bit) - Expected  128.0, actual    102 (0.80x)
Window at  19 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  20 - Testing collisions ( 32-bit) - Expected  128.0, actual    138 (1.08x) (11)
Window at  21 - Testing collisions ( 32-bit) - Expected  128.0, actual    126 (0.98x) (-1)
Window at  22 - Testing collisions ( 32-bit) - Expected  128.0, actual    143 (1.12x) (16)
Window at  23 - Testing collisions ( 32-bit) - Expected  128.0, actual    127 (0.99x)
Window at  24 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  25 - Testing collisions ( 32-bit) - Expected  128.0, actual    128 (1.00x) (1)
Window at  26 - Testing collisions ( 32-bit) - Expected  128.0, actual    141 (1.10x) (14)
Window at  27 - Testing collisions ( 32-bit) - Expected  128.0, actual    163 (1.27x) (36)
Window at  28 - Testing collisions ( 32-bit) - Expected  128.0, actual    139 (1.09x) (12)
Window at  29 - Testing collisions ( 32-bit) - Expected  128.0, actual    123 (0.96x)
Window at  30 - Testing collisions ( 32-bit) - Expected  128.0, actual    119 (0.93x)
Window at  31 - Testing collisions ( 32-bit) - Expected  128.0, actual    107 (0.84x)
Window at  32 - Testing collisions ( 32-bit) - Expected  128.0, actual    128 (1.00x) (1)
Window at  33 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  34 - Testing collisions ( 32-bit) - Expected  128.0, actual    117 (0.91x)
Window at  35 - Testing collisions ( 32-bit) - Expected  128.0, actual    124 (0.97x)
Window at  36 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at  37 - Testing collisions ( 32-bit) - Expected  128.0, actual    137 (1.07x) (10)
Window at  38 - Testing collisions ( 32-bit) - Expected  128.0, actual    115 (0.90x)
Window at  39 - Testing collisions ( 32-bit) - Expected  128.0, actual    117 (0.91x)
Window at  40 - Testing collisions ( 32-bit) - Expected  128.0, actual    114 (0.89x)
Window at  41 - Testing collisions ( 32-bit) - Expected  128.0, actual    108 (0.84x)
Window at  42 - Testing collisions ( 32-bit) - Expected  128.0, actual    124 (0.97x)
Window at  43 - Testing collisions ( 32-bit) - Expected  128.0, actual    135 (1.05x) (8)
Window at  44 - Testing collisions ( 32-bit) - Expected  128.0, actual    127 (0.99x)
Window at  45 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at  46 - Testing collisions ( 32-bit) - Expected  128.0, actual    132 (1.03x) (5)
Window at  47 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  48 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  49 - Testing collisions ( 32-bit) - Expected  128.0, actual    132 (1.03x) (5)
Window at  50 - Testing collisions ( 32-bit) - Expected  128.0, actual    112 (0.88x)
Window at  51 - Testing collisions ( 32-bit) - Expected  128.0, actual    132 (1.03x) (5)
Window at  52 - Testing collisions ( 32-bit) - Expected  128.0, actual    134 (1.05x) (7)
Window at  53 - Testing collisions ( 32-bit) - Expected  128.0, actual    134 (1.05x) (7)
Window at  54 - Testing collisions ( 32-bit) - Expected  128.0, actual    138 (1.08x) (11)
Window at  55 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at  56 - Testing collisions ( 32-bit) - Expected  128.0, actual    127 (0.99x)
Window at  57 - Testing collisions ( 32-bit) - Expected  128.0, actual    127 (0.99x)
Window at  58 - Testing collisions ( 32-bit) - Expected  128.0, actual    121 (0.95x)
Window at  59 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at  60 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  61 - Testing collisions ( 32-bit) - Expected  128.0, actual    124 (0.97x)
Window at  62 - Testing collisions ( 32-bit) - Expected  128.0, actual    126 (0.98x) (-1)
Window at  63 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  64 - Testing collisions ( 32-bit) - Expected  128.0, actual    120 (0.94x)
Window at  65 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  66 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  67 - Testing collisions ( 32-bit) - Expected  128.0, actual    119 (0.93x)
Window at  68 - Testing collisions ( 32-bit) - Expected  128.0, actual    116 (0.91x)
Window at  69 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  70 - Testing collisions ( 32-bit) - Expected  128.0, actual    135 (1.05x) (8)
Window at  71 - Testing collisions ( 32-bit) - Expected  128.0, actual    120 (0.94x)
Window at  72 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)

[[[ Keyset 'Cyclic' Tests ]]]

Keyset 'Cyclic' - 8 cycles of 4 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    115 (0.99x) (-1)
Testing distribution - Worst bias is the 17-bit window at bit 13 - 0.072%

Keyset 'Cyclic' - 8 cycles of 5 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    102 (0.88x)
Testing distribution - Worst bias is the 17-bit window at bit  3 - 0.050%

Keyset 'Cyclic' - 8 cycles of 6 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    122 (1.05x) (6)
Testing distribution - Worst bias is the 17-bit window at bit  7 - 0.124%

Keyset 'Cyclic' - 8 cycles of 7 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    112 (0.96x)
Testing distribution - Worst bias is the 17-bit window at bit  6 - 0.119%

Keyset 'Cyclic' - 8 cycles of 8 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    137 (1.18x) (21)
Testing distribution - Worst bias is the 17-bit window at bit  5 - 0.124%

Keyset 'Cyclic' - 8 cycles of 12 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    120 (1.03x) (4)
Testing distribution - Worst bias is the 17-bit window at bit 11 - 0.078%


[[[ Keyset 'TwoBytes' Tests ]]]

Keyset 'TwoBytes' - up-to-4-byte keys, 652545 total keys
Testing collisions ( 32-bit) - Expected   49.6, actual     49 (0.99x)
Testing distribution - Worst bias is the 16-bit window at bit  5 - 0.182%

Keyset 'TwoBytes' - up-to-8-byte keys, 5471025 total keys
Testing collisions ( 32-bit) - Expected 3483.1, actual   3495 (1.00x) (12)
Testing distribution - Worst bias is the 20-bit window at bit 24 - 0.060%

Keyset 'TwoBytes' - up-to-12-byte keys, 18616785 total keys
Testing collisions ( 32-bit) - Expected 40289.5, actual  40140 (1.00x) (-149)
Testing distribution - Worst bias is the 20-bit window at bit  5 - 0.011%

Keyset 'TwoBytes' - up-to-16-byte keys, 44251425 total keys
Testing collisions ( 32-bit) - Expected 227182.3, actual 226668 (1.00x) (-514)
Testing distribution - Worst bias is the 20-bit window at bit  5 - 0.005%

Keyset 'TwoBytes' - up-to-20-byte keys, 86536545 total keys
Testing collisions ( 32-bit) - Expected 865959.1, actual 864893 (1.00x) (-1066)
Testing distribution - Worst bias is the 20-bit window at bit  7 - 0.004%

Keyset 'TwoBytes' - up-to-24-byte keys, 149633745 total keys
Testing collisions ( 32-bit) - Expected 2576560.5, actual 2574508 (1.00x) (-2052)
Testing distribution - Worst bias is the 20-bit window at bit 12 - 0.001%


[[[ Keyset 'Text' Tests ]]]

Keyset 'Text' - keys of form "FooXXXXBar" - 14776336 keys
Testing collisions ( 32-bit) - Expected 25389.0, actual  25458 (1.00x) (69)
Testing distribution - Worst bias is the 20-bit window at bit  5 - 0.018%

Keyset 'Text' - keys of form "FooBarXXXX" - 14776336 keys
Testing collisions ( 32-bit) - Expected 25389.0, actual  25478 (1.00x) (89)
Testing distribution - Worst bias is the 20-bit window at bit 26 - 0.020%

Keyset 'Text' - keys of form "XXXXFooBar" - 14776336 keys
Testing collisions ( 32-bit) - Expected 25389.0, actual  25265 (1.00x) (-124)
Testing distribution - Worst bias is the 20-bit window at bit 31 - 0.025%

Keyset 'Words' - 4000000 random keys of len 6-16 from alnum charset
Testing collisions ( 32-bit) - Expected 1862.1, actual   1926 (1.03x) (64)
Testing distribution - Worst bias is the 19-bit window at bit  8 - 0.031%

Keyset 'Words' - 4000000 random keys of len 6-16 from password charset
Testing collisions ( 32-bit) - Expected 1862.1, actual   1785 (0.96x)
Testing distribution - Worst bias is the 19-bit window at bit  6 - 0.028%

Keyset 'Words' - 479823 dict words
Testing collisions ( 32-bit) - Expected   26.8, actual     23 (0.86x)
Testing distribution - Worst bias is the 16-bit window at bit 22 - 0.114%


[[[ Keyset 'Zeroes' Tests ]]]

Keyset 'Zeroes' - 204800 keys
Testing collisions ( 32-bit) - Expected    4.9, actual      5 (1.02x) (1)
Testing collisions (high 21-29 bits) - Worst is 27 bits: 160/156 (1.02x)
Testing collisions (low  21-29 bits) - Worst is 27 bits: 180/156 (1.15x)
Testing distribution - Worst bias is the 15-bit window at bit 15 - 0.338%


[[[ Keyset 'Seed' Tests ]]]

Keyset 'Seed' - 5000000 keys
Testing collisions ( 32-bit) - Expected 2909.3, actual   2920 (1.00x) (11)
Testing distribution - Worst bias is the 19-bit window at bit  3 - 0.035%


[[[ Keyset 'PerlinNoise' Tests ]]]

Testing 16777216 coordinates (L2) : 
Testing collisions ( 32-bit) - Expected 32725.4, actual  32598 (1.00x) (-127)

Testing AV variant, 128 count with 4 spacing, 4-12:
Testing collisions ( 32-bit) - Expected 1116.2, actual   1162 (1.04x) (46)


[[[ Diff 'Differential' Tests ]]]

Testing 8303632 up-to-5-bit differentials in 64-bit keys -> 32 bit hashes.
1000 reps, 8303632000 total tests, expecting 1.93 random collisions..........
0 total collisions, of which 0 single collisions were ignored

Testing 11017632 up-to-4-bit differentials in 128-bit keys -> 32 bit hashes.
1000 reps, 11017632000 total tests, expecting 2.57 random collisions..........
5 total collisions, of which 5 single collisions were ignored

Testing 2796416 up-to-3-bit differentials in 256-bit keys -> 32 bit hashes.
1000 reps, 2796416000 total tests, expecting 0.65 random collisions..........
0 total collisions, of which 0 single collisions were ignored


[[[ DiffDist 'Differential Distribution' Tests ]]]

Testing bit 0
Testing collisions ( 32-bit) - Expected  511.9, actual    514 (1.00x) (3)
Testing distribution - Worst bias is the 18-bit window at bit  3 - 0.039%

Testing bit 1
Testing collisions ( 32-bit) - Expected  511.9, actual    497 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 26 - 0.073%

Testing bit 2
Testing collisions ( 32-bit) - Expected  511.9, actual    514 (1.00x) (3)
Testing distribution - Worst bias is the 18-bit window at bit  7 - 0.091%

Testing bit 3
Testing collisions ( 32-bit) - Expected  511.9, actual    515 (1.01x) (4)
Testing distribution - Worst bias is the 18-bit window at bit 19 - 0.068%

Testing bit 4
Testing collisions ( 32-bit) - Expected  511.9, actual    507 (0.99x) (-4)
Testing distribution - Worst bias is the 18-bit window at bit 25 - 0.068%

Testing bit 5
Testing collisions ( 32-bit) - Expected  511.9, actual    481 (0.94x)
Testing distribution - Worst bias is the 18-bit window at bit 27 - 0.044%

Testing bit 6
Testing collisions ( 32-bit) - Expected  511.9, actual    509 (0.99x) (-2)
Testing distribution - Worst bias is the 18-bit window at bit 24 - 0.051%

Testing bit 7
Testing collisions ( 32-bit) - Expected  511.9, actual    527 (1.03x) (16)
Testing distribution - Worst bias is the 18-bit window at bit 12 - 0.043%

Testing bit 8
Testing collisions ( 32-bit) - Expected  511.9, actual    545 (1.06x) (34)
Testing distribution - Worst bias is the 18-bit window at bit 27 - 0.067%

Testing bit 9
Testing collisions ( 32-bit) - Expected  511.9, actual    528 (1.03x) (17)
Testing distribution - Worst bias is the 18-bit window at bit 12 - 0.094%

Testing bit 10
Testing collisions ( 32-bit) - Expected  511.9, actual    528 (1.03x) (17)
Testing distribution - Worst bias is the 18-bit window at bit 13 - 0.087%

Testing bit 11
Testing collisions ( 32-bit) - Expected  511.9, actual    491 (0.96x)
Testing distribution - Worst bias is the 18-bit window at bit  4 - 0.054%

Testing bit 12
Testing collisions ( 32-bit) - Expected  511.9, actual    493 (0.96x)
Testing distribution - Worst bias is the 18-bit window at bit 21 - 0.061%

Testing bit 13
Testing collisions ( 32-bit) - Expected  511.9, actual    520 (1.02x) (9)
Testing distribution - Worst bias is the 17-bit window at bit  2 - 0.049%

Testing bit 14
Testing collisions ( 32-bit) - Expected  511.9, actual    496 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 23 - 0.082%

Testing bit 15
Testing collisions ( 32-bit) - Expected  511.9, actual    500 (0.98x)
Testing distribution - Worst bias is the 16-bit window at bit 16 - 0.035%

Testing bit 16
Testing collisions ( 32-bit) - Expected  511.9, actual    494 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit  1 - 0.062%

Testing bit 17
Testing collisions ( 32-bit) - Expected  511.9, actual    508 (0.99x) (-3)
Testing distribution - Worst bias is the 18-bit window at bit  7 - 0.078%

Testing bit 18
Testing collisions ( 32-bit) - Expected  511.9, actual    486 (0.95x)
Testing distribution - Worst bias is the 17-bit window at bit 16 - 0.087%

Testing bit 19
Testing collisions ( 32-bit) - Expected  511.9, actual    487 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit  8 - 0.070%

Testing bit 20
Testing collisions ( 32-bit) - Expected  511.9, actual    521 (1.02x) (10)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.093%

Testing bit 21
Testing collisions ( 32-bit) - Expected  511.9, actual    504 (0.98x) (-7)
Testing distribution - Worst bias is the 18-bit window at bit  8 - 0.054%

Testing bit 22
Testing collisions ( 32-bit) - Expected  511.9, actual    487 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit 16 - 0.063%

Testing bit 23
Testing collisions ( 32-bit) - Expected  511.9, actual    513 (1.00x) (2)
Testing distribution - Worst bias is the 18-bit window at bit 17 - 0.085%

Testing bit 24
Testing collisions ( 32-bit) - Expected  511.9, actual    496 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.050%

Testing bit 25
Testing collisions ( 32-bit) - Expected  511.9, actual    478 (0.93x)
Testing distribution - Worst bias is the 18-bit window at bit 26 - 0.090%

Testing bit 26
Testing collisions ( 32-bit) - Expected  511.9, actual    538 (1.05x) (27)
Testing distribution - Worst bias is the 18-bit window at bit  1 - 0.055%

Testing bit 27
Testing collisions ( 32-bit) - Expected  511.9, actual    538 (1.05x) (27)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.057%

Testing bit 28
Testing collisions ( 32-bit) - Expected  511.9, actual    480 (0.94x)
Testing distribution - Worst bias is the 18-bit window at bit  6 - 0.046%

Testing bit 29
Testing collisions ( 32-bit) - Expected  511.9, actual    507 (0.99x) (-4)
Testing distribution - Worst bias is the 18-bit window at bit  3 - 0.083%

Testing bit 30
Testing collisions ( 32-bit) - Expected  511.9, actual    444 (0.87x)
Testing distribution - Worst bias is the 18-bit window at bit  0 - 0.086%

Testing bit 31
Testing collisions ( 32-bit) - Expected  511.9, actual    524 (1.02x) (13)
Testing distribution - Worst bias is the 18-bit window at bit 22 - 0.076%

Testing bit 32
Testing collisions ( 32-bit) - Expected  511.9, actual    531 (1.04x) (20)
Testing distribution - Worst bias is the 18-bit window at bit 21 - 0.090%

Testing bit 33
Testing collisions ( 32-bit) - Expected  511.9, actual    516 (1.01x) (5)
Testing distribution - Worst bias is the 17-bit window at bit 19 - 0.061%

Testing bit 34
Testing collisions ( 32-bit) - Expected  511.9, actual    483 (0.94x)
Testing distribution - Worst bias is the 17-bit window at bit 16 - 0.067%

Testing bit 35
Testing collisions ( 32-bit) - Expected  511.9, actual    498 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 24 - 0.075%

Testing bit 36
Testing collisions ( 32-bit) - Expected  511.9, actual    516 (1.01x) (5)
Testing distribution - Worst bias is the 18-bit window at bit 24 - 0.090%

Testing bit 37
Testing collisions ( 32-bit) - Expected  511.9, actual    469 (0.92x)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.072%

Testing bit 38
Testing collisions ( 32-bit) - Expected  511.9, actual    523 (1.02x) (12)
Testing distribution - Worst bias is the 18-bit window at bit 22 - 0.068%

Testing bit 39
Testing collisions ( 32-bit) - Expected  511.9, actual    537 (1.05x) (26)
Testing distribution - Worst bias is the 18-bit window at bit 31 - 0.058%

Testing bit 40
Testing collisions ( 32-bit) - Expected  511.9, actual    478 (0.93x)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.063%

Testing bit 41
Testing collisions ( 32-bit) - Expected  511.9, actual    549 (1.07x) (38)
Testing distribution - Worst bias is the 18-bit window at bit 16 - 0.049%

Testing bit 42
Testing collisions ( 32-bit) - Expected  511.9, actual    506 (0.99x) (-5)
Testing distribution - Worst bias is the 18-bit window at bit 16 - 0.065%

Testing bit 43
Testing collisions ( 32-bit) - Expected  511.9, actual    497 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit  0 - 0.053%

Testing bit 44
Testing collisions ( 32-bit) - Expected  511.9, actual    545 (1.06x) (34)
Testing distribution - Worst bias is the 18-bit window at bit  4 - 0.053%

Testing bit 45
Testing collisions ( 32-bit) - Expected  511.9, actual    514 (1.00x) (3)
Testing distribution - Worst bias is the 18-bit window at bit 11 - 0.077%

Testing bit 46
Testing collisions ( 32-bit) - Expected  511.9, actual    522 (1.02x) (11)
Testing distribution - Worst bias is the 17-bit window at bit 18 - 0.054%

Testing bit 47
Testing collisions ( 32-bit) - Expected  511.9, actual    532 (1.04x) (21)
Testing distribution - Worst bias is the 18-bit window at bit  2 - 0.060%

Testing bit 48
Testing collisions ( 32-bit) - Expected  511.9, actual    501 (0.98x)
Testing distribution - Worst bias is the 18-bit window at bit 26 - 0.075%

Testing bit 49
Testing collisions ( 32-bit) - Expected  511.9, actual    573 (1.12x) (62)
Testing distribution - Worst bias is the 18-bit window at bit  1 - 0.091%

Testing bit 50
Testing collisions ( 32-bit) - Expected  511.9, actual    502 (0.98x) (-9)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.060%

Testing bit 51
Testing collisions ( 32-bit) - Expected  511.9, actual    530 (1.04x) (19)
Testing distribution - Worst bias is the 18-bit window at bit 22 - 0.065%

Testing bit 52
Testing collisions ( 32-bit) - Expected  511.9, actual    519 (1.01x) (8)
Testing distribution - Worst bias is the 18-bit window at bit  1 - 0.092%

Testing bit 53
Testing collisions ( 32-bit) - Expected  511.9, actual    516 (1.01x) (5)
Testing distribution - Worst bias is the 18-bit window at bit 23 - 0.069%

Testing bit 54
Testing collisions ( 32-bit) - Expected  511.9, actual    479 (0.94x)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.050%

Testing bit 55
Testing collisions ( 32-bit) - Expected  511.9, actual    468 (0.91x)
Testing distribution - Worst bias is the 18-bit window at bit  5 - 0.085%

Testing bit 56
Testing collisions ( 32-bit) - Expected  511.9, actual    509 (0.99x) (-2)
Testing distribution - Worst bias is the 18-bit window at bit 18 - 0.131%

Testing bit 57
Testing collisions ( 32-bit) - Expected  511.9, actual    531 (1.04x) (20)
Testing distribution - Worst bias is the 18-bit window at bit 16 - 0.065%

Testing bit 58
Testing collisions ( 32-bit) - Expected  511.9, actual    496 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 18 - 0.069%

Testing bit 59
Testing collisions ( 32-bit) - Expected  511.9, actual    573 (1.12x) (62)
Testing distribution - Worst bias is the 18-bit window at bit 31 - 0.108%

Testing bit 60
Testing collisions ( 32-bit) - Expected  511.9, actual    498 (0.97x)
Testing distribution - Worst bias is the 17-bit window at bit 29 - 0.068%

Testing bit 61
Testing collisions ( 32-bit) - Expected  511.9, actual    535 (1.05x) (24)
Testing distribution - Worst bias is the 18-bit window at bit 18 - 0.048%

Testing bit 62
Testing collisions ( 32-bit) - Expected  511.9, actual    486 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit 12 - 0.073%

Testing bit 63
Testing collisions ( 32-bit) - Expected  511.9, actual    499 (0.97x)
Testing distribution - Worst bias is the 17-bit window at bit  1 - 0.050%


[[[ MomentChi2 Tests ]]]

Analyze hashes produced from a serie of linearly increasing numbers of 32-bit, using a step of 2 ... 
Target values to approximate : 1391290.000000 - 686.666667 
8 threads starting...  done
Popcount 1 stats : 1391278.355784 - 687.296919
Popcount 0 stats : 1391331.788563 - 687.302010
MomentChi2 for bits 1 :  0.0986837 
MomentChi2 for bits 0 :   1.27098 

Derivative stats (transition from 2 consecutive values) : 
Popcount 1 stats : 1391309.544447 - 687.347996
Popcount 0 stats : 1391312.299642 - 687.307717
MomentChi2 for deriv b1 :  0.278007 
MomentChi2 for deriv b0 :  0.361924 

  Great 


[[[ Prng Tests ]]]

Skipping PRNG test; it is designed for hashes >= 64-bits

[[[ BadSeeds Tests ]]]

Testing 10 internal bad seeds:
0x1077bd26 0x1c07e567 0x1c2e04b6 0x2179e8c6 0x7ca5ded3 0x7d9bbad9 0x9ac97b61 0xb6957619 0xbb54fecc 0xfac5c910 PASS


Input vcode 0x00000001, Output vcode 0x00000001, Result vcode 0x00000001
Verification value is 0x00000001 - Testing took 954.421568 seconds
-------------------------------------------------------------------------------
[sanmayce@djudjeto build]$ 
*/

/*
-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]------------------------------------------------------------------------
Testfile Name: Japanese_bonanza_(39-Japanese_Dictionaries_EPWING-jisx0208j-converted-to-UTF8-JSON)_30449301-lines.tar
Testfile Size: 2678497280
Hashtable entries (2^32): 4294967296

Pippip_AES_TriXZi_Mikayla_4HEADS:
19284+449723+3129858+11647535+30223987+60652125+105608079+161942771+225736709+294413368= 893,823,439 ! BEST DISPERSION !
MeowHash:
19284+449734+3129858+11647480+30224062+60652244+105608245+161940749+225731787+294412145= 893,815,588
wyhash f4:
19284+449729+3129906+11647471+30224627+60652499+105607262+161940071+225732342+294411133= 893,814,324
komihash 5.27:
19284+449732+3129860+11647525+30224181+60651948+105606947+161942055+225734445+294410475= 893,816,452
XXH3_64bits 0.8.3:
19284+449727+3129782+11647394+30224248+60651516+105605006+161939617+225734683+294412832= 893,814,089
-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]------------------------------------------------------------------------

-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]---------------------------------------------------------
Testfile Name: www.kaggle.com_3m-academic-papers-titles-and-abstracts_cleaned_papers.csv
Testfile Size: 4146849636
Hashtable entries (2^32): 4294967296

Pippip_AES_TriXZi_Mikayla_4HEADS:
16399+507863+4661399+18384571+46720535+90354618+149662682+227582479+325944157+444149463= 1,307,984,166
MeowHash:
16399+507862+4661520+18384187+46720333+90355219+149662516+227582427+325944646+444142847= 1,307,977,956
wyhash f4:
16399+507862+4661498+18384390+46720973+90353268+149664375+227586151+325945511+444145232= 1,307,985,659
komihash 5.27:
16399+507867+4661411+18384388+46720708+90356047+149663716+227588131+325948362+444142022= 1,307,989,051 ! BEST DISPERSION !
XXH3_64bits 0.8.3:
16399+507864+4661344+18383931+46719322+90356135+149662304+227589735+325943520+444145266= 1,307,985,820
-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]---------------------------------------------------------

-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]---------------------------------------------------------------
Testfile Name: enwiktionary-20260501-pages-articles.xml
Testfile Size: 11682653744
Hashtable entries (2^32): 4294967296

Pippip_AES_TriXZi_Mikayla_4HEADS:
28411+1277973+19072508+116812092+350533419+482956981+638354069+803903437+989707036+1175603239= 4,578,249,165
MeowHash:
28411+1277967+19072264+116811730+350539150+482959808+638365708+803889755+989718998+1175609255= 4,578,273,046
wyhash:
28411+1277961+19072284+116812244+350544980+482959893+638347125+803889039+989723614+1175605202= 4,578,260,753
komihash 5.27:
28411+1277981+19071827+116811015+350537739+482970561+638349677+803881579+989720528+1175620438= 4,578,269,756
XXH3_64bits 0.8.3:
28411+1277977+19072021+116812460+350536782+482959539+638356745+803901554+989728359+1175614052= 4,578,287,900 ! BEST DISPERSION !
-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]---------------------------------------------------------------

-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]--------------------------------------------------------------------
Testfile Name: SUPRAPIG_Ebooks-in-Russian_156-series_(FB2-31640_RTF-3906).tar
Testfile Size: 62112181760
Hashtable entries (2^32): 4294967296

Pippip_AES_TriXZi_Mikayla_4HEADS:
29405+676468+20884650+994628254+4009704498+4129705164+4202945411+4228440464+4235104080+4240633606= 26,062,752,000
MeowHash:
29405+676475+20884559+994642592+4009717613+4129709918+4202950238+4228435332+4235091912+4240628183= 26,062,766,227 ! BEST DISPERSION !
wyhash f4:
29405+676470+20884457+994623744+4009696961+4129718368+4202958238+4228433368+4235112540+4240627113= 26,062,760,664
komihash 5.27:
29405+676465+20884437+994620066+4009709718+4129711303+4202947533+4228441921+4235097830+4240624447= 26,062,743,125
XXH3_64bits 0.8.3:
29405+676472+20884427+994623179+4009649177+4129721732+4202943769+4228431615+4235117216+4240638035= 26,062,715,027
-[ Cumulative 'Unique_Hashes' for BBs=2..11 ]--------------------------------------------------------------------
*/

// Testmachine: laptop Dell Precision 7560, RAM: 4x32GB DDR4 3200MHz, rank 2, CPU: i7-11850H 'Tiger Lake' max 4800MHz
// Testcompiler: CLANG 20.1.8 -O3 -march=native
// Note: All the runs are in performance mode, highest niceness.
/*
Torture TEST #1: Hashing "370,000+ English Wordlist" Extravaganza Benchmark
```
---------------------------------------- [ RESULT ] ----------------------------------------
Hasher                                                               : Pippip_FOX 128-bit
Hash Table slots                                                     : 4,294,967,296
Total (unique) keys hashed                                           : 8,427,158,320
Keys:Slots ratio                                                     : 1.96
Hashing Speed, in Keys-Per-Second                                    : 5,683,852            ! Fastest !
Average Key Length                                                   : 24
Maximum-Collision-Depth (within a single slot), The-Lower-The-Better : 16
Number of slots with MCD, The-Lower-The-Better                       : 3
Empty Slots, The-Lower-The-Better                                    : 603,720,798
Dispersion Quality: 100% - (Empty Slots * 100% / Total Slots)        : 85.9435%
--------------------------------------------------------------------------------------------

---------------------------------------- [ RESULT ] ----------------------------------------
Hasher                                                               : wyhash32 32-bit
Hash Table slots                                                     : 4,294,967,296
Total (unique) keys hashed                                           : 8,427,158,320
Keys:Slots ratio                                                     : 1.96
Hashing Speed, in Keys-Per-Second                                    : 5,652,776
Average Key Length                                                   : 24
Maximum-Collision-Depth (within a single slot), The-Lower-The-Better : 47                   ! Not Good: both Pippip_FOX and farmhash32 have 3x shorter hashchain !
Number of slots with MCD, The-Lower-The-Better                       : 1
Empty Slots, The-Lower-The-Better                                    : 603,820,158
Dispersion Quality: 100% - (Empty Slots * 100% / Total Slots)        : 85.9412%
--------------------------------------------------------------------------------------------

---------------------------------------- [ RESULT ] ----------------------------------------
Hasher                                                               : farmhash32 32-bit
Hash Table slots                                                     : 4,294,967,296
Total (unique) keys hashed                                           : 8,427,158,320
Keys:Slots ratio                                                     : 1.96
Hashing Speed, in Keys-Per-Second                                    : 5,563,894
Average Key Length                                                   : 24
Maximum-Collision-Depth (within a single slot), The-Lower-The-Better : 16
Number of slots with MCD, The-Lower-The-Better                       : 1
Empty Slots, The-Lower-The-Better                                    : 603,697,239          ! Best Dispersion !
Dispersion Quality: 100% - (Empty Slots * 100% / Total Slots)        : 85.9441%
--------------------------------------------------------------------------------------------
```
    
Torture TEST #2: Hashing "Carnegie Mellon University Pronunciation Dictionary" Extravaganza Benchmark
```
---------------------------------------- [ RESULT ] ----------------------------------------
Hasher                                                               : Pippip_FOX 128-bit
Hash Table slots                                                     : 4,294,967,296
Total (unique) keys hashed                                           : 4,682,808,964
Keys:Slots ratio                                                     : 1.09
Hashing Speed, in Keys-Per-Second                                    : 5,481,664            ! Fastest !
Average Key Length                                                   : 31
Maximum-Collision-Depth (within a single slot), The-Lower-The-Better : 12
Number of slots with MCD, The-Lower-The-Better                       : 14
Empty Slots, The-Lower-The-Better                                    : 1,443,611,491
Dispersion Quality: 100% - (Empty Slots * 100% / Total Slots)        : 66.3883%
--------------------------------------------------------------------------------------------

---------------------------------------- [ RESULT ] ----------------------------------------
Hasher                                                               : wyhash32 32-bit
Hash Table slots                                                     : 4,294,967,296
Total (unique) keys hashed                                           : 4,682,808,964
Keys:Slots ratio                                                     : 1.09
Hashing Speed, in Keys-Per-Second                                    : 5,355,585
Average Key Length                                                   : 31
Maximum-Collision-Depth (within a single slot), The-Lower-The-Better : 24                   ! Not Good: both Pippip_FOX and farmhash32 have 2x shorter hashchain !
Number of slots with MCD, The-Lower-The-Better                       : 1
Empty Slots, The-Lower-The-Better                                    : 1,443,694,420
Dispersion Quality: 100% - (Empty Slots * 100% / Total Slots)        : 66.3864%
--------------------------------------------------------------------------------------------

---------------------------------------- [ RESULT ] ----------------------------------------
Hasher                                                               : farmhash32 32-bit
Hash Table slots                                                     : 4,294,967,296
Total (unique) keys hashed                                           : 4,682,808,964
Keys:Slots ratio                                                     : 1.09
Hashing Speed, in Keys-Per-Second                                    : 5,273,787
Average Key Length                                                   : 31
Maximum-Collision-Depth (within a single slot), The-Lower-The-Better : 12
Number of slots with MCD, The-Lower-The-Better                       : 7
Empty Slots, The-Lower-The-Better                                    : 1,443,578,275
Dispersion Quality: 100% - (Empty Slots * 100% / Total Slots)        : 66.3891%             ! Best Dispersion !
--------------------------------------------------------------------------------------------
```
*/

// FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_4HEADS 'VierKöpfe': the 100% FREE lookuper, last update: 2026-Aug-21, Kaze (sanmayce@sanmayce.com). ]
