// FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla: the 100% FREE lookuper, last update: 2026-Aug-09, Kaze (sanmayce@sanmayce.com). [
// This latest revision was written when Mikayla "saveafox" left this world.

/*
---------------------------------------------------------------------------
  FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla (FOX Variant)
---------------------------------------------------------------------------
  The Fastest Lookuper. Engineered for maximum sequential throughput.

  DESCRIPTION:
  A brutally fast, non-incremental, 128-bit SIMD vector hash built for 
  modern x86-64 architectures. Designed to saturate out-of-order (OOO) 
  execution pipelines using AES-NI hardware acceleration.

  VALIDATION: 
  SMHasher3 Verified (Passed).

  WARNING: 
  Built for speed, not standard compliance. Short-key processing 
  (0-8 bytes) intentionally disregards out-of-bounds memory read 
  safety to prioritize absolute minimum cycle-counts. 
---------------------------------------------------------------------------
*/

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

// Actually 'FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_FOX'
void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla (const char *str, size_t wrdlen, uint32_t seed, void *output) {
	__m128i chunkA;
	__m128i chunkB;
	__m128i stateMIX;
	uint64_t hashLH;
	uint64_t hashRH;

// ### 1. `0x6C62272E07BB0142` (The FNV-128 Offset Basis)
// 
// * **Origin:** This is the upper 64 bits of the **128-bit FNV offset basis**.
// * **Derivation:** The full 128-bit FNV offset basis is a massive, mathematically derived integer (`144066263297769815596495629667062367629`), which in hexadecimal is `0x6C62272E07BB014262B821756295C58D`. The first half is `0x6C62272E07BB0142`.
// * **Use Case:** It acts as the seed/starting state for Fowler-Noll-Vo (FNV) 128-bit non-cryptographic hashes.
// ### 2. `0x9E3779B97F4A7C15` (The Golden Ratio Constant)
// * **Origin:** This is derived from the **Golden Ratio** ($\phi$).
// * **Derivation:** It represents the fractional part of $\phi \times 2^{64}$. Specifically, $2^{64} / \phi \approx 11400714819323198485$, which translates directly to `0x9E3779B97F4A7C15` in 64-bit hexadecimal.
// * **Name/Use Case:** Widely known as the **RC5 Magic Constant** ($Q_{64}$), the **Golden Gamma**, or `pow64_over_phi`. It is incredibly popular for scattering bits cleanly, featuring heavily in SplitMix64 pseudo-random number generators, the Tiny Encryption Algorithm (TEA), and SpookyHash.

// * `0x6A09E667F3BCC908` – Fractional part of $\sqrt{2}$. (SHA-512 IV 0)
// * `0xBB67AE8584CAA73B` – Fractional part of $\sqrt{3}$. (SHA-512 IV 1)
// * `0x3C6EF372FE94F82B` – Fractional part of $\sqrt{5}$. (SHA-512 IV 2)
// * `0x428A2F98D728AE22` – Fractional part of $\sqrt[3]{2}$. (SHA-512 Round Constant 0)
// 
// **2. Pi and Euler's Number (The Blowfish / RC5 Companions)**
// 
// * `0x243F6A8885A308D3` – Derived from the fractional digits of **$\pi$** (Pi). Famous for being the initialization vector for the Blowfish cipher.
// * `0xB7E151628AED2A6B` – Derived from the fractional digits of **$e$** (Euler's number). This is the companion constant ($P_{64}$) used right alongside the Golden Ratio constant in the RC5 cipher initialization.

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
					chunkA = _mm_loadu_si128((__m128i *)(str));
					chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
					stateA = _mm_aesenc_si128(stateA, chunkA);
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateC = _mm_aesenc_si128(stateC, chunkB);
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

// https://godbolt.org/z/o3ooEnToM
// x86-64 clang 22.1.0
// -O3 -maes
/*
.LCPI0_0:
        .quad   -7046029254386353131
        .quad   7809847782465536322
.LCPI0_1:
        .quad   -4942790177534073029
        .quad   7640891576956012808
.LCPI0_2:
        .quad   4794697086780616226
        .quad   4354685564936845355
.LCPI0_3:
        .quad   7809847782465536322
        .quad   -7046029254386353131
.LCPI0_4:
        .quad   7640891576956012808
        .quad   -4942790177534073029
.LCPI0_5:
        .quad   4354685564936845355
        .quad   4794697086780616226
FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla(char const*, unsigned long, unsigned int, void*):
        mov     r8, rcx
        mov     eax, esi
        xor     eax, edx
        movd    xmm0, eax
        pshufd  xmm0, xmm0, 0
        cmp     rsi, 9
        jb      .LBB0_9
        cmp     rsi, 17
        jb      .LBB0_8
        lea     rcx, [rsi - 1]
        mov     rdx, rcx
        shr     rdx, 5
        lea     rax, [rdx + 1]
        test    cl, 32
        jne     .LBB0_5
        shl     rax, 4
        mov     rcx, rsi
        sub     rcx, rax
        add     rcx, rdi
        shl     rdx, 4
        add     rdx, 16
        movdqa  xmm1, xmmword ptr [rip + .LCPI0_0]
        movdqa  xmm2, xmmword ptr [rip + .LCPI0_1]
        movdqa  xmm3, xmmword ptr [rip + .LCPI0_2]
        xor     eax, eax
.LBB0_4:
        movdqu  xmm4, xmmword ptr [rdi + rax]
        movdqu  xmm5, xmmword ptr [rcx + rax]
        aesenc  xmm1, xmm4
        aesenc  xmm2, xmm5
        aesenc  xmm3, xmm4
        aesenc  xmm3, xmm5
        add     rax, 16
        cmp     rdx, rax
        jne     .LBB0_4
        jmp     .LBB0_10
.LBB0_9:
        mov     rax, qword ptr [rdi]
        lea     ecx, [8*rsi]
        neg     cl
        shl     rax, cl
        movq    xmm1, rax
        shr     rax, cl
        movq    xmm4, rax
        movdqa  xmm5, xmm1
        punpcklqdq      xmm5, xmm4
        punpcklqdq      xmm4, xmm1
        movdqa  xmm1, xmmword ptr [rip + .LCPI0_0]
        aesenc  xmm1, xmm5
        movdqa  xmm2, xmmword ptr [rip + .LCPI0_1]
        aesenc  xmm2, xmm4
        movdqa  xmm3, xmmword ptr [rip + .LCPI0_2]
        aesenc  xmm3, xmm5
        aesenc  xmm3, xmm4
        jmp     .LBB0_10
.LBB0_8:
        movq    xmm1, qword ptr [rdi]
        pshufd  xmm2, xmm1, 68
        movq    xmm1, qword ptr [rdi + rsi - 8]
        pshufd  xmm3, xmm1, 68
        pxor    xmm2, xmm0
        pxor    xmm3, xmm0
        movdqa  xmm1, xmmword ptr [rip + .LCPI0_0]
        aesenc  xmm1, xmm2
        movdqa  xmm2, xmmword ptr [rip + .LCPI0_1]
        aesenc  xmm2, xmm3
        movdqa  xmm3, xmmword ptr [rip + .LCPI0_2]
        jmp     .LBB0_10
.LBB0_5:
        shr     rax
        shl     rdx, 4
        mov     rcx, rsi
        sub     rcx, rdx
        movdqa  xmm1, xmmword ptr [rip + .LCPI0_0]
        movdqa  xmm2, xmmword ptr [rip + .LCPI0_1]
        movdqa  xmm3, xmmword ptr [rip + .LCPI0_2]
        movdqa  xmm6, xmmword ptr [rip + .LCPI0_3]
        movdqa  xmm5, xmmword ptr [rip + .LCPI0_4]
        movdqa  xmm4, xmmword ptr [rip + .LCPI0_5]
.LBB0_6:
        movdqu  xmm7, xmmword ptr [rdi]
        movdqu  xmm8, xmmword ptr [rdi + 16]
        movdqu  xmm9, xmmword ptr [rdi + rcx - 16]
        movdqu  xmm10, xmmword ptr [rdi + rcx]
        add     rdi, 32
        aesenc  xmm1, xmm7
        aesenc  xmm6, xmm8
        aesenc  xmm2, xmm9
        aesenc  xmm5, xmm10
        aesenc  xmm3, xmm7
        aesenc  xmm4, xmm8
        aesenc  xmm3, xmm9
        aesenc  xmm4, xmm10
        dec     rax
        jne     .LBB0_6
        aesenc  xmm0, xmm6
        aesenc  xmm0, xmm5
        aesenc  xmm0, xmm4
.LBB0_10:
        aesenc  xmm0, xmm1
        aesenc  xmm0, xmm2
        aesenc  xmm0, xmm3
        movq    rcx, xmm0
        pshufd  xmm0, xmm0, 238
        movq    rax, xmm0
        mul     rcx
        xor     esi, edx
        xor     esi, eax
        mov     dword ptr [r8], esi
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
-- Configuring done (1.1s)
-- Generating done (0.0s)
-- Build files have been written to: /home/sanmayce/Downloads/aug-08/smhasher3_mybuild_2026-Aug-08/smhasher/build
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

Verification value 0x067E98AB ....... FAIL! (Expected 0xDFE2D53C)
Running sanity check 1       .......... PASS
Running AppendedZeroesTest .......... PASS

[[[ Speed Tests ]]]

Bulk speed test - 262144-byte keys
Alignment  7 - 28.125 bytes/cycle - 48414.05 MiB/sec @ 1805 MHz
Alignment  6 - 28.122 bytes/cycle - 48408.88 MiB/sec @ 1805 MHz
Alignment  5 - 28.129 bytes/cycle - 48420.05 MiB/sec @ 1805 MHz
Alignment  4 - 28.130 bytes/cycle - 48422.08 MiB/sec @ 1805 MHz
Alignment  3 - 28.126 bytes/cycle - 48415.05 MiB/sec @ 1805 MHz
Alignment  2 - 28.126 bytes/cycle - 48415.38 MiB/sec @ 1805 MHz
Alignment  1 - 28.123 bytes/cycle - 48410.47 MiB/sec @ 1805 MHz
Alignment  0 - 28.127 bytes/cycle - 48417.33 MiB/sec @ 1805 MHz
Average      - 28.126 bytes/cycle - 48415.41 MiB/sec @ 1805 MHz

Small key speed test -    1-byte keys -    18.88 cycles/hash
Small key speed test -    2-byte keys -    19.07 cycles/hash
Small key speed test -    3-byte keys -    19.79 cycles/hash
Small key speed test -    4-byte keys -    19.09 cycles/hash
Small key speed test -    5-byte keys -    19.16 cycles/hash
Small key speed test -    6-byte keys -    18.93 cycles/hash
Small key speed test -    7-byte keys -    18.94 cycles/hash
Small key speed test -    8-byte keys -    18.96 cycles/hash
Small key speed test -    9-byte keys -    17.99 cycles/hash
Small key speed test -   10-byte keys -    17.93 cycles/hash
Small key speed test -   11-byte keys -    18.63 cycles/hash
Small key speed test -   12-byte keys -    19.16 cycles/hash
Small key speed test -   13-byte keys -    18.43 cycles/hash
Small key speed test -   14-byte keys -    17.96 cycles/hash
Small key speed test -   15-byte keys -    18.33 cycles/hash
Small key speed test -   16-byte keys -    18.22 cycles/hash
Small key speed test -   17-byte keys -    19.21 cycles/hash
Small key speed test -   18-byte keys -    19.24 cycles/hash
Small key speed test -   19-byte keys -    19.40 cycles/hash
Small key speed test -   20-byte keys -    19.37 cycles/hash
Small key speed test -   21-byte keys -    20.18 cycles/hash
Small key speed test -   22-byte keys -    19.66 cycles/hash
Small key speed test -   23-byte keys -    19.59 cycles/hash
Small key speed test -   24-byte keys -    19.59 cycles/hash
Small key speed test -   25-byte keys -    19.65 cycles/hash
Small key speed test -   26-byte keys -    19.65 cycles/hash
Small key speed test -   27-byte keys -    19.72 cycles/hash
Small key speed test -   28-byte keys -    19.31 cycles/hash
Small key speed test -   29-byte keys -    20.07 cycles/hash
Small key speed test -   30-byte keys -    19.61 cycles/hash
Small key speed test -   31-byte keys -    19.46 cycles/hash
Small key speed test -   32-byte keys -    19.00 cycles/hash
Average                                    19.130 cycles/hash
Average, weighted by key length freq.      18.882 cycles/hash (using 93.0% of top-7m Tranco DNS names dataset)
Average, weighted by key length freq.      18.306 cycles/hash (using 27.1% of startup-1M UMASH trace dataset)

[[[ 'Hashmap' Speed Tests ]]]

std::unordered_map
Init std HashMapTest:     264.224 cycles/op (479823 inserts, 1% deletions)
Running std HashMapTest:  265.937 cycles/op (5.1 stdv)

greg7mdp/parallel-hashmap
Init fast HashMapTest:    277.735 cycles/op (479823 inserts, 1% deletions)
Running fast HashMapTest: 223.395 cycles/op (3.0 stdv)  ....... PASS

[[[ Avalanche Tests ]]]

Testing   24-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.652000%
Testing   32-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.531333%
Testing   40-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.660667%
Testing   48-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.620000%
Testing   56-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.682000%
Testing   64-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.603333%
Testing   72-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.629333%
Testing   80-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.748667%
Testing   96-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.677333%
Testing  112-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.664000%
Testing  128-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.668667%
Testing  160-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.668000%
Testing  512-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.702000%
Testing 1024-bit keys ->  32-bit hashes, 300000 reps.......... worst bias is 0.758000%

[[[ Keyset 'Sparse' Tests ]]]

Keyset 'Sparse' - 16-bit keys with up to 9 bits set - 50643 keys
Testing collisions ( 32-bit) - Expected    0.3, actual      1 (3.35x) (1) !
Testing collisions (high 19-25 bits) - Worst is 25 bits: 48/38 (1.26x)
Testing collisions (low  19-25 bits) - Worst is 19 bits: 2278/2368 (0.96x)
Testing distribution - Worst bias is the 12-bit window at bit  0 - 0.380%

Keyset 'Sparse' - 24-bit keys with up to 8 bits set - 1271626 keys
Testing collisions ( 32-bit) - Expected  188.2, actual    179 (0.95x)
Testing distribution - Worst bias is the 17-bit window at bit  4 - 0.068%

Keyset 'Sparse' - 32-bit keys with up to 7 bits set - 4514873 keys
Testing collisions ( 32-bit) - Expected 2372.2, actual   2409 (1.02x) (37)
Testing distribution - Worst bias is the 19-bit window at bit 12 - 0.051%

Keyset 'Sparse' - 40-bit keys with up to 6 bits set - 4598479 keys
Testing collisions ( 32-bit) - Expected 2460.8, actual   2400 (0.98x)
Testing distribution - Worst bias is the 19-bit window at bit 12 - 0.038%

Keyset 'Sparse' - 48-bit keys with up to 6 bits set - 14196869 keys
Testing collisions ( 32-bit) - Expected 23437.8, actual  23404 (1.00x) (-33)
Testing distribution - Worst bias is the 20-bit window at bit 13 - 0.025%

Keyset 'Sparse' - 56-bit keys with up to 5 bits set - 4216423 keys
Testing collisions ( 32-bit) - Expected 2069.0, actual   2126 (1.03x) (58)
Testing distribution - Worst bias is the 19-bit window at bit 27 - 0.074%

Keyset 'Sparse' - 64-bit keys with up to 5 bits set - 8303633 keys
Testing collisions ( 32-bit) - Expected 8021.7, actual   7936 (0.99x) (-85)
Testing distribution - Worst bias is the 20-bit window at bit 28 - 0.042%

Keyset 'Sparse' - 72-bit keys with up to 5 bits set - 15082603 keys
Testing collisions ( 32-bit) - Expected 26451.8, actual  26442 (1.00x) (-9)
Testing distribution - Worst bias is the 20-bit window at bit 18 - 0.016%

Keyset 'Sparse' - 96-bit keys with up to 4 bits set - 3469497 keys
Testing collisions ( 32-bit) - Expected 1401.0, actual   1387 (0.99x) (-13)
Testing distribution - Worst bias is the 19-bit window at bit 15 - 0.066%

Keyset 'Sparse' - 160-bit keys with up to 4 bits set - 26977161 keys
Testing collisions ( 32-bit) - Expected 84546.1, actual  84403 (1.00x) (-143)
Testing distribution - Worst bias is the 20-bit window at bit 18 - 0.008%

Keyset 'Sparse' - 256-bit keys with up to 3 bits set - 2796417 keys
Testing collisions ( 32-bit) - Expected  910.2, actual    915 (1.01x) (5)
Testing distribution - Worst bias is the 19-bit window at bit 31 - 0.087%

Keyset 'Sparse' - 512-bit keys with up to 3 bits set - 22370049 keys
Testing collisions ( 32-bit) - Expected 58155.4, actual  58449 (1.01x) (294)
Testing distribution - Worst bias is the 20-bit window at bit 16 - 0.016%

Keyset 'Sparse' - 1024-bit keys with up to 2 bits set - 524801 keys
Testing collisions ( 32-bit) - Expected   32.1, actual     42 (1.31x) (10)
Testing distribution - Worst bias is the 16-bit window at bit 19 - 0.136%

Keyset 'Sparse' - 2048-bit keys with up to 2 bits set - 2098177 keys
Testing collisions ( 32-bit) - Expected  512.4, actual    496 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 10 - 0.097%


[[[ Keyset 'Permutation' Tests ]]]

Combination Lowbits Tests:
Keyset 'Combination' - up to 7 blocks from a set of 8 - 2396744 keys
Testing collisions ( 32-bit) - Expected  668.6, actual    651 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 27 - 0.068%


Combination Highbits Tests
Keyset 'Combination' - up to 7 blocks from a set of 8 - 2396744 keys
Testing collisions ( 32-bit) - Expected  668.6, actual    647 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 13 - 0.070%


Combination Hi-Lo Tests:
Keyset 'Combination' - up to 6 blocks from a set of 15 - 12204240 keys
Testing collisions ( 32-bit) - Expected 17322.9, actual  17243 (1.00x) (-79)
Testing distribution - Worst bias is the 20-bit window at bit 28 - 0.024%


Combination 0x80000000 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8169 (1.00x) (-17)
Testing distribution - Worst bias is the 19-bit window at bit 14 - 0.025%


Combination 0x00000001 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8117 (0.99x) (-69)
Testing distribution - Worst bias is the 20-bit window at bit 17 - 0.028%


Combination 0x8000000000000000 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8124 (0.99x) (-62)
Testing distribution - Worst bias is the 20-bit window at bit  0 - 0.043%


Combination 0x0000000000000001 Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8263 (1.01x) (77)
Testing distribution - Worst bias is the 20-bit window at bit 23 - 0.040%


Combination 16-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   7900 (0.96x)
Testing distribution - Worst bias is the 20-bit window at bit 18 - 0.026%


Combination 16-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8108 (0.99x) (-78)
Testing distribution - Worst bias is the 20-bit window at bit 12 - 0.035%


Combination 32-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8236 (1.01x) (50)
Testing distribution - Worst bias is the 20-bit window at bit  1 - 0.050%


Combination 32-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8121 (0.99x) (-65)
Testing distribution - Worst bias is the 20-bit window at bit  9 - 0.030%


Combination 64-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8188 (1.00x) (2)
Testing distribution - Worst bias is the 20-bit window at bit 12 - 0.031%


Combination 64-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8327 (1.02x) (141)
Testing distribution - Worst bias is the 20-bit window at bit 22 - 0.032%


Combination 128-bytes [0-1] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8158 (1.00x) (-28)
Testing distribution - Worst bias is the 20-bit window at bit 25 - 0.044%


Combination 128-bytes [0-last] Tests:
Keyset 'Combination' - up to 22 blocks from a set of 2 - 8388606 keys
Testing collisions ( 32-bit) - Expected 8186.7, actual   8236 (1.01x) (50)
Testing distribution - Worst bias is the 20-bit window at bit 27 - 0.021%


[[[ Keyset 'Window' Tests ]]]

Keyset 'Window' -  72-bit key,  20-bit window - 72 tests, 1048576 keys per test
Window at   0 - Testing collisions ( 32-bit) - Expected  128.0, actual    146 (1.14x) (19)
Window at   1 - Testing collisions ( 32-bit) - Expected  128.0, actual    143 (1.12x) (16)
Window at   2 - Testing collisions ( 32-bit) - Expected  128.0, actual    141 (1.10x) (14)
Window at   3 - Testing collisions ( 32-bit) - Expected  128.0, actual    146 (1.14x) (19)
Window at   4 - Testing collisions ( 32-bit) - Expected  128.0, actual    139 (1.09x) (12)
Window at   5 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at   6 - Testing collisions ( 32-bit) - Expected  128.0, actual    140 (1.09x) (13)
Window at   7 - Testing collisions ( 32-bit) - Expected  128.0, actual    148 (1.16x) (21)
Window at   8 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at   9 - Testing collisions ( 32-bit) - Expected  128.0, actual    133 (1.04x) (6)
Window at  10 - Testing collisions ( 32-bit) - Expected  128.0, actual    111 (0.87x)
Window at  11 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at  12 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  13 - Testing collisions ( 32-bit) - Expected  128.0, actual    118 (0.92x)
Window at  14 - Testing collisions ( 32-bit) - Expected  128.0, actual    111 (0.87x)
Window at  15 - Testing collisions ( 32-bit) - Expected  128.0, actual    118 (0.92x)
Window at  16 - Testing collisions ( 32-bit) - Expected  128.0, actual    108 (0.84x)
Window at  17 - Testing collisions ( 32-bit) - Expected  128.0, actual    147 (1.15x) (20)
Window at  18 - Testing collisions ( 32-bit) - Expected  128.0, actual    136 (1.06x) (9)
Window at  19 - Testing collisions ( 32-bit) - Expected  128.0, actual    111 (0.87x)
Window at  20 - Testing collisions ( 32-bit) - Expected  128.0, actual    112 (0.88x)
Window at  21 - Testing collisions ( 32-bit) - Expected  128.0, actual    128 (1.00x) (1)
Window at  22 - Testing collisions ( 32-bit) - Expected  128.0, actual    136 (1.06x) (9)
Window at  23 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  24 - Testing collisions ( 32-bit) - Expected  128.0, actual    149 (1.16x) (22)
Window at  25 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  26 - Testing collisions ( 32-bit) - Expected  128.0, actual    111 (0.87x)
Window at  27 - Testing collisions ( 32-bit) - Expected  128.0, actual    119 (0.93x)
Window at  28 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at  29 - Testing collisions ( 32-bit) - Expected  128.0, actual    134 (1.05x) (7)
Window at  30 - Testing collisions ( 32-bit) - Expected  128.0, actual    136 (1.06x) (9)
Window at  31 - Testing collisions ( 32-bit) - Expected  128.0, actual    148 (1.16x) (21)
Window at  32 - Testing collisions ( 32-bit) - Expected  128.0, actual    137 (1.07x) (10)
Window at  33 - Testing collisions ( 32-bit) - Expected  128.0, actual    144 (1.13x) (17)
Window at  34 - Testing collisions ( 32-bit) - Expected  128.0, actual    139 (1.09x) (12)
Window at  35 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at  36 - Testing collisions ( 32-bit) - Expected  128.0, actual     97 (0.76x)
Window at  37 - Testing collisions ( 32-bit) - Expected  128.0, actual    119 (0.93x)
Window at  38 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  39 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  40 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at  41 - Testing collisions ( 32-bit) - Expected  128.0, actual    121 (0.95x)
Window at  42 - Testing collisions ( 32-bit) - Expected  128.0, actual    149 (1.16x) (22)
Window at  43 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  44 - Testing collisions ( 32-bit) - Expected  128.0, actual    109 (0.85x)
Window at  45 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  46 - Testing collisions ( 32-bit) - Expected  128.0, actual    131 (1.02x) (4)
Window at  47 - Testing collisions ( 32-bit) - Expected  128.0, actual    126 (0.98x) (-1)
Window at  48 - Testing collisions ( 32-bit) - Expected  128.0, actual    141 (1.10x) (14)
Window at  49 - Testing collisions ( 32-bit) - Expected  128.0, actual    134 (1.05x) (7)
Window at  50 - Testing collisions ( 32-bit) - Expected  128.0, actual    133 (1.04x) (6)
Window at  51 - Testing collisions ( 32-bit) - Expected  128.0, actual    149 (1.16x) (22)
Window at  52 - Testing collisions ( 32-bit) - Expected  128.0, actual    128 (1.00x) (1)
Window at  53 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  54 - Testing collisions ( 32-bit) - Expected  128.0, actual    154 (1.20x) (27)
Window at  55 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  56 - Testing collisions ( 32-bit) - Expected  128.0, actual    119 (0.93x)
Window at  57 - Testing collisions ( 32-bit) - Expected  128.0, actual    110 (0.86x)
Window at  58 - Testing collisions ( 32-bit) - Expected  128.0, actual    119 (0.93x)
Window at  59 - Testing collisions ( 32-bit) - Expected  128.0, actual    122 (0.95x)
Window at  60 - Testing collisions ( 32-bit) - Expected  128.0, actual    127 (0.99x)
Window at  61 - Testing collisions ( 32-bit) - Expected  128.0, actual    134 (1.05x) (7)
Window at  62 - Testing collisions ( 32-bit) - Expected  128.0, actual    125 (0.98x)
Window at  63 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  64 - Testing collisions ( 32-bit) - Expected  128.0, actual    132 (1.03x) (5)
Window at  65 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  66 - Testing collisions ( 32-bit) - Expected  128.0, actual    121 (0.95x)
Window at  67 - Testing collisions ( 32-bit) - Expected  128.0, actual    123 (0.96x)
Window at  68 - Testing collisions ( 32-bit) - Expected  128.0, actual    113 (0.88x)
Window at  69 - Testing collisions ( 32-bit) - Expected  128.0, actual    121 (0.95x)
Window at  70 - Testing collisions ( 32-bit) - Expected  128.0, actual    129 (1.01x) (2)
Window at  71 - Testing collisions ( 32-bit) - Expected  128.0, actual    130 (1.02x) (3)
Window at  72 - Testing collisions ( 32-bit) - Expected  128.0, actual    146 (1.14x) (19)

[[[ Keyset 'Cyclic' Tests ]]]

Keyset 'Cyclic' - 8 cycles of 4 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    122 (1.05x) (6)
Testing distribution - Worst bias is the 17-bit window at bit  1 - 0.085%

Keyset 'Cyclic' - 8 cycles of 5 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual     88 (0.76x)
Testing distribution - Worst bias is the 17-bit window at bit  6 - 0.064%

Keyset 'Cyclic' - 8 cycles of 6 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    158 (1.36x) (42)
Testing distribution - Worst bias is the 17-bit window at bit  2 - 0.117%

Keyset 'Cyclic' - 8 cycles of 7 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    109 (0.94x)
Testing distribution - Worst bias is the 17-bit window at bit 12 - 0.085%

Keyset 'Cyclic' - 8 cycles of 8 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    110 (0.94x)
Testing distribution - Worst bias is the 17-bit window at bit 19 - 0.074%

Keyset 'Cyclic' - 8 cycles of 12 bytes - 1000000 keys
Testing collisions ( 32-bit) - Expected  116.4, actual    137 (1.18x) (21)
Testing distribution - Worst bias is the 17-bit window at bit  6 - 0.077%


[[[ Keyset 'TwoBytes' Tests ]]]

Keyset 'TwoBytes' - up-to-4-byte keys, 652545 total keys
Testing collisions ( 32-bit) - Expected   49.6, actual     62 (1.25x) (13)
Testing distribution - Worst bias is the 16-bit window at bit 28 - 0.092%

Keyset 'TwoBytes' - up-to-8-byte keys, 5471025 total keys
Testing collisions ( 32-bit) - Expected 3483.1, actual   3535 (1.01x) (52)
Testing distribution - Worst bias is the 20-bit window at bit  9 - 0.074%

Keyset 'TwoBytes' - up-to-12-byte keys, 18616785 total keys
Testing collisions ( 32-bit) - Expected 40289.5, actual  40389 (1.00x) (100)
Testing distribution - Worst bias is the 20-bit window at bit  9 - 0.025%

Keyset 'TwoBytes' - up-to-16-byte keys, 44251425 total keys
Testing collisions ( 32-bit) - Expected 227182.3, actual 227262 (1.00x) (80)
Testing distribution - Worst bias is the 20-bit window at bit 10 - 0.007%

Keyset 'TwoBytes' - up-to-20-byte keys, 86536545 total keys
Testing collisions ( 32-bit) - Expected 865959.1, actual 865863 (1.00x) (-96)
Testing distribution - Worst bias is the 20-bit window at bit 11 - 0.003%

Keyset 'TwoBytes' - up-to-24-byte keys, 149633745 total keys
Testing collisions ( 32-bit) - Expected 2576560.5, actual 2579059 (1.00x) (2499)
Testing distribution - Worst bias is the 20-bit window at bit 25 - 0.002%


[[[ Keyset 'Text' Tests ]]]

Keyset 'Text' - keys of form "FooXXXXBar" - 14776336 keys
Testing collisions ( 32-bit) - Expected 25389.0, actual  25302 (1.00x) (-87)
Testing distribution - Worst bias is the 20-bit window at bit 24 - 0.016%

Keyset 'Text' - keys of form "FooBarXXXX" - 14776336 keys
Testing collisions ( 32-bit) - Expected 25389.0, actual  25311 (1.00x) (-78)
Testing distribution - Worst bias is the 20-bit window at bit 25 - 0.025%

Keyset 'Text' - keys of form "XXXXFooBar" - 14776336 keys
Testing collisions ( 32-bit) - Expected 25389.0, actual  25200 (0.99x) (-189)
Testing distribution - Worst bias is the 20-bit window at bit  6 - 0.030%

Keyset 'Words' - 4000000 random keys of len 6-16 from alnum charset
Testing collisions ( 32-bit) - Expected 1862.1, actual   1933 (1.04x) (71)
Testing distribution - Worst bias is the 19-bit window at bit 30 - 0.072%

Keyset 'Words' - 4000000 random keys of len 6-16 from password charset
Testing collisions ( 32-bit) - Expected 1862.1, actual   1923 (1.03x) (61)
Testing distribution - Worst bias is the 19-bit window at bit  0 - 0.041%

Keyset 'Words' - 479823 dict words
Testing collisions ( 32-bit) - Expected   26.8, actual     19 (0.71x)
Testing distribution - Worst bias is the 16-bit window at bit 27 - 0.177%


[[[ Keyset 'Zeroes' Tests ]]]

Keyset 'Zeroes' - 204800 keys
Testing collisions ( 32-bit) - Expected    4.9, actual      4 (0.82x)
Testing collisions (high 21-29 bits) - Worst is 29 bits: 42/39 (1.08x)
Testing collisions (low  21-29 bits) - Worst is 29 bits: 46/39 (1.18x)
Testing distribution - Worst bias is the 15-bit window at bit 28 - 0.264%


[[[ Keyset 'Seed' Tests ]]]

Keyset 'Seed' - 5000000 keys
Testing collisions ( 32-bit) - Expected 2909.3, actual   2915 (1.00x) (6)
Testing distribution - Worst bias is the 19-bit window at bit 10 - 0.037%


[[[ Keyset 'PerlinNoise' Tests ]]]

Testing 16777216 coordinates (L2) : 
Testing collisions ( 32-bit) - Expected 32725.4, actual  32974 (1.01x) (249)

Testing AV variant, 128 count with 4 spacing, 4-12:
Testing collisions ( 32-bit) - Expected 1116.2, actual   1179 (1.06x) (63)


[[[ Diff 'Differential' Tests ]]]

Testing 8303632 up-to-5-bit differentials in 64-bit keys -> 32 bit hashes.
1000 reps, 8303632000 total tests, expecting 1.93 random collisions..........
2 total collisions, of which 2 single collisions were ignored

Testing 11017632 up-to-4-bit differentials in 128-bit keys -> 32 bit hashes.
1000 reps, 11017632000 total tests, expecting 2.57 random collisions..........
2 total collisions, of which 2 single collisions were ignored

Testing 2796416 up-to-3-bit differentials in 256-bit keys -> 32 bit hashes.
1000 reps, 2796416000 total tests, expecting 0.65 random collisions..........
0 total collisions, of which 0 single collisions were ignored


[[[ DiffDist 'Differential Distribution' Tests ]]]

Testing bit 0
Testing collisions ( 32-bit) - Expected  511.9, actual    486 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit 13 - 0.071%

Testing bit 1
Testing collisions ( 32-bit) - Expected  511.9, actual    494 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 24 - 0.064%

Testing bit 2
Testing collisions ( 32-bit) - Expected  511.9, actual    524 (1.02x) (13)
Testing distribution - Worst bias is the 18-bit window at bit 10 - 0.058%

Testing bit 3
Testing collisions ( 32-bit) - Expected  511.9, actual    510 (1.00x) (-1)
Testing distribution - Worst bias is the 18-bit window at bit 10 - 0.066%

Testing bit 4
Testing collisions ( 32-bit) - Expected  511.9, actual    535 (1.05x) (24)
Testing distribution - Worst bias is the 18-bit window at bit 16 - 0.078%

Testing bit 5
Testing collisions ( 32-bit) - Expected  511.9, actual    566 (1.11x) (55)
Testing distribution - Worst bias is the 18-bit window at bit 27 - 0.083%

Testing bit 6
Testing collisions ( 32-bit) - Expected  511.9, actual    497 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit  1 - 0.063%

Testing bit 7
Testing collisions ( 32-bit) - Expected  511.9, actual    487 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit 22 - 0.047%

Testing bit 8
Testing collisions ( 32-bit) - Expected  511.9, actual    490 (0.96x)
Testing distribution - Worst bias is the 18-bit window at bit  8 - 0.082%

Testing bit 9
Testing collisions ( 32-bit) - Expected  511.9, actual    497 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.069%

Testing bit 10
Testing collisions ( 32-bit) - Expected  511.9, actual    534 (1.04x) (23)
Testing distribution - Worst bias is the 16-bit window at bit 20 - 0.042%

Testing bit 11
Testing collisions ( 32-bit) - Expected  511.9, actual    472 (0.92x)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.052%

Testing bit 12
Testing collisions ( 32-bit) - Expected  511.9, actual    533 (1.04x) (22)
Testing distribution - Worst bias is the 18-bit window at bit 26 - 0.055%

Testing bit 13
Testing collisions ( 32-bit) - Expected  511.9, actual    512 (1.00x) (1)
Testing distribution - Worst bias is the 18-bit window at bit 17 - 0.095%

Testing bit 14
Testing collisions ( 32-bit) - Expected  511.9, actual    521 (1.02x) (10)
Testing distribution - Worst bias is the 18-bit window at bit 29 - 0.084%

Testing bit 15
Testing collisions ( 32-bit) - Expected  511.9, actual    479 (0.94x)
Testing distribution - Worst bias is the 18-bit window at bit 11 - 0.054%

Testing bit 16
Testing collisions ( 32-bit) - Expected  511.9, actual    486 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.103%

Testing bit 17
Testing collisions ( 32-bit) - Expected  511.9, actual    460 (0.90x)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.097%

Testing bit 18
Testing collisions ( 32-bit) - Expected  511.9, actual    488 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit  7 - 0.079%

Testing bit 19
Testing collisions ( 32-bit) - Expected  511.9, actual    510 (1.00x) (-1)
Testing distribution - Worst bias is the 18-bit window at bit 29 - 0.081%

Testing bit 20
Testing collisions ( 32-bit) - Expected  511.9, actual    542 (1.06x) (31)
Testing distribution - Worst bias is the 18-bit window at bit 12 - 0.054%

Testing bit 21
Testing collisions ( 32-bit) - Expected  511.9, actual    543 (1.06x) (32)
Testing distribution - Worst bias is the 18-bit window at bit 18 - 0.047%

Testing bit 22
Testing collisions ( 32-bit) - Expected  511.9, actual    501 (0.98x)
Testing distribution - Worst bias is the 18-bit window at bit 27 - 0.069%

Testing bit 23
Testing collisions ( 32-bit) - Expected  511.9, actual    529 (1.03x) (18)
Testing distribution - Worst bias is the 17-bit window at bit  9 - 0.062%

Testing bit 24
Testing collisions ( 32-bit) - Expected  511.9, actual    493 (0.96x)
Testing distribution - Worst bias is the 18-bit window at bit  9 - 0.057%

Testing bit 25
Testing collisions ( 32-bit) - Expected  511.9, actual    464 (0.91x)
Testing distribution - Worst bias is the 18-bit window at bit  3 - 0.075%

Testing bit 26
Testing collisions ( 32-bit) - Expected  511.9, actual    526 (1.03x) (15)
Testing distribution - Worst bias is the 18-bit window at bit 30 - 0.062%

Testing bit 27
Testing collisions ( 32-bit) - Expected  511.9, actual    498 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 11 - 0.081%

Testing bit 28
Testing collisions ( 32-bit) - Expected  511.9, actual    510 (1.00x) (-1)
Testing distribution - Worst bias is the 18-bit window at bit 15 - 0.062%

Testing bit 29
Testing collisions ( 32-bit) - Expected  511.9, actual    539 (1.05x) (28)
Testing distribution - Worst bias is the 18-bit window at bit  5 - 0.055%

Testing bit 30
Testing collisions ( 32-bit) - Expected  511.9, actual    540 (1.05x) (29)
Testing distribution - Worst bias is the 18-bit window at bit  6 - 0.057%

Testing bit 31
Testing collisions ( 32-bit) - Expected  511.9, actual    536 (1.05x) (25)
Testing distribution - Worst bias is the 18-bit window at bit 25 - 0.045%

Testing bit 32
Testing collisions ( 32-bit) - Expected  511.9, actual    490 (0.96x)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.078%

Testing bit 33
Testing collisions ( 32-bit) - Expected  511.9, actual    517 (1.01x) (6)
Testing distribution - Worst bias is the 18-bit window at bit  2 - 0.057%

Testing bit 34
Testing collisions ( 32-bit) - Expected  511.9, actual    494 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 31 - 0.072%

Testing bit 35
Testing collisions ( 32-bit) - Expected  511.9, actual    487 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit 11 - 0.102%

Testing bit 36
Testing collisions ( 32-bit) - Expected  511.9, actual    532 (1.04x) (21)
Testing distribution - Worst bias is the 18-bit window at bit  0 - 0.050%

Testing bit 37
Testing collisions ( 32-bit) - Expected  511.9, actual    486 (0.95x)
Testing distribution - Worst bias is the 18-bit window at bit  7 - 0.061%

Testing bit 38
Testing collisions ( 32-bit) - Expected  511.9, actual    505 (0.99x) (-6)
Testing distribution - Worst bias is the 18-bit window at bit 13 - 0.059%

Testing bit 39
Testing collisions ( 32-bit) - Expected  511.9, actual    516 (1.01x) (5)
Testing distribution - Worst bias is the 18-bit window at bit 18 - 0.065%

Testing bit 40
Testing collisions ( 32-bit) - Expected  511.9, actual    478 (0.93x)
Testing distribution - Worst bias is the 18-bit window at bit 13 - 0.058%

Testing bit 41
Testing collisions ( 32-bit) - Expected  511.9, actual    522 (1.02x) (11)
Testing distribution - Worst bias is the 17-bit window at bit  9 - 0.037%

Testing bit 42
Testing collisions ( 32-bit) - Expected  511.9, actual    504 (0.98x) (-7)
Testing distribution - Worst bias is the 18-bit window at bit 13 - 0.045%

Testing bit 43
Testing collisions ( 32-bit) - Expected  511.9, actual    463 (0.90x)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.083%

Testing bit 44
Testing collisions ( 32-bit) - Expected  511.9, actual    510 (1.00x) (-1)
Testing distribution - Worst bias is the 18-bit window at bit 24 - 0.040%

Testing bit 45
Testing collisions ( 32-bit) - Expected  511.9, actual    505 (0.99x) (-6)
Testing distribution - Worst bias is the 16-bit window at bit 20 - 0.042%

Testing bit 46
Testing collisions ( 32-bit) - Expected  511.9, actual    483 (0.94x)
Testing distribution - Worst bias is the 18-bit window at bit 20 - 0.079%

Testing bit 47
Testing collisions ( 32-bit) - Expected  511.9, actual    529 (1.03x) (18)
Testing distribution - Worst bias is the 17-bit window at bit 20 - 0.061%

Testing bit 48
Testing collisions ( 32-bit) - Expected  511.9, actual    512 (1.00x) (1)
Testing distribution - Worst bias is the 18-bit window at bit  3 - 0.076%

Testing bit 49
Testing collisions ( 32-bit) - Expected  511.9, actual    551 (1.08x) (40)
Testing distribution - Worst bias is the 18-bit window at bit 22 - 0.104%

Testing bit 50
Testing collisions ( 32-bit) - Expected  511.9, actual    501 (0.98x)
Testing distribution - Worst bias is the 18-bit window at bit 21 - 0.091%

Testing bit 51
Testing collisions ( 32-bit) - Expected  511.9, actual    505 (0.99x) (-6)
Testing distribution - Worst bias is the 18-bit window at bit 18 - 0.091%

Testing bit 52
Testing collisions ( 32-bit) - Expected  511.9, actual    523 (1.02x) (12)
Testing distribution - Worst bias is the 18-bit window at bit  2 - 0.060%

Testing bit 53
Testing collisions ( 32-bit) - Expected  511.9, actual    458 (0.89x)
Testing distribution - Worst bias is the 18-bit window at bit 17 - 0.058%

Testing bit 54
Testing collisions ( 32-bit) - Expected  511.9, actual    507 (0.99x) (-4)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.074%

Testing bit 55
Testing collisions ( 32-bit) - Expected  511.9, actual    490 (0.96x)
Testing distribution - Worst bias is the 18-bit window at bit 10 - 0.051%

Testing bit 56
Testing collisions ( 32-bit) - Expected  511.9, actual    512 (1.00x) (1)
Testing distribution - Worst bias is the 18-bit window at bit 25 - 0.085%

Testing bit 57
Testing collisions ( 32-bit) - Expected  511.9, actual    530 (1.04x) (19)
Testing distribution - Worst bias is the 18-bit window at bit 10 - 0.042%

Testing bit 58
Testing collisions ( 32-bit) - Expected  511.9, actual    521 (1.02x) (10)
Testing distribution - Worst bias is the 18-bit window at bit 14 - 0.084%

Testing bit 59
Testing collisions ( 32-bit) - Expected  511.9, actual    515 (1.01x) (4)
Testing distribution - Worst bias is the 18-bit window at bit  3 - 0.062%

Testing bit 60
Testing collisions ( 32-bit) - Expected  511.9, actual    475 (0.93x)
Testing distribution - Worst bias is the 18-bit window at bit 26 - 0.048%

Testing bit 61
Testing collisions ( 32-bit) - Expected  511.9, actual    518 (1.01x) (7)
Testing distribution - Worst bias is the 18-bit window at bit  0 - 0.074%

Testing bit 62
Testing collisions ( 32-bit) - Expected  511.9, actual    532 (1.04x) (21)
Testing distribution - Worst bias is the 18-bit window at bit 31 - 0.097%

Testing bit 63
Testing collisions ( 32-bit) - Expected  511.9, actual    494 (0.97x)
Testing distribution - Worst bias is the 18-bit window at bit 29 - 0.045%


[[[ MomentChi2 Tests ]]]

Analyze hashes produced from a serie of linearly increasing numbers of 32-bit, using a step of 2 ... 
Target values to approximate : 1391290.000000 - 686.666667 
8 threads starting...  done
Popcount 1 stats : 1391300.486620 - 687.323545
Popcount 0 stats : 1391328.534942 - 687.354850
MomentChi2 for bits 1 :  0.0800364 
MomentChi2 for bits 0 :   1.08073 

Derivative stats (transition from 2 consecutive values) : 
Popcount 1 stats : 1391348.317809 - 687.414767
Popcount 0 stats : 1391305.224970 - 687.327286
MomentChi2 for deriv b1 :   2.47508 
MomentChi2 for deriv b0 :  0.168705 

  Great 


[[[ Prng Tests ]]]

Skipping PRNG test; it is designed for hashes >= 64-bits

[[[ BadSeeds Tests ]]]

Testing 10 internal bad seeds:
0x1077bd26 0x1c07e567 0x1c2e04b6 0x2179e8c6 0x7ca5ded3 0x7d9bbad9 0x9ac97b61 0xb6957619 0xbb54fecc 0xfac5c910 PASS


Input vcode 0x00000001, Output vcode 0x00000001, Result vcode 0x00000001
Verification value is 0x00000001 - Testing took 624.365049 seconds
-------------------------------------------------------------------------------
[sanmayce@djudjeto build]$
*/

// FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla: the 100% FREE lookuper, last update: 2026-Aug-09, Kaze (sanmayce@sanmayce.com). ]

