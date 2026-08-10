// Pippipify.c, revision 3

// gcc -O3 -maes -march=native Pippipify.c -o Pippipify
// ./Pippipify /path/to/large_file.bin

#define _FILE_OFFSET_BITS 64
#define eXdupe // Forces FNV1A_Pippip to store the full __m128i state

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <immintrin.h>

// --- Begin Included Algorithm ---
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
					_mm_prefetch(str, _MM_HINT_T0);
					_mm_prefetch(str+NDhead, _MM_HINT_T0);
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
// --- End Included Algorithm ---

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file> [seed]\n", argv[0]);
        return 1;
    }

    const char *filepath = argv[1];
    uint32_t seed = (argc >= 3) ? (uint32_t)strtoul(argv[2], NULL, 0) : 0;

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("[ERROR] Failed to open file");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("[ERROR] Failed to stat file");
        close(fd);
        return 1;
    }

    size_t filesize = (size_t)st.st_size;

    // Handle empty file edge case
    if (filesize == 0) {
        printf("00000000000000000000000000000000  %s\n", filepath);
        close(fd);
        return 0;
    }

    // Map entire address space of the file lazily
    void *mapped = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("[ERROR] mmap failed");
        close(fd);
        return 1;
    }

    // Advise the kernel that we will blast through the memory sequentially
    madvise(mapped, filesize, MADV_SEQUENTIAL | MADV_WILLNEED);

    // Provide a strictly typed 128-bit structure memory destination for _mm_storeu_si128
    hashPippip128_t hash128;
    FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla((const char *)mapped, filesize, seed, &hash128);

    // x86-64 is little-endian. _mm_storeu_si128 writes the lowest 64 bits to index 0. 
    // To represent 128-bit logically, we print High (index 1) followed by Low (index 0).
    printf("%016" PRIx64 "%016" PRIx64 "  %s\n", hash128.high, hash128.low, filepath);

    // Cleanup
    munmap(mapped, filesize);
    close(fd);

    return 0;
}

