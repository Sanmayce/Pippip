// Pippipify.c, written by Grok, 2025-Jul-25, updated 2025-Sep-15

/*
[sanmayce@djudjeto checksum_showdown_128bit]$ gcc Pippipify.c -maes -o Pippipify.elf -O3 -static
[sanmayce@djudjeto ~]$ ./Pippipify.elf xxhash.h
Streaming Mode (chunk size: 4096 bytes):
 128-bit hash: 0x144e76e4e10723cfdcd79b2d1ec648ba

In-One-Go Mode:
Debug: File size = 268319 bytes
Debug: Successfully read 268319 bytes
 128-bit hash: 0x144e76e4e10723cfdcd79b2d1ec648ba
[sanmayce@djudjeto ~]$ 
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

// Chunk size for streaming mode (4KB = 2^12, used for file buffer size)
#define CHUNK_SIZE 4096

typedef struct {
    uint64_t low;
    uint64_t high;
} hashPippip128_t;

#define _PADr_KAZE(x, n) (((x) << (n)) >> (n))
#define _PAD_KAZE(x, n) (((x) << (n)))

static inline uint64_t fold64(uint64_t A, uint64_t B) {
    #if defined(__GNUC__) || defined(__clang__)
        __uint128_t r = (__uint128_t)A * B;
        return (uint64_t)r ^ (uint64_t)(r >> 64);
    #else
        uint64_t hash64 = A ^ B;
        hash64 *= 1099511628211;
        return hash64;
    #endif
}


// Core hash function (128-bit output only)
void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla(const char *str, size_t wrdlen, uint32_t seed, void *output) {
    __m128i chunkA, chunkB, stateMIX;
    uint64_t hashLH, hashRH;
    stateMIX = _mm_set1_epi32((uint32_t)wrdlen ^ seed);

    if (wrdlen > 8) {
        __m128i stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        __m128i stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        __m128i stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        size_t Cycles, NDhead;

        if (wrdlen > 16) {
            Cycles = ((wrdlen - 1) >> 5) + 1;
            NDhead = wrdlen - (Cycles << 4);
            if (Cycles & 1) {
                #pragma nounroll
                for (; Cycles--; str += 16) {
                    _mm_prefetch(str + 512, _MM_HINT_T0);
                    chunkA = _mm_loadu_si128((__m128i *)(str));
                    stateA = _mm_aesenc_si128(stateA, chunkA);
                    chunkB = _mm_loadu_si128((__m128i *)(str + NDhead));
                    stateC = _mm_aesenc_si128(stateC, chunkA);
                    stateB = _mm_aesenc_si128(stateB, chunkB);
                    stateC = _mm_aesenc_si128(stateC, chunkB);
                }
            } else {
                Cycles = Cycles >> 1;
                __m128i stateA2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
                __m128i stateB2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
                __m128i stateC2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
                #pragma nounroll
                for (; Cycles--; str += 32) {
                    _mm_prefetch(str + 512, _MM_HINT_T0);
                    _mm_prefetch(str + NDhead + 512, _MM_HINT_T0);
                    chunkA = _mm_loadu_si128((__m128i *)(str));
                    __m128i chunkA2 = _mm_loadu_si128((__m128i *)(str + 16));
                    stateA = _mm_aesenc_si128(stateA, chunkA);
                    stateA2 = _mm_aesenc_si128(stateA2, chunkA2);
                    chunkB = _mm_loadu_si128((__m128i *)(str + NDhead));
                    __m128i chunkB2 = _mm_loadu_si128((__m128i *)(str + NDhead + 16));
                    stateC = _mm_aesenc_si128(stateC, chunkA);
                    stateB = _mm_aesenc_si128(stateB, chunkB);
                    stateC = _mm_aesenc_si128(stateC, chunkB);
                    stateC2 = _mm_aesenc_si128(stateC2, chunkA2);
                    stateB2 = _mm_aesenc_si128(stateB2, chunkB2);
                    stateC2 = _mm_aesenc_si128(stateC2, chunkB2);
                    stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
                    stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
                    stateMIX = _mm_aesenc_si128(stateMIX, stateC2);
                }
            }
        } else { // 9..16
            NDhead = wrdlen - 8;
            hashLH = (*(uint64_t *)(str));
            hashRH = (*(uint64_t *)(str + NDhead));
            chunkA = _mm_set_epi64x(hashLH, hashLH);
            stateA = _mm_aesenc_si128(stateA, chunkA);
            chunkB = _mm_set_epi64x(hashRH, hashRH);
            stateC = _mm_aesenc_si128(stateC, chunkA);
            stateB = _mm_aesenc_si128(stateB, chunkB);
            stateC = _mm_aesenc_si128(stateC, chunkB);
        }
        stateMIX = _mm_aesenc_si128(stateMIX, stateA);
        stateMIX = _mm_aesenc_si128(stateMIX, stateB);
        stateMIX = _mm_aesenc_si128(stateMIX, stateC);
    } else {
        hashLH = _PADr_KAZE(*(uint64_t *)(str), (8 - wrdlen) << 3);
        hashRH = _PAD_KAZE(*(uint64_t *)(str), (8 - wrdlen) << 3);
        chunkA = _mm_set_epi64x(hashLH, hashLH);
        chunkB = _mm_set_epi64x(hashRH, hashRH);
        stateMIX = _mm_aesenc_si128(stateMIX, chunkA);
        stateMIX = _mm_aesenc_si128(stateMIX, chunkB);
    }

    _mm_storeu_si128((__m128i *)output, stateMIX); // Always 128-bit output
}

// Compute hash in streaming mode (128-bit output)
int compute_streaming_hash(const char *filename, hashPippip128_t *hash128) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return -1;
    }

    // Get file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Cannot seek to end of file %s\n", filename);
        fclose(file);
        return -1;
    }
    off_t file_size = ftell(file);
    if (file_size < 0) {
        fprintf(stderr, "Error: Cannot determine size of file %s\n", filename);
        fclose(file);
        return -1;
    }
    rewind(file);

    uint32_t seed = 42;
    __m128i stateMIX = _mm_set1_epi32((uint32_t)file_size ^ seed);

    if (file_size <= 8) {
        uint8_t buffer[16];
        memset(buffer, 0, 16);
        size_t read = fread(buffer, 1, file_size, file);
        if (read != (size_t)file_size) {
            fprintf(stderr, "Error: Failed to read file %s\n", filename);
            fclose(file);
            return -1;
        }
        uint64_t hashLH = _PADr_KAZE(*(uint64_t *)buffer, (8 - file_size) << 3);
        uint64_t hashRH = _PAD_KAZE(*(uint64_t *)buffer, (8 - file_size) << 3);
        __m128i chunkA = _mm_set_epi64x(hashLH, hashLH);
        __m128i chunkB = _mm_set_epi64x(hashRH, hashRH);
        stateMIX = _mm_aesenc_si128(stateMIX, chunkA);
        stateMIX = _mm_aesenc_si128(stateMIX, chunkB);
    } else if (file_size <= 16) {
        uint8_t buffer[16];
        size_t read = fread(buffer, 1, file_size, file);
        if (read != (size_t)file_size) {
            fprintf(stderr, "Error: Failed to read file %s\n", filename);
            fclose(file);
            return -1;
        }
        __m128i stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        __m128i stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        __m128i stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        size_t NDhead = file_size - 8;
        uint64_t hashLH = *(uint64_t *)buffer;
        uint64_t hashRH = *(uint64_t *)(buffer + NDhead);
        __m128i chunkA = _mm_set_epi64x(hashLH, hashLH);
        __m128i chunkB = _mm_set_epi64x(hashRH, hashRH);
        stateA = _mm_aesenc_si128(stateA, chunkA);
        stateC = _mm_aesenc_si128(stateC, chunkA);
        stateB = _mm_aesenc_si128(stateB, chunkB);
        stateC = _mm_aesenc_si128(stateC, chunkB);
        stateMIX = _mm_aesenc_si128(stateMIX, stateA);
        stateMIX = _mm_aesenc_si128(stateMIX, stateB);
        stateMIX = _mm_aesenc_si128(stateMIX, stateC);
    } else {
        size_t Cycles = ((file_size - 1) >> 5) + 1;
        off_t NDhead = file_size - (Cycles << 4);

        FILE *fp_a = file;  // Stream A starts at 0
        FILE *fp_b = fopen(filename, "rb");
        if (!fp_b) {
            fprintf(stderr, "Error: Cannot open second stream for file %s\n", filename);
            fclose(file);
            return -1;
        }
        if (fseek(fp_b, NDhead, SEEK_SET) != 0) {
            fprintf(stderr, "Error: Cannot seek to NDhead in file %s\n", filename);
            fclose(file);
            fclose(fp_b);
            return -1;
        }

        // Set buffer size to CHUNK_SIZE for streaming efficiency
        setvbuf(fp_a, NULL, _IOFBF, CHUNK_SIZE);
        setvbuf(fp_b, NULL, _IOFBF, CHUNK_SIZE);

        __m128i stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        __m128i stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        __m128i stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);

        if (Cycles & 1) {
            #pragma nounroll
            for (; Cycles--; ) {
                uint8_t buf_a[16];
                size_t read_a = fread(buf_a, 1, 16, fp_a);
                if (read_a != 16) {
                    if (read_a > 0) {
                        memset(buf_a + read_a, 0, 16 - read_a);
                    } else {
                        fprintf(stderr, "Error: Failed to read from stream A\n");
                        fclose(fp_a);
                        fclose(fp_b);
                        return -1;
                    }
                }
                __m128i chunkA = _mm_loadu_si128((__m128i *)buf_a);

                uint8_t buf_b[16];
                size_t read_b = fread(buf_b, 1, 16, fp_b);
                if (read_b != 16) {
                    if (read_b > 0) {
                        memset(buf_b + read_b, 0, 16 - read_b);
                    } else {
                        fprintf(stderr, "Error: Failed to read from stream B\n");
                        fclose(fp_a);
                        fclose(fp_b);
                        return -1;
                    }
                }
                __m128i chunkB = _mm_loadu_si128((__m128i *)buf_b);

                stateA = _mm_aesenc_si128(stateA, chunkA);
                stateC = _mm_aesenc_si128(stateC, chunkA);
                stateB = _mm_aesenc_si128(stateB, chunkB);
                stateC = _mm_aesenc_si128(stateC, chunkB);
            }
        } else {
            Cycles >>= 1;
            __m128i stateA2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
            __m128i stateB2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
            __m128i stateC2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
            #pragma nounroll
            for (; Cycles--; ) {
                uint8_t buf_a1[16];
                size_t read_a1 = fread(buf_a1, 1, 16, fp_a);
                if (read_a1 != 16) {
                    if (read_a1 > 0) {
                        memset(buf_a1 + read_a1, 0, 16 - read_a1);
                    } else {
                        fprintf(stderr, "Error: Failed to read from stream A\n");
                        fclose(fp_a);
                        fclose(fp_b);
                        return -1;
                    }
                }
                __m128i chunkA = _mm_loadu_si128((__m128i *)buf_a1);

                uint8_t buf_a2[16];
                size_t read_a2 = fread(buf_a2, 1, 16, fp_a);
                if (read_a2 != 16) {
                    if (read_a2 > 0) {
                        memset(buf_a2 + read_a2, 0, 16 - read_a2);
                    } else {
                        fprintf(stderr, "Error: Failed to read from stream A\n");
                        fclose(fp_a);
                        fclose(fp_b);
                        return -1;
                    }
                }
                __m128i chunkA2 = _mm_loadu_si128((__m128i *)buf_a2);

                uint8_t buf_b1[16];
                size_t read_b1 = fread(buf_b1, 1, 16, fp_b);
                if (read_b1 != 16) {
                    if (read_b1 > 0) {
                        memset(buf_b1 + read_b1, 0, 16 - read_b1);
                    } else {
                        fprintf(stderr, "Error: Failed to read from stream B\n");
                        fclose(fp_a);
                        fclose(fp_b);
                        return -1;
                    }
                }
                __m128i chunkB = _mm_loadu_si128((__m128i *)buf_b1);

                uint8_t buf_b2[16];
                size_t read_b2 = fread(buf_b2, 1, 16, fp_b);
                if (read_b2 != 16) {
                    if (read_b2 > 0) {
                        memset(buf_b2 + read_b2, 0, 16 - read_b2);
                    } else {
                        fprintf(stderr, "Error: Failed to read from stream B\n");
                        fclose(fp_a);
                        fclose(fp_b);
                        return -1;
                    }
                }
                __m128i chunkB2 = _mm_loadu_si128((__m128i *)buf_b2);

                stateA = _mm_aesenc_si128(stateA, chunkA);
                stateA2 = _mm_aesenc_si128(stateA2, chunkA2);
                stateC = _mm_aesenc_si128(stateC, chunkA);
                stateB = _mm_aesenc_si128(stateB, chunkB);
                stateC = _mm_aesenc_si128(stateC, chunkB);
                stateC2 = _mm_aesenc_si128(stateC2, chunkA2);
                stateB2 = _mm_aesenc_si128(stateB2, chunkB2);
                stateC2 = _mm_aesenc_si128(stateC2, chunkB2);
                stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
                stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
                stateMIX = _mm_aesenc_si128(stateMIX, stateC2);
            }
        }

        stateMIX = _mm_aesenc_si128(stateMIX, stateA);
        stateMIX = _mm_aesenc_si128(stateMIX, stateB);
        stateMIX = _mm_aesenc_si128(stateMIX, stateC);

        fclose(fp_b);
    }

    uint64_t result[2];
    _mm_storeu_si128((__m128i *)result, stateMIX);
    hash128->low = result[0];
    hash128->high = result[1];

    fclose(file);
    return 0;
}

// Compute hash in one-go mode (128-bit output)
int compute_one_go_hash(const char *filename, hashPippip128_t *hash128) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return -1;
    }

    // Get file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: Cannot seek to end of file %s\n", filename);
        fclose(file);
        return -1;
    }
    off_t file_size = ftell(file);
    if (file_size < 0) {
        fprintf(stderr, "Error: Cannot determine size of file %s\n", filename);
        fclose(file);
        return -1;
    }
    rewind(file);

    fprintf(stderr, "Debug: File size = %lld bytes\n", (long long)file_size);

    // Allocate aligned memory for file
    char *buffer = NULL;
    if (posix_memalign((void **)&buffer, 16, file_size + 16) != 0) {
        fprintf(stderr, "Error: Aligned memory allocation failed for %lld bytes\n", (long long)file_size);
        fclose(file);
        return -1;
    }

    // Initialize buffer with zeros to avoid uninitialized memory access
    memset(buffer, 0, file_size + 16);

    // Read file
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Error: Read %zu bytes, expected %lld bytes from file %s\n",
                bytes_read, (long long)file_size, filename);
        free(buffer);
        fclose(file);
        return -1;
    }

    fprintf(stderr, "Debug: Successfully read %zu bytes\n", bytes_read);

    // Compute 128-bit hash
    FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla(buffer, file_size, 42, hash128);

    free(buffer);
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    hashPippip128_t hash128_stream, hash128_one_go;

/*
__________.__              .__       .__  _____       
\______   \__|_____ ______ |__|_____ |__|/ ____\__.__.
 |     ___/  \____ \\____ \|  \____ \|  \   __<   |  |
 |    |   |  |  |_> >  |_> >  |  |_> >  ||  |  \___  |
 |____|   |__|   __/|   __/|__|   __/|__||__|  / ____|
             |__|   |__|      |__|             \/     
*/                                                               

    // Streaming mode
    printf("Streaming Mode (chunk size: %d bytes):\n", CHUNK_SIZE);
    if (compute_streaming_hash(argv[1], &hash128_stream) == 0) {
        printf(" 128-bit hash: 0x%016llx%016llx\n",
               (unsigned long long)hash128_stream.high, (unsigned long long)hash128_stream.low);
    } else {
        return 1;
    }

    // In-One-Go Mode
    printf("\nIn-One-Go Mode:\n");
    if (compute_one_go_hash(argv[1], &hash128_one_go) == 0) {
        printf(" 128-bit hash: 0x%016llx%016llx\n",
               (unsigned long long)hash128_one_go.high, (unsigned long long)hash128_one_go.low);
    } else {
        return 1;
    }

    return 0;
}

