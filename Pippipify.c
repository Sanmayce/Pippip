// Pippiify.c, written by Grok, 2025-Jul-25

/*
[sanmayce@d8 hashBBs_ver7]$ gcc Pippipify.c -maes -o Pippipify.elf
[sanmayce@d8 hashBBs_ver7]$ ls -l
-rw-r--r-- 1 sanmayce sanmayce 5694801920 Jun  1  2024 github.com_Sefaria-Project_2024-Jun-01_16833-TXTs.tar

[sanmayce@d8 hashBBs_ver7]$ ./Pippipify.elf github.com_Sefaria-Project_2024-Jun-01_16833-TXTs.tar 
Streaming Mode (chunk size: 4096 bytes):
  32-bit hash: 0xee686b67
  64-bit hash: 0xe11caa51ee686b67
 128-bit hash: 0xfe2a30199f0cb14d46071046668b6a2f

In-One-Go Mode:
Debug: File size = 5694801920 bytes
Debug: Successfully read 5694801920 bytes
Debug: Successfully initialized context
Debug: Successfully updated context
Debug: Successfully finalized 32-bit hash
  32-bit hash: 0xee686b67
  64-bit hash: 0xe11caa51ee686b67
 128-bit hash: 0xfe2a30199f0cb14d46071046668b6a2f
[sanmayce@d8 hashBBs_ver7]$ 
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

// Default hash size is 32 bits unless eXdupe is defined (128 bits).
// HashInBITS defines the slot size for deduplication (default 2^26 = 64M slots,
// each containing an 8-byte pointer, requiring 512MB total).
#define HashInBITS 32
#define MASK ((1ULL << HashInBITS) - 1)
#define _PADr_KAZE(x, n) (((x) << (n)) >> (n))
#define _PAD_KAZE(x, n) (((x) << (n)))

// Chunk size for streaming mode (4KB = 2^12, aligns with Lasse's requirement)
#define CHUNK_SIZE 4096

typedef struct {
    uint64_t low;
    uint64_t high;
} hashPippip128_t;

// Streaming context for incremental hashing
typedef struct {
    __m128i stateMIX; // Current hash state
    uint64_t total_bytes; // Total bytes processed
    uint32_t seed; // Initial seed
    uint8_t buffer[16]; // Buffer for partial chunks
    size_t buffer_len; // Bytes in buffer
} PippipContext;

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

// Initialize streaming context
void pippip_init(PippipContext *ctx, uint32_t seed) {
    ctx->stateMIX = _mm_set1_epi32((uint32_t)0 ^ seed);
    ctx->total_bytes = 0;
    ctx->seed = seed;
    ctx->buffer_len = 0;
}

// Update streaming context with a chunk of data
void pippip_update(PippipContext *ctx, const char *data, size_t len) {
    size_t i = 0;
    __m128i stateA, stateB, stateC, chunkA;

    // Process buffered data if any
    if (ctx->buffer_len > 0) {
        size_t to_copy = 16 - ctx->buffer_len < len ? 16 - ctx->buffer_len : len;
        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;
        ctx->total_bytes += to_copy;

        if (ctx->buffer_len == 16) {
            chunkA = _mm_loadu_si128((__m128i *)ctx->buffer);
            stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
            stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
            stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
            stateA = _mm_aesenc_si128(stateA, chunkA);
            stateC = _mm_aesenc_si128(stateC, chunkA);
            stateB = _mm_aesenc_si128(stateB, chunkA);
            stateC = _mm_aesenc_si128(stateC, chunkA);
            ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, stateA);
            ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, stateB);
            ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, stateC);
            ctx->buffer_len = 0;
        }
    }

    // Process full 16-byte chunks
    while (len >= 16) {
        stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
        _mm_prefetch(data + 512, _MM_HINT_T0);
        chunkA = _mm_loadu_si128((__m128i *)(data + i));
        stateA = _mm_aesenc_si128(stateA, chunkA);
        stateC = _mm_aesenc_si128(stateC, chunkA);
        stateB = _mm_aesenc_si128(stateB, chunkA);
        stateC = _mm_aesenc_si128(stateC, chunkA);
        ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, stateA);
        ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, stateB);
        ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, stateC);
        i += 16;
        len -= 16;
    }
    ctx->total_bytes += i;

    // Buffer remaining data
    if (len > 0) {
        memcpy(ctx->buffer + ctx->buffer_len, data + i, len);
        ctx->buffer_len += len;
        ctx->total_bytes += len;
    }
}

// Finalize streaming hash (32-bit output)
uint32_t pippip_final(PippipContext *ctx) {
    __m128i chunkA, chunkB;
    uint64_t hashLH, hashRH;

    // Process any remaining buffered data
    if (ctx->buffer_len > 0) {
        hashLH = _PADr_KAZE(*(uint64_t *)(ctx->buffer), (16 - ctx->buffer_len) << 3);
        hashRH = _PAD_KAZE(*(uint64_t *)(ctx->buffer), (16 - ctx->buffer_len) << 3);
        chunkA = _mm_set_epi64x(hashLH, hashLH);
        chunkB = _mm_set_epi64x(hashRH, hashRH);
        ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, chunkA);
        ctx->stateMIX = _mm_aesenc_si128(ctx->stateMIX, chunkB);
        ctx->buffer_len = 0;
    }

    uint64_t result[2];
    _mm_storeu_si128((__m128i *)result, ctx->stateMIX);
    uint64_t hash64 = fold64(result[0], result[1]);
    return (uint32_t)hash64 ^ ctx->total_bytes;
}

// Original function (32-bit or 128-bit output based on eXdupe)
void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla(const char *str, size_t wrdlen, uint32_t seed, void *output) {
    PippipContext ctx;
    pippip_init(&ctx, seed);
    pippip_update(&ctx, str, wrdlen);
    #ifdef eXdupe
        uint64_t result[2];
        _mm_storeu_si128((__m128i *)result, ctx.stateMIX);
        ((hashPippip128_t *)output)->low = result[0];
        ((hashPippip128_t *)output)->high = result[1];
    #else
        *(uint32_t *)output = pippip_final(&ctx);
    #endif
}

// 64-bit hash function
uint64_t pippip_hash64(const char *str, size_t len, uint32_t seed) {
    PippipContext ctx;
    pippip_init(&ctx, seed);
    pippip_update(&ctx, str, len);
    uint64_t result[2];
    _mm_storeu_si128((__m128i *)result, ctx.stateMIX);
    return fold64(result[0], result[1]) ^ ctx.total_bytes;
}

// Flexible-length hash function
void pippip_hash(const char *str, size_t len, uint32_t seed, void *output, size_t result_len) {
    PippipContext ctx;
    pippip_init(&ctx, seed);
    pippip_update(&ctx, str, len);
    uint64_t result[2];
    _mm_storeu_si128((__m128i *)result, ctx.stateMIX);
    uint64_t hash64 = fold64(result[0], result[1]) ^ ctx.total_bytes;

    if (result_len == 4) {
        *(uint32_t *)output = (uint32_t)hash64;
    } else if (result_len == 8) {
        *(uint64_t *)output = hash64;
    } else if (result_len == 16) {
        ((hashPippip128_t *)output)->low = result[0];
        ((hashPippip128_t *)output)->high = result[1];
    } else {
        // Unsupported length, default to 32-bit
        *(uint32_t *)output = (uint32_t)hash64;
    }
}

// Compute hash in streaming mode
int compute_streaming_hash(const char *filename, uint32_t *hash32, uint64_t *hash64, hashPippip128_t *hash128) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return -1;
    }

    PippipContext ctx;
    pippip_init(&ctx, 42); // Fixed seed for consistency
    char buffer[CHUNK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        pippip_update(&ctx, buffer, bytes_read);
    }

    if (ferror(file)) {
        fprintf(stderr, "Error: Failed to read file %s\n", filename);
        fclose(file);
        return -1;
    }

    // Compute 32-bit hash
    *hash32 = pippip_final(&ctx);

    // Compute 64-bit and 128-bit hashes
    uint64_t result[2];
    _mm_storeu_si128((__m128i *)result, ctx.stateMIX);
    *hash64 = fold64(result[0], result[1]) ^ ctx.total_bytes;
    hash128->low = result[0];
    hash128->high = result[1];

    fclose(file);
    return 0;
}

// Compute hash in one-go mode
int compute_one_go_hash(const char *filename, uint32_t *hash32, uint64_t *hash64, hashPippip128_t *hash128) {
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

    // Compute hashes using streaming API for consistency
    PippipContext ctx;
    pippip_init(&ctx, 42);
    fprintf(stderr, "Debug: Successfully initialized context\n");
    pippip_update(&ctx, buffer, file_size);
    fprintf(stderr, "Debug: Successfully updated context\n");
    *hash32 = pippip_final(&ctx);
    fprintf(stderr, "Debug: Successfully finalized 32-bit hash\n");

    // Compute 64-bit and 128-bit hashes
    uint64_t result[2];
    _mm_storeu_si128((__m128i *)result, ctx.stateMIX);
    *hash64 = fold64(result[0], result[1]) ^ ctx.total_bytes;
    hash128->low = result[0];
    hash128->high = result[1];

    free(buffer);
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    uint32_t hash32_stream, hash32_one_go;
    uint64_t hash64_stream, hash64_one_go;
    hashPippip128_t hash128_stream, hash128_one_go;

    // Streaming mode
    printf("Streaming Mode (chunk size: %d bytes):\n", CHUNK_SIZE);
    if (compute_streaming_hash(argv[1], &hash32_stream, &hash64_stream, &hash128_stream) == 0) {
        printf("  32-bit hash: 0x%08x\n", hash32_stream);
        printf("  64-bit hash: 0x%016llx\n", (unsigned long long)hash64_stream);
        printf(" 128-bit hash: 0x%016llx%016llx\n", 
               (unsigned long long)hash128_stream.high, (unsigned long long)hash128_stream.low);
    } else {
        return 1;
    }

    // In-one-go mode
    printf("\nIn-One-Go Mode:\n");
    if (compute_one_go_hash(argv[1], &hash32_one_go, &hash64_one_go, &hash128_one_go) == 0) {
        printf("  32-bit hash: 0x%08x\n", hash32_one_go);
        printf("  64-bit hash: 0x%016llx\n", (unsigned long long)hash64_one_go);
        printf(" 128-bit hash: 0x%016llx%016llx\n", 
               (unsigned long long)hash128_one_go.high, (unsigned long long)hash128_one_go.low);
    } else {
        return 1;
    }

    return 0;
}
