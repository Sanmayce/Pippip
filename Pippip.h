// FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ZMMmax: the 100% FREE lookuper, last update: 2025-Aug-03, Kaze (sanmayce@sanmayce.com). [
// Note2: 'ZMMmax' variant outperforms all hashers known to me, see below. 
// Note1: This latest revision was written when Mikayla "saveafox" left this world.

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
#if defined(ZMM)

#endif
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

void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla (const char *str, size_t wrdlen, uint32_t seed, void *output) {
	__m128i chunkA;
	__m128i chunkB;
	__m128i stateMIX;
	uint64_t hashLH;
	uint64_t hashRH;
	stateMIX = _mm_set1_epi32( (uint32_t)wrdlen ^ seed );
	if (wrdlen > 8) {
		__m128i stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
		__m128i stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
		__m128i stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
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
					stateA = _mm_aesenc_si128(stateA, chunkA);
					chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateC = _mm_aesenc_si128(stateC, chunkB);
				}
			} else {
				Cycles = Cycles>>1;
				__m128i stateA2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
				__m128i stateB2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
				__m128i stateC2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
				#pragma nounroll
				for(; Cycles--; str += 32) {
					_mm_prefetch(str+512, _MM_HINT_T0);
					_mm_prefetch(str+NDhead+512, _MM_HINT_T0);
					chunkA = _mm_loadu_si128((__m128i *)(str));
					__m128i chunkA2 = _mm_loadu_si128((__m128i *)(str+16));
					stateA = _mm_aesenc_si128(stateA, chunkA);
					stateA2 = _mm_aesenc_si128(stateA2, chunkA2);
					chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
					__m128i chunkB2 = _mm_loadu_si128((__m128i *)(str+NDhead+16));
					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateC = _mm_aesenc_si128(stateC, chunkB);
					stateC2 = _mm_aesenc_si128(stateC2, chunkA2);
					stateB2 = _mm_aesenc_si128(stateB2, chunkB2);
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
		hashLH = _PADr_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3);
		hashRH = _PAD_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3);
	    chunkA = _mm_set_epi64x(hashLH, hashLH);
	    chunkB = _mm_set_epi64x(hashRH, hashRH);
	    stateMIX = _mm_aesenc_si128(stateMIX, chunkA);
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

// The next variant gives the same hash as above function, but is slower (using i7-1185G7), 24GiB/s vs 32GiB/s:
/*
Setting CPU to performance mode...
performance
Size: 2398523392
Read: 2398523392
Hasher,BB_Size,Total_Hashes,Unique_Hashes,Collisions,Time_s,Speed_GBs,SpeedRAW_GBs
MeowHash,	2,	2398523391,	65536,		2398457855,	72.979,	0.061,	0.116
MeowHash,	3,	2398523390,	16744355,		2381779035,	195.632,	0.034,	0.172
MeowHash,	4,	2398523389,	1352629000,		1045894389,	191.611,	0.047,	0.230
MeowHash,	5,	2398523388,	1625608394,		772914994,	194.317,	0.057,	0.302
MeowHash,	6,	2398523387,	1628133893,		770389494,	192.328,	0.070,	0.362
MeowHash,	7,	2398523386,	1629290910,		769232476,	195.025,	0.080,	0.405
MeowHash,	8,	2398523385,	1630412672,		768110713,	194.804,	0.092,	0.454
MeowHash,	9,	2398523384,	1631404757,		767118627,	192.512,	0.104,	0.529
MeowHash,	10,	2398523383,	1632232090,		766291293,	193.915,	0.115,	0.593
MeowHash,	11,	2398523382,	1632981722,		765541660,	196.047,	0.125,	0.660
MeowHash,	12,	2398523381,	1633666083,		764857298,	195.954,	0.137,	0.689
MeowHash,	13,	2398523380,	1634349465,		764173915,	196.194,	0.148,	0.748
MeowHash,	14,	2398523379,	1634962485,		763560894,	194.982,	0.160,	0.790
MeowHash,	15,	2398523378,	1635498823,		763024555,	193.395,	0.173,	0.889
MeowHash,	16,	2398523377,	1635993829,		762529548,	186.891,	0.191,	0.981
MeowHash,	18,	2398523375,	1636931129,		761592246,	189.587,	0.212,	1.006
MeowHash,	20,	2398523373,	1637837557,		760685816,	195.708,	0.228,	1.158
MeowHash,	22,	2398523371,	1638657246,		759866125,	195.512,	0.251,	1.243
MeowHash,	24,	2398523369,	1639470642,		759052727,	195.605,	0.274,	1.393
MeowHash,	26,	2398523367,	1640139815,		758383552,	194.471,	0.299,	1.566
MeowHash,	28,	2398523365,	1640793570,		757729795,	195.224,	0.320,	1.616
MeowHash,	30,	2398523363,	1641359072,		757164291,	198.519,	0.338,	1.824
MeowHash,	32,	2398523361,	1641838774,		756684587,	196.239,	0.364,	2.029
MeowHash,	48,	2398523345,	1644354207,		754169138,	195.975,	0.547,	2.796
MeowHash,	64,	2398523329,	1646138401,		752384928,	199.666,	0.716,	3.756
MeowHash,	80,	2398523313,	1646904081,		751619232,	202.002,	0.885,	4.626
MeowHash,	96,	2398523297,	1647449500,		751073797,	200.314,	1.071,	5.326
MeowHash,	128,	2398523265,	1648393343,		750129922,	205.561,	1.391,	6.905
MeowHash,	256,	2398523137,	1650949450,		747573687,	222.994,	2.564,	11.252
MeowHash,	512,	2398522881,	1655012437,		743510444,	490.642,	2.331,	16.776
MeowHash,	1024,	2398522369,	1661943136,		736579233,	547.066,	4.181,	22.758
MeowHash,	2048,	2398521345,	1673909229,		724612116,	626.384,	7.304,	27.904
MeowHash,	8192,	2398515201,	1694706087,		703809114,	1034.948,	17.681,	32.962
Pippip_AES_TriXZi_Mikayla,	2,	2398523391,	65535,		2398457856,	25.212,	0.177,	0.574
Pippip_AES_TriXZi_Mikayla,	3,	2398523390,	16744106,		2381779284,	45.016,	0.149,	1.113
Pippip_AES_TriXZi_Mikayla,	4,	2398523389,	1352622786,		1045900603,	47.351,	0.189,	1.406
Pippip_AES_TriXZi_Mikayla,	5,	2398523388,	1625624460,		772898928,	47.838,	0.233,	1.372
Pippip_AES_TriXZi_Mikayla,	6,	2398523387,	1628174625,		770348762,	45.814,	0.293,	1.579
Pippip_AES_TriXZi_Mikayla,	7,	2398523386,	1629312029,		769211357,	47.844,	0.327,	1.903
Pippip_AES_TriXZi_Mikayla,	8,	2398523385,	1630417890,		768105495,	45.089,	0.396,	2.131
Pippip_AES_TriXZi_Mikayla,	9,	2398523384,	1631378691,		767144693,	47.364,	0.424,	2.548
Pippip_AES_TriXZi_Mikayla,	10,	2398523383,	1632226360,		766297023,	47.543,	0.470,	2.900
Pippip_AES_TriXZi_Mikayla,	11,	2398523382,	1632981452,		765541930,	48.510,	0.507,	3.071
Pippip_AES_TriXZi_Mikayla,	12,	2398523381,	1633613141,		764910240,	46.111,	0.581,	3.122
Pippip_AES_TriXZi_Mikayla,	13,	2398523380,	1634360577,		764162803,	45.522,	0.638,	3.493
Pippip_AES_TriXZi_Mikayla,	14,	2398523379,	1634960052,		763563327,	42.568,	0.735,	5.173
Pippip_AES_TriXZi_Mikayla,	15,	2398523378,	1635490304,		763033074,	48.888,	0.685,	3.748
Pippip_AES_TriXZi_Mikayla,	16,	2398523377,	1636031584,		762491793,	47.056,	0.760,	4.780
Pippip_AES_TriXZi_Mikayla,	18,	2398523375,	1636927783,		761595592,	65.870,	0.610,	3.685
Pippip_AES_TriXZi_Mikayla,	20,	2398523373,	1637822409,		760700964,	61.926,	0.721,	3.826
Pippip_AES_TriXZi_Mikayla,	22,	2398523371,	1638640302,		759883069,	61.841,	0.795,	5.066
Pippip_AES_TriXZi_Mikayla,	24,	2398523369,	1639496048,		759027321,	62.003,	0.865,	5.228
Pippip_AES_TriXZi_Mikayla,	26,	2398523367,	1640166506,		758356861,	64.954,	0.894,	5.163
Pippip_AES_TriXZi_Mikayla,	28,	2398523365,	1640752327,		757771038,	61.143,	1.023,	6.370
Pippip_AES_TriXZi_Mikayla,	30,	2398523363,	1641343737,		757179626,	64.543,	1.038,	7.000
Pippip_AES_TriXZi_Mikayla,	32,	2398523361,	1641827945,		756695416,	64.398,	1.110,	5.821
Pippip_AES_TriXZi_Mikayla,	48,	2398523345,	1644347374,		754175971,	81.165,	1.321,	7.618
Pippip_AES_TriXZi_Mikayla,	64,	2398523329,	1646147408,		752375921,	78.795,	1.814,	9.824
Pippip_AES_TriXZi_Mikayla,	80,	2398523313,	1646878125,		751645188,	83.282,	2.146,	13.270
Pippip_AES_TriXZi_Mikayla,	96,	2398523297,	1647477381,		751045916,	80.048,	2.679,	17.521
Pippip_AES_TriXZi_Mikayla,	128,	2398523265,	1648394353,		750128912,	99.425,	2.876,	15.102
Pippip_AES_TriXZi_Mikayla,	256,	2398523137,	1650915581,		747607556,	133.876,	4.272,	25.848
Pippip_AES_TriXZi_Mikayla,	512,	2398522881,	1655018548,		743504333,	208.170,	5.494,	30.018
Pippip_AES_TriXZi_Mikayla,	1024,	2398522369,	1661965052,		736557317,	404.595,	5.654,	30.865
Pippip_AES_TriXZi_Mikayla,	2048,	2398521345,	1673883213,		724638132,	489.037,	9.355,	32.423
Pippip_AES_TriXZi_Mikayla,	8192,	2398515201,	1694739980,		703775221,	959.925,	19.063,	32.793
Pippip_AES_TriXZi_Mikayla_ZMM,	2,	2398523391,	65535,		2398457856,	25.495,	0.175,	0.800
Pippip_AES_TriXZi_Mikayla_ZMM,	3,	2398523390,	16744106,		2381779284,	46.368,	0.145,	1.075
Pippip_AES_TriXZi_Mikayla_ZMM,	4,	2398523389,	1352622786,		1045900603,	48.503,	0.184,	1.405
Pippip_AES_TriXZi_Mikayla_ZMM,	5,	2398523388,	1625624460,		772898928,	48.457,	0.230,	1.433
Pippip_AES_TriXZi_Mikayla_ZMM,	6,	2398523387,	1628174625,		770348762,	47.707,	0.281,	1.834
Pippip_AES_TriXZi_Mikayla_ZMM,	7,	2398523386,	1629312029,		769211357,	46.924,	0.333,	2.669
Pippip_AES_TriXZi_Mikayla_ZMM,	8,	2398523385,	1630417890,		768105495,	47.977,	0.372,	2.067
Pippip_AES_TriXZi_Mikayla_ZMM,	9,	2398523384,	1631378691,		767144693,	46.666,	0.431,	2.250
Pippip_AES_TriXZi_Mikayla_ZMM,	10,	2398523383,	1632226360,		766297023,	45.916,	0.486,	2.504
Pippip_AES_TriXZi_Mikayla_ZMM,	11,	2398523382,	1632981452,		765541930,	45.848,	0.536,	3.348
Pippip_AES_TriXZi_Mikayla_ZMM,	12,	2398523381,	1633613141,		764910240,	46.464,	0.577,	3.051
Pippip_AES_TriXZi_Mikayla_ZMM,	13,	2398523380,	1634360577,		764162803,	46.521,	0.624,	3.420
Pippip_AES_TriXZi_Mikayla_ZMM,	14,	2398523379,	1634960052,		763563327,	48.155,	0.649,	4.202
Pippip_AES_TriXZi_Mikayla_ZMM,	15,	2398523378,	1635490304,		763033074,	48.334,	0.693,	4.375
Pippip_AES_TriXZi_Mikayla_ZMM,	16,	2398523377,	1636031584,		762491793,	48.007,	0.744,	4.635
Pippip_AES_TriXZi_Mikayla_ZMM,	18,	2398523375,	1636927783,		761595592,	63.294,	0.635,	3.972
Pippip_AES_TriXZi_Mikayla_ZMM,	20,	2398523373,	1637822409,		760700964,	64.109,	0.697,	3.943
Pippip_AES_TriXZi_Mikayla_ZMM,	22,	2398523371,	1638640302,		759883069,	60.633,	0.811,	4.006
Pippip_AES_TriXZi_Mikayla_ZMM,	24,	2398523369,	1639496048,		759027321,	61.156,	0.877,	5.602
Pippip_AES_TriXZi_Mikayla_ZMM,	26,	2398523367,	1640166506,		758356861,	63.955,	0.908,	5.569
Pippip_AES_TriXZi_Mikayla_ZMM,	28,	2398523365,	1640752327,		757771038,	63.484,	0.985,	5.799
Pippip_AES_TriXZi_Mikayla_ZMM,	30,	2398523363,	1641343737,		757179626,	64.886,	1.033,	6.062
Pippip_AES_TriXZi_Mikayla_ZMM,	32,	2398523361,	1641827945,		756695416,	62.121,	1.151,	7.382
Pippip_AES_TriXZi_Mikayla_ZMM,	48,	2398523345,	1644347374,		754175971,	81.317,	1.319,	7.224
Pippip_AES_TriXZi_Mikayla_ZMM,	64,	2398523329,	1646147408,		752375921,	81.563,	1.753,	10.770
Pippip_AES_TriXZi_Mikayla_ZMM,	80,	2398523313,	1646878125,		751645188,	82.762,	2.159,	13.300
Pippip_AES_TriXZi_Mikayla_ZMM,	96,	2398523297,	1647477381,		751045916,	82.018,	2.615,	16.006
Pippip_AES_TriXZi_Mikayla_ZMM,	128,	2398523265,	1648394353,		750128912,	94.987,	3.010,	14.539
Pippip_AES_TriXZi_Mikayla_ZMM,	256,	2398523137,	1650915581,		747607556,	125.087,	4.572,	17.338
Pippip_AES_TriXZi_Mikayla_ZMM,	512,	2398522881,	1655018548,		743504333,	222.675,	5.136,	19.677
Pippip_AES_TriXZi_Mikayla_ZMM,	1024,	2398522369,	1661965052,		736557317,	412.953,	5.539,	21.949
Pippip_AES_TriXZi_Mikayla_ZMM,	2048,	2398521345,	1673883213,		724638132,	523.867,	8.733,	23.044
Pippip_AES_TriXZi_Mikayla_ZMM,	8192,	2398515201,	1694739980,		703775221,	1142.170,	16.021,	24.386
*/
#if defined(ZMM)
void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ZMM (const char *str, size_t wrdlen, uint32_t seed, void *output) {
	__m128i chunkA;
	__m128i chunkB;
	__m128i stateMIX;
	uint64_t hashLH;
	uint64_t hashRH;
	stateMIX = _mm_set1_epi32( (uint32_t)wrdlen ^ seed );
	if (wrdlen > 8) {
		__m128i stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
		__m128i stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
		__m128i stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
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
					stateA = _mm_aesenc_si128(stateA, chunkA);
					chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateC = _mm_aesenc_si128(stateC, chunkB);
				}
			} else {
				if ( (Cycles & 3) == 0 ) {
					// New codepath ZMM (-O3 -mavx512f -maes -mbmi2 -march=tigerlake -DZMM) [
					Cycles = Cycles>>2;
					__m128i stateA2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateB2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateC2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					#pragma nounroll
					for(; Cycles--; str += 64) {
						_mm_prefetch(str+2048, _MM_HINT_T0);
						_mm_prefetch(str+NDhead+2048, _MM_HINT_T0);
				        __m512i chunk_zmm = _mm512_loadu_si512((__m512i*)str);
				        __m512i chunk_zmm_offset = _mm512_loadu_si512((__m512i*)(str+NDhead));
				        __m128i chunkA = _mm512_extracti64x2_epi64(chunk_zmm, 0);
				        __m128i chunkA2 = _mm512_extracti64x2_epi64(chunk_zmm, 1);
				        __m128i chunkB = _mm512_extracti64x2_epi64(chunk_zmm_offset, 0);
				        __m128i chunkB2 = _mm512_extracti64x2_epi64(chunk_zmm_offset, 1);
				        stateA = _mm_aesenc_si128(stateA, chunkA);
				        stateA2 = _mm_aesenc_si128(stateA2, chunkA2);
				        stateB = _mm_aesenc_si128(stateB, chunkB);
				        stateB2 = _mm_aesenc_si128(stateB2, chunkB2);
				        stateC = _mm_aesenc_si128(stateC, chunkA);
				        stateC = _mm_aesenc_si128(stateC, chunkB);
				        stateC2 = _mm_aesenc_si128(stateC2, chunkA2);
				        stateC2 = _mm_aesenc_si128(stateC2, chunkB2);
				        __m128i chunkA3 = _mm512_extracti64x2_epi64(chunk_zmm, 2);
				        __m128i chunkA4 = _mm512_extracti64x2_epi64(chunk_zmm, 3);
				        __m128i chunkB3 = _mm512_extracti64x2_epi64(chunk_zmm_offset, 2);
				        __m128i chunkB4 = _mm512_extracti64x2_epi64(chunk_zmm_offset, 3);
				        stateA = _mm_aesenc_si128(stateA, chunkA3);
				        stateA2 = _mm_aesenc_si128(stateA2, chunkA4);
				        stateB = _mm_aesenc_si128(stateB, chunkB3);
				        stateB2 = _mm_aesenc_si128(stateB2, chunkB4);
				        stateC = _mm_aesenc_si128(stateC, chunkA3);
				        stateC = _mm_aesenc_si128(stateC, chunkB3);
				        stateC2 = _mm_aesenc_si128(stateC2, chunkA4);
				        stateC2 = _mm_aesenc_si128(stateC2, chunkB4);
				    }
					stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateC2);
					// New codepath ZMM (-O3 -mavx512f -maes -mbmi2 -march=tigerlake -DZMM) ]
				} else {
					Cycles = Cycles>>1;
					__m128i stateA2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateB2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateC2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					#pragma nounroll
					for(; Cycles--; str += 32) {
						_mm_prefetch(str+512, _MM_HINT_T0);
						_mm_prefetch(str+NDhead+512, _MM_HINT_T0);
						chunkA = _mm_loadu_si128((__m128i *)(str));
						__m128i chunkA2 = _mm_loadu_si128((__m128i *)(str+16));
						stateA = _mm_aesenc_si128(stateA, chunkA);
						stateA2 = _mm_aesenc_si128(stateA2, chunkA2);
						chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
						__m128i chunkB2 = _mm_loadu_si128((__m128i *)(str+NDhead+16));
						stateC = _mm_aesenc_si128(stateC, chunkA);
						stateB = _mm_aesenc_si128(stateB, chunkB);
						stateC = _mm_aesenc_si128(stateC, chunkB);
						stateC2 = _mm_aesenc_si128(stateC2, chunkA2);
						stateB2 = _mm_aesenc_si128(stateB2, chunkB2);
						stateC2 = _mm_aesenc_si128(stateC2, chunkB2);
					}
					stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateC2);
				}
			}
		} else { // 9..16
			NDhead = wrdlen - (1<<3);
			hashLH = (*(uint64_t *)(str));
			hashRH = (*(uint64_t *)(str+NDhead));
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
		hashLH = _PADr_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3);
		hashRH = _PAD_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3);
	    chunkA = _mm_set_epi64x(hashLH, hashLH);
	    chunkB = _mm_set_epi64x(hashRH, hashRH);
	    stateMIX = _mm_aesenc_si128(stateMIX, chunkA);
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
#endif

// The ZMMmax dominates! In contrast to above variant it ourperforms xxh3 by 64/41=1.56x 
/*
Setting CPU to performance mode...
performance
Size: 2398523392
Read: 2398523392
Hasher,BB_Size,Total_Hashes,Unique_Hashes,Collisions,Time_s,Speed_GBs,SpeedRAW_GBs
Pippip_AES_TriXZi_Mikayla_ZMMmax,	2,	2398523391,	65535,		2398457856,	20.022,	0.223,	0.497
Pippip_AES_TriXZi_Mikayla_ZMMmax,	3,	2398523390,	16744106,		2381779284,	57.520,	0.117,	0.694
Pippip_AES_TriXZi_Mikayla_ZMMmax,	4,	2398523389,	1352622786,		1045900603,	87.383,	0.102,	1.945
Pippip_AES_TriXZi_Mikayla_ZMMmax,	5,	2398523388,	1625624460,		772898928,	53.191,	0.210,	1.149
Pippip_AES_TriXZi_Mikayla_ZMMmax,	6,	2398523387,	1628174625,		770348762,	79.344,	0.169,	1.440
Pippip_AES_TriXZi_Mikayla_ZMMmax,	7,	2398523386,	1629312029,		769211357,	49.893,	0.313,	1.767
Pippip_AES_TriXZi_Mikayla_ZMMmax,	8,	2398523385,	1630417890,		768105495,	71.040,	0.252,	1.906
Pippip_AES_TriXZi_Mikayla_ZMMmax,	9,	2398523384,	1631378691,		767144693,	57.653,	0.349,	2.265
Pippip_AES_TriXZi_Mikayla_ZMMmax,	10,	2398523383,	1632226360,		766297023,	61.972,	0.360,	2.463
Pippip_AES_TriXZi_Mikayla_ZMMmax,	11,	2398523382,	1632981452,		765541930,	52.076,	0.472,	2.627
Pippip_AES_TriXZi_Mikayla_ZMMmax,	12,	2398523381,	1633613141,		764910240,	89.222,	0.300,	6.180
Pippip_AES_TriXZi_Mikayla_ZMMmax,	13,	2398523380,	1634360577,		764162803,	52.295,	0.555,	3.256
Pippip_AES_TriXZi_Mikayla_ZMMmax,	14,	2398523379,	1634960052,		763563327,	69.479,	0.450,	3.366
Pippip_AES_TriXZi_Mikayla_ZMMmax,	15,	2398523378,	1635490304,		763033074,	62.438,	0.537,	3.661
Pippip_AES_TriXZi_Mikayla_ZMMmax,	16,	2398523377,	1636031584,		762491793,	57.822,	0.618,	3.856
Pippip_AES_TriXZi_Mikayla_ZMMmax,	18,	2398523375,	1636927783,		761595592,	84.300,	0.477,	3.440
Pippip_AES_TriXZi_Mikayla_ZMMmax,	20,	2398523373,	1637822409,		760700964,	86.147,	0.519,	3.198
Pippip_AES_TriXZi_Mikayla_ZMMmax,	22,	2398523371,	1638640302,		759883069,	73.465,	0.669,	3.584
Pippip_AES_TriXZi_Mikayla_ZMMmax,	24,	2398523369,	1639496048,		759027321,	82.662,	0.649,	3.768
Pippip_AES_TriXZi_Mikayla_ZMMmax,	26,	2398523367,	1640166506,		758356861,	88.427,	0.657,	4.082
Pippip_AES_TriXZi_Mikayla_ZMMmax,	28,	2398523365,	1640752327,		757771038,	73.346,	0.853,	4.422
Pippip_AES_TriXZi_Mikayla_ZMMmax,	30,	2398523363,	1641343737,		757179626,	90.118,	0.744,	7.063
Pippip_AES_TriXZi_Mikayla_ZMMmax,	32,	2398523361,	1641827945,		756695416,	68.896,	1.038,	4.837
Pippip_AES_TriXZi_Mikayla_ZMMmax,	48,	2398523345,	1644347374,		754175971,	111.811,	0.959,	8.237
Pippip_AES_TriXZi_Mikayla_ZMMmax,	64,	2398523329,	1646147408,		752375921,	122.841,	1.164,	16.502
Pippip_AES_TriXZi_Mikayla_ZMMmax,	80,	2398523313,	1646878125,		751645188,	107.480,	1.663,	9.626
Pippip_AES_TriXZi_Mikayla_ZMMmax,	96,	2398523297,	1647477381,		751045916,	103.118,	2.080,	11.764
Pippip_AES_TriXZi_Mikayla_ZMMmax,	128,	2398523265,	1648406970,		750116295,	135.750,	2.106,	14.195
Pippip_AES_TriXZi_Mikayla_ZMMmax,	256,	2398523137,	1650983359,		747539778,	138.650,	4.124,	18.868
Pippip_AES_TriXZi_Mikayla_ZMMmax,	512,	2398522881,	1655034855,		743488026,	195.449,	5.852,	39.461
Pippip_AES_TriXZi_Mikayla_ZMMmax,	1024,	2398522369,	1661953271,		736569098,	258.192,	8.859,	52.553
Pippip_AES_TriXZi_Mikayla_ZMMmax,	2048,	2398521345,	1673890300,		724631045,	323.753,	14.131,	61.253
Pippip_AES_TriXZi_Mikayla_ZMMmax,	8192,	2398515201,	1694717306,		703797895,	745.589,	24.543,	64.253
*/
// Let us compare the collisions for Fedora testdataset:
/*
Pippip_AES_TriXZi_Mikayla,	128,	2398523265,	1648394353,		750128912,	99.425,	2.876,	15.102
Pippip_AES_TriXZi_Mikayla,	256,	2398523137,	1650915581,		747607556,	133.876,	4.272,	25.848
Pippip_AES_TriXZi_Mikayla,	512,	2398522881,	1655018548,		743504333,	208.170,	5.494,	30.018
Pippip_AES_TriXZi_Mikayla,	1024,	2398522369,	1661965052,		736557317,	404.595,	5.654,	30.865
Pippip_AES_TriXZi_Mikayla,	2048,	2398521345,	1673883213,		724638132,	489.037,	9.355,	32.423
Pippip_AES_TriXZi_Mikayla,	8192,	2398515201,	1694739980,		703775221,	959.925,	19.063,	32.793

Pippip_AES_TriXZi_Mikayla_ZMMmax,	128,	2398523265,	1648406970,		750116295,	135.750,	2.106,	14.195 ! 750116295-750128912= -12,617 i.e. better than Pippip_AES_TriXZi_Mikayla
Pippip_AES_TriXZi_Mikayla_ZMMmax,	256,	2398523137,	1650983359,		747539778,	138.650,	4.124,	18.868 ! 747539778-747607556= -67,778 i.e. better than Pippip_AES_TriXZi_Mikayla
Pippip_AES_TriXZi_Mikayla_ZMMmax,	512,	2398522881,	1655034855,		743488026,	195.449,	5.852,	39.461 ! 743488026-743504333= -16,307 i.e. better than Pippip_AES_TriXZi_Mikayla
Pippip_AES_TriXZi_Mikayla_ZMMmax,	1024,	2398522369,	1661953271,		736569098,	258.192,	8.859,	52.553 ! 736569098-736557317= 11,781
Pippip_AES_TriXZi_Mikayla_ZMMmax,	2048,	2398521345,	1673890300,		724631045,	323.753,	14.131,	61.253 ! 724631045-724638132= -7,087 i.e. better than Pippip_AES_TriXZi_Mikayla
Pippip_AES_TriXZi_Mikayla_ZMMmax,	8192,	2398515201,	1694717306,		703797895,	745.589,	24.543,	64.253 ! 703797895-703775221= 22,674

XXH3_64bits 0.8.3,	128,	2398523265,	1648387301,		750135964,	210.107,	1.361,	8.906 ! 750135964-750116295= 19,669 i.e. worse than Pippip_AES_TriXZi_Mikayla_ZMMmax
XXH3_64bits 0.8.3,	256,	2398523137,	1650961642,		747561495,	176.009,	3.249,	12.057 ! 747561495-747539778= 21,717 i.e. worse than Pippip_AES_TriXZi_Mikayla_ZMMmax
XXH3_64bits 0.8.3,	512,	2398522881,	1655001212,		743521669,	248.454,	4.603,	18.357 ! 743521669-743488026= 33,643 i.e. worse than Pippip_AES_TriXZi_Mikayla_ZMMmax
XXH3_64bits 0.8.3,	1024,	2398522369,	1661947538,		736574831,	287.056,	7.969,	25.772 ! 736574831-736569098= 5,733 i.e. worse than Pippip_AES_TriXZi_Mikayla_ZMMmax
XXH3_64bits 0.8.3,	2048,	2398521345,	1673886241,		724635104,	642.147,	7.124,	33.020 ! 724635104-724631045= 4,059 i.e. worse than Pippip_AES_TriXZi_Mikayla_ZMMmax
XXH3_64bits 0.8.3,	8192,	2398515201,	1694695692,		703819509,	969.465,	18.876,	40.195 ! 703819509-703797895= 21,614 i.e. worse than Pippip_AES_TriXZi_Mikayla_ZMMmax
*/

#if defined(ZMM)
void FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ZMMmax (const char *str, size_t wrdlen, uint32_t seed, void *output) {
	__m128i chunkA;
	__m128i chunkB;
	__m128i stateMIX;
	uint64_t hashLH;
	uint64_t hashRH;
	stateMIX = _mm_set1_epi32( (uint32_t)wrdlen ^ seed );
	if (wrdlen > 8) {
		__m128i stateA = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
		__m128i stateB = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
		__m128i stateC = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
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
					stateA = _mm_aesenc_si128(stateA, chunkA);
					chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
					stateC = _mm_aesenc_si128(stateC, chunkA);
					stateB = _mm_aesenc_si128(stateB, chunkB);
					stateC = _mm_aesenc_si128(stateC, chunkB);
				}
			} else {
				if ( (Cycles & 3) == 0 ) {
					// New codepath ZMM (-O3 -mavx512f -mvaes -mbmi2 -march=tigerlake -DZMM) [
					Cycles = Cycles>>2;
					__m128i stateA2;// = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateB2;// = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateC2;// = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
			        __m512i StateA_zmm = _mm512_set_epi64( 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL );
			        __m512i StateB_zmm = _mm512_set_epi64( 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL );
			        __m512i StateC_zmm = _mm512_set_epi64( 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL, 0x6c62272e07bb0142ULL, 0x9e3779b97f4a7c15ULL );

					#pragma nounroll
					for(; Cycles--; str += 64) {
				        __m512i chunk_zmm = _mm512_loadu_si512((__m512i*)str);
				        __m512i chunk_zmm_offset = _mm512_loadu_si512((__m512i*)(str+NDhead));
						_mm_prefetch(str+2048, _MM_HINT_T0);
						_mm_prefetch(str+NDhead+2048, _MM_HINT_T0);
				        StateA_zmm = _mm512_aesenc_epi128(StateA_zmm, chunk_zmm);
				        StateB_zmm = _mm512_aesenc_epi128(StateB_zmm, chunk_zmm_offset);
				        StateC_zmm = _mm512_aesenc_epi128(StateC_zmm, chunk_zmm);
				        StateC_zmm = _mm512_aesenc_epi128(StateC_zmm, chunk_zmm_offset);
				    }

			        stateA2 = _mm512_extracti64x2_epi64(StateA_zmm, 0);
			        stateB2 = _mm512_extracti64x2_epi64(StateB_zmm, 0);
			        stateC2 = _mm512_extracti64x2_epi64(StateC_zmm, 0);
					stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateC2);

			        stateA2 = _mm512_extracti64x2_epi64(StateA_zmm, 1);
			        stateB2 = _mm512_extracti64x2_epi64(StateB_zmm, 1);
			        stateC2 = _mm512_extracti64x2_epi64(StateC_zmm, 1);
					stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateC2);

			        stateA2 = _mm512_extracti64x2_epi64(StateA_zmm, 2);
			        stateB2 = _mm512_extracti64x2_epi64(StateB_zmm, 2);
			        stateC2 = _mm512_extracti64x2_epi64(StateC_zmm, 2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateC2);

			        stateA2 = _mm512_extracti64x2_epi64(StateA_zmm, 3);
			        stateB2 = _mm512_extracti64x2_epi64(StateB_zmm, 3);
			        stateC2 = _mm512_extracti64x2_epi64(StateC_zmm, 3);

					stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateC2);

					// New codepath ZMM (-O3 -mavx512f -maes -mbmi2 -march=tigerlake -DZMM) ]
				} else {
					Cycles = Cycles>>1;
					__m128i stateA2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateB2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					__m128i stateC2 = _mm_set_epi64x(0x6c62272e07bb0142, 0x9e3779b97f4a7c15);
					#pragma nounroll
					for(; Cycles--; str += 32) {
						_mm_prefetch(str+512, _MM_HINT_T0);
						_mm_prefetch(str+NDhead+512, _MM_HINT_T0);
						chunkA = _mm_loadu_si128((__m128i *)(str));
						__m128i chunkA2 = _mm_loadu_si128((__m128i *)(str+16));
						stateA = _mm_aesenc_si128(stateA, chunkA);
						stateA2 = _mm_aesenc_si128(stateA2, chunkA2);
						chunkB = _mm_loadu_si128((__m128i *)(str+NDhead));
						__m128i chunkB2 = _mm_loadu_si128((__m128i *)(str+NDhead+16));
						stateC = _mm_aesenc_si128(stateC, chunkA);
						stateB = _mm_aesenc_si128(stateB, chunkB);
						stateC = _mm_aesenc_si128(stateC, chunkB);
						stateC2 = _mm_aesenc_si128(stateC2, chunkA2);
						stateB2 = _mm_aesenc_si128(stateB2, chunkB2);
						stateC2 = _mm_aesenc_si128(stateC2, chunkB2);
					}
					stateMIX = _mm_aesenc_si128(stateMIX, stateA2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateB2);
					stateMIX = _mm_aesenc_si128(stateMIX, stateC2);
				}
			}
		} else { // 9..16
			NDhead = wrdlen - (1<<3);
			hashLH = (*(uint64_t *)(str));
			hashRH = (*(uint64_t *)(str+NDhead));
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
		hashLH = _PADr_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3);
		hashRH = _PAD_KAZE(*(uint64_t *)(str+0), (8-wrdlen)<<3);
	    chunkA = _mm_set_epi64x(hashLH, hashLH);
	    chunkB = _mm_set_epi64x(hashRH, hashRH);
	    stateMIX = _mm_aesenc_si128(stateMIX, chunkA);
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
#endif

// The above monster GCC: (GNU) 15.1.1 assembler:
// gcc -DZMM -static -O3 -march=tigerlake hashBBs_r9.c xxhash.c -o hashBBs_r9_GCC_tigerlakeZMM.elf
// gcc -DZMM -O3 -march=tigerlake hashBBs_r9.c -o hashBBs_r9_GCC_tigerlakeZMM.elf.asm -S
/*
FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ZMMmax:
.LFB7514:
	.cfi_startproc
	xorl	%esi, %edx
	movq	%rdi, %rax
	vpbroadcastd	%edx, %xmm0
	vmovdqa	%xmm0, %xmm1
	cmpq	$8, %rsi
	jbe	.L142
	cmpq	$16, %rsi
	ja	.L154
	vmovdqa	.LC8(%rip), %xmm3
	vpbroadcastq	(%rdi), %xmm4
	vpbroadcastq	-8(%rdi,%rsi), %xmm2
	vaesenc	%xmm4, %xmm3, %xmm4
	vaesenc	%xmm2, %xmm3, %xmm3
	vaesenc	%xmm2, %xmm4, %xmm2
.L146:
	vaesenc	%xmm4, %xmm1, %xmm1
	vaesenc	%xmm3, %xmm1, %xmm1
	vaesenc	%xmm2, %xmm1, %xmm0
	jmp	.L150
	.p2align 4,,10
	.p2align 3
.L142:
	movl	$8, %edx
	movq	(%rdi), %rax
	subl	%esi, %edx
	sall	$3, %edx
	shlx	%rdx, %rax, %rax
	shrx	%rdx, %rax, %rdx
	vpbroadcastq	%rdx, %xmm1
	vaesenc	%xmm1, %xmm0, %xmm0
	vpbroadcastq	%rax, %xmm1
	vaesenc	%xmm1, %xmm0, %xmm0
.L150:
	vmovq	%xmm0, %rdx
	vpextrq	$1, %xmm0, %rax
	mulx	%rax, %rax, %r10
	xorq	%r10, %rax
	xorl	%eax, %esi
	movl	%esi, (%rcx)
	ret
	.p2align 4,,10
	.p2align 3
.L154:
	leaq	-1(%rsi), %rdi
	movq	%rsi, %rdx
	shrq	$5, %rdi
	incq	%rdi
	movq	%rdi, %r8
	salq	$4, %r8
	subq	%r8, %rdx
	testb	$1, %dil
	jne	.L155
	testb	$3, %dil
	jne	.L147
	vmovdqa64	.LC9(%rip), %zmm2
	shrq	$2, %rdi
	addq	$2048, %rax
	salq	$6, %rdi
	addq	%rax, %rdi
	vmovdqa64	%zmm2, %zmm7
	vmovdqa64	%zmm2, %zmm6
	.p2align 4,,10
	.p2align 3
.L148:
	vmovdqu64	-2048(%rax), %zmm3
	vmovdqu64	-2048(%rax,%rdx), %zmm1
	prefetcht0	(%rax)
	prefetcht0	(%rdx,%rax)
	addq	$64, %rax
	vaesenc	%zmm3, %zmm2, %zmm2
	vaesenc	%zmm1, %zmm7, %zmm4
	vaesenc	%zmm3, %zmm6, %zmm5
	vaesenc	%zmm1, %zmm2, %zmm1
	vmovdqa64	%zmm5, %zmm6
	vmovdqa64	%zmm4, %zmm7
	vmovdqa64	%zmm1, %zmm2
	cmpq	%rdi, %rax
	jne	.L148
	vaesenc	%xmm5, %xmm0, %xmm0
	vextracti64x2	$1, %zmm5, %xmm6
	vextracti64x2	$1, %zmm4, %xmm3
	vaesenc	%xmm4, %xmm0, %xmm0
	vextracti64x2	$1, %zmm1, %xmm2
	vaesenc	%xmm1, %xmm0, %xmm0
	vaesenc	%xmm6, %xmm0, %xmm0
	vextracti64x2	$2, %zmm5, %xmm6
	vextracti64x2	$3, %zmm5, %xmm5
	vaesenc	%xmm3, %xmm0, %xmm0
	vextracti64x2	$2, %zmm4, %xmm3
	vextracti64x2	$3, %zmm4, %xmm4
	vaesenc	%xmm2, %xmm0, %xmm0
	vextracti64x2	$2, %zmm1, %xmm2
	vextracti64x2	$3, %zmm1, %xmm1
	vaesenc	%xmm6, %xmm0, %xmm0
	vaesenc	%xmm3, %xmm0, %xmm0
	vaesenc	%xmm2, %xmm0, %xmm0
	vmovdqa	.LC8(%rip), %xmm2
	vaesenc	%xmm5, %xmm0, %xmm0
	vaesenc	%xmm4, %xmm0, %xmm0
	vmovdqa	%xmm2, %xmm3
	vmovdqa	%xmm2, %xmm4
	vaesenc	%xmm1, %xmm0, %xmm1
	vzeroupper
	jmp	.L146
	.p2align 4,,10
	.p2align 3
.L155:
	vmovdqa	.LC8(%rip), %xmm2
	leaq	(%rax,%r8), %rdi
	vmovdqa	%xmm2, %xmm3
	vmovdqa	%xmm2, %xmm4
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L145:
	vmovdqu	(%rax), %xmm5
	vmovdqu	(%rax,%rdx), %xmm0
	addq	$16, %rax
	vaesenc	%xmm5, %xmm2, %xmm2
	vaesenc	%xmm5, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm3, %xmm3
	vaesenc	%xmm0, %xmm2, %xmm2
	cmpq	%rdi, %rax
	jne	.L145
	jmp	.L146
	.p2align 4,,10
	.p2align 3
.L147:
	vmovdqa	.LC8(%rip), %xmm1
	shrq	%rdi
	addq	$512, %rax
	salq	$5, %rdi
	addq	%rax, %rdx
	vmovdqa	%xmm1, %xmm9
	vmovdqa	%xmm1, %xmm10
	vmovdqa	%xmm1, %xmm2
	addq	%rax, %rdi
	vmovdqa	%xmm1, %xmm3
	vmovdqa	%xmm1, %xmm4
	.p2align 4,,10
	.p2align 3
.L149:
	vmovdqu	-512(%rax), %xmm8
	vmovdqu	-496(%rax), %xmm6
	prefetcht0	(%rax)
	addq	$32, %rax
	prefetcht0	(%rdx)
	vmovdqu	-512(%rdx), %xmm7
	vmovdqu	-496(%rdx), %xmm5
	addq	$32, %rdx
	vaesenc	%xmm8, %xmm2, %xmm2
	vaesenc	%xmm6, %xmm1, %xmm1
	vaesenc	%xmm8, %xmm4, %xmm4
	vaesenc	%xmm6, %xmm10, %xmm10
	vaesenc	%xmm7, %xmm3, %xmm3
	vaesenc	%xmm7, %xmm2, %xmm2
	vaesenc	%xmm5, %xmm9, %xmm9
	vaesenc	%xmm5, %xmm1, %xmm1
	cmpq	%rax, %rdi
	jne	.L149
	vaesenc	%xmm10, %xmm0, %xmm0
	vaesenc	%xmm9, %xmm0, %xmm0
	vaesenc	%xmm1, %xmm0, %xmm1
	jmp	.L146
	.cfi_endproc

	.ident	"GCC: (GNU) 15.1.1 20250521 (Red Hat 15.1.1-2)"
*/

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

// https://godbolt.org/
// x86-64 clang 20.1.0
// -O3 -maes -mbmi2
/*
...
*/

// https://godbolt.org/
// x86-64 gcc 14.2
// -O3 -maes -mbmi2
/*
...
*/

