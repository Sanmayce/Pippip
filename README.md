# Pippip
FASTEST AES-based hash function for hashtable lookups

<img width="810" height="1158" alt="fastest" src="https://github.com/user-attachments/assets/f52af8d8-449e-4a2b-9d19-7ff3260bfa9a" />
    

    
The 'FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ZMMmax' monster GCC: (GNU) 15.1.1 assembler:  
gcc -DZMM -static -O3 -march=tigerlake hashBBs_r9.c xxhash.c -o hashBBs_r9_GCC_tigerlakeZMM.elf  
gcc -DZMM -O3 -march=tigerlake hashBBs_r9.c -o hashBBs_r9_GCC_tigerlakeZMM.elf.asm -S  
    
```
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
```
    
The FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ZMMmax dominates! It outperforms xxh3 by 64/41=1.56x 
    
```
Setting CPU to performance mode...
performance
Size: 2398523392
Read: 2398523392
Hasher,BB_Size,Total_Hashes,Unique_Hashes,Collisions,Time_s,Speed_GBs,SpeedRAW_GBs

// Let us compare the collisions for Fedora testdataset:

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
```
    
With the included 'hashBBs_ver8_Fedora.tar.gz' benchmark (being both synthetic and non-synthetic) following 3 charts were created, bolder lines represent RAW hashing i.e. without lookuping:

Intel 3rd gen CPU:
<img width="1566" height="1858" alt="i7-IvyBridge" src="https://github.com/user-attachments/assets/c043b392-1c8a-4afb-b009-f5f271cb188c" />

Intel 7th gen CPU:
<img width="1555" height="1748" alt="i3-KabyLake" src="https://github.com/user-attachments/assets/f032299d-5ad2-4412-8093-8ef28550b365" />

Intel 11th gen CPU:
<img width="1522" height="1560" alt="i7-Tigerlake" src="https://github.com/user-attachments/assets/28f35a5c-843f-405b-bfae-3c3ab06788e9" />


Enfun!
