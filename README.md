# Pippip
FASTEST AES-based hash function for hashtable lookups

<img width="810" height="1158" alt="fastest" src="https://github.com/user-attachments/assets/f52af8d8-449e-4a2b-9d19-7ff3260bfa9a" />
    

    
// The 'FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla_ZMMmax' monster GCC: (GNU) 15.1.1 assembler:
// gcc -DZMM -static -O3 -march=tigerlake hashBBs_r9.c xxhash.c -o hashBBs_r9_GCC_tigerlakeZMM.elf
// gcc -DZMM -O3 -march=tigerlake hashBBs_r9.c -o hashBBs_r9_GCC_tigerlakeZMM.elf.asm -S
    
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

    
With the included 'hashBBs_ver8_Fedora.tar.gz' benchmark (being both synthetic and non-synthetic) following 3 charts were created, bolder lines represent RAW hashing i.e. without lookuping:

Intel 3rd gen CPU:
<img width="1566" height="1858" alt="i7-IvyBridge" src="https://github.com/user-attachments/assets/c043b392-1c8a-4afb-b009-f5f271cb188c" />

Intel 7th gen CPU:
<img width="1555" height="1748" alt="i3-KabyLake" src="https://github.com/user-attachments/assets/f032299d-5ad2-4412-8093-8ef28550b365" />

Intel 11th gen CPU:
<img width="1522" height="1560" alt="i7-Tigerlake" src="https://github.com/user-attachments/assets/28f35a5c-843f-405b-bfae-3c3ab06788e9" />


Enfun!
