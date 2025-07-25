# Pippip
FASTEST AES-based hash function for hashtable lookups

<img width="810" height="1158" alt="fastest" src="https://github.com/user-attachments/assets/f52af8d8-449e-4a2b-9d19-7ff3260bfa9a" />

Note1: Compiler used: GCC 14.2.1 (-O3 -mavx2 -maes -mbmi2)
Note2: The generated GCC assembler for Pippip:
```
FNV1A_Pippip_Yurii_OOO_128bit_AES_TriXZi_Mikayla:
.LFB6794:
	.cfi_startproc
	xorl	%esi, %edx
	movq	%rdi, %rax
	vmovd	%edx, %xmm6
	vpbroadcastd	%xmm6, %xmm0
	vmovdqa	%xmm0, %xmm1
	cmpq	$8, %rsi
	jbe	.L100
	cmpq	$16, %rsi
	ja	.L109
	vmovdqa	.LC8(%rip), %xmm3
	vmovddup	(%rdi), %xmm4
	vmovddup	-8(%rdi,%rsi), %xmm2
	vaesenc	%xmm4, %xmm3, %xmm4
	vaesenc	%xmm2, %xmm3, %xmm3
	vaesenc	%xmm2, %xmm4, %xmm2
.L104:
	vaesenc	%xmm4, %xmm1, %xmm1
	vaesenc	%xmm3, %xmm1, %xmm1
	vaesenc	%xmm2, %xmm1, %xmm0
	jmp	.L106
	.p2align 4,,10
	.p2align 3
.L100:
	movl	$8, %edx
	movq	(%rdi), %rax
	subl	%esi, %edx
	sall	$3, %edx
	shlx	%rdx, %rax, %rax
	shrx	%rdx, %rax, %rdx
	vmovq	%rdx, %xmm7
	vmovq	%rax, %xmm3
	vpunpcklqdq	%xmm7, %xmm7, %xmm1
	vaesenc	%xmm1, %xmm0, %xmm0
	vpunpcklqdq	%xmm3, %xmm3, %xmm1
	vaesenc	%xmm1, %xmm0, %xmm0
.L106:
	vmovq	%xmm0, %rdx
	vpextrq	$1, %xmm0, %rax
	mulx	%rax, %rax, %rdx
	xorq	%rdx, %rax
	xorl	%eax, %esi
	movl	%esi, (%rcx)
	ret
	.p2align 4,,10
	.p2align 3
.L109:
	leaq	-1(%rsi), %rdi
	movq	%rsi, %r8
	shrq	$5, %rdi
	addq	$1, %rdi
	movq	%rdi, %rdx
	salq	$4, %rdx
	subq	%rdx, %r8
	testb	$1, %dil
	je	.L102
	vmovdqa	.LC8(%rip), %xmm2
	addq	%rax, %rdx
	vmovdqa	%xmm2, %xmm3
	vmovdqa	%xmm2, %xmm4
	.p2align 6
	.p2align 4
	.p2align 3
.L103:
	vmovdqu	(%rax), %xmm0
	vmovdqu	(%rax,%r8), %xmm5
	addq	$16, %rax
	vaesenc	%xmm0, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm2, %xmm0
	vaesenc	%xmm5, %xmm3, %xmm3
	vaesenc	%xmm5, %xmm0, %xmm2
	cmpq	%rdx, %rax
	jne	.L103
	jmp	.L104
	.p2align 4,,10
	.p2align 3
.L102:
	vmovdqa	.LC8(%rip), %xmm1
	shrq	%rdi
	leaq	512(%rax), %rdx
	leaq	512(%rax,%r8), %rax
	salq	$5, %rdi
	vmovdqa	%xmm1, %xmm9
	vmovdqa	%xmm1, %xmm10
	vmovdqa	%xmm1, %xmm2
	addq	%rdx, %rdi
	vmovdqa	%xmm1, %xmm3
	vmovdqa	%xmm1, %xmm4
	.p2align 4
	.p2align 3
.L105:
	vmovdqu	-512(%rdx), %xmm5
	prefetcht0	(%rdx)
	addq	$32, %rdx
	vmovdqu	-528(%rdx), %xmm7
	vmovdqu	-512(%rax), %xmm8
	vmovdqu	-496(%rax), %xmm6
	prefetcht0	(%rax)
	addq	$32, %rax
	vaesenc	%xmm5, %xmm4, %xmm4
	vaesenc	%xmm7, %xmm1, %xmm1
	vaesenc	%xmm5, %xmm2, %xmm5
	vaesenc	%xmm7, %xmm10, %xmm10
	vaesenc	%xmm8, %xmm3, %xmm3
	vaesenc	%xmm8, %xmm5, %xmm2
	vaesenc	%xmm6, %xmm9, %xmm9
	vaesenc	%xmm6, %xmm1, %xmm1
	cmpq	%rdi, %rdx
	jne	.L105
	vaesenc	%xmm10, %xmm0, %xmm0
	vaesenc	%xmm9, %xmm0, %xmm0
	vaesenc	%xmm1, %xmm0, %xmm1
	jmp	.L104
	.cfi_endproc
```

Enfun!
