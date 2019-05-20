




















	.file "ecc-256-redc.asm"


 













.globl nettle_ecc_256_redc
.type nettle_ecc_256_redc,%function
nettle_ecc_256_redc:
	
    
  
  
	
	push	%rbx
	push	%rbp
	push	%r12

	mov	(%rsi), %rdi
	
	mov	%rdi, %rbx
	mov	%rdi, %rbp
	shl	$32, %rbx
	shr	$32, %rbp
	xor	%r11,%r11
	xor	%r12,%r12
	sub	%rbx, %r11
	sbb	%rbp, %r12
	sbb	%rdi, %rbx
	sbb	$0, %rbp

	mov	8(%rsi), %rcx
	mov	16(%rsi), %rax
	mov	24(%rsi), %rdx
	sub	%r11, %rcx
	sbb	%r12, %rax
	sbb	%rbx, %rdx
	sbb	%rbp, %rdi		

	
	mov	%rcx, %rbx
	mov	%rcx, %rbp
	shl	$32, %rbx
	shr	$32, %rbp
	xor	%r11,%r11
	xor	%r12,%r12
	sub	%rbx, %r11
	sbb	%rbp, %r12
	sbb	%rcx, %rbx
	sbb	$0, %rbp

	mov	32(%rsi), %r8
	sub	%r11, %rax
	sbb	%r12, %rdx
	sbb	%rbx, %r8
	sbb	%rbp, %rcx

	
	mov	%rax, %rbx
	mov	%rax, %rbp
	shl	$32, %rbx
	shr	$32, %rbp
	xor	%r11,%r11
	xor	%r12,%r12
	sub	%rbx, %r11
	sbb	%rbp, %r12
	sbb	%rax, %rbx
	sbb	$0, %rbp

	mov	40(%rsi), %r9
	sub	%r11, %rdx
	sbb	%r12, %r8
	sbb	%rbx, %r9
	sbb	%rbp, %rax

	
	mov	%rdx, %rbx
	mov	%rdx, %rbp
	shl	$32, %rbx
	shr	$32, %rbp
	xor	%r11,%r11
	xor	%r12,%r12
	sub	%rbx, %r11
	sbb	%rbp, %r12
	sbb	%rdx, %rbx
	sbb	$0, %rbp

	mov	48(%rsi), %r10
	sub	%r11, %r8
	sbb	%r12, %r9
	sbb	%rbx, %r10
	sbb	%rbp, %rdx

	add	%r8, %rdi
	adc	%r9, %rcx
	adc	%r10, %rax
	adc	56(%rsi), %rdx

	
	
	sbb	%rbx, %rbx
	mov	%rbx, %r11
	mov	%rbx, %r12
	mov	%ebx, %ebp
	neg	%r11
	shl	$32, %r12
	and	$-2, %ebp

	add	%r11, %rdi
	mov	%rdi, (%rsi)
	adc	%r12, %rcx
	mov	%rcx, 8(%rsi)
	adc	%rbx, %rax
	mov	%rax, 16(%rsi)
	adc	%rbp, %rdx

	mov	%rdx, 24(%rsi)

	pop	%r12
	pop	%rbp
	pop	%rbx
	
    
  
  
	ret
.size nettle_ecc_256_redc, . - nettle_ecc_256_redc

.section .note.GNU-stack,"",%progbits
