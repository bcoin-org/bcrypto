




















	.file "ecc-384-modp.asm"
















	
	


.globl nettle_ecc_384_modp
.type nettle_ecc_384_modp,%function
nettle_ecc_384_modp:
	
    
  
  

	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	
	
	
	
	
	
	
	
	
	
	
	

	mov	80(%rsi), %r13
	mov	88(%rsi), %r14
	
	mov	%r13, %r9
	mov	%r14, %r10
	mov	%r14, %rax
	shr	$32, %r10
	shl	$32, %rax
	shr	$32, %r9
	or	%rax, %r9

	
	
	
	
	mov	%r9, %rax
	neg	%rax
	sbb	%r10, %r9
	sbb	$0, %r10

	xor	%r15, %r15
	add	%r13, %r9
	adc	%r14, %r10
	adc	$0, %r15

	
	add	48(%rsi), %r9
	adc	56(%rsi), %r10
	adc	$0, %r15		

	
	mov	(%rsi), %rbx
	add	%r9, %rbx
	mov	8(%rsi), %rcx
	adc	%r10, %rcx
	mov	16(%rsi), %rdx
	mov	64(%rsi), %r11
	adc	%r11, %rdx
	mov	24(%rsi), %rbp
	mov	72(%rsi), %r12
	adc	%r12, %rbp
	mov	32(%rsi), %rdi
	adc	%r13, %rdi
	mov	40(%rsi), %r8
	adc	%r14, %r8
	sbb	%r14, %r14
	neg	%r14		

	push	%rsi

	
	add	%r9, %rdx
	adc	%r10, %rbp
	adc	%r11, %rdi
	adc	%r12, %r8
	adc	$0, %r14

	
	mov	%r12, %rsi
	shl	$32, %r13
	shr	$32, %rsi
	or	%rsi, %r13

	mov	%r11, %rsi
	shl	$32, %r12
	shr	$32, %rsi
	or	%rsi, %r12

	mov	%r10, %rsi
	shl	$32, %r11
	shr	$32, %rsi
	or	%rsi, %r11

	mov	%r9, %rsi
	shl	$32, %r10
	shr	$32, %rsi
	or	%rsi, %r10

	shl	$32, %r9

	
	
	
	

	mov	%r9, %rsi
	neg	%rsi
	sbb	%r10, %r9
	sbb	%r11, %r10
	sbb	%r12, %r11
	sbb	%r13, %r12
	sbb	$0, %r13

	add	%rsi, %rbx
	adc	%r9, %rcx
	adc	%r10, %rdx
	adc	%r11, %rbp
	adc	%r12, %rdi
	adc	%r13, %r8
	adc	$0, %r14

	
	
	mov	%r14, %r9
	mov	%r14, %r10
	shl	$32, %r10
	sub	%r10, %r9
	sbb	$0, %r10

	
	mov	%r15, %r11
	mov	%r15, %r12
	shl	$32, %r12
	sub	%r12, %r11
	sbb	$0, %r12
	add	%r14, %r11		

	xor	%r14, %r14
	add	%r9, %rbx
	adc	%r10, %rcx
	adc	%r11, %rdx
	adc	%r12, %rbp
	adc	%r15, %rdi
	adc	%rax, %r8		
	adc	$0, %r14		

	
	mov	%r14, %r9
	mov	%r14, %r10
	shl	$32, %r10
	sub	%r10, %r9
	sbb	$0, %r10

	pop	%rsi

	add	%r9, %rbx
	mov	%rbx, (%rsi)
	adc	%r10, %rcx
	mov	%rcx, 8(%rsi)
	adc	%r14, %rdx
	mov	%rdx, 16(%rsi)
	adc	$0, %rbp
	mov	%rbp, 24(%rsi)
	adc	$0, %rdi
	mov	%rdi, 32(%rsi)
	adc	$0, %r8
	mov	%r8, 40(%rsi)

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx

	
    
  
  
	ret
.size nettle_ecc_384_modp, . - nettle_ecc_384_modp

.section .note.GNU-stack,"",%progbits
