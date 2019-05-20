




















	.file "ecc-521-modp.asm"

















.globl nettle_ecc_521_modp
.type nettle_ecc_521_modp,%function
nettle_ecc_521_modp:
	
    
  
  
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	
	mov	72(%rsi), %rbx
	mov	%rbx, %rax
	shl	$55, %rax
	shr	$9, %rbx

	mov	80(%rsi), %rcx
	mov	%rcx, %r12
	shr	$9, %rcx
	shl	$55, %r12
	or	%r12, %rbx

	mov	88(%rsi), %rdx
	mov	%rdx, %r12
	shr	$9, %rdx
	shl	$55, %r12
	or	%r12, %rcx

	mov	96(%rsi), %rbp
	mov	%rbp, %r12
	shr	$9, %rbp
	shl	$55, %r12
	or	%r12, %rdx

	mov	104(%rsi), %rdi
	mov	%rdi, %r12
	shr	$9, %rdi
	shl	$55, %r12
	or	%r12, %rbp

	mov	112(%rsi), %r8
	mov	%r8, %r12
	shr	$9, %r8
	shl	$55, %r12
	or	%r12, %rdi

	mov	120(%rsi), %r9
	mov	%r9, %r12
	shr	$9, %r9
	shl	$55, %r12
	or	%r12, %r8

	mov	128(%rsi), %r10
	mov	%r10, %r12
	shr	$9, %r10
	shl	$55, %r12
	or	%r12, %r9

	mov	136(%rsi), %r11
	mov	%r11, %r12
	shr	$9, %r11
	shl	$55, %r12
	or	%r12, %r10

	add	  (%rsi), %rax
	adc	 8(%rsi), %rbx
	adc	16(%rsi), %rcx
	adc	24(%rsi), %rdx
	adc	32(%rsi), %rbp
	adc	40(%rsi), %rdi
	adc	48(%rsi), %r8
	adc	56(%rsi), %r9
	adc	64(%rsi), %r10
	adc	$0, %r11

	
	
	mov	%r10, %r12
	shr	$9, %r12
	and	$0x1ff, %r10
	mov	%r11, %r13
	shl	$55, %r11
	shr	$9, %r13
	or	%r11, %r12

	add	%r12, %rax
	mov	%rax, (%rsi)
	adc	%r13, %rbx
	mov	%rbx, 8(%rsi)
	adc	$0, %rcx
	mov	%rcx, 16(%rsi)
	adc	$0, %rdx
	mov	%rdx, 24(%rsi)
	adc	$0, %rbp
	mov	%rbp, 32(%rsi)
	adc	$0, %rdi
	mov	%rdi, 40(%rsi)
	adc	$0, %r8
	mov	%r8, 48(%rsi)
	adc	$0, %r9
	mov	%r9, 56(%rsi)
	adc	$0, %r10
	mov	%r10, 64(%rsi)

	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	
    
  
  
	ret
.size nettle_ecc_521_modp, . - nettle_ecc_521_modp

.section .note.GNU-stack,"",%progbits
