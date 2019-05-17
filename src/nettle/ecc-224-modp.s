




















	.file "ecc-224-modp.asm"




 








	
.globl nettle_ecc_224_modp
.type nettle_ecc_224_modp,%function
nettle_ecc_224_modp:
	
    
  
  
	mov	48(%rsi), %rax
	mov	56(%rsi), %rdx
	
	mov	%rax, %r9
	mov	%rax, %r10
	shl	$32, %r9
	shr	$32, %r10
	mov	%rdx, %r11
	mov	%rdx, %rdi
	shl	$32, %rdi
	shr	$32, %r11
	or	%rdi, %r10

	xor	%r8, %r8
	mov	16(%rsi), %rdi
	mov	24(%rsi), %rcx
	sub	%r9, %rdi
	sbb	%r10, %rcx
	sbb	%r11, %rax
	sbb	$0, %rdx		

	adc	32(%rsi), %rax
	adc	40(%rsi), %rdx
	adc	$0, %r8

	
	
	mov	%rax, %r9
	mov	%rax, %r10
	add	%rdi, %rax
	mov	%rdx, %r11
	mov	%rdx, %rdi
	adc	%rcx, %rdx
	mov	%r8, %rcx
	adc	$0, %r8

	
	shl	$32, %r9
	shr	$32, %r10
	shl	$32, %rdi
	shr	$32, %r11
	shl	$32, %rcx
	or	%rdi, %r10
	or	%rcx, %r11

	mov	(%rsi), %rdi
	mov	8(%rsi), %rcx
	sub	%r9, %rdi
	sbb	%r10, %rcx
	sbb	%r11, %rax
	sbb	$0, %rdx
	sbb	$0, %r8

	
	
	
	

	mov	%rdx, %r9
	mov	%rdx, %r10
	mov	%r8, %r11
	movl	%edx, %edx	
	sub	%rdx, %r10			
	shr	$32, %r9
	shl	$32, %r8
	or	%r8, %r9

	sub	%r9, %rdi
	sbb	$0, %r10
	sbb	$0, %r11
	add	%r10, %rcx
	adc	%r11, %rax
	adc	$0, %rdx

	mov	%rdi, (%rsi)
	mov	%rcx, 8(%rsi)
	mov	%rax, 16(%rsi)
	mov	%rdx, 24(%rsi)

	
    
  
  
	ret
.size nettle_ecc_224_modp, . - nettle_ecc_224_modp

.section .note.GNU-stack,"",%progbits
