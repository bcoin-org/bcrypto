





















 






 



	.file "memxor.asm"

	.text

	
	
	.align 16


.globl nettle_memxor
.type nettle_memxor,%function
nettle_memxor:
	
    
  
  

	test	%rdx, %rdx
	
	
	mov	%rdi, %rax
	jz	.Ldone
	add 	%rdx, %rdi
	and	$7, %rdi
	
	jz	.Laligned

	cmp	$8, %rdx
	jc	.Lfinal_next

	
	
	
	
.Lalign_loop:
	
	sub	$1, %rdx
	movb	(%rsi, %rdx), %r8b
	xorb	%r8b, (%rax, %rdx)
	sub	$1, %rdi
	jnz	.Lalign_loop

.Laligned:

	cmp	$16, %rdx
	jnc	.Lsse2_case


	
	
	test	$8, %rdx
	jz	.Lword_next

	sub	$8, %rdx
	jz	.Lone_word

	mov	(%rsi, %rdx), %r8
	xor	%r8, (%rax, %rdx)
	
	jmp	.Lword_next

	.align 16


.Lword_loop:
	mov	8(%rsi, %rdx), %r8
	mov	(%rsi, %rdx), %r9
	xor	%r8, 8(%rax, %rdx)
	xor	%r9, (%rax, %rdx)

.Lword_next:
	sub	$16, %rdx
	ja	.Lword_loop	
	jnz	.Lfinal

	
	mov	8(%rsi, %rdx), %r8
	xor	%r8, 8(%rax, %rdx)
	
.Lone_word:
	mov	(%rsi, %rdx), %r8
	xor	%r8, (%rax, %rdx)

	
    
  
  
	ret

.Lfinal:
	add	$15, %rdx

.Lfinal_loop:
	movb	(%rsi, %rdx), %r8b
	xorb	%r8b, (%rax, %rdx)
.Lfinal_next:
	sub	$1, %rdx
	jnc	.Lfinal_loop

.Ldone:
	
    
  
  
	ret



.Lsse2_case:
	lea	(%rax, %rdx), %r8
	test	$8, %r8
	jz	.Lsse2_next
	sub	$8, %rdx
	mov	(%rsi, %rdx), %r8
	xor	%r8, (%rax, %rdx)
	jmp	.Lsse2_next

	.align 16

.Lsse2_loop:
	movdqu	(%rsi, %rdx), %xmm0
	movdqa	(%rax, %rdx), %xmm1
	pxor	%xmm0, %xmm1
	movdqa	%xmm1, (%rax, %rdx)
.Lsse2_next:
	sub	$16, %rdx
	ja	.Lsse2_loop
	
	
	
	jnz	.Lfinal		

	
	movdqu	(%rsi), %xmm0
	movdqa	(%rax), %xmm1
	pxor	%xmm0, %xmm1
	movdqa	%xmm1, (%rax)

	
    
  
  
	ret
	

.size nettle_memxor, . - nettle_memxor

.section .note.GNU-stack,"",%progbits
