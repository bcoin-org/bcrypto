






































 
 
 


 














	.file "camellia-crypt-internal.asm"
	
	
	
	
	
	.text
	.align 16

.globl _nettle_camellia_crypt
.type _nettle_camellia_crypt,%function
_nettle_camellia_crypt:

	
    
  
  
	test	%rcx, %rcx
	jz	.Lend

	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	sub	$8, %rdi
.Lblock_loop:
	
	mov	(%r9), %rax
	bswap	%rax
	mov	8(%r9), %rbx
	bswap	%rbx
	add	$16, %r9
	mov	%edi, %r10d
	mov	%rsi, %r13

	
	xor	(%r13), %rax
	add	$8, %r13

	
	
	movzbl	%al, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rax

	
	movzbl	%al, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rax

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	0(%r13), %rbx
	xor	%r12, %rbx

	
	
	movzbl	%bl, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rbx

	
	movzbl	%bl, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rbx

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	8(%r13), %rax
	xor	%r12, %rax

	
	
	movzbl	%al, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rax

	
	movzbl	%al, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rax

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	16(%r13), %rbx
	xor	%r12, %rbx

	
	
	movzbl	%bl, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rbx

	
	movzbl	%bl, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rbx

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	24(%r13), %rax
	xor	%r12, %rax

	
	
	movzbl	%al, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rax

	
	movzbl	%al, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rax

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	32(%r13), %rbx
	xor	%r12, %rbx
 
	
	
	movzbl	%bl, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rbx

	
	movzbl	%bl, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rbx

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	40(%r13), %rax
	xor	%r12, %rax

	
.Lround_loop:
	add	$64, %r13
	
	mov	%rax, %rbp
	shr	$32, %rbp
	andl	-16 + 4(%r13), %ebp
	roll	$1, %ebp

	xor	%rbp, %rax
	movl	-16(%r13), %ebp
	orl	%eax, %ebp
	shl	$32, %rbp
	xor	%rbp, %rax

	
	movl	-8(%r13), %ebp
	orl	%ebx, %ebp
	shl	$32, %rbp
	xor	%rbp, %rbx
	mov	%rbx, %rbp
	shr	$32, %rbp
	andl	-8 + 4(%r13), %ebp
	roll	$1, %ebp

	xor	%rbp, %rbx	

	
	
	movzbl	%al, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rax

	
	movzbl	%al, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rax

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	0(%r13), %rbx
	xor	%r12, %rbx

	
	
	movzbl	%bl, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rbx

	
	movzbl	%bl, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rbx

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	8(%r13), %rax
	xor	%r12, %rax

	
	
	movzbl	%al, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rax

	
	movzbl	%al, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rax

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	16(%r13), %rbx
	xor	%r12, %rbx

	
	
	movzbl	%bl, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rbx

	
	movzbl	%bl, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rbx

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	24(%r13), %rax
	xor	%r12, %rax

	
	
	movzbl	%al, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rax

	
	movzbl	%al, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%ah, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rax

	
	movzbl	%al, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%ah, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rax

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	32(%r13), %rbx
	xor	%r12, %rbx
 
	
	
	movzbl	%bl, %ebp
	movl	(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	3072(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	movl	3072(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	2048(%rdx,%rbp,4), %r11d
	rol	$16, %rbx

	
	movzbl	%bl, %ebp
	xorl	2048(%rdx,%rbp,4), %r12d
	movzbl	%bh, %ebp
	xorl	1024(%rdx,%rbp,4), %r12d
	ror	$32, %rbx

	
	movzbl	%bl, %ebp
	xorl	1024(%rdx,%rbp,4), %r11d
	movzbl	%bh, %ebp
	xorl	(%rdx,%rbp,4), %r11d
	ror	$16, %rbx

	
	
	xorl	%r11d, %r12d
	rorl	$8, %r11d
	xorl	%r12d, %r11d
	shl	$32, %r12
	or	%r11, %r12
	xor	40(%r13), %rax
	xor	%r12, %rax


	sub 	$8, %r10	
	ja	.Lround_loop

	bswap	%rax
	mov	%rax, 8(%r8)
	xor	48(%r13), %rbx
	bswap	%rbx
	mov	%rbx, (%r8)
	add	$16, %r8
	sub	$16, %rcx

	ja	.Lblock_loop

	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
.Lend:
	
    
  
  
	ret
.size _nettle_camellia_crypt, . - _nettle_camellia_crypt

.section .note.GNU-stack,"",%progbits
