




















	.file "poly1305-internal.asm"









	
	
	.text
	
	
	
	
	.align 16

.globl nettle_poly1305_set_key
.type nettle_poly1305_set_key,%function
nettle_poly1305_set_key:
	
    
  
  
	mov	$0x0ffffffc0fffffff, %r8
	mov	(%rsi), %rax
	and	%r8, %rax
	and	$-4, %r8
	mov	%rax, (%rdi)
	mov	8(%rsi), %rax
	and	%r8, %rax
	mov	%rax, 8 (%rdi)
	shr	$2, %rax
	imul	$5, %rax
	mov	%rax, 16 (%rdi)
	xor	%eax, %eax
	mov	%rax, 40 (%rdi)
	mov	%rax, 48 (%rdi)
	mov	%eax, 36 (%rdi)
	
	
    
  
  
	ret

.size nettle_poly1305_set_key, . - nettle_poly1305_set_key
























	
	
.globl _nettle_poly1305_block
.type _nettle_poly1305_block,%function
_nettle_poly1305_block:
	
    
  
  
	mov	(%rsi), %rcx
	mov	8(%rsi), %rsi
	mov	%edx,	%r8d

	
	
	

	add	40 (%rdi), %rcx
	adc	48 (%rdi), %rsi
	adc	36 (%rdi), %r8d
	mov	0 (%rdi), %rax
	mul	%rcx			
	mov	%rax, %r9
	mov	%rdx, %r10
	mov	16 (%rdi), %rax	
	mov	%rax, %r11
	mul	%rsi			
	imul	%r8, %r11			
	imul	0 (%rdi), %r8	
	add	%rax, %r9
	adc	%rdx, %r10
	mov	0 (%rdi), %rax
	mul	%rsi			
	add	%rax, %r11
	adc	%rdx, %r8
	mov	8 (%rdi), %rax
	mul	%rcx			
	add	%rax, %r11
	adc	%rdx, %r8
	mov	%r8, %rax
	shr	$2, %rax
	imul	$5, %rax
	and	$3, %r8d
	add	%rax, %r9
	adc	%r11, %r10
	adc	$0, %r8d
	mov	%r9, 40 (%rdi)
	mov	%r10, 48 (%rdi)
	mov	%r8d, 36 (%rdi)
	
    
  
  
	ret
.size _nettle_poly1305_block, . - _nettle_poly1305_block

	
	
	
	
	
.globl nettle_poly1305_digest
.type nettle_poly1305_digest,%function
nettle_poly1305_digest:
	
    
  
  

	mov	40 (%rdi), %r9
	mov	48 (%rdi), %r10
	mov	36 (%rdi), %r11d
	mov	%r11d, %eax
	shr	$2, %eax
	and	$3, %r11
	imul	$5, %eax
	add	%rax, %r9
	adc	$0, %r10
	adc	$0, %r11d



	
	mov	$5, %rcx
	xor	%rax, %rax
	add	%r9, %rcx
	adc	%r10, %rax
	adc	$0, %r11d
	cmp	$4, %r11d
	cmovnc	%rcx, %r9
	cmovnc	%rax, %r10

	add	%r9, (%rsi)
	adc	%r10, 8(%rsi)

	xor	%eax, %eax
	mov	%rax, 40 (%rdi)
	mov	%rax, 48 (%rdi)
	mov	%eax, 36 (%rdi)
	
    
  
  
	ret


.section .note.GNU-stack,"",%progbits
