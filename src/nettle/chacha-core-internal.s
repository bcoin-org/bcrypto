





































	
	
	.text
	.align 16

.globl _nettle_chacha_core
.type _nettle_chacha_core,%function
_nettle_chacha_core:
	
    
  
  

	movups	(%rsi), %xmm0
	movups	16(%rsi), %xmm1
	movups	32(%rsi), %xmm2
	movups	48(%rsi), %xmm3

	shrl	$1, %edx

	.align 16

.Loop:
	
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movaps	%xmm3, %xmm4
	
	pshufhw	$0xb1, %xmm3, %xmm3
	pshuflw	$0xb1, %xmm3, %xmm3


	paddd	%xmm3, %xmm2
	pxor	%xmm2, %xmm1
	movaps	%xmm1, %xmm4
	pslld	$12, %xmm1
	psrld	$20, %xmm4
	por	%xmm4, %xmm1

	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movaps	%xmm3, %xmm4
	pslld	$8, %xmm3
	psrld	$24, %xmm4
	por	%xmm4, %xmm3
		
	paddd	%xmm3, %xmm2
	pxor	%xmm2, %xmm1
	movaps	%xmm1, %xmm4
	pslld	$7, %xmm1
	psrld	$25, %xmm4
	por	%xmm4, %xmm1

	pshufd	$0x39, %xmm1, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	pshufd	$0x93, %xmm3, %xmm3

	
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movaps	%xmm3, %xmm4
	
	pshufhw	$0xb1, %xmm3, %xmm3
	pshuflw	$0xb1, %xmm3, %xmm3


	paddd	%xmm3, %xmm2
	pxor	%xmm2, %xmm1
	movaps	%xmm1, %xmm4
	pslld	$12, %xmm1
	psrld	$20, %xmm4
	por	%xmm4, %xmm1

	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movaps	%xmm3, %xmm4
	pslld	$8, %xmm3
	psrld	$24, %xmm4
	por	%xmm4, %xmm3
		
	paddd	%xmm3, %xmm2
	pxor	%xmm2, %xmm1
	movaps	%xmm1, %xmm4
	pslld	$7, %xmm1
	psrld	$25, %xmm4
	por	%xmm4, %xmm1

	pshufd	$0x93, %xmm1, %xmm1
	pshufd	$0x4e, %xmm2, %xmm2
	pshufd	$0x39, %xmm3, %xmm3

	decl	%edx
	jnz	.Loop

	movups	(%rsi), %xmm4
	movups	16(%rsi), %xmm5
	paddd	%xmm4, %xmm0
	paddd	%xmm5, %xmm1
	movups	%xmm0,(%rdi)
	movups	%xmm1,16(%rdi)
	movups	32(%rsi), %xmm4
	movups	48(%rsi), %xmm5
	paddd	%xmm4, %xmm2
	paddd	%xmm5, %xmm3
	movups	%xmm2,32(%rdi)
	movups	%xmm3,48(%rdi)
	
    
  
  
	ret
.size _nettle_chacha_core, . - _nettle_chacha_core

.section .note.GNU-stack,"",%progbits
