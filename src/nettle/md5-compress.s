


















































	.file "md5-compress.asm"

	
	.text
	.align 16

.globl _nettle_md5_compress
.type _nettle_md5_compress,%function
_nettle_md5_compress:
	
    
  
  
	
	push	%rbp
	push	%rbx

	
	movl	(%rdi),   %eax
	movl	4(%rdi),  %ebx
	movl	8(%rdi),  %ecx
	movl	12(%rdi), %ebp

	
	addl	$0xd76aa478, %eax
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%ebx, %r8d
	xorl	%ebp, %r8d
	addl	(%rsi), %eax
	addl	%r8d, %eax
	roll	$7, %eax
	addl	%ebx, %eax
	
	addl	$0xe8c7b756, %ebp
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%eax, %r8d
	xorl	%ecx, %r8d
	addl	4(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$12, %ebp
	addl	%eax, %ebp
	
	addl	$0x242070db, %ecx
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ebp, %r8d
	xorl	%ebx, %r8d
	addl	8(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$17, %ecx
	addl	%ebp, %ecx
	
	addl	$0xc1bdceee, %ebx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ecx, %r8d
	xorl	%eax, %r8d
	addl	12(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$22, %ebx
	addl	%ecx, %ebx
	
	addl	$0xf57c0faf, %eax
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%ebx, %r8d
	xorl	%ebp, %r8d
	addl	16(%rsi), %eax
	addl	%r8d, %eax
	roll	$7, %eax
	addl	%ebx, %eax
	
	addl	$0x4787c62a, %ebp
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%eax, %r8d
	xorl	%ecx, %r8d
	addl	20(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$12, %ebp
	addl	%eax, %ebp
	
	addl	$0xa8304613, %ecx
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ebp, %r8d
	xorl	%ebx, %r8d
	addl	24(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$17, %ecx
	addl	%ebp, %ecx
	
	addl	$0xfd469501, %ebx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ecx, %r8d
	xorl	%eax, %r8d
	addl	28(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$22, %ebx
	addl	%ecx, %ebx
	
	addl	$0x698098d8, %eax
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%ebx, %r8d
	xorl	%ebp, %r8d
	addl	32(%rsi), %eax
	addl	%r8d, %eax
	roll	$7, %eax
	addl	%ebx, %eax
	
	addl	$0x8b44f7af, %ebp
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%eax, %r8d
	xorl	%ecx, %r8d
	addl	36(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$12, %ebp
	addl	%eax, %ebp
	
	addl	$0xffff5bb1, %ecx
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ebp, %r8d
	xorl	%ebx, %r8d
	addl	40(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$17, %ecx
	addl	%ebp, %ecx
	
	addl	$0x895cd7be, %ebx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ecx, %r8d
	xorl	%eax, %r8d
	addl	44(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$22, %ebx
	addl	%ecx, %ebx
	
	addl	$0x6b901122, %eax
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%ebx, %r8d
	xorl	%ebp, %r8d
	addl	48(%rsi), %eax
	addl	%r8d, %eax
	roll	$7, %eax
	addl	%ebx, %eax
	
	addl	$0xfd987193, %ebp
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%eax, %r8d
	xorl	%ecx, %r8d
	addl	52(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$12, %ebp
	addl	%eax, %ebp
	
	addl	$0xa679438e, %ecx
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ebp, %r8d
	xorl	%ebx, %r8d
	addl	56(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$17, %ecx
	addl	%ebp, %ecx
	
	addl	$0x49b40821, %ebx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ecx, %r8d
	xorl	%eax, %r8d
	addl	60(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$22, %ebx
	addl	%ecx, %ebx

	
	addl	$0xf61e2562, %eax
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%ebp, %r8d
	xorl	%ecx, %r8d
	addl	4(%rsi), %eax
	addl	%r8d, %eax
	roll	$5, %eax
	addl	%ebx, %eax
	
	addl	$0xc040b340, %ebp
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ecx, %r8d
	xorl	%ebx, %r8d
	addl	24(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$9, %ebp
	addl	%eax, %ebp
	
	addl	$0x265e5a51, %ecx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ebx, %r8d
	xorl	%eax, %r8d
	addl	44(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$14, %ecx
	addl	%ebp, %ecx
	
	addl	$0xe9b6c7aa, %ebx
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%eax, %r8d
	xorl	%ebp, %r8d
	addl	(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$20, %ebx
	addl	%ecx, %ebx
	
	addl	$0xd62f105d, %eax
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%ebp, %r8d
	xorl	%ecx, %r8d
	addl	20(%rsi), %eax
	addl	%r8d, %eax
	roll	$5, %eax
	addl	%ebx, %eax
	
	addl	$0x02441453, %ebp
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ecx, %r8d
	xorl	%ebx, %r8d
	addl	40(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$9, %ebp
	addl	%eax, %ebp
	
	addl	$0xd8a1e681, %ecx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ebx, %r8d
	xorl	%eax, %r8d
	addl	60(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$14, %ecx
	addl	%ebp, %ecx
	
	addl	$0xe7d3fbc8, %ebx
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%eax, %r8d
	xorl	%ebp, %r8d
	addl	16(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$20, %ebx
	addl	%ecx, %ebx
	
	addl	$0x21e1cde6, %eax
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%ebp, %r8d
	xorl	%ecx, %r8d
	addl	36(%rsi), %eax
	addl	%r8d, %eax
	roll	$5, %eax
	addl	%ebx, %eax
	
	addl	$0xc33707d6, %ebp
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ecx, %r8d
	xorl	%ebx, %r8d
	addl	56(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$9, %ebp
	addl	%eax, %ebp
	
	addl	$0xf4d50d87, %ecx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ebx, %r8d
	xorl	%eax, %r8d
	addl	12(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$14, %ecx
	addl	%ebp, %ecx
	
	addl	$0x455a14ed, %ebx
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%eax, %r8d
	xorl	%ebp, %r8d
	addl	32(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$20, %ebx
	addl	%ecx, %ebx
	
	addl	$0xa9e3e905, %eax
	
	movl	%ecx, %r8d
	xorl	%ebx, %r8d
	andl	%ebp, %r8d
	xorl	%ecx, %r8d
	addl	52(%rsi), %eax
	addl	%r8d, %eax
	roll	$5, %eax
	addl	%ebx, %eax
	
	addl	$0xfcefa3f8, %ebp
	
	movl	%ebx, %r8d
	xorl	%eax, %r8d
	andl	%ecx, %r8d
	xorl	%ebx, %r8d
	addl	8(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$9, %ebp
	addl	%eax, %ebp
	
	addl	$0x676f02d9, %ecx
	
	movl	%eax, %r8d
	xorl	%ebp, %r8d
	andl	%ebx, %r8d
	xorl	%eax, %r8d
	addl	28(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$14, %ecx
	addl	%ebp, %ecx
	
	addl	$0x8d2a4c8a, %ebx
	
	movl	%ebp, %r8d
	xorl	%ecx, %r8d
	andl	%eax, %r8d
	xorl	%ebp, %r8d
	addl	48(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$20, %ebx
	addl	%ecx, %ebx

	
	addl	$0xfffa3942, %eax
	
	movl	%ebx, %r8d
	xorl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	20(%rsi), %eax
	addl	%r8d, %eax
	roll	$4, %eax
	addl	%ebx, %eax
	
	addl	$0x8771f681, %ebp
	
	movl	%eax, %r8d
	xorl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	32(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$11, %ebp
	addl	%eax, %ebp
	
	addl	$0x6d9d6122, %ecx
	
	movl	%ebp, %r8d
	xorl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	44(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$16, %ecx
	addl	%ebp, %ecx
	
	addl	$0xfde5380c, %ebx
	
	movl	%ecx, %r8d
	xorl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	56(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$23, %ebx
	addl	%ecx, %ebx
	
	addl	$0xa4beea44, %eax
	
	movl	%ebx, %r8d
	xorl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	4(%rsi), %eax
	addl	%r8d, %eax
	roll	$4, %eax
	addl	%ebx, %eax
	
	addl	$0x4bdecfa9, %ebp
	
	movl	%eax, %r8d
	xorl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	16(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$11, %ebp
	addl	%eax, %ebp
	
	addl	$0xf6bb4b60, %ecx
	
	movl	%ebp, %r8d
	xorl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	28(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$16, %ecx
	addl	%ebp, %ecx
	
	addl	$0xbebfbc70, %ebx
	
	movl	%ecx, %r8d
	xorl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	40(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$23, %ebx
	addl	%ecx, %ebx
	
	addl	$0x289b7ec6, %eax
	
	movl	%ebx, %r8d
	xorl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	52(%rsi), %eax
	addl	%r8d, %eax
	roll	$4, %eax
	addl	%ebx, %eax
	
	addl	$0xeaa127fa, %ebp
	
	movl	%eax, %r8d
	xorl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$11, %ebp
	addl	%eax, %ebp
	
	addl	$0xd4ef3085, %ecx
	
	movl	%ebp, %r8d
	xorl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	12(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$16, %ecx
	addl	%ebp, %ecx
	
	addl	$0x04881d05, %ebx
	
	movl	%ecx, %r8d
	xorl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	24(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$23, %ebx
	addl	%ecx, %ebx
	
	addl	$0xd9d4d039, %eax
	
	movl	%ebx, %r8d
	xorl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	36(%rsi), %eax
	addl	%r8d, %eax
	roll	$4, %eax
	addl	%ebx, %eax
	
	addl	$0xe6db99e5, %ebp
	
	movl	%eax, %r8d
	xorl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	48(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$11, %ebp
	addl	%eax, %ebp
	
	addl	$0x1fa27cf8, %ecx
	
	movl	%ebp, %r8d
	xorl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	60(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$16, %ecx
	addl	%ebp, %ecx
	
	addl	$0xc4ac5665, %ebx
	
	movl	%ecx, %r8d
	xorl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	8(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$23, %ebx
	addl	%ecx, %ebx

	
	addl	$0xf4292244, %eax
	
	movl	%ebp, %r8d
	notl	%r8d
	orl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	(%rsi), %eax
	addl	%r8d, %eax
	roll	$6, %eax
	addl	%ebx, %eax
	
	addl	$0x432aff97, %ebp
	
	movl	%ecx, %r8d
	notl	%r8d
	orl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	28(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$10, %ebp
	addl	%eax, %ebp
	
	addl	$0xab9423a7, %ecx
	
	movl	%ebx, %r8d
	notl	%r8d
	orl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	56(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$15, %ecx
	addl	%ebp, %ecx
	
	addl	$0xfc93a039, %ebx
	
	movl	%eax, %r8d
	notl	%r8d
	orl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	20(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$21, %ebx
	addl	%ecx, %ebx
	
	addl	$0x655b59c3, %eax
	
	movl	%ebp, %r8d
	notl	%r8d
	orl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	48(%rsi), %eax
	addl	%r8d, %eax
	roll	$6, %eax
	addl	%ebx, %eax
	
	addl	$0x8f0ccc92, %ebp
	
	movl	%ecx, %r8d
	notl	%r8d
	orl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	12(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$10, %ebp
	addl	%eax, %ebp
	
	addl	$0xffeff47d, %ecx
	
	movl	%ebx, %r8d
	notl	%r8d
	orl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	40(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$15, %ecx
	addl	%ebp, %ecx
	
	addl	$0x85845dd1, %ebx
	
	movl	%eax, %r8d
	notl	%r8d
	orl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	4(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$21, %ebx
	addl	%ecx, %ebx
	
	addl	$0x6fa87e4f, %eax
	
	movl	%ebp, %r8d
	notl	%r8d
	orl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	32(%rsi), %eax
	addl	%r8d, %eax
	roll	$6, %eax
	addl	%ebx, %eax
	
	addl	$0xfe2ce6e0, %ebp
	
	movl	%ecx, %r8d
	notl	%r8d
	orl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	60(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$10, %ebp
	addl	%eax, %ebp
	
	addl	$0xa3014314, %ecx
	
	movl	%ebx, %r8d
	notl	%r8d
	orl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	24(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$15, %ecx
	addl	%ebp, %ecx
	
	addl	$0x4e0811a1, %ebx
	
	movl	%eax, %r8d
	notl	%r8d
	orl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	52(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$21, %ebx
	addl	%ecx, %ebx
	
	addl	$0xf7537e82, %eax
	
	movl	%ebp, %r8d
	notl	%r8d
	orl	%ebx, %r8d
	xorl	%ecx, %r8d
	addl	16(%rsi), %eax
	addl	%r8d, %eax
	roll	$6, %eax
	addl	%ebx, %eax
	
	addl	$0xbd3af235, %ebp
	
	movl	%ecx, %r8d
	notl	%r8d
	orl	%eax, %r8d
	xorl	%ebx, %r8d
	addl	44(%rsi), %ebp
	addl	%r8d, %ebp
	roll	$10, %ebp
	addl	%eax, %ebp
	
	addl	$0x2ad7d2bb, %ecx
	
	movl	%ebx, %r8d
	notl	%r8d
	orl	%ebp, %r8d
	xorl	%eax, %r8d
	addl	8(%rsi), %ecx
	addl	%r8d, %ecx
	roll	$15, %ecx
	addl	%ebp, %ecx
	
	addl	$0xeb86d391, %ebx
	
	movl	%eax, %r8d
	notl	%r8d
	orl	%ecx, %r8d
	xorl	%ebp, %r8d
	addl	36(%rsi), %ebx
	addl	%r8d, %ebx
	roll	$21, %ebx
	addl	%ecx, %ebx

	
	addl	%eax, (%rdi)
	addl	%ebx, 4(%rdi)
	addl	%ecx, 8(%rdi)
	addl	%ebp, 12(%rdi)

	pop	%rbx
	pop	%rbp
	
    
  
  

	ret
.size _nettle_md5_compress, . - _nettle_md5_compress

.section .note.GNU-stack,"",%progbits
