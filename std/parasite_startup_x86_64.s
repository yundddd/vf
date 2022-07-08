/*
 * x86-64 System V ABI mandates:
 * 1) %rsp must be 16-byte aligned right before the function call.
 * 2) The deepest stack frame should be zero (the %rbp).
 *
 */
.section .text.startup
.weak _start
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
