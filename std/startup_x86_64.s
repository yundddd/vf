/*
 * x86-64 System V ABI mandates:
 * 1) %rsp must be 16-byte aligned right before the function call.
 * 2) The deepest stack frame should be zero (the %rbp).
 *
 */

.section .text.startup
.weak _start
_start:
pop %rdi                   # argc   (first arg, %rdi)
mov %rsp, %rsi             # argv[] (second arg, %rsi)
lea 8(%rsi,%rdi,8),%rdx    # then a nullptr then envp (third arg, %rdx)
movq %rdx, _environ(%rip)  # save envp to global
xor %ebp, %ebp             # zero the stack frame
and $-16, %rsp  # x86 ABI : esp must be 16-byte aligned before call
call main       # main() returns the status code, we'll exit with it.
mov %eax, %edi  # retrieve exit code (32 bit)
mov $60, %eax   # NR_exit == 60
syscall         # really exit
hlt             # ensure it does not return

.section .data
.global _environ

_environ:
    .quad 0
