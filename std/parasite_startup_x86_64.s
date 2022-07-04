
.section .text.startup
.weak _start
_start:
mov (%rsp), %rdi  ; argc   (first arg, %rdi)
mov %rsp, %rsi    ; argv[] (second arg, %rsi)

push %rax
push %rcx
push %rdx
push %rdi
push %r11
push %r12
push %rsp

lea 8(%rsi,%rdi,8),%rdx  ; then a nullptr then envp (third arg, %rdx)
xor %ebp, %ebp           ; zero the stack frame
and $-16, %rsp  ; x86 ABI : esp must be 16-byte aligned before call
call main       ; main() returns the status code, we'll exit with it.
mov %eax, %edi  ; retrieve exit code (32 bit)
mov $60, %eax   ; NR_exit == 60
syscall         ; really exit
hlt             ; ensure it does not return
