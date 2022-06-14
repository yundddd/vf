.intel_syntax noprefix
.text
    .globl _start

    _start:
        xor rbp,rbp
        pop rdi
        mov rsi,rsp
        and rsp,-16
        call main

        mov rdi,rax /* syscall param 1 = rax (ret value of main) */
        mov rax,60 /* SYS_exit */
        syscall

        ret /* should never be reached, but if the OS somehow fails
               to kill us, it will cause a segmentation fault */

