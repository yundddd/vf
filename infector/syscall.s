// Putting it all together, our _start function needs to:
// - zero rbp
// - put argc into rdi (1st parameter for main)
// - put the stack address of argv[0] into rsi (2nd param for main),
//   which will be interpreted as an array of char pointers.
// - align stack to 16-bytes
// - call main

.intel_syntax noprefix
.text
    .globl _start, syscall

    _start:
	// _start function
	
        xor rbp,rbp  /* xoring a value with itself = 0 */
        pop rdi      /* rdi = argc */
        	     /* the pop instruction already added 8 to rsp */
        mov rsi,rsp  /* rest of the stack as an array of char ptr */

        and rsp,-16
        call main    // call main function 

	// _EXIT
	// man 2 _EXIT
	mov rdi,rax /* syscall param 1 = rax (ret value of main) */
        mov rax,60 /* SYS_exit */
        syscall
	ret

    syscall:
        mov rax,rdi
        mov rdi,rsi
        mov rsi,rdx
        mov rdx,rcx
        mov r10,r8
        mov r8,r9
        syscall
        ret
