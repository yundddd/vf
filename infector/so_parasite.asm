BITS 64

global _start

section .text
_start:
	; Save register state, RBX can be safely used
	push rax
	push rcx
	push rdx
	push rdi
	push r11
	push r12
	
	jmp	parasite
	message:	db	"------ If you see this message, this binary was infected. ------", 0xa
	msg_len:    equ $-message

parasite:

	; Print our message
	xor	rax, rax					; Zero out RAX
	add	rax, 0x1					; Syscall number of write() - 0x1
	mov rdi, rax					; File descriptor - 0x1 (STDOUT)
	lea rsi, [rel message]			; Addresses the label relative to RIP (Instruction Pointer), i.e. 
									; dynamically identifying the address of the 'message' label.
	xor rdx, rdx
	mov dl, msg_len					
	syscall					

	pop r12
	pop r11
	pop rdi
	pop rdx
	pop rcx
	pop rax
	
	; The following is expected to be patched to jump to the original entry point
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop