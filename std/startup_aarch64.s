.section .text.startup
.weak _start
_start:
ldr x0, [sp]       /* argc (x0) was in the stack */
add x1, sp, 8      /* argv (x1) = sp */
lsl x2, x0, 3      /* envp (x2) = 8*argc ... */
add x2, x2, 8      /*           + 8 (skip null) */
add x2, x2, x1     /*           + argv */
and sp, x1, -16    /* sp must be 16-byte aligned in the callee */
adrp x3, _environ  /* save envp to global */
str x2, [x3, :lo12:_environ]
bl main     /* main() returns the status code, we'll exit with it. */    
mov x8, 93   
svc #0

.section .data
.global _environ

_environ:
    .xword 0
