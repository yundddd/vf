.section .text.startup
.weak _start
_start:
    /* .inst 0xd4200000 */
    /* Push x0 x1 to stack. x0 has atexit function pointer. */
stp x0, x1, [sp, #-16]!

ldr x0, [sp, 16]  /* argc (x0) was in the stack */
add x1, sp, 24    /* argv (x1) = sp */

lsl x2, x0, 3   /* envp (x2) = 8*argc ... */
add x2, x2, 8   /*          + 8 (skip null) */
add x2, x2, x1  /*          + argv */

    /* because we pushed x0 and x1 to stack, the original way of alignment wont
     work anymore. but OS should always give us an aligned sp first.
     and sp, x1, #0xfffffffffffffff0 */

bl main      
ldp x0, x1, [sp], #16    /* restore x0 */
                            
nop                         /* to be patched */
