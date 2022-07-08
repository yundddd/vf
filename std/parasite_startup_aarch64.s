/* This is the canonical entry point, usually the first thing in the text
   segment.
   Note that the code in the .init section has already been run.
   This includes _init and _libc_init
   At this entry point, most registers' values are unspecified, except:

   x0/w0	Contains a function pointer to be registered with `atexit'.
		This is how the dynamic linker arranges to have DT_FINI
		functions called for shared libraries that have been loaded
		before this code runs.

   sp		The stack contains the arguments and environment:
		0(sp)			argc
		8(sp)			argv[0]
		...
		(8*argc)(sp)		NULL
		(8*(argc+1))(sp)	envp[0]
		...
					NULL

When the parasite finishes execution, we need to restore the origina stack
frame as if nothing happened before.
*/

/* use a customed linker script to make sure this is the first in text. */
.section .text.start_parasite 
.global _start
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
