[![CircleCI](https://circleci.com/gh/yundddd/vt.svg?style=shield)](https://app.circleci.com/pipelines/github/yundddd/vt)

Writing a virus is hard due to the following reasons:

# The parasite must be self-contained
This means that it relies on no external linking, is position independent (PIC), and is able to dynamically adjust memory addresses based on the host; the addresses will change between each infection due to address space layout randomization (ASLR). This implies we cannot refer to any thing that lives outside of .text section, or anything that doesn't use relative addressing. This poses difficulties because some system calls require initialized strings. To work around this, we provide a generic wrapper for you to define a string literal in text section with relative addressing code in macro.hh. One may also merge .rodata into .text. It may work on x86 PC relative instructions, but on aarch64, it may not. If your virus is not constrained by code size, feel free to use string.hh and simply append charaters to it. One might think putting a char[] on stack and initialize it there might work, however the compiler might try to be smart and put it in .rodata for you. Do an objdump to confirm before you go with this route.

# No global variables

We should not refer to anything in .data sections that is global, such as environ and errno. Our build system macro is setup in a way that prevents linker from finding them and will error out at compile time. We should not use global C++ objects, since we don't have glibc's .init and friends. If you still want to, the constructors and destructors will not be called. This also applies to function static or anything that has global life time.

# No glibc

We rolled our own startup code as well as common utilities. Note that a subset of them are not suitable for viruses as they might take up too much space (ex. sprintf). Use them for developing viruses only. The startup code maybe patched to hand control back to host, while restoring important registers as if nothing has happened before host's entry. 

# Your virus needs to be patched to hand control back to host.

Our startup code follows this convention for patching: for x86-64, the last 8 nop instructions should be patched to a jump instruction; for aarch64, the last nop instruction (4bytes) should be patched to a branch instruction.

# Your virus needs to be inserted to the host binary in an appropriate place.

We provided algorithms for users to choose, each with their own trade-offs on space, efficiency, and potential virus life-time (detectability). Please see //infector for more information.

# It's hard to test viruses.

Our build system is setup in a way that allows us to select two binary modes (virus and normal). The former links our virus startup code, that enables patching and register restoration. The latter is simplier, and exposes environ, makes writing unittests/tools easier since we are not writing viruses any more. We also provide a test framework, that mimics GTEST framework, to make testing familiar to users.
