#pragma once

#include <elf.h>
#include <span>

namespace vf::redirection {

class LibcStartMainPatcher {
 public:
  // @param parasite_entry_address Parasite's vaddr start. This is where the
  //                               binary will first run.
  // @param parasite_file_offset   Parasite's file insertion offset
  // @param parasite_patch_offset  The offset start from the parasite to be
  //                               patched. This is usually a dummy instruction
  //                               inside the parasite that will be used to hand
  //                               control back to the host.
  // @param victim                 The victim to be patched
  bool operator()(Elf64_Addr parasite_entry_address,
                  Elf64_Off parasite_file_offset,
                  Elf64_Off patch_offset_from_parasite_start,
                  std::span<std::byte> victim);
};

}  //  namespace vf::redirection