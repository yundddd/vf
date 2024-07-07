#pragma once
#include <elf.h>

namespace vf::infector {
// This struct defines infection result that tells us where
// in the infected binary we can find the virus as well as
// the entry address.
struct InjectionResult {
  // Parasite vaddr start address.
  Elf64_Addr parasite_entry_address;
  // Parasite file start offset.
  Elf64_Off parasite_file_offset;
};
}  // namespace vf::infector