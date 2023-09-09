#pragma once
#include <elf.h>

namespace vt::infector {
struct InjectionResult {
  // Parasite vaddr start address.
  Elf64_Addr parasite_entry_address;
  // Parasite file start offset.
  Elf64_Off parasite_file_offset;
};
}  // namespace vt::infector