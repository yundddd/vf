#pragma once
#include <elf.h>
#include "common/mmap.hh"

namespace vt::common {

// Patch the parasite code and hand control back to the host.
bool patch_parasite_and_relinquish_control(
    Elf64_Half binary_type, Elf64_Addr original_entry_point,
    Elf64_Addr parasite_load_address, size_t parasite_offset,
    size_t parasite_size, vt::common::Mmap<PROT_READ | PROT_WRITE>& mapping);

}  // namespace vt::common