#include "redirection/patching.hh"

namespace vf::redirection {

namespace {
constexpr uint16_t call_op_code = 0x15ff;
constexpr uint8_t jmp_op_code = 0xe9;
}  // namespace

Elf64_Addr branch_destination(const std::byte* branch_inst,
                              Elf64_Addr branch_instruction_vaddr) {
  auto op = *reinterpret_cast<const uint8_t*>(branch_inst);
  switch (op) {
    case 0xff:
      // Call near, absolute indirect, address given in r/m32
      // RIP relative: 0xff 0x15 + 32bit offset
      branch_inst += 2;
      return *reinterpret_cast<const int32_t*>(branch_inst) +
             branch_instruction_vaddr + 6;
    case 0xe8:
      // Call near, relative, displacement relative to next instruction
      // RIP relative: 0xe8 + 32bit offset
      branch_inst++;
      return *reinterpret_cast<const int32_t*>(branch_inst) +
             branch_instruction_vaddr + 5;
    default:
      return 0;
  }
}

// call: ff 15 xxxxxxxx The rel32 offset is from the next instruction after
// the jmp. The patched jump instruction is always 6 bytes.
void patch_branch_with_return(std::byte* instruction_ptr, Elf64_Addr src_vaddr,
                              Elf64_Addr dst_vaddr) {
  // https://www.felixcloutier.com/x86/call
  int32_t rel = dst_vaddr - (src_vaddr + 6);

  *reinterpret_cast<uint16_t*>(instruction_ptr) = call_op_code;
  *(int32_t*)(instruction_ptr + 2) = rel;
}

// jmp rel32 e9 xxxxxxxx The rel32 offset is from the next instruction after
// the jmp. The patched jump instruction is always 5 bytes.
// https://www.felixcloutier.com/x86/jmp
void patch_branch(std::byte* instruction_ptr, Elf64_Addr src_vaddr,
                  Elf64_Addr dst_vaddr) {
  int32_t rel = dst_vaddr - (src_vaddr + 5);

  *reinterpret_cast<uint8_t*>(instruction_ptr) = jmp_op_code;
  *(int32_t*)(instruction_ptr + 1) = rel;
}

}  //  namespace vf::redirection