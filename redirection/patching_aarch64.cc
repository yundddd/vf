#include "redirection/patching.hh"

namespace vf::redirection {

namespace {
constexpr uint32_t branch_op_code_mask = 0b111111;
constexpr uint32_t branch_link_op_code = 0b100101;
constexpr uint32_t branch_op_code = 0b000101;
}  // namespace

Elf64_Addr branch_destination(const std::byte* branch_inst,
                              Elf64_Addr branch_instruction_vaddr) {
  // https://developer.arm.com/documentation/ddi0602/2023-06/Base-Instructions/BL--Branch-with-Link-?lang=en
  const uint32_t inst = *reinterpret_cast<const uint32_t*>(branch_inst);
  auto rel_div_4 = inst & (~(branch_op_code_mask << 26));
  auto rel = rel_div_4 * 4;
  return rel + branch_instruction_vaddr;
}

// https://developer.arm.com/documentation/ddi0602/2023-06/Base-Instructions/BL--Branch-with-Link-?lang=en
void patch_branch_with_return(std::byte* instruction_ptr, Elf64_Addr src_vaddr,
                              Elf64_Addr dst_vaddr) {
  int32_t rel = dst_vaddr - src_vaddr;
  rel /= 4;

  auto* inst = reinterpret_cast<uint32_t*>(instruction_ptr);

  *inst = rel;

  *inst &= ~(branch_op_code_mask << 26);

  constexpr auto op_code = branch_link_op_code << 26;

  *inst |= (op_code);
}

// b imm26
// 000101 imm26
// imm26 = rel / 4
// The rel is offset from the current instruction (b xxx)
// The patched jump instruction is always 4 bytes.
// https://developer.arm.com/documentation/ddi0602/2023-06/Base-Instructions/B--Branch-
void patch_branch(std::byte* instruction_ptr, Elf64_Addr src_vaddr,
                  Elf64_Addr dst_vaddr) {
  int32_t rel = dst_vaddr - src_vaddr;
  rel /= 4;

  auto* inst = reinterpret_cast<uint32_t*>(instruction_ptr);

  *inst = rel;

  *inst &= ~(branch_op_code_mask << 26);

  constexpr auto op_code = branch_op_code << 26;

  *inst |= (op_code);
}

}  //  namespace vf::redirection