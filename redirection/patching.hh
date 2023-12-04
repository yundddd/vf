#pragma once

#include <elf.h>
#include <cstddef>

namespace vf::redirection {

// Decode the jmp/branch/branch link destination vaddr.
// @param branch_inst A pointer to the branch instruction.
// @param branch_instruction_vaddr The current branch instruction's vaddr.
Elf64_Addr branch_destination(const std::byte* branch_inst,
                              Elf64_Addr branch_instruction_vaddr);

// Patch an instruction to become a branch with return.
// @param instruction_ptr A pointer to the position to patch.
// @param src_vaddr Source vaddr. Used to calculate relative offset.
// @param dst_vaddr Destination vaddr. Used to calculate relative offset.
void patch_branch_with_return(std::byte* instruction_ptr, Elf64_Addr src_vaddr,
                              Elf64_Addr dst_vaddr);

// Patch an instruction to become a branch.
// @param instruction_ptr A pointer to the position to patch.
// @param src_vaddr Source vaddr. Used to calculate relative offset.
// @param dst_vaddr Destination vaddr. Used to calculate relative offset.
void patch_branch(std::byte* instruction_ptr, Elf64_Addr src_vaddr,
                  Elf64_Addr dst_vaddr);

}  //  namespace vf::redirection