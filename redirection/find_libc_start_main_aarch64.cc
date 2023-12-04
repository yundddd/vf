#include "redirection/find_libc_start_main.hh"

namespace vf::redirection {
std::optional<Elf64_Off> find_glibc_main_bl_instruction_offset(
    std::span<std::byte> victim, Elf64_Off search_start) {
  // https://developer.arm.com/documentation/ddi0602/2023-06/Base-Instructions/BL--Branch-with-Link-?lang=en
  // https://github.com/bminor/glibc/blob/master/sysdeps/aarch64/start.S
  constexpr uint32_t bl_mask = 0b100101;
  auto cur = search_start;
  size_t max_instructions_to_search = 32;
  while (max_instructions_to_search--) {
    const uint32_t* cur_instruction =
        reinterpret_cast<const uint32_t*>(&victim[cur]);
    if ((*cur_instruction >> 26) == bl_mask) {
      return cur;
    }
    cur += 4;
  }
  return std::nullopt;
}

}  //  namespace vf::redirection