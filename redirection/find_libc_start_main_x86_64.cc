#include "redirection/find_libc_start_main.hh"
namespace vf::redirection {
std::optional<Elf64_Off> find_glibc_main_bl_instruction_offset(
    std::span<std::byte> victim, Elf64_Off search_start) {
  // https://github.com/bminor/glibc/blob/master/sysdeps/x86_64/start.S
  //  try to match two cases:
  //  case 1: e8 xx xx xx xx f4 xx xx (encoding)
  //  427c6b:       e8 40 22 fe ff          callq  409eb0
  //  427c70:       f4                      hlt
  //
  //  case 2: ff 15 xx xx xx xx f4 xx (encoding)
  //  14c5698:      ff 15 3a 99 a0 03       callq  *0x3a0993a(%rip)
  //  14c569e:      f4                      hlt
  constexpr uint64_t pattern1 = 0x0000f400000000e8;
  constexpr uint64_t pattern2 = 0x00f40000000015ff;
  constexpr uint64_t mask1 = 0xff00000000ff;
  constexpr uint64_t mask2 = 0xff00000000ffff;

  size_t max_bytes_to_search = 50;
  while (max_bytes_to_search--) {
    auto entry = *reinterpret_cast<uint64_t*>(&victim[search_start]);

    if (((entry & mask1) == pattern1) || ((entry & mask2) == pattern2)) {
      if (std::to_integer<uint8_t>(victim[search_start - 1]) == 0x67) {
        // If instruction is prefixed with addr32 just give up.
        break;
      }
      return search_start;
    }
    search_start++;
  }

  return std::nullopt;
}

}  //  namespace vf::redirection