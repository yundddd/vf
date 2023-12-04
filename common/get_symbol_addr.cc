#include "common/get_symbol_addr.hh"

namespace vf::common {
extern "C" {  // need to refer to symbols without name mangling
// We rely on the linker script to provide these symbols.
extern std::byte __parasite_start[];
extern std::byte __parasite_end[];
// This one comes from startup script.
extern std::byte _patch_return[];
}
// These are necessary to prevent compiler from generating instructions that
// rely on .got.
std::byte* get_parasite_start_address() {
  std::byte* ret = nullptr;
  //  1: get the parasite_start symbol's page address
  //  2: add the lower 12 bits offset to acquire full address.
  //  3: return to caller.
#if defined(__aarch64__)
  asm("adrp %0, __parasite_start\n"
      "add %0, %0, :lo12:__parasite_start\n"
      : "=r"(ret));
#elif defined(__x86_64__)
  // load effective address (rip relative)
  // att syntax
  asm("lea __parasite_start(%%rip), %0\n" : "=r"(ret));
#else
#error "not supported arch"
#endif
  return ret;
}

std::byte* get_parasite_end_address() {
  std::byte* ret = nullptr;
#if defined(__aarch64__)
  asm("adrp %0, __parasite_end\n"
      "add %0, %0, :lo12:__parasite_end\n"
      : "=r"(ret));
#elif defined(__x86_64__)
  asm("lea __parasite_end(%%rip), %0\n" : "=r"(ret));
#else
#error "not supported arch"
#endif
  return ret;
}

std::byte* get_parasite_patch_address() {
  std::byte* ret = nullptr;
#if defined(__aarch64__)
  asm("adrp %0, _patch_return\n"
      "add %0, %0, :lo12:_patch_return\n"
      : "=r"(ret));
#elif defined(__x86_64__)
  asm("lea _patch_return(%%rip), %0\n" : "=r"(ret));
#else
#error "not supported arch"
#endif
  return ret;
}

std::ptrdiff_t get_parasite_len() {
  return get_parasite_end_address() - get_parasite_start_address();
}

ptrdiff_t get_patch_return_offset_from_parasite_start() {
  return get_parasite_patch_address() - get_parasite_start_address();
}

}  // namespace vf::common