#pragma once
namespace vt::common {
extern "C" {  // need to refer to symbols without name mangling
// We rely on the linker script to provide these symbols.
extern long long __parasite_start[];
extern long long __parasite_end[];

// These are necessary to prevent compiler from generating instructions that
// rely on .got.
void* get_parasite_start_address() {
  unsigned long ret = 0;
  //  1: get the parasite_start symbol's page address
  //  2: add the lower 12 bits offset to acquire full address.
  //  3: return to caller.
#if defined(__aarch64__)
  asm volatile(
      "adrp %0, __parasite_start\n"
      "add %0, %0, :lo12:__parasite_start\n"
      : "=r"(ret));
#elif defined(__x86_64__)
  // load effective address (rip relative)
  // att syntax
  asm volatile("lea __parasite_start(%%rip), %0\n" : "=r"(ret));
#else
#error "not supported arch"
#endif
  return (void*)ret;
}

void* get_parasite_end_address() {
  unsigned long ret = 0;
#if defined(__aarch64__)
  asm volatile(
      "adrp %0, __parasite_end\n"
      "add %0, %0, :lo12:__parasite_end\n"
      : "=r"(ret));
#elif defined(__x86_64__)
  asm volatile("lea __parasite_end(%%rip), %0\n" : "=r"(ret));
#else
#error "not supported arch"
#endif
  return (void*)ret;
}

unsigned long long get_parasite_len() {
  return (char*)get_parasite_end_address() -
         (char*)get_parasite_start_address();
}
}
}  // namespace vt::common
