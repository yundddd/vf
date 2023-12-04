#pragma once
#include <cstddef>

namespace vf::common {

// WARNING: these functions rely on the cc_nostdlib_binary() rule's linker
// script and startup assembler to work. In other words, they only work inside
// the virus. These are necessary to prevent compiler from generating
// instructions that rely on .got.
std::byte* get_parasite_start_address();

std::byte* get_parasite_end_address();

std::byte* get_parasite_patch_address();

std::ptrdiff_t get_parasite_len();

ptrdiff_t get_patch_return_offset_from_parasite_start();

}  // namespace vf::common