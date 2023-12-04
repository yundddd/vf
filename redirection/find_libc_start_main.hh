#pragma once

#include <elf.h>
#include <optional>
#include <span>

namespace vf::redirection {
std::optional<Elf64_Off> find_glibc_main_bl_instruction_offset(
    std::span<std::byte> victim, Elf64_Off search_start);

}  //  namespace vf::redirection