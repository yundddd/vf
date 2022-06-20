#pragma once
#include "common/file_descriptor.hh"
#include "common/mmap.hh"

namespace vt::infector {
bool silvio_infect(vt::common::Mmap<PROT_READ> host_mapping,
                   vt::common::Mmap<PROT_READ | PROT_WRITE> parasite_mapping,
                   vt::common::Mmap<PROT_READ | PROT_WRITE> output_mapping);
}