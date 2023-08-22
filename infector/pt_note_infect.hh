#pragma once
#include "common/mmap.hh"

namespace vt::infector {

bool pt_note_infect64(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      common::Mmap<PROT_READ> parasite_mapping);

struct PtNoteInfect {
  static size_t output_size(size_t host_size, size_t parasite_size);
  bool operator()(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                  common::Mmap<PROT_READ> parasite_mapping) {
    return pt_note_infect64(std::move(host_mapping),
                            std::move(parasite_mapping));
  }
};

}  // namespace vt::infector