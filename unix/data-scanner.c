#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

void do_elf_checks(Elf32_Ehdr *ehdr)
{
        if (strncmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
                fprintf(stderr, "File not ELF\n");
                exit(1);
        }

        if (ehdr->e_type != ET_EXEC) {
                fprintf(stderr, "ELF type not ET_EXEC or ET_DYN\n");
                exit(1);
        }

        if (ehdr->e_machine != EM_386 && ehdr->e_machine != EM_486) {
                fprintf(stderr, "ELF machine type not EM_386 or EM_486\n");
                exit(1);
        }

        if (ehdr->e_version != EV_CURRENT) {
                fprintf(stderr, "ELF version not current\n");
                exit(1);
        }
}

int main(int argc, char *argv[])
{
	Elf32_Ehdr ehdr;
        Elf32_Phdr *phdr;
	int fd, entry, i, exit_level = 0;
	char *data;

	if (argc != 2) {
		fprintf(stderr, "usage: %s file\n", argv[0]);
		exit(1);
	}

        fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
                perror("open");
                exit(1);
        }

        if (read(fd, &ehdr, sizeof(ehdr)) < 0) {
                perror("read");
                exit(1);
        }

	do_elf_checks(&ehdr);

	printf("Starting scan... ");
	entry = ehdr.e_entry;

/* allocate memory for phdr tables */

        data = (char *)malloc(sizeof(*phdr)*ehdr.e_phnum);
        if (data == NULL) {
                perror("malloc");
                exit(1);
        }

/* read the phdr's */

        if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
                perror("lseek");
                exit(1);
        }

        if (read(fd, data, sizeof(*phdr)*ehdr.e_phnum) < 0) {
                perror("read");
                exit(1);
        }

        phdr = (Elf32_Phdr *)data;

        for (i = 0; i < ehdr.e_phnum; i++) {
                if (phdr->p_type == PT_LOAD && phdr->p_offset) {
/* is this the data segment ? */
			int vaddr = phdr->p_vaddr;

			if (
				entry >= vaddr &&
				entry < (vaddr + phdr->p_memsz)
			) {
				printf(
					"\n\n"
					"SUSPICIOUS ENTRY POINT "
					"IN DATA SEGMENT."
					"\n\n"
				);

				exit_level = 1;
				break;
			}
		}

		++phdr;
	}	

	printf("DONE\n");
	exit(exit_level);
}

