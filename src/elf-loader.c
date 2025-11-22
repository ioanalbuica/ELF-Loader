// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <elf.h>

#define STACK_SIZE 8388608
#define POINTERS_SIZE 16384
#define STRINGS_SIZE 16384
#define PAGE_SIZE 4096

struct ATENTRY {
	unsigned long id;
	unsigned long value;
};

void *memset(void *source, int value, size_t num)
{
	for (size_t i = 0; i < num; i++)
		((unsigned char *)source)[i] = (unsigned char)value;
	return source;
}

size_t strlen(const char *str)
{
	size_t i = 0;

	while (1) {
		if (str[i] == 0)
			break;
		i++;
	}
	return i;
}

void *memcpy(void *destination, const void *source, size_t num)
{
	for (size_t i = 0; i < num; i++)
		((char *)destination)[i] = ((char *)source)[i];
	return destination;
}

void get_random_bytes(char *buf, int len)
{
	int fd = open("dev/random", O_RDONLY, 1);

	read(fd, buf, len);
	close(fd);
}


void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	void *elf_contents = map_elf(filename);
	char *elf_byte_contents = (char *)elf_contents;

	if (elf_byte_contents[0] != 0x7f || elf_byte_contents[1] != 'E' || elf_byte_contents[2] != 'L' || elf_byte_contents[3] != 'F')
		exit(3);

	if (elf_byte_contents[4] != 2)
		exit(4);

	unsigned long load_base = 0;

	if (*(unsigned short *)(elf_contents + 0x10) == ET_DYN) {
		load_base = (unsigned long)mmap(NULL, 1000 * PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		munmap((void *)load_base, 1000 * PAGE_SIZE);
	}

	unsigned long e_entry = *(unsigned long *)(elf_contents + 0x18);
	unsigned int e_phoff = *(unsigned int *)(elf_contents + 0x20);
	unsigned short e_phentsize = *(unsigned short *)(elf_contents + 0x36);
	unsigned short e_phnum = *(unsigned short *)(elf_contents + 0x38);

	for (int i = 0; i < e_phnum; i++) {
		unsigned int p_type = *(unsigned int *)(elf_contents + e_phoff + i * e_phentsize);

		if (p_type != 1)
			continue;

		unsigned int p_flags = *(unsigned int *)(elf_contents + e_phoff + i * e_phentsize + 0x4);
		unsigned long p_offset = *(unsigned long *)(elf_contents + e_phoff + i * e_phentsize + 0x8);
		unsigned long p_vaddr = *(unsigned long *)(elf_contents + e_phoff + i * e_phentsize + 0x10);
		unsigned long p_filesz = *(unsigned long *)(elf_contents + e_phoff + i * e_phentsize + 0x20);
		unsigned long p_memsz = *(unsigned long *)(elf_contents + e_phoff + i * e_phentsize + 0x28);

		unsigned long aligned_addr = (p_vaddr + load_base) & (-PAGE_SIZE);
		unsigned long map_size = p_memsz + p_vaddr + load_base - aligned_addr;

		mmap((void *)aligned_addr, map_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		memcpy((void *)(p_vaddr + load_base), elf_contents + p_offset, p_filesz);
		if (p_memsz > p_filesz)
			memset((void *)(load_base + p_vaddr + p_filesz), 0, p_memsz - p_filesz);

		mprotect((void *)aligned_addr, map_size, ((p_flags & 1) << 2) | (p_flags & 2) | (p_flags >> 2 & 1));
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */
	void *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
	void *argc_addr = stack + STACK_SIZE - POINTERS_SIZE - STRINGS_SIZE;
	void *strs_addr = stack + STACK_SIZE - STRINGS_SIZE;
	void *esp = argc_addr;
	size_t len = 0;
	char rand[16];
	int envc = 0;

	memset(stack, 0, STACK_SIZE);
	get_random_bytes(rand, 16);
	while (envp[envc])
		envc++;

	*((unsigned long *)esp) = argc;
	esp += sizeof(unsigned long);
	for (int i = 0; i < argc; i++) {
		len = strlen(argv[i]) + 1;
		memcpy(strs_addr, argv[i], len);
		*(void **)esp = strs_addr;
		strs_addr += len;
		esp += sizeof(void *);
	}
	*(void **)esp = NULL;
	esp += sizeof(void *);

	for (int i = 0; i < envc; i++) {
		len = strlen(envp[i]) + 1;
		memcpy(strs_addr, envp[i], len);
		*(void **)esp = strs_addr;
		strs_addr += len;
		esp += sizeof(void *);
	}
	*(void **)esp = NULL;
	esp += sizeof(void *);

	struct ATENTRY *at = (struct ATENTRY *)esp;
	int i = 0;

	at[i].id = AT_PHENT;
	at[i].value = e_phentsize;
	i++;

	at[i].id = AT_PHNUM;
	at[i].value = e_phnum;
	i++;

	at[i].id = AT_PAGESZ;
	at[i].value = PAGE_SIZE;
	i++;

	at[i].id = AT_BASE;
	at[i].value = 0;
	i++;

	at[i].id = AT_ENTRY;
	at[i].value = e_entry + load_base;
	i++;

	at[i].id = AT_UID;
	at[i].value = getuid();
	i++;

	at[i].id = AT_RANDOM;
	at[i].value = (unsigned long)rand;
	i++;

	at[i].id = AT_NULL;
	at[i].value = 0;
	i++;

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */
	// TODO: Set the entry point and the stack pointer
	void (*entry)() = (void (*)())(e_entry + load_base);

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(argc_addr), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
