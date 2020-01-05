#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#define OUT_ELF_FILE	"test.elf"
#define PHNUM	1
#define LOAD_VADDR	0x400000

const char load_data_char_list[] =
	"\n !\"#$%&'()*+,-./0123456789:;<=>?@"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"[\\]^_`"
	"abcdefghijklmnopqrstuvwxyz"
	"{|}~";
static unsigned char load_data_char_list_len;

const unsigned char load_data_loop[] = {
	0xeb, 0xfe		/* jmp . */
};
#define LOAD_DATA_LOOP_SZ	2

const unsigned char load_data_exit[] = {
	0x48, 0x31, 0xff,				/* xor	%rdi,	%rdi */
	0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,	/* mov	$60,	%rax */
	0x0f, 0x05					/* syscall */
};
#define LOAD_DATA_EXIT_SZ	16

const unsigned char load_data_write[] = {
	0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,	/* mov	$1,	%rdi */
	0x48, 0xc7, 0xc6, 0x78, 0x00, 0x40, 0x00,	/* mov	$0x400078,%rsi*/
	0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,	/* mov	$1,	%rdx */
	0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,	/* mov	$1,	%rax */
	0x0f, 0x05,					/* syscall */
	0x48, 0x31, 0xff,				/* xor	%rdi,	%rdi */
	0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,	/* mov	$60,	%rax */
	0x0f, 0x05					/* syscall */
};
#define LOAD_DATA_WRITE_SZ	42

const unsigned char load_data_write2[] = {
	0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,	/* mov	$1,	%rdi */
	0x48, 0xc7, 0xc6, 0x78, 0x00, 0x40, 0x00,	/* mov	$0x400078,%rsi*/
	0x48, 0x83, 0xc6, 0x01,				/* add	$1,	%rsi */
	0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,	/* mov	$1,	%rdx */
	0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,	/* mov	$1,	%rax */
	0x0f, 0x05,					/* syscall */
	0x48, 0x31, 0xff,				/* xor	%rdi,	%rdi */
	0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,	/* mov	$60,	%rax */
	0x0f, 0x05					/* syscall */
};
#define LOAD_DATA_WRITE2_SZ	46

#define LOAD_DATA_SZ	LOAD_DATA_WRITE2_SZ
#define LOAD_DATA	load_data_write2

static void write_elf64_ehdr(FILE *fp)
{
	Elf64_Ehdr ehdr;
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_ident[EI_ABIVERSION] = 0;
	unsigned char i;
	for (i = EI_PAD; i < EI_NIDENT; i++)
		ehdr.e_ident[i] = 0;
	ehdr.e_type = ET_EXEC;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_phoff = sizeof(Elf64_Ehdr);
	ehdr.e_shoff = 0;
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof(Elf64_Ehdr);
	ehdr.e_phentsize = sizeof(Elf64_Phdr);
	ehdr.e_phnum = PHNUM;
	ehdr.e_shentsize = 0;
	ehdr.e_shnum = 0;
	ehdr.e_shstrndx = SHN_UNDEF;

	ehdr.e_entry =
		LOAD_VADDR + sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * PHNUM)
		+ load_data_char_list_len;

	size_t n = fwrite(&ehdr, 1, sizeof(Elf64_Ehdr), fp);
	if (n != sizeof(Elf64_Ehdr)) {
		perror("fwrite(ehdr)");
		exit(EXIT_FAILURE);
	}
}

static void write_elf64_phdr(FILE *fp)
{
	Elf64_Phdr phdr;
	phdr.p_type = PT_LOAD;
	phdr.p_flags = PF_X | PF_R;
	phdr.p_offset = 0;
	phdr.p_vaddr = LOAD_VADDR;
	phdr.p_paddr = phdr.p_vaddr;
	phdr.p_filesz = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * PHNUM)
		+ load_data_char_list_len + LOAD_DATA_SZ;
	phdr.p_memsz = phdr.p_filesz;
	phdr.p_align = 0x200000;

	size_t n = fwrite(&phdr, 1, sizeof(Elf64_Phdr), fp);
	if (n != sizeof(Elf64_Phdr)) {
		perror("fwrite(phdr)");
		exit(EXIT_FAILURE);
	}
}

static void write_load_data(FILE *fp)
{
	size_t n;

	n = fwrite(load_data_char_list, 1, load_data_char_list_len, fp);
	if (n != load_data_char_list_len) {
		perror("fwrite(char list)");
		exit(EXIT_FAILURE);
	}

	n = fwrite(LOAD_DATA, 1, LOAD_DATA_SZ, fp);
	if (n != LOAD_DATA_SZ) {
		perror("fwrite(load data)");
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	printf("char list addr: 0x%08lx\n",
	       LOAD_VADDR + sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * PHNUM));

	load_data_char_list_len = strlen(load_data_char_list);

	FILE *fp = fopen(OUT_ELF_FILE, "w+b");
	if (fp == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	write_elf64_ehdr(fp);
	write_elf64_phdr(fp);
	write_load_data(fp);

	fclose(fp);

	return EXIT_SUCCESS;
}
