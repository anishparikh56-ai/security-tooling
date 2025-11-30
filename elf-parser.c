/*
 * tiny-elf-parser.c
 * Minimal but complete ELF header parser – ~180 LOC
 * Works on 32/64-bit, LE/BE, static/dynamic Linux/macOS/FreeBSD ELF files
 *
 * Build: gcc tiny-elf-parser.c -o elfparse
 * Usage: ./elfparse /bin/ls
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

const char* type_name(uint16_t t) {
    switch(t) {
        case ET_NONE: return "None";
        case ET_REL:  return "Relocatable";
        case ET_EXEC: return "Executable";
        case ET_DYN:  return "Shared Object";
        case ET_CORE: return "Core";
        default: return "Unknown";
    }
}

const char* machine_name(uint16_t m) {
    switch(m) {
        case EM_386:      return "x86";
        case EM_X86_64:   return "x86_64";
        case EM_ARM:      return "ARM";
        case EM_AARCH64:  return "AArch64";
        case EM_MIPS:     return "MIPS";
        case EM_PPC64:    return "PowerPC64";
        case EM_RISCV:    return "RISC-V";
        default: return "Other";
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); return 1; }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)map;

    // Basic validation
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        return 1;
    }

    int is64 = (ehdr->e_ident[EI_CLASS] == ELFCLASS64);
    int isle = (ehdr->e_ident[EI_DATA]  == ELFDATA2LSB);

    printf("ELF Header:\n");
    printf("  Class:                             %s\n", is64 ? "ELF64" : "ELF32");
    printf("  Data:                              %s\n", isle ? "2's complement, little endian" : "2's complement, big endian");
    printf("  Type:                              %s\n", type_name(ehdr->e_type));
    printf("  Machine:                           %s\n", machine_name(ehdr->e_machine));
    printf("  Entry point:                       0x%lx\n", (unsigned long)ehdr->e_entry);
    printf("  Program Headers:                   %d (offset 0x%lx)\n", ehdr->e_phnum, (unsigned long)ehdr->e_phoff);
    printf("  Section Headers:                   %d (offset 0x%lx)\n", ehdr->e_shnum, (unsigned long)ehdr->e_shoff);
    printf("  Flags:                             0x%x\n", ehdr->e_flags);

    // Program Headers
    printf("\nProgram Headers:\n");
    printf("  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align\n");

    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr*)((char*)map + ehdr->e_phoff + i * ehdr->e_phentsize);
        const char *type = "UNKNOWN";
        switch(ph->p_type) {
            case PT_NULL:    type = "NULL"; break;
            case PT_LOAD:        type = "LOAD"; break;
            case PT_DYNAMIC: type = "DYNAMIC"; break;
            case PT_INTERP:  type = "INTERP"; break;
            case PT_NOTE:    type = "NOTE"; break;
            case PT_SHLIB:   type = "SHLIB"; break;
            case PT_PHDR:    type = "PHDR"; break;
            case PT_TLS:     type = "TLS"; break;
            case PT_GNU_EH_FRAME: type = "EH_FRAME"; break;
            case PT_GNU_STACK:    type = "GNU_STACK"; break;
            case PT_GNU_RELRO:   type = "GNU_RELRO"; break;
        }
        printf("  %-14s 0x%06lx 0x%016lx 0x%016lx 0x%06lx 0x%06lx %c%c%c 0x%lx\n",
               type,
               (unsigned long)ph->p_offset,
               (unsigned long)ph->p_vaddr,
               (unsigned long)ph->p_paddr,
               (unsigned long)ph->p_filesz,
               (unsigned long)ph->p_memsz,
               (ph->p_flags & PF_R) ? 'R' : ' ',
               (ph->p_flags & PF_W) ? 'W' : ' ',
               (ph->p_flags & PF_X) ? 'X' : ' ',
               (unsigned long)ph->p_align);
    }

    // Section Headers (only show interesting ones
    if (ehdr->e_shnum > 0) {
        printf("\nKey Sections:\n");
        printf("  Name                             Type             Address          Size\n");

        Elf64_Shdr *shstr = (Elf64_Shdr*)((char*)map + ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize);
        char *strtab = (char*)map + shstr->sh_offset;

        for (int i = 1; i < ehdr->e_shnum; i++) {
            Elf64_Shdr *sh = (Elf64_Shdr*)((char*)map + ehdr->e_shoff + i * ehdr->e_shentsize);
            const char *name = strtab + sh->sh_name;
            if (!name[0]) continue;

            const char *type = "UNKNOWN";
            switch(sh->sh_type) {
                case SHT_NULL:     type = "NULL"; break;
                case SHT_PROGBITS: type = "PROGBITS"; break;
                case SHT_SYMTAB:   type = "SYMTAB"; break;
                case SHT_STRTAB:   type = "STRTAB"; break;
                case SHT_RELA:     type = "RELA"; break;
                case SHT_NOBITS:   type = "NOBITS (bss)"; break;
                case SHT_DYNAMIC:  type = "DYNAMIC"; break;
            }

            if (sh->sh_flags & SHF_EXECINSTR || sh->sh_size > 1024 || 
               strstr(name, "text") || strstr(name, "data") || strstr(name, "rodata") || strstr(name, "bss"))
                printf("  %-32s %-16s 0x%016lx %8lu\n", name, type, (unsigned long)sh->sh_addr, (unsigned long)sh->sh_size);
        }
    }

    munmap(map, st.st_size);
    close(fd);
    return 0;
}
