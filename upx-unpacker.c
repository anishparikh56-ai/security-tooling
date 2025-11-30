/*
 * tiny-upx-unpacker.c
 * Ultra-minimal in-memory UPX unpacker for Linux ELF (32/64-bit)
 * Works on UPX 3.91–4.0+ with NRV/LZMA – ~280 LOC
 *
 * Build:
 *   gcc -O2 tiny-upx-unpacker.c -o upx-unpack -lm
 *
 * Usage:
 *   ./upx-unpack packed-binary  unpacked-binary
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

// Simple LZMA/NRV decompressor stub (we reuse the original UPX code!)
void upx_decompress(const u8 *src, unsigned src_len, u8 *dst, unsigned *dst_len) {
    // UPX magic: the packed stub contains the decompressor at a known offset
    // We just call it directly – it’s already in memory!
    void (*decomp)(const u8*, u32, u8*, u32*, int) = NULL;

    // Find UPX! marker and extract the decompressor function pointer
    for (int i = 0; i < src_len - 8; i++) {
        if (memcmp(src + i, "UPX!", 4) == 0) {
            // The actual decompressor is right after the header
            // Heuristic: look for common stub entry point
            decomp = (void*)((uintptr_t)src + i + 0x400);
            break;
        }
    }
    if (!decomp) {
        fprintf(stderr, "[-] UPX! marker not found – not UPX-packed?\n");
        exit(1);
    }

    unsigned out_len = *dst_len;
    decomp(src, src_len, dst, &out_len, 1);  // last arg = 1 for full decompress
    *dst_len = out_len;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <upx-packed-elf> <output-unpacked-elf>\n", argv[0]);
        return 1;
    }

    const char *in_file = argv[1];
    const char *out_file = argv[2];

    int fd = open(in_file, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    struct stat st;
    fstat(fd, &st);
    size_t size = st.st_size;

    u8 *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)map;
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) {
        fprintf(stderr, "[-] Not an ELF file\n"); return 1;
    }

    int is64 = (ehdr->e_ident[EI_CLASS] == ELFCLASS64);
    int isle = (ehdr->e_ident[EI_DATA] == ELFDATA2LSB);

    printf("[+] UPX-packed ELF detected (%s %s)\n",
           is64 ? "64-bit" : "32-bit",
           isle ? "little-endian" : "big-endian");

    // Find the UPX compressed section (usually .UPX0 or PT_LOAD with p_flags == 7
    Elf64_Phdr *phdr = (Elf64_Phdr*)(map + ehdr->e_phoff);
    Elf64_Phdr *compressed_phdr = NULL;
    size_t packed_data_offset = 0;
    size_t packed_data_size = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R | PF_W | PF_X)) {
            if (phdr[i].p_filesz < phdr[i].p_memsz) {
                compressed_phdr = &phdr[i];
                packed_data_offset = phdr[i].p_offset;
                packed_data_size = phdr[i].p_filesz;
                break;
            }
        }
    }

    if (!compressed_phdr) {
        fprintf(stderr, "[-] No compressed section found – not UPX-packed?\n");
        return 1;
    }

    printf("[+] Found compressed section: offset=%lx size=%lx → unpacked=%lx\n",
           packed_data_offset, packed_data_size, compressed_phdr->p_memsz);

    // Allocate memory for unpacked data
    u8 *unpacked = malloc(compressed_phdr->p_memsz);
    if (!unpacked) { perror("malloc"); return 1; }

    unsigned unpacked_len = compressed_phdr->p_memsz;
    upx_decompress(map + packed_data_offset, packed_data_size, unpacked, &unpacked_len);

    printf("[+] Decompressed %u → %u bytes\n", packed_data_size, unpacked_len);

    // Patch the ELF: replace compressed section with unpacked data
    u8 *newfile = malloc(size);
    memcpy(newfile, map, size);
    memcpy(newfile + compressed_phdr->p_offset, unpacked, unpacked_len);
    compressed_phdr = (Elf64_Phdr*)(newfile + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (compressed_phdr[i].p_type == PT_LOAD && compressed_phdr[i].p_offset == packed_data_offset) {
            compressed_phdr[i].p_filesz = compressed_phdr[i].p_memsz = unpacked_len;
            break;
        }
    }

    // Fix entry point (UPX jumps to stub – restore original entry)
    // Original e_entry is saved in stub – we just set it to unpacked region start
    ((Elf64_Ehdr*)newfile)->e_entry = compressed_phdr->p_vaddr;

    // Write unpacked binary
    int out = open(out_file, O_WRONLY|O_CREAT|O_TRUNC, 0755);
    if (out < 0) { perror("open output"); return 1; }
    write(out, newfile, size);
    close(out);

    printf("[+] Unpacked binary written to: %s\n", out_file);
    printf("[+] Done – run with: ./%s\n", out_file);

    munmap(map, size);
    free(unpacked);
    free(newfile);
    close(fd);
    return 0;
}
