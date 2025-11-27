// strings2.c - Strings 2.0  (2025 edition)
// Compile: gcc -o strings2 strings2.c -lm
// Usage:   ./strings2 malware.exe
//          ./strings2 firmware.bin -l 8 -e 7.0
//          ./strings2 dump.mem -x

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <stdint.h>

#ifndef M_LOG2E
#define M_LOG2E 1.44269504088896340736
#endif

double entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i]) {
            double p = (double)freq[i] / len;
            h -= p * log2(p);
        }
    }
    return h;
}

int is_printable_ascii(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 32 || buf[i] > 126) {
            if (buf[i] != '\n' && buf[i] != '\t' && buf[i] != '\r') return 0;
        }
    }
    return 1;
}

void print_string(const uint8_t *buf, size_t len, unsigned long long offset, int show_hex) {
    double ent = entropy(buf, len);

    const char *color = "";
    if (ent < 4.0)       color = "\033[32m";   // green  – very interesting
    else if (ent < 6.0)  color = "\033[33m";   // yellow – maybe
    else                 color = "\033[31m";   // red    – probably garbage

    printf("%s0x%08llx  [ent:%.2f]  ", color, offset, ent);

    if (show_hex) {
        for (size_t i = 0; i < len; i++) {
            if (isprint(buf[i]) || buf[i] == '\n' || buf[i] == '\t')
                printf("%c", buf[i]);
            else
                printf(".");
        }
        printf("  |  ");
        for (size_t i = 0; i < len; i++) printf("%02x ", buf[i]);
        printf("\n");
    } else {
        fwrite(buf, 1, len, stdout);
        printf("\n");
    }
    printf("\033[0m");
}

void process_buffer(uint8_t *buf, size_t size, int min_len, double max_ent, int show_hex) {
    size_t i = 0;

    while (i < size) {
        // Skip non-printable runs
        while (i < size && !isprint(buf[i]) && buf[i] != '\n' && buf[i] != '\t') i++;
        if (i >= size) break;

        size_t start = i;
        while (i < size && (isprint(buf[i]) || buf[i] == '\n' || buf[i] == '\t')) i++;

        size_t len = i - start;
        if (len < (size_t)min_len) continue;

        // Unicode detection (UTF-16LE / UTF-16BE)
        if (len >= 4 && buf[start] == 0 && buf[start+2] == 0 && isprint(buf[start+1])) {
            // Likely UTF-16LE
            size_t j = start;
            while (j + 1 < size && (buf[j] == 0 && isprint(buf[j+1]))) j += 2;
            if ((j - start) / 2 >= (size_t)min_len) {
                printf("0x%08llx  [UTF-16LE]  ", (unsigned long long)start);
                for (size_t k = start + 1; k < j; k += 2) {
                    if (isprint(buf[k])) putchar(buf[k]);
                }
                printf("\n");
            }
            i = j;
            continue;
        }

        double ent = entropy(buf + start, len);
        if (ent > max_ent) continue;  // skip high-entropy junk

        print_string(buf + start, len, start, show_hex);
    }
}

int main(int argc, char **argv) {
    int min_len = 6;
    double max_entropy = 7.0;
    int show_hex = 0;
    char *filename = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i+1 < argc) min_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "-e") == 0 && i+1 < argc) max_entropy = atof(argv[++i]);
        else if (strcmp(argv[i], "-x") == 0) show_hex = 1;
        else filename = argv[i];
    }

    if (!filename) {
        fprintf(stderr, "Strings 2.0 - modern strings with entropy + unicode + color\n");
        fprintf(stderr, "Usage: %s [-l minlen] [-e max_entropy] [-x] <file>\n", argv[0]);
        fprintf(stderr, "  -l 8      → min length 8 (default 6)\n");
        fprintf(stderr, "  -e 6.5    → hide strings with entropy > 6.5 (default 7.0)\n");
        fprintf(stderr, "  -x        → show hex dump next to string\n");
        return 1;
    }

    FILE *f = fopen(filename, "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc(size);
    if (!buf) { perror("malloc"); fclose(f); return 1; }

    fread(buf, 1, size, f);
    fclose(f);

    printf("Strings from '%s' (min_len=%d, max_entropy=%.1f)\n\n", filename, min_len, max_entropy);

    process_buffer(buf, size, min_len, max_entropy, show_hex);

    free(buf);
    return 0;
}
