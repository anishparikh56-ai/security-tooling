// zipcrack.c - Lightning-fast PKZIP (ZipCrypto) cracker in C (2025)
// Compile:
//   Linux/macOS: gcc -O3 -o zipcrack zipcrack.c -lpthread
//   Windows:     x86_64-w64-mingw32-gcc -O3 -o zipcrack.exe zipcrack.c -lpthread
// Usage:
//   ./zipcrack protected.zip
//   ./zipcrack file.zip rockyou.txt
//   ./zipcrack backup.zip -t 16

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef unsigned char u8;
typedef unsigned int  u32;

u32 crc_table[256];
int table_ready = 0;

void make_crc_table() {
    for (int n = 0; n < 256; n++) {
        u32 c = n;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ ((c & 1) ? 0xedb88320 : 0);
        crc_table[n] = c;
    }
    table_ready = 1;
}

u32 crc32(u32 crc, const u8 *buf, int len) {
    if (!table_ready) make_crc_table();
    crc = crc ^ 0xffffffff;
    for (int i = 0; i < len; i++)
        crc = crc_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffff;
}

u32 keys[3];

void init_keys(const char *pass) {
    keys[0] = 0x12345678;
    keys[1] = 0x23456789;
    keys[2] = 0x34567890;
    for (int i = 0; pass[i]; i++) {
        keys[0] = crc32(keys[0], (u8*)&pass[i], 1);
        keys[1] = (keys[1] + (keys[0] & 0xff)) * 0x8088405 + 1;
        keys[2] = crc32(keys[2], (u8*)&keys[1] >> 24, 1);
    }
}

u8 decrypt_byte() {
    u32 temp = (keys[2] & 0xffff) | 2;
    return (temp * (temp ^ 1)) >> 8;
}

int try_password(const char *pass, u8 *ciphertext, int len) {
    init_keys(pass);
    for (int i = 0; i < len; i++) {
        u8 c = ciphertext[i] ^ decrypt_byte();
        keys[0] = crc32(keys[0], &c, 1);
        keys[1] = (keys[1] + (keys[0] & 0xff)) * 0x8088405 + 1;
        keys[2] = crc32(keys[2], (u8*)&keys[1] >> 24, 1);
    }
    // Check last byte high bit (PKZIP magic)
    u8 last = ciphertext[len-1] ^ decrypt_byte();
    return (last & 0x80) || (keys[2] >> 16 == (ciphertext[len-1] ^ last));
}

typedef struct {
    char **list;
    u8 *ct;
    int ct_len;
    char *found;
    int done;
} task_t;

void *worker(void *arg) {
    task_t *t = (task_t*)arg;
    char **words = t->list;
    for (int i = 0; words[i] && !t->done; i++) {
        if (try_password(words[i], t->ct, t->ct_len)) {
            t->found = words[i];
            t->done = 1;
            printf("\033[1;32m[+] PASSWORD FOUND: %s\033[0m\n", words[i]);
            return NULL;
        }
    }
    return NULL;
}

const char *builtin[] = {
    "123456","password","123456789","12345","12345678","qwerty","abc123","111111",
    "admin","letmein","welcome","monkey","password123","sunshine","princess",
    "flower","football","iloveyou","admin123","password1","123123","000000",
    NULL
};

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("zipcrack – PKZIP (ZipCrypto) cracker in C (2025)\n");
        printf("Usage:\n");
        printf("  %s protected.zip [wordlist.txt]\n", argv[0]);
        printf("  %s backup.zip rockyou.txt\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    struct stat st;
    fstat(fd, &st);
    u8 *data = malloc(st.st_size);
    read(fd, data, st.st_size);
    close(fd);

    // Find encryption header (12 bytes before file data)
    u8 *ct = NULL;
    int ct_len = 0;
    for (off_t i = 30; i < st.st_size - 12; i++) {
        if (data[i] == 0x50 && data[i+1] == 0x4b && data[i+2] == 0x03 && data[i+4] == 0x14) {
            if (data[i+10] & 1) { // encrypted
                ct = data + i + 30 + 12; // skip local header + filename
                ct_len = 12;
                break;
            }
        }
    }
    if (!ct) {
        printf("[-] Not a password-protected legacy ZIP (or AES)\n");
        return 1;
    }

    char **wordlist = (char**)builtin;
    int words = 22;
    if (argc > 2) {
        FILE *f = fopen(argv[2], "r");
        if (!f) { perror("wordlist"); return 1; }
        char line[256];
        wordlist = malloc(10000000 * sizeof(char*));
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            wordlist[words++] = strdup(line);
        }
        fclose(f);
    }

    printf("[*] Loaded %d passwords | Threads: %d | Target: %s\n",
           words, sysconf(_SC_NPROCESSORS_ONLN), argv[1]);

    int threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t *th = malloc(threads * sizeof(pthread_t));
    task_t *tasks = calloc(threads, sizeof(task_t));

    for (int i = 0; i < threads; i++) {
        tasks[i].list = wordlist + (i * words / threads);
        tasks[i].ct = ct;
        tasks[i].ct_len = ct_len;
        pthread_create(&th[i], NULL, worker, &tasks[i]);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(th[i], NULL);
        if (tasks[i].found) {
            for (int j = 0; j < threads; j++) tasks[j].done = 1;
        }
    }

    if (!tasks[0].found) printf("\033[1;31m[-] Password not found in wordlist\033[0m\n");

    return 0;
}
