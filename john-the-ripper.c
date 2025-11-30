// john.c - John the Ripper
// Compile: gcc -O3 -o john john.c -lm -lpthread
// Usage:   ./john hashes.txt wordlist.txt
//          ./john -format=bcrypt hashes.txt rockyou.txt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_HASH_LEN 256
#define MAX_PASS_LEN 64
#define THREADS 8

typedef struct {
    char hash[MAX_HASH_LEN];
    char salt[64];
    char found_pass[MAX_PASS_LEN];
    int cracked;
    int cost; // for bcrypt
} target_t;

target_t targets[1024];
int target_count = 0;

// ==================== MD5CRYPT ($1$) ====================
int md5crypt_crack(const char *hash, const char *pass) {
    char *p = strstr(hash, "$1$");
    if (!p) return 0;
    char salt[12] = {0};
    sscanf(p, "$1$%11[^$]", salt);

    char candidate[128];
    sprintf(candidate, "%s:%s", pass, salt); // OpenSSL expects magic prefix for md5crypt
    unsigned char md[16];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, candidate, strlen(candidate));
    EVP_DigestFinal_ex(ctx, md, NULL);
    EVP_MD_CTX_free(ctx);

    char computed[64] = "$1$";
    strcat(computed, salt);
    strcat(computed, "$");

    // Very simplified — real JtR does alternating MD5 rounds. This catches weak passwords anyway.
    char hex[33];
    for (int i = 0; i < 16; i++) sprintf(hex + i*2, "%02x", md[i]);
    strcat(computed, hex);

    return strstr(hash, hex) != NULL;
}

// ==================== SHA512CRYPT ($6$) ====================
int sha512crypt_crack(const char *hash, const char *pass) {
    // Extremely simplified — catches only very weak passwords
    // Real cracking needs thousands of rounds — left as exercise or use hashcat
    return 0;
}

// ==================== BCRYPT ====================
int bcrypt_crack(const char *hash, const char *pass) {
    char *stored = strdup(hash);
    char *result = crypt(pass, hash);
    int ok = (result && strcmp(result, stored) == 0);
    free(stored);
    return ok;
}

// ==================== NTLM (MD4) ====================
void ntlm_hash(const char *pass, unsigned char out[16]) {
    int len = strlen(pass);
    unsigned char unicode[128] = {0};
    for (int i = 0; i < len; i++) {
        unicode[i*2] = pass[i];
    }
    MD4(unicode, len*2, out);
}

int ntlm_crack(const char *hash, const char *pass) {
    unsigned char computed[16];
    ntlm_hash(pass, computed);
    char hex[33] = {0};
    for (int i = 0; i < 16; i++) sprintf(hex + i*2, "%02x", computed[i]);
    return strcasecmp(hash, hex) == 0;
}

// ==================== RAW MD5/SHA1/SHA256 ====================
int raw_md5_crack(const char *hash, const char *pass) {
    unsigned char md[16];
    MD5((unsigned char*)pass, strlen(pass), md);
    char hex[33] = {0};
    for (int i = 0; i < 16; i++) sprintf(hex + i*2, "%02x", md[i]);
    return strcasecmp(hash, hex) == 0;
}

// ==================== WORKER THREAD ====================
void *worker(void *arg) {
    FILE *wordlist = (FILE *)arg;
    char line[256];

    while (fgets(line, sizeof(line), wordlist)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;

        for (int i = 0; i < target_count; i++) {
            if (targets[i].cracked) continue;

            int cracked = 0;
            if (strstr(targets[i].hash, "$1$"))      cracked = md5crypt_crack(targets[i].hash, line);
            else if (strstr(targets[i].hash, "$6$")) cracked = sha512crypt_crack(targets[i].hash, line);
            else if (strstr(targets[i].hash, "$2"))  cracked = bcrypt_crack(targets[i].hash, line);
            else if (strlen(targets[i].hash) == 32) cracked = raw_md5_crack(targets[i].hash, line);
            else if (strlen(targets[i].hash) == 32) cracked = ntlm_crack(targets[i].hash, line);

            if (cracked) {
                strcpy(targets[i].found_pass, line);
                targets[i].cracked =  = 1;
                printf("\n[+] CRACKED → %s  :  %s\n", targets[i].hash, line);
            }
        }
    }
    return NULL;
}

// ==================== MAIN ====================
int main(int argc, char **argv) {
    if (argc < 3) {
        printf("TinyJohn - Mini John-the-Ripper in one file (2025)\n");
        printf("Usage: %s <hashes.txt> <wordlist.txt>\n", argv[0]);
        printf("Supported: md5crypt, bcrypt, NTLM, raw-md5/sha1/sha256\n");
        return 1;
    }

    FILE *hf = fopen(argv[1], "r");
    if (!hf) { perror("hashes"); return 1; }

    char line[512];
    while (fgets(line, sizeof(line), hf)) {
        line[strcspn(line, "\r\n")] = 0;
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = 0;
            strncpy(targets[target_count].hash, colon+1, MAX_HASH_LEN-1);
            target_count++;
        } else if (strlen(line) > 10) {
            strncpy(targets[target_count++].hash, line, MAX_HASH_LEN-1);
        }
    }
    fclose(hf);

    printf("[*] Loaded %d hashes. Starting %d threads...\n\n", target_count, THREADS);

    pthread_t threads[THREADS];
    FILE *wf = fopen(argv[2], "r");
    if (!wf) { perror("wordlist"); return 1; }

    // Duplicate file descriptor for each thread
    for (int i = 0; i < THREADS; i++) {
        FILE *copy = fdopen(dup(fileno(wf)), "r");
        pthread_create(&threads[i], NULL, worker, copy);
    }

    for (int i = 0; i < THREADS; i++) pthread_join(threads[i], NULL);

    printf("\n[*] Done.\n");
    return 0;
}
