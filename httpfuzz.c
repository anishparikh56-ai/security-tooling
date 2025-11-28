// httpfuzz.c - Ultra-fast HTTP Verb/Method Fuzzer in C (2025)
// Compile: gcc -O3 -o httpfuzz httpfuzz.c -lpthread
// Usage:   ./httpfuzz https://target.com
//          ./httpfuzz http://10.10.10.8/api/ -t 100

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define THREADS 64
SSL_CTX *ctx = NULL;

const char *methods[] = {
    "GET","POST","PUT","DELETE","OPTIONS","HEAD","TRACE","CONNECT","PATCH",
    "PROPFIND","PROPPATCH","MKCOL","COPY","MOVE","LOCK","UNLOCK",
    "VERSION-CONTROL","REPORT","CHECKOUT","CHECKIN","UNCHECKOUT","MKWORKSPACE",
    "UPDATE","LABEL","MERGE","BASELINE-CONTROL","MKACTIVITY",
    "ORDERPATCH","ACL","SEARCH","BCOPY","BDELETE","BMOVE","BPROPFIND","BPROPPATCH",
    "NOTIFY","POLL","SUBSCRIBE","UNSUBSCRIBE",
    "DEBUG","BREW","WHEN","DO","BREW","WHEN","PROPFPATCH","REPORT",
    NULL
};

const char *dangerous[] = {"PUT","DELETE","PROPFIND","MOVE","COPY","MKCOL","DEBUG","BREW","WHEN","DO"};

char target_host[256];
char target_path[512] = "/";
int target_port = 80;
int is_https = 0;
int found_any = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void send_request(SSL *ssl, int sock, const char *method) {
    char request[1024];
    snprintf(request, sizeof(request),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: httpfuzz/2025\r\n"
        "Connection: close\r\n"
        "\r\n", method, target_path, target_host);

    if (is_https) SSL_write(ssl, request, strlen(request));
    else write(sock, request, strlen(request));
}

void check_method(const char *method) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(target_port);
    inet_pton(AF_INET, target_host, &server.sin_addr);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(sock);
        return;
    }

    SSL *ssl = NULL;
    if (is_https) {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(sock);
            return;
        }
    }

    send_request(ssl, sock, method);

    char resp[4096] = {0};
    int n = is_https ? SSL_read(ssl, resp, sizeof(resp)-1) : read(sock, resp, sizeof(resp)-1);

    if (n > 0) {
        resp[n] = 0;
        char *code = strstr(resp, "HTTP/1.") ? strstr(resp, " ") + 1 : NULL;
        if (code) code = strtok(code, " ");

        int is_danger = 0;
        for (int i = 0; dangerous[i]; i++) {
            if (strcmp(method, dangerous[i]) == 0) { is_danger = 1; break; }
        }

        if (strstr(resp, "200") || strstr(resp, "201") || strstr(resp, "204") ||
            strstr(resp, "PUT") || strstr(resp, "DELETE") || strstr(resp, "PROPFIND")) {

            pthread_mutex_lock(&lock);
            found_any = 1;
            printf("\033[1;32m[+] %s → %s %s\033[0m", method,
                   code ? code : "???",
                   is_danger ? "← DANGEROUS" : "");
            if (strstr(resp, "Microsoft") || strstr(resp, "PROPFIND")) {
                printf("  → WebDAV ENABLED!");
            }
            if (strstr(resp, "DEBUG")) printf("  → DEBUG MODE?");
            printf("\n");
            pthread_mutex_unlock(&lock);
        }
        else if (strstr(resp, "405") == NULL && strstr(resp, "501") == NULL) {
            pthread_mutex_lock(&lock);
            printf("\033[1;33m[*] %s → %s (unusual)\033[0m\n", method, code ? code : "???");
            pthread_mutex_unlock(&lock);
        }
    }

    if (is_https) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(sock);
}

void *worker(void *arg) {
    const char **list = (const char **)arg;
    for (int i = 0; list[i]; i++) {
        check_method(list[i]);
        usleep(1000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("httpfuzz – Fast HTTP Verb/Method Fuzzer in C (2025)\n");
        printf("Usage:\n");
        printf("  %s http://target.com\n", argv[0]);
        printf("  %s https://intranet.local/api/\n", argv[0]);
        printf("  %s http://10.0.0.5 -t 128\n", argv[0]);
        return 1;
    }

    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());

    char *url = argv[1];
    if (strncmp(url, "https://", 8) == 0) {
        is_https = 1;
        target_port = 443;
        url += 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        url += 7;
    }

    char *path = strchr(url, '/');
    if (path) {
        strcpy(target_path, path);
        *path = 0;
    }
    strcpy(target_host, url);

    printf("[*] Target: %s%s (port %d) | Threads: %d\n",
           target_host, target_path, target_port, THREADS);

    pthread_t th[THREADS];
    for (int i = 0; i < THREADS; i++) {
        pthread_create(&th[i], NULL, worker, (void*)methods);
    }
    for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);

    if (!found_any) printf("\033[1;31m[-] No interesting methods found (405/501 only)\033[0m\n");
    else printf("\n\033[1;35m[+] Done – dangerous methods found above!\033[0m\n");

    if (is_https) SSL_CTX_free(ctx);
    return 0;
}
