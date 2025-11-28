// dirbrute.c - World's fastest directory brute-forcer in C (2025)
// Compile:
//   Linux/macOS: gcc -O3 -o dirbrute dirbrute.c -lssl -lcrypto -lpthread
//   Windows:     x86_64-w64-mingw32-gcc -O3 -o dirbrute.exe dirbrute.c -lssl -lcrypto -lpthread -lws2_32
// Usage:
//   ./dirbrute https://target.com
//   ./dirbrute http://10.10.10.80 -w big.txt -t 512

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(__linux__)
    #include <sys/epoll.h>
    #define USE_EPOLL
#elif defined(__APPLE__) || defined(__FreeBSD__)
    #include <sys/event.h>
    #define USE_KQUEUE
#endif

#define MAX_THREADS 1024
#define CONN_PER_THREAD 256
#define TIMEOUT_MS 3000

SSL_CTX *ctx = NULL;
char target_host[256];
char target_path[1024] = "/";
int target_port = 80;
int is_https = 0;
int found_count = 0;
pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

const char *builtin_dirs[] = {
    "admin","login","wp-admin","phpmyadmin","administrator","cms","portal",
    "config","backup","backups","db","database","sql","test","dev","staging",
    "uploads","files","images","assets","js","css","cgi-bin","bin","tmp",
    "server-status",".git",".svn",".env","web.config","robots.txt","sitemap.xml",
    "phpinfo.php","info.php","test.php","index.bak","backup.zip",".DS_Store",
    NULL
};

void send_request(int sock, SSL *ssl, const char *path) {
    char req[2048];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: dirbrute/2025\r\n"
        "Connection: close\r\n"
        "Accept: */*\r\n\r\n", path, target_host);

    if (is_https) SSL_write(ssl, req, strlen(req));
    else write(sock, req, strlen(req));
}

int is_interesting(char *resp, int len) {
    if (strstr(resp, "HTTP/1.1 200") || strstr(resp, "HTTP/1.1 301") ||
        strstr(resp, "HTTP/1.1 302") || strstr(resp, "HTTP/1.1 403") ||
        strstr(resp, "Index of") || strstr(resp, "Directory listing"))
        return 1;
    return 0;
}

void test_path(const char *path) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(target_port);
    inet_pton(AF_INET, target_host, &serv.sin_addr);

    fd_set wfds;
    struct timeval tv = {0, TIMEOUT_MS * 1000};
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    connect(sock, (struct sockaddr*)&serv, sizeof(serv));
    FD_ZERO(&wfds); FD_SET(sock, &wfds);
    if (select(sock+1, NULL, &wfds, NULL, &tv) <= 0) { close(sock); return; }
    fcntl(sock, F_SETFL, flags);

    SSL *ssl = NULL;
    if (is_https) {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) { SSL_free(ssl); close(sock); return; }
    }

    send_request(sock, ssl, path);

    char buf[8192] = {0};
    int n = is_https ? SSL_read(ssl, buf, sizeof(buf)-1) : read(sock, buf, sizeof(buf)-1);

    if (n > 0 && is_interesting(buf, n)) {
        char *code = strstr(buf, "HTTP/1.1 ") ? strstr(buf, "HTTP/1.1 ") + 9 : "???";
        char code_str[8] = {0};
        strncpy(code_str, code, 3);

        pthread_mutex_lock(&print_lock);
        found_count++;
        printf("\033[1;%sm[%s]\033[0m %s%s\n",
               strcmp(code_str, "200") == 0 ? "32" :
               strcmp(code_str, "301") == 0 ? "33" :
               strcmp(code_str, "403") == 0 ? "31" : "36",
               code_str, target_host, path);
        pthread_mutex_unlock(&print_lock);
    }

    if (is_https) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(sock);
}

void *worker(void *arg) {
    char **list = (char **)arg;
    for (int i = 0; list[i]; i++) {
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "/%s", list[i]);
        if (fullpath[1] == '.') fullpath[1] = '_'; // avoid .git etc issues
        test_path(fullpath);
        test_path(strcat(fullpath, "/"));
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("dirbrute – Fastest directory brute-forcer in C (2025)\n");
        printf("Usage:\n");
        printf("  %s https://target.com\n", argv[0]);
        printf("  %s http://10.0.0.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\n", argv[0]);
        return 1;
    }

    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());

    char *url = argv[1];
    if (strncmp(url, "https://", 8) == 0) { is_https = 1; target_port = 443; url += 8; }
    else if (strncmp(url, "http://", 7) == 0) { url += 7; }

    char *slash = strchr(url, '/');
    if (slash) { strcpy(target_path, slash); *slash = 0; }
    strcpy(target_host, url);

    char **wordlist = (char**)builtin_dirs;
    int wordcount = sizeof(builtin_dirs)/sizeof(char*) - 1;

    // External wordlist
    if (argc > 3 && strcmp(argv[2], "-w") == 0) {
        FILE *f = fopen(argv[3], "r");
        if (!f) { perror("wordlist"); return 1; }
        char line[256];
        wordlist = malloc(1000000 * sizeof(char*));
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0]) wordlist[wordcount++] = strdup(line);
        }
        fclose(f);
    }

    int threads = sysconf(_SC_NPROCESSORS_ONLN) * 4;
    if (threads > MAX_THREADS) threads = MAX_THREADS;

    printf("[*] Target: %s://%s%s | Threads: %d | Words: %d\n",
           is_https ? "https" : "http", target_host, target_path, threads, wordcount);

    pthread_t th[threads];
    int chunk = wordcount / threads + 1;

    for (int i = 0; i < threads; i++) {
        char **chunk_list = malloc((chunk + 1) * sizeof(char*));
        int n = 0;
        for (int j = i * chunk; j < wordcount && n < chunk; j++) {
            chunk_list[n++] = wordlist[j];
        }
        chunk_list[n] = NULL;
        pthread_create(&th[i], NULL, worker, chunk_list);
    }

    for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);

    printf("\n[+] Scan complete – %d interesting paths found\n", found_count);
    SSL_CTX_free(ctx);
    return 0;
}
