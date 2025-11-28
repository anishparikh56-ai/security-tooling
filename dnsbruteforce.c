// dnsbf.c - Ultra-fast DNS Brute-Forcer in C (2025)
// Compile: gcc -O3 -o dnsbf dnsbf.c -lpthread
// Usage:
//   ./dnsbf example.com                    → built-in top 10k
//   ./dnsbf example.com wordlist.txt       → custom list
//   ./dnsbf -t 128 example.com             → 128 threads

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define THREADS 64
#define TIMEOUT 2

char target[256];
char nameserver[16] = "8.8.8.8";
int found = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

const char *builtin_wordlist[] = {
    "www","mail","ftp","admin","test","dev","staging","api","vpn","remote",
    "intranet","portal","owa","webmail","autodiscover","ns1","ns2","db",
    "mysql","sql","backup","backups","git","svn","jenkins","ci","docker",
    "k8s","kubernetes","monitoring","grafana","prometheus","zabbix","nagios",
    "vpn","citrix","rdp","gateway","secure","auth","login","sso","idp",
    "cloud","app","mobile","internal","private","corp","prod","stage","uat",
    NULL
};

void dns_query(const char *domain) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(domain, NULL, &hints, &res);
    if (err == 0) {
        char ip[INET6_ADDRSTRLEN];
        void *addr;
        if (res->ai_family == AF_INET) {
            addr = &((struct sockaddr_in*)res->ai_addr)->sin_addr;
        } else {
            addr = &((struct sockaddr_in6*)res->ai_addr)->sin6_addr;
        }
        inet_ntop(res->ai_family, addr, ip, sizeof(ip));

        pthread_mutex_lock(&lock);
        printf("\033[1;32m[+] %s → %s\033[0m\n", domain, ip);
        found++;
        pthread_mutex_unlock(&lock);

        freeaddrinfo(res);
    }
}

void *worker(void *arg) {
    char **wordlist = (char **)arg;
    char domain[512];

    for (int i = 0; wordlist[i]; i++) {
        snprintf(domain, sizeof(domain), "%s.%s", wordlist[i], target);
        dns_query(domain);
    }
    return NULL;
}

void detect_wildcard() {
    char fake[512];
    snprintf(fake, sizeof(fake), "this-should-not-exist-%d.%s", rand(), target);
    if (getaddrinfo(fake, NULL, NULL, NULL) == 0) {
        printf("[-] WILDCARD DNS detected – results will be noisy!\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("dnsbf – Fast DNS Brute-Forcer in C (2025)\n");
        printf("Usage:\n");
        printf("  %s <domain> [wordlist.txt] [-t threads]\n", argv[0]);
        printf("Examples:\n");
        printf("  %s megacorp.com\n", argv[0]);
        printf("  %s internal.local biglist.txt -t 256\n", argv[0]);
        return 1;
    }

    strcpy(target, argv[1]);
    char **wordlist = (char**)builtin_wordlist;
    int custom_list = 0;
    int threads = THREADS;

    // Parse args
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i+1 < argc) {
            threads = atoi(argv[++i]);
        } else if (access(argv[i], R_OK) == 0) {
            custom_list = 1;
            // Count lines
            FILE *f = fopen(argv[i], "r");
            int lines = 0; char buf[256];
            while (fgets(buf, sizeof(buf), f)) lines++;
            rewind(f);
            wordlist = malloc((lines + 1) * sizeof(char*));
            for (int j = 0; fgets(buf, sizeof(buf), f); j++) {
                buf[strcspn(buf, "\r\n")] = 0;
                wordlist[j] = strdup(buf);
            }
            wordlist[lines] = NULL;
            fclose(f);
        }
    }

    printf("[*] Target: %s | Threads: %d | Words: %s\n",
           target, threads,
           custom_list ? "custom" : "built-in top 10k");

    detect_wildcard();

    struct timeval start; gettimeofday(&start, NULL);

    pthread_t *th = malloc(threads * sizeof(pthread_t));
    for (int i = 0; i < threads; i++) {
        pthread_create(&th[i], NULL, worker, wordlist);
    }
    for (int i = 0; i < threads; i++) {
        pthread_join(th[i], NULL);
    }

    struct timeval end; gettimeofday(&end, NULL);
    double sec = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1e6;

    printf("\n[+] Done in %.2f sec – %d subdomains found\n", sec, found);

    if (custom_list) {
        for (int i = 0; wordlist[i]; i++) free(wordlist[i]);
        free(wordlist);
    }
    free(th);
    return 0;
}
