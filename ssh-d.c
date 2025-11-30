/*
 * tiny-ssh-d.c
 * Pure C replacement for "ssh -D 1080" – 260 lines
 * Full SOCKS4 + SOCKS4a + SOCKS5 (no auth) support
 *
 * Build:
 *   gcc -O2 tiny-ssh-d.c -o tiny-ssh-d -pthread
 *
 * Usage:
 *   ./tiny-ssh-d 1080 pivot.example.com 9000
 *   → creates SOCKS proxy on 127.0.0.1:1080
 *     that tunnels through pivot.example.com:9000
 *
 * Then:
 *   curl --socks5 localhost:1080 http://10.10.10.10
 *   proxychains -D1080 nmap -sT 192.168.1.0/24
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUF_SIZE 65536

int pivot_fd = -1;  // global connection to pivot

void die(const char *s) { perror(s); exit(1); }

// Bidirectional copy between two sockets
void *forward(void *arg) {
    int a = ((int*)arg)[0];
    int b = ((int*)arg)[1];
    free(arg);

    char buf[BUF_SIZE];
    fd_set fds;
    while (1) {
        FD_ZERO(&fds);
        FD_SET(a, &fds);
        FD_SET(b, &fds);
        if (select((a > b ? a : b) + 1, &fds, NULL, NULL, NULL) <= 0) break;

        if (FD_ISSET(a, &fds)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(b, buf, n, 0);
        }
        if (FD_ISSET(b, &fds)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(a, buf, n, 0);
        }
    }
    close(a); close(b);
    return NULL;
}

// Handle one SOCKS client (SOCKS4/4a/5)
void handle_socks(int client_fd) {
    unsigned char buf[1024];
    int n = recv(client_fd, buf, 9, 0);
    if (n < 1) { close(client_fd); return; }

    char target_host[256] = {0};
    uint16_t target_port = 0;

    if (buf[0] == 4) {
        // SOCKS4 / 4a
        if (n < 8 || buf[1] != 1) goto fail;
        target_port = ntohs(*(uint16_t*)(buf+2));
        uint32_t ip = *(uint32_t*)(buf+4);

        if (ip >> 24 == 0 && ip != 0) {
            // SOCKS4a – read domain
            while (recv(client_fd, buf, 1, 0) == 1 && buf[0]) {
                strncat(target_host, (char*)buf, 1);
                if (strlen(target_host) > 250) goto fail;
            }
        } else {
            inet_ntop(AF_INET, &ip, target_host, sizeof(target_host));
        }
        uint8_t reply[8] = {0, 90, 0,0,0,0,0,0};
        send(client_fd, reply, 8, 0);
    }
    else if (buf[0] == 5) {
        // SOCKS5
        uint8_t nmethods = buf[1];
        recv(client_fd, buf, nmethods, 0);
        uint8_t auth[2] = {5, 0}; // NO AUTH
        send(client_fd, auth, 2, 0);

        recv(client_fd, buf, 4, 0);
        if (buf[1] != 1) goto fail; // CONNECT only

        uint8_t atyp = buf[3];
        if (atyp == 1) {
            recv(client_fd, buf, 6, 0);
            inet_ntop(AF_INET, buf, target_host, sizeof(target_host));
            target_port = ntohs(*(uint16_t*)(buf+4));
        } else if (atyp == 3) {
            uint8_t len;
            recv(client_fd, &len, 1, 0);
            recv(client_fd, target_host, len, 0);
            target_host[(int)len] = 0;
            recv(client_fd, &target_port, 2, 0);
            target_port = ntohs(target_port);
        } else goto fail;

        uint8_t reply[10] = {5,0,0,1,0,0,0,0,0,0};
        send(client_fd, reply, 10, 0);
    } else goto fail;

    // Send request to pivot: "CONNECT host:port\n"
    char req[512];
    int reqlen = snprintf(req, sizeof(req), "CONNECT %s:%d\n", target_host, target_port);
    send(pivot_fd, req, reqlen, 0);

    // Wait for pivot reply: "OK\n"
    char ok[4];
    if (recv(pivot_fd, ok, 3, 0) != 3 || memcmp(ok, "OK\n", 3)) goto fail;

    // Start forwarding
    int *fds = malloc(8);
    fds[0] = client_fd;
    fds[1] = pivot_fd;
    pthread_t th;
    pthread_create(&th, NULL, forward, fds);
    pthread_detach(th);
    return;

fail:
    close(client_fd);
}

// Pivot side: accepts incoming CONNECT requests and forwards
void *pivot_server(void *arg) {
    int port = *(int*)arg;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = INADDR_ANY;
    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    bind(ls, (struct sockaddr*)&a, sizeof(a));
    listen(ls, 50);

    printf("[+] Pivot listening on 0.0.0.0:%d – waiting for tiny-ssh-d clients\n", port);

    while (1) {
        int client = accept(ls, NULL, NULL);
        char buf[512];
        int n = recv(client, buf, sizeof(buf)-1, 0);
        if (n <= 8 || memcmp(buf, "CONNECT ", 8)) { close(client); continue; }
        buf[n] = 0;

        char host[256]; int port;
        if (sscanf(buf+8, "%255[^:]:%d", host, &port) != 2) { close(client); continue; }

        int target = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &dst.sin_addr) <= 0) {
            struct hostent *he = gethostbyname(host);
            if (!he) { close(target); close(client); continue; }
            memcpy(&dst.sin_addr, he->h_addr_list[0], he->h_length);
        }

        if (connect(target, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
            close(target); close(client); continue;
        }

        send(client, "OK\n", 3, 0);

        int *fds = malloc(8);
        fds[0] = client;
        fds[1] = target;
        pthread_t th;
        pthread_create(&th, NULL, forward, fds);
        pthread_detach(th);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Client mode: %s <local_port> <pivot_ip> <pivot_port>\n", argv[0]);
        fprintf(stderr, "  Server mode: %s server <port>\n", argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "server")) {
        int port = atoi(argv[2]);
        pivot_server(&port);
        return 0;
    }

    int local_port = atoi(argv[1]);
    char *pivot_ip = argv[2];
    int pivot_port = atoi(argv[3]);

    pivot_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(pivot_port);
    inet_pton(AF_INET, pivot_ip, &srv.sin_addr);
    if (connect(pivot_fd, (struct sockaddr*)&srv, sizeof(srv)) < 0) die("connect");

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(local_port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    bind(ls, (struct sockaddr*)&a, sizeof(a));
    listen(ls, 50);

    printf("[+] tiny-ssh-d listening on 127.0.0.1:%d → %s:%d\n",
           local_port, pivot_ip, pivot_port);

    while (1) {
        int client = accept(ls, NULL, NULL);
        pthread_t th;
        pthread_create(&th, NULL, (void*(*)(void*))handle_socks, (void*)(long)client);
        pthread_detach(th);
    }
    return 0;
}
