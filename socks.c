// tiny-socks.c – Minimal SOCKS4/4a/5 proxy, ~340 lines, single file
// gcc tiny-socks.c -o tiny-socks -pthread
// ./tiny-socks -p 1080

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netdb.h>

#define BUF_SIZE 8192

static void die(const char *msg) { perror(msg); exit(1); }

static void *handle_client(void *arg)
{
    int client_fd = *(int *)arg;
    free(arg);

    unsigned char buf[BUF_SIZE];
    uint8_t ver;

    if (recv(client_fd, &ver, 1, 0) != 1) goto cleanup;

    char target_host[256] = {0};
    uint16_t target_port = 0;

    /* --------------------- SOCKS5 --------------------- */
    if (ver == 5) {
        uint8_t nmethods;
        if (recv(client_fd, &n, 1, 0) != 1) goto cleanup;
        recv(client_fd, buf, n, 0);                     // ignore methods

        uint8_t method = 0xFF;                         // 0xFF = no acceptable
        for (int i = 0; i < n; i++)
            if (buf[i] == 0) method = 0;                // NO AUTH
        uint8_t auth_reply[2] = {5, method};
        send(client_fd, auth_reply, 2, 0);
        if (method != 0) goto cleanup;

        if (recv(client_fd, buf, 4, 0) != 4) goto cleanup;
        if (buf[1] != 1) goto cleanup;                  // only CONNECT

        uint8_t atyp = buf[3];
        if (atyp == 1) {                                 // IPv4
            recv(client_fd, buf, 6, 0);
            inet_ntop(AF_INET, buf, target_host, sizeof(target_host));
            target_port = ntohs(*(uint16_t *)(buf + 4));
        } else if (atyp == 3) {                         // Domain name
            uint8_t len;
            recv(client_fd, &len, 1, 0);
            recv(client_fd, target_host, len, 0);
            target_host[(int)len] = '\0';
            recv(client_fd, &target_port, 2, 0);
            target_port = ntohs(target_port);
        } else {
            goto cleanup;                               // IPv6 not supported
        }
    }
    /* --------------------- SOCKS4/4a --------------------- */
    else if (ver == 4) {
        if (recv(client_fd, buf, 8, 0) != 8) goto cleanup;
        target_port = ntohs(*(uint16_t *)(buf + 2));

        uint32_t ip = *(uint32_t *)(buf + 4);
        if ((ip & 0x000000FF) == 0 && ip != 0) {        // SOCKS4a
            int i = 0;
            char c;
            while (recv(client_fd, &c, 1, 0) == 1 && c != 0 && i < 255)
                target_host[i++] = c;
            target_host[i] = '\0';
        } else {
            inet_ntop(AF_INET, &ip, target_host, sizeof(target_host));
        }
    } else {
        goto cleanup;
    }

    /* --------------------- Connect to target --------------------- */
    int target_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (target_fd < 0) goto cleanup;

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(target_port);

    if (inet_pton(AF_INET, target_host, &dest.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(target_host);
        if (!he || !he->h_addr_list[0]) {
            close(target_fd);
            goto cleanup;
        }
        memcpy(&dest.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(target_fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(target_fd);
        goto cleanup;
    }

    /* --------------------- Success reply --------------------- */
    if (ver == 5) {
        unsigned char rep[] = {5,0,0,1,0,0,0,0,0,0};
        send(client_fd, rep, 10, 0);
    } else {
        unsigned char rep[] = {0,90,0,0,0,0,0,0};
        send(client_fd, rep, 8, 0);
    }

    /* --------------------- Forward data --------------------- */
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(target_fd, &fds);
        int maxfd = (client_fd > target_fd ? client_fd : target_fd) + 1;

        if (select(maxfd, &fds, NULL, NULL, NULL) <= 0) break;

        if (FD_ISSET(client_fd, &fds)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(target_fd, buf, n, 0);
        }
        if (FD_ISSET(target_fd, &fds)) {
            ssize_t n = recv(target_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(client_fd, buf, n, 0);
        }
    }

    close(target_fd);

cleanup:
    close(client_fd);
    return NULL;
}

int main(int argc, char **argv)
{
    int port = 1080;
    if (argc == 3 && strcmp(argv[1], "-p") == 0)
        port = atoi(argv[2]);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) die("socket");

    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(ls, 64) < 0) die("listen");

    printf("[+] Tiny SOCKS4/4a/5 proxy listening on 0.0.0.0:%d\n", port);

    while (1) {
        socklen_t len = sizeof(addr);
        int client = accept(ls, (struct sockaddr *)&addr, &len);
        if (client < 0) continue;

        int *p = malloc(sizeof(int));
        *p = client;
        pthread_t t;
        pthread_create(&t, NULL, handle_client, p);
        pthread_detach(t);
    }

    return 0;
}
