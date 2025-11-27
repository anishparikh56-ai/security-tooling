// mync.c - a tiny netcat-like tool
// Compile: gcc -o mync mync.c -Wall
// Usage examples:
//   mync google.com 80          -> connect (then type HTTP requests)
//   mync -l 1337                -> listen on port 1337
//   mync -l 1337 -e ./myshell   -> reverse shell server
//   mync 10.0.0.5 1-1000          -> simple port scanner

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

void usage(char *name) {
    printf("Usage:\n");
    printf("  %s host port              - connect to host:port\n", name);
    printf("  %s -l port [-e cmd]       - listen on port (optionally exec cmd)\n", name);
    printf("  %s host start-end         - scan ports\n", name);
    exit(1);
}

int create_socket() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        exit(1);
    }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    return s;
}

void connect_mode(char *host, int port) {
    int s = create_socket();
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) {
            fprintf(stderr, "Can't resolve %s\n", host);
            exit(1);
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }

    // bidirectional copy between stdin/stdout and socket
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(s, &fds);
        int maxfd = s + 1;

        if (select(maxfd, &fds, NULL, NULL, NULL) < 0) break;

        if (FD_ISSET(0, &fds)) {
            char buf[4096];
            int n = read(0, buf, sizeof(buf));
            if (n <= 0) break;
            send(s, buf, n, 0);
        }
        if (FD_ISSET(s, &fds)) {
            char buf[4096];
            int n = recv(s, buf, sizeof(buf), 0);
            if (n <= 0) break;
            write(1, buf, n);
        }
    }
    close(s);
}

void listen_mode(int port, char *exec_cmd) {
    int server = create_socket();

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(server, 1) < 0) {
        perror("listen");
        exit(1);
    }

    printf("[+] Listening on port %d\n", port);

    while (1) {
        int client = accept(server, NULL, NULL);
        if (client < 0) continue;

        printf("[+] Connection received\n");

        if (exec_cmd) {
            dup2(client, 0);
            dup2(client, 1);
            dup2(client, 2);
            execl("/bin/sh", "sh", "-c", exec_cmd, NULL);
            perror("execl");
            exit(1);
        } else {
            // same bidirectional copy as connect_mode
            while (1) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(0, &fds);
                FD_SET(client, &fds);
                int maxfd = client + 1;

                if (select(maxfd, &fds, NULL, NULL, NULL) < 0) break;

                if (FD_ISSET(0, &fds)) {
                    char buf[4096];
                    ssize_t n = read(0, buf, sizeof(buf));
                    if (n <= 0) break;
                    send(client, buf, n, 0);
                }
                if (FD_ISSET(client, &fds)) {
                    char buf[4096];
                    ssize_t n = recv(client, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    write(1, buf, n);
                }
            }
        }
        close(client);
    }
    close(server);
}

void scan_mode(char *host, int start, int end) {
    for (int port = start; port <= end; port++) {
        int s = create_socket();
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host, &addr.sin_addr);

        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);

        connect(s, (struct sockaddr*)&addr, sizeof(addr));

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv = {0, 500000}; // 0.5s timeout

        if (select(s+1, NULL, &wfds, NULL, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) printf("%s:%d open\n", host, port);
        }
        close(s);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) usage(argv[0]);

    if (strcmp(argv[1], "-l") == 0) {
        if (argc < 3) usage(argv[0]);
        int port = atoi(argv[2]);
        char *exec_cmd = NULL;
        if (argc > 4 && strcmp(argv[3], "-e") == 0) {
            exec_cmd = argv[4];
        }
        listen_mode(port, exec_cmd);
    } else if (strchr(argv[2], '-') != NULL) {
        // scan mode
        char *host = argv[1];
        int dash = strchr(argv[2], '-') - argv[2];
        int start = atoi(argv[2]);
        int end = atoi(argv[2] + dash + 1);
        scan_mode(host, start, end);
    } else {
        // connect mode
        char *host = argv[1];
        int port = atoi(argv[2]);
        connect_mode(host, port);
    }

    return 0;
}
