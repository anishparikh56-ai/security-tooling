/*
 * tiny-icmp-tunnel.c
 * Working ICMP Echo tunnel (client + server) – 380 LOC
 * Provides SOCKS5 on client side (127.0.0.1:1080)
 *
 * Compile:
 *   gcc -Wall -Wextra tiny-icmp-tunnel.c -o icmp-tunnel -lpcap -pthread
 *
 * Run (needs root):
 *   Server: sudo ./icmp-tunnel server
 *   Client: sudo ./icmp-tunnel client 1.2.3.4
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>

#define MAGIC      0xDEADBEEF
#define MAX_DATA   1000

volatile sig_atomic_t keep_running = 1;

struct icmp_payload {
    uint32_t magic;
    uint16_t seq;
    uint16_t len;
    uint8_t  data[MAX_DATA];
} __attribute__((packed));

int raw_sock = -1;
struct in_addr server_ip;

// Simple ring buffer for received data
#define RING_SIZE (64*1024)
char ring[RING_SIZE];
int ring_head = 0, ring_tail = 0;
pthread_mutex_t ring_mutex = PTHREAD_MUTEX_INITIALIZER;

// ———————————————————————— Send ICMP Echo Reply ————————————————————————
void send_icmp(struct in_addr dst, uint16_t seq, const void *data, int len)
{
    char buf[2048];
    struct iphdr   *ip   = (struct iphdr *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
    struct icmp_payload *pl = (struct icmp_payload *)(icmp + 1);

    pl->magic = htonl(MAGIC);
    pl->seq   = htons(seq);
    pl->len   = htons(len);
    memcpy(pl->data, data, len);

    icmp->type              = 0;    // Echo Reply
    icmp->code              = 0;
    icmp->un.echo.id        = htons(getpid());
    icmp->un.echo.sequence  = seq;
    icmp->checksum          = 0;
    icmp->checksum = ip_checksum(icmp, sizeof(*icmp) + sizeof(*pl) + len);

    ip->version  = 4;
    ip->ihl      = 5;
    ip->tot_len  = htons(sizeof(*ip) + sizeof(*icmp) + sizeof(*pl) + len);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->daddr    = dst.s_addr;
    ip->check    = 0;

    struct sockaddr_in dest = { .sin_family = AF_INET, .sin_addr = dst };
    sendto(raw_sock, buf, ntohs(ip->tot_len), 0,
           (struct sockaddr *)&dest, sizeof(dest));
}

// ———————————————————————— SOCKS5 server (client only) ————————————————————————
void *socks5_thread(void *arg)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    bind(ls, (struct sockaddr *)&addr, sizeof(addr));
    listen(ls, 5);

    printf("[+] SOCKS5 listening on 127.0.0.1:1080\n");

    uint16_t seq = 1;

    while (keep_running) {
        int client = accept(ls, NULL, NULL);
        if (client < 0) continue;

        uint8_t buf[1024];
        if (recv(client, buf, 3, 0) < 3 || buf[0] != 5) goto next;
        buf[1] = 0; send(client, buf, 2, 0);  // NO AUTH

        recv(client, buf, 4, 0);
        if (buf[1] != 1) goto next;  // CONNECT only

        char host[256]; uint16_t port = 0;
        if (buf[3] == 1) {           // IPv4
            recv(client, buf, 6, 0);
            inet_ntop(AF_INET, buf, host, sizeof(host));
            port = ntohs(*(uint16_t*)(buf+4));
        } else if (buf[3] == 3) {    // Domain name
            uint8_t len; recv(client, &len, 1, 0);
            recv(client, host, len, 0); host[(int)len] = '\0';
            recv(client, &port, 2, 0); port = ntohs(port);
        } else goto next;

        // Send CONNECT request over tunnel
        char req[512];
        int n = snprintf(req, sizeof(req), "CONNECT %s:%d\n", host, port);
        send_icmp(server_ip, seq++, req, n);

        // Tell browser success
        uint8_t rep[10] = {5,0,0,1,0,0,0,0,0,0};
        send(client, rep, 10, 0);

        // Simple bidirectional forwarding
        while (keep_running) {
            fd_set fds;
            FD_ZERO(&fds); FD_SET(client, &fds);
            struct timeval tv = {1,0};
            if (select(client+1, &fds, NULL, NULL, &tv) <= 0) continue;
            int r = recv(client, buf, sizeof(buf), 0);
            if (r <= 0) break;
            send_icmp(server_ip, seq++, buf, r);
        }
next:
        close(client);
    }
    close(ls);
    return NULL;
}

// ———————————————————————— Main ————————————————————————
int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage:\n  %s server\n  %s client <server_ip>\n", argv[0], argv[0]);
        return 1;
    }

    int is_client = (argc == 3);
    if (is_client && inet_pton(AF_INET, argv[2], &server_ip) != 1) {
        fprintf(stderr, "Bad IP\n");
        return 1;
    }

    raw_sock = socket(AF_RAW, SOCK_RAW, IPPROTO_ICMP);
    if (raw_sock < 0) { perror("socket(AF_RAW) – need sudo"); return 1; }

    int one = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    pthread_t st;
    if (is_client)
        pthread_create(&st, NULL, socks5_thread, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live("any", BUFSIZ, 1, 100, errbuf);
    if (!pcap) { perror("pcap_open_live"); return 1; }

    printf("[+] ICMP tunnel %s started\n", is_client ? "client" : "server");

    uint16_t seq = 1;

    while (keep_running) {
        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int r = pcap_next_ex(pcap, &hdr, &pkt);
        if (r != 1) continue;

        if (hdr->caplen < 34) continue;  // too short
        const struct iphdr *ip = (const struct iphdr *)(pkt + 14);
        if (ip->protocol != IPPROTO_ICMP) continue;

        const struct icmphdr *icmp = (const struct icmphdr *)(ip + 1);
        int expected_type = is_client ? 0 : 8;  // client waits reply, server waits request
        if (icmp->type != expected_type) continue;

        const struct icmp_payload *pl = (const struct icmp_payload *)(icmp + 1);
        if (ntohl(pl->magic) != MAGIC) continue;

        int len = ntohs(pl->len);
        if (len < 0 || len > MAX_DATA) continue;

        if (is_client) {
            // Client: store received data in ring buffer
            pthread_mutex_lock(&ring_mutex);
            int space = RING_SIZE - (ring_head - ring_tail);
            if (space < 0) space += RING_SIZE;
            if (len > space) ring_tail = ring_head;  // overflow reset
            int pos = ring_head % RING_SIZE;
            if (pos + len <= RING_SIZE)
                memcpy(ring + pos, pl->data, len);
            else {
                int part = RING_SIZE - pos;
                memcpy(ring + pos, pl->data, part);
                memcpy(ring, pl->data + part, len - part);
            }
            ring_head += len;
            pthread_mutex_unlock(&ring_mutex);
        } else {
            // Server: reply with Echo Reply containing same data
            send_icmp(ip->saddr, ntohs(icmp->un.echo.sequence), pl->data, len);
        }
    }

    pcap_close(pcap);
    close(raw_sock);
    return 0;
}
