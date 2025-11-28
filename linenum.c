// cenum.c - Fast Linux PrivEsc Enum in pure C (2025)
// Compile: gcc -O2 -o cenum cenum.c
// Run:     ./cenum

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <sys/stat.h>

void header(const char *title) {
    printf("\n\033[1;34m=== %s ===\033[0m\n", title);
}

void run(const char *cmd) {
    printf("\033[33m$ %s\033[0m\n", cmd);
    fflush(stdout);
    system(cmd);
    printf("\n");
}

int is_readable(const char *path) {
    return access(path, R_OK) == 0;
}

void find_suid_sgid() {
    header("SUID/SGID Binaries (GTFOBins candidates)");
    run("find / -perm -u=s -o -perm -g=s -type f 2>/dev/null | grep -v '/snap/' | head -20");
}

void world_writable() {
    header("World-Writable Files (excluding /tmp, /dev/shm)");
    run("find / -writable -type f 2>/dev/null | grep -vE '/proc|/sys|/tmp|/dev/shm' | head -15");
}

void interesting_files() {
    header("Interesting Files");
    const char *files[] = {
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/root/.bash_history", "/home/*/.bash_history",
        "/var/log/auth.log", "/var/log/secure",
        "/var/www/html/config.php", "/opt/*.py",
        NULL
    };
    for (int i = 0; files[i]; i++) {
        if (is_readable(files[i])) {
            printf("  Readable: %s\n", files[i]);
            if (strstr(files[i], ".history")) run(("tail -20 " + (strlen(files[i]) > 15 ? "..." : "") + files[i]).c_str());
        }
    }
}

void kernel_exploits() {
    header("Kernel & Possible Exploits");
    struct utsname u;
    uname(&u);
    printf("OS: %s %s %s\n", u.sysname, u.release, u.machine);

    // Most common exploitable kernels (2025 still relevant)
    const char *vuln[] = {
        "5.4.0-",   "DirtyPipe (CVE-2022-0847)",
        "5.8.0-",   "DirtyPipe",
        "5.10.0-",  "DirtyPipe (some builds)",
        "4.15.",    "CVE-2021-4034 PwnKit",
        "5.15.",    "CVE-2022-25636 netfilter",
        NULL
    };
    for (int i = 0; vuln[i]; i += 2) {
        if (strstr(u.release, vuln[i])) {
            printf("  VULNERABLE → %s\n", vuln[i+1]);
        }
    }
}

void cron_jobs() {
    header("Cron Jobs (writable scripts?)");
    run("ls -la /etc/cron* /var/spool/cron* 2>/dev/null");
}

void services() {
    header("Running Services (as root?)");
    run("ps aux | grep '^root' | grep -vE 'kthreadd|rcu_gp' | head -10");
}

void sudo_l() {
    header("Sudo -l (what can we run as root?)");
    run("sudo -l 2>/dev/null || echo '[-] sudo -l failed (password required?)'");
}

void capabilities() {
    header("Files with Capabilities (cap_setuid+ep = root?)");
    run("getcap -r / 2>/dev/null | grep -v 'cap_chown'");
}

void docker_sudoers() {
    header("Docker / Container Escape Checks");
    if (is_readable("/.dockerenv")) printf("  Inside Docker container\n");
    if (getenv("DOCKER_CONTAINER")) printf("  Docker detected via env\n");
    run("id | grep -o 'docker\|root'");
}

int main() {
    printf("\033[1;31m");
    printf("  ___ _   _ _   _ _   _ __  __ \n");
    printf(" / ___| | | | \\ | | | | |  \\/  |\n");
    printf("| |   | | | |  \\| | | | | |\\/| |\n");
    printf("| |___| |_| | |\\  | |_| | |  | |\n");
    printf(" \\____|\\___/|_| \\_|\\___/|_|  |_|\n");
    printf("\033[0m");
    printf("        Linux Enum in C – 2025 Edition\n\n");

    if (geteuid() == 0) printf("\033[1;32m[+] Already root!\033[0m\n\n");
    else printf("[*] Current user: %s (uid=%d)\n\n", getlogin(), geteuid());

    kernel_exploits();
    sudo_l();
    find_suid_sgid();
    capabilities();
    cron_jobs();
    world_writable();
    interesting_files();
    services();
    docker_sudoers();

    printf("\033[1;35m[+] Enumeration complete. Go pwn.\033[0m\n");
    return 0;
}
