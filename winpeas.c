// winpeas-c.c - Windows PrivEsc Enum in pure C (2025)
// Compile (x64): x86_64-w64-mingw32-gcc -O2 -o winpeas-c.exe winpeas-c.c -ladvapi32 -luserenv
// Compile (x86): i686-w64-mingw32-gcc -O2 -o winpeas-c-32.exe winpeas-c.c -ladvapi32 -luserenv
// Run:    winpeas-c.exe

#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <userenv.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "netapi32.lib")

void header(const char* t) {
    printf("\n\033[1;34m=== %s ===\033[0m\n", t);
}

void run(const char* cmd) {
    printf("\033[33m> %s\033[0m\n", cmd);
    system(cmd);
    printf("\n");
}

void check_token() {
    header("Current User & Privileges");
    char user[256], domain[256];
    DWORD sz = 256;
    GetUserNameEx(NameSamCompatible, user, &sz);
    printf("User: %s\n", user);

    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD len;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len)) {
            printf("UAC Elevation: %s\n", elevation.TokenIsElevated ? "YES (Admin)" : "No");
        }
        CloseHandle(token);
    }
}

void unquoted_paths() {
    header("Unquoted Service Paths");
    run("wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\"\"");
}

void writable_services() {
    header("Writable Service Binaries (Potential Hijack)");
    run("powershell -c \"Get-Acl 'C:\\Program Files*\\*.exe' 'C:\\*.exe' 2>$null | Where-Object {$_.Access | Where-Object {$_.IdentityReference -match 'Everyone|Users|BUILTIN\\\\Users' -and $_.FileSystemRights -match 'FullControl|Modify|Write'}} | Select-Object Path -Unique\" || echo '(PowerShell blocked)'");
}

void scheduled_tasks() {
    header("Scheduled Tasks with Writable Scripts");
    run("schtasks /query /fo LIST /v | findstr /i \"TaskName Command\"");
    run("dir \"C:\\Windows\\Tasks\" *.job 2>nul || echo '(no .job files)'");
}

void always_install_elevated() {
    header("AlwaysInstallElevated Registry Check");
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(val);
        if (RegQueryValueEx(hKey, "AlwaysInstallElevated", NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val == 1) {
            printf("[+] AlwaysInstallElevated = 1 in HKCU → MSI @pwn\n");
        }
        RegCloseKey(hKey);
    }
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(val);
        if (RegQueryValueEx(hKey, "AlwaysInstallElevated", NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val == 1) {
            printf("[+] AlwaysInstallElevated = 1 in HKLM → MSI @pwn\n");
        }
        RegCloseKey(hKey);
    }
}

void hotfixes() {
    header("Missing Critical Hotfixes (2025)");
    const char* critical[] = {
        "KB5034441", "PrintNightmare",
        "KB5028407", "Follina / MSDT",
        "KB5036893", "April 2024 Privilege Escalation",
        "KB5040435", "July 2025 ZeroLogon-like",
        NULL
    };
    char output[1024];
    FILE *fp = _popen("wmic qfe get HotFixID", "r");
    if (fp) {
        while (fgets(output, sizeof(output), fp)) {
            for (int i = 0; critical[i]; i += 2) {
                if (strstr(output, critical[i])) {
                    printf("[!] INSTALLED: %s (%s)\n", critical[i], critical[i+1]);
                }
            }
        }
        _pclose(fp);
    }
}

void interesting_files() {
    header("Interesting Files (SAM, Unattend, Credentials)");
    const char* files[] = {
        "C:\\Windows\\Panther\\Unattend.xml",
        "C:\\Windows\\Panther\\Unattended.xml",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\repair\\SAM",
        "C:\\unattend.xml",
        "C:\\sysprep\\sysprep.xml",
        NULL
    };
    for (int i = 0; files[i]; i++) {
        if (GetFileAttributes(files[i]) != INVALID_FILE_ATTRIBUTES) {
            printf("[+] EXISTS: %s\n", files[i]);
        }
    }
}

void path_hijack() {
    header("PATH Hijacking Candidates");
    char path[8192] = {0};
    GetEnvironmentVariable("PATH", path, sizeof(path));
    char *p = strtok(path, ";");
    while (p) {
        char test[1024];
        snprintf(test, sizeof(test), "%s\\cmd.exe", p);
        if (GetFileAttributes(test) == INVALID_FILE_ATTRIBUTES) {
            printf("Writable PATH dir (no cmd.exe): %s\n", p);
        }
        p = strtok(NULL, ";");
    }
}

int main() {
    printf("\033[1;31m");
    printf("  __      __._.\n");
    printf(" /  \\    /  \\| |\n");
    printf(" \\   \\/\\/   /| |\n");
    printf("  \\        / | |\n");
    printf("   \\__/\\__/  |_|\n");
    printf("\033[0m");
    printf("       winpeas-c – Windows Enum in C (2025)\n\n");

    check_token();
    unquoted_paths();
    writable_services();
    scheduled_tasks();
    always_install_elevated();
    hotfixes();
    interesting_files();
    path_hijack();

    printf("\033[1;35m[+] Enumeration complete. Happy hunting.\033[0m\n");
    return 0;
}
