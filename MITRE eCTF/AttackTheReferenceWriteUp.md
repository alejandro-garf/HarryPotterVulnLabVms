# eCTF 2026 — Attack the Reference Design
**Competition Writeup | CSUF Team | Design Phase Flag**

---

## Overview

This writeup documents the process of capturing four flags by attacking a deployment of the MITRE eCTF 2026 Reference Design. The reference design implements no security measures, making it vulnerable to a range of attacks. The attack package provided by the organizers was used to provision two Hardware Security Module (HSM) boards and interact with them using the eCTF host tools.

**Flags captured:**
- `ectf{boot_e2218e27c4d4255d}` — Boot Reference Flag
- `ectf{update_8193461bae8c46d1}` — Read Update Flag
- `ectf{design_f1ba8321b19521e6}` — Read Design Flag
- `ectf{steal_6dc6921061cf5b43}` — Steal Design Flag

---

## Environment

- **OS:** Linux Mint
- **Hardware:** Two MSP-LITO-L2228 attack boards (green sticker, secure bootloader), two XDS110 debuggers
- **Tools:** eCTF host tools via `uvx`

---

## Step 1 — Obtaining and Decrypting the Attack Package

The encrypted attack package was downloaded from the competition portal. The decryption key and command were provided by the organizers via Zulip.

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -salt -k 010203040506070809000a0b0c0d0e0f -in mitre.enc -out mitre.zip
```

After decryption, the attack package contained:
- `attacker.prot` — encrypted firmware image for the attacker HSM
- `engineer.prot` — encrypted firmware image for the engineer HSM
- `scenario_info.yaml` — scenario configuration including group IDs and attacker PIN

Inspecting `scenario_info.yaml` revealed the attacker PIN and group permissions:

```yaml
group_ids:
  calibration: 321b
  telemetry: '6209'
  update: a4b5
hsms:
  attacker:
    permissions: a4b5=--C:6209=R-C:321b=RWC
    pin: '405984'
```

---

## Step 2 — Flashing the Attack Boards

Two attack boards were connected to the host computer via their respective XDS110 debuggers. Each board was put into bootloader mode by holding the PB21 button and tapping NRST, confirmed by the LED blinking red.

Serial ports were identified by running `ls /dev/tty*` with and without each board plugged in. With both boards connected:

- **Attacker board:** `/dev/ttyACM2`, `/dev/ttyACM3`
- **Engineer board:** `/dev/ttyACM0`, `/dev/ttyACM1`
  
<img width="1299" height="775" alt="Flashedattckerboard" src="https://github.com/user-attachments/assets/21f8f1af-2440-4de2-b6d3-3dcf7b6f777e" />

<img width="1212" height="755" alt="flashedengineer" src="https://github.com/user-attachments/assets/4ce37da3-779a-4c26-92d9-0061ac83562a" />

Each board was erased, flashed with its respective firmware, and started:

```bash
uvx ectf hw /dev/ttyACM2 erase
uvx ectf hw /dev/ttyACM2 flash attacker.prot
uvx ectf hw /dev/ttyACM2 start

uvx ectf hw /dev/ttyACM0 erase
uvx ectf hw /dev/ttyACM0 flash engineer.prot
uvx ectf hw /dev/ttyACM0 start
```

Successful flashing was confirmed by the LED changing from blinking red to solid.

---

## Step 3 — Boot Reference Flag and Read Flags

With the attacker board running, the list command was issued using the attacker PIN. Because the reference design implements no authentication, the PIN is accepted without any validation.

```bash
uvx ectf tools /dev/ttyACM2 list 405984
```

The list command succeeded and the boot reference flag was returned in the debug output.

> **Boot Reference Flag:** `ectf{boot_e2218e27c4d4255d}`

<img width="1602" height="408" alt="listsuccesful" src="https://github.com/user-attachments/assets/5228a1d1-7d45-480e-88c1-f061376e7d15" />

A read command was then issued to retrieve the contents of slot 0, which belonged to the update group:

```bash
uvx ectf tools /dev/ttyACM2 read -f 405984 0 out
```

The file was successfully read and written to the output directory. The flag was embedded in the file contents.

> **Read Update Flag:** `ectf{update_8193461bae8c46d1}`

<img width="1842" height="374" alt="readfile" src="https://github.com/user-attachments/assets/acf7a530-8729-4967-a281-5ee20b455ef3" />

<img width="1924" height="1098" alt="readupdateflag" src="https://github.com/user-attachments/assets/e64d976a-f23b-40b5-863e-dbf9fc4bf0f4" />

The same approach was used against the engineer board. Because the reference design implements no PIN validation, any PIN is accepted:

```bash
uvx ectf tools /dev/ttyACM0 list 123456
uvx ectf tools /dev/ttyACM0 read -f 405984 0 out
```

> **Read Design Flag:** `ectf{design_f1ba8321b19521e6}`

<img width="1582" height="256" alt="engineerbopardlistsuccesful" src="https://github.com/user-attachments/assets/d0e34839-4028-4f6b-8319-c17cc9392a47" />

<img width="1800" height="544" alt="readdesignflag" src="https://github.com/user-attachments/assets/ede48610-f7ee-4018-a202-da38b28d4b86" />

---

## Step 4 — Steal Design Flag

The steal design flag requires receiving a file from the engineer HSM onto the attacker HSM — a transfer the attacker should not have permission to perform. The two boards were wired together over UART1 (PA8 TX → PA9 RX and PA9 RX → PA8 TX, with a shared GND) to enable board-to-board communication.

In one terminal, the engineer board was put into listen mode:

```bash
uvx ectf tools /dev/ttyACM0 listen
```

In a second terminal, the attacker board was used to receive the file from slot 0 on the engineer board into slot 1:

```bash
uvx ectf tools /dev/ttyACM2 receive 405984 0 1
```

The receive was successful. To obtain the flag, the bootloader digest of the received file was queried while the attacker board was in bootloader mode:

```bash
uvx ectf hw /dev/ttyACM2 digest 1
```

The resulting digest was submitted to the eCTF API:

```bash
uvx ectf api steal mitre {digest}
```

> **Steal Design Flag:** `ectf{steal_6dc6921061cf5b43}`

<img width="3024" height="1148" alt="succesfulreceive" src="https://github.com/user-attachments/assets/699839b4-5478-4e50-a723-8bccc5666821" />

<img width="1420" height="348" alt="apidigest" src="https://github.com/user-attachments/assets/a0b08bdf-7406-478e-b75c-dfb27d1ceb9b" />

<img width="3490" height="480" alt="stealflag" src="https://github.com/user-attachments/assets/6bb60c2c-feda-4415-9e5b-d749bc238257" />

---

## Root Cause Analysis

All flags were captured due to a complete absence of security controls in the reference design:

- **No PIN validation** — any PIN is accepted for any operation on any HSM.
- **No permission enforcement** — the attacker HSM was able to receive files from the engineer HSM despite lacking receive permissions for those groups.
- **No file access controls** — file contents are returned in plaintext to any caller.

These vulnerabilities are intentional in the reference design, which serves as a baseline for teams to build secure implementations upon.
