# Target Details

| IP            | Hostname/Box | Operating System /Platform |
| ------------- | ------------ | -------------------------- |
| 192.168.1.110 | Blackpearl       | Linux 4.15 - 5.6      |

# Box Outline
Nmap scans revealed ports 22, 53 and 80 as open. Port 80 lead to the default page of an nginx server. When viewing the page source, there was information disclosure "<!-- Webmaster: alek@blackpearl.tcm -->" that eluded to a user named "alek" with a domain named "blackpearl.tcm". I performed directory discovery, and found a useful path: 'view-source:http://192.168.1.110/secret'. This revealed a note that stated directory discovery was not the route to go for this machine. I then researched port 53 by doing a dns recon. This revealed one record: blackpearl.tcm. I added this domain name and tied it to the ip address of the machine '192.168.1.110' by adding it to my /etc/hosts file. I navigated to blackpearl.tcm and came across a default php page. Now that I know blackpearl.tcm is valid, I ran another directory discovery and it revealed the following path: blackpearl.tcm/navigate/login.php (Navigate CMS portal). I began researching for vulnerabilities for this CMS. I found the following "Navigate CMS Unauthenticated Remote Code Execution" via Rapid7 and ran it successfully to gain low level privileges. I then downloaded linpeas on the target system in order to reveal any additional vulnerabilities. There was an indicator that I might be able to exploit "Unknown SUID binaries". Once I discovered specific folders that maybe executed with owner permissions when the SUID bit was set, I conducted online research and found a script that allowed me to exploit the php folder and gained root privileges. Once I had root access, I read the contents of the flag.txt, and cat /etc/passwd.

# Scanning and Enumeration
Ran nmap scan
```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -Pn -T4 -p- -A 192.168.1.110
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 21:10 EDT
Nmap scan report for 192.168.1.110
Host is up (0.0011s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66381450ae7dab3972bf419c39251a0f (RSA)
|   256 a62e7771c6496fd573e9227d8b1ca9c6 (ECDSA)
|_  256 890b73c153c8e1885ec316ded1e5260d (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
MAC Address: 08:00:27:52:06:39 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.09 ms 192.168.1.110

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.11 seconds
```
Port 80
I found the default page to an nginx server

<img width="590" alt="default nginx server page" src="https://github.com/JustChief/Write-ups/assets/14989943/3d406d73-0f02-4648-b5a8-4270190e8d05">

Viewing the page source, I found a commented out note: <!-- Webmaster: alek@blackpearl.tcm -->
<img width="589" alt="page source for nginx - information disclosure" src="https://github.com/JustChief/Write-ups/assets/14989943/04b24924-30fe-43fa-8a00-d6ec0f2eadad">

Directory Busting
```bash
┌──(root㉿kali)-[/home/kali]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://192.168.1.110/FUZZ 
```

ffuf-ing led to a /secret. Navigating to the path, the following screenshot was taken.
<img width="786" alt="secret directory path" src="https://github.com/JustChief/Write-ups/assets/14989943/0e0c3dce-d014-4604-ab5e-5436653b1746">

Port 22
	Maybe bruteforce alek@192.168.1.110?

Port 53
Exploring port 53, we did a dns recon
<img width="786" alt="dns recon blackpearl tcm" src="https://github.com/JustChief/Write-ups/assets/14989943/2de9c734-3163-426c-997b-262d1a232f99">

This indicated there is a dns record pointing to blackpearl.tcm. In order for me to get to that location, I needed to add the IP address to my /etc/hosts file

<img width="786" alt="adding blackpearl tcm to etc-hosts" src="https://github.com/JustChief/Write-ups/assets/14989943/60769c97-3b2c-40d1-b523-0bcdff88ad60">

So when I navigate to blackpearl.tcm, I get a live link to a default PHP page
<img width="1052" alt="php page for blackpearl tcm" src="https://github.com/JustChief/Write-ups/assets/14989943/f0645a61-f587-444b-b9e4-978191044b5f">

Now that I have some additional information, I ran another ffuf. This time on the address http://blackpearl.tcm
```bash
┌──(root㉿kali)-[/home/kali]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://blackpearl.tcm/FUZZ

```
This scan revealed the path "/navigate"
<img width="1048" alt="navigate csm home page" src="https://github.com/JustChief/Write-ups/assets/14989943/8c9c90e3-e22f-4ba5-bc2a-93bba3a8a18e">

**Background information**
	

# Exploitation
After googling, I found two resources that indicated this 'Navigate CMS' can be exploited.
	1. https://www.rapid7.com/db/modules/exploit/multi/http/navigate_cms_rce/
	2. https://www.exploit-db.com/exploits/45561

### Vulnerability
#### Navigate CMS Unauthenticated Remote Code Execution (Rapid7)

| Disclosed | Created |
| --------- | ---------- |
|  09/26/2018         |      03/19/2019      |
#### Description
This module exploits insufficient sanitization in the database::protect method, of Navigate CMS versions 2.8 and prior, to bypass authentication. The module then uses a path traversal vulnerability in navigate_upload.php that allows authenticated users to upload PHP files to arbitrary locations. Together these vulnerabilities allow an unauthenticated attacker to execute arbitrary PHP code remotely. This module was tested against Navigate CMS 2.8.

`msf > use exploit/multi/http/navigate_cms_rce`
<img width="1120" alt="options for navigate rce exploit" src="https://github.com/JustChief/Write-ups/assets/14989943/8a16a741-28e8-44b5-a2c7-76044b898b0d">

Successful exploit led to a meterpreter shell as www-data user
<img width="1120" alt="shell from navigate rce exploit" src="https://github.com/JustChief/Write-ups/assets/14989943/d1147fd4-e93c-432f-81a4-c7aa3cf506f3">

#tip type shell to drop into a shell
#tip if there is no designator, then I need to spawn a tty shell
In order to do this with the following resource (https://wiki.zacheller.dev/pentest/privilege-escalation/spawning-a-tty-shell) we need to determine if python is installed on the machine using `which python`. Once that was determined, the following code was ran. Doing this allowed us a clearer interface with details such as who we were logged in as, and where.
`python -c 'import pty; pty.spawn("/bin/bash")'``

<img width="1120" alt="python execution dropping into shell" src="https://github.com/JustChief/Write-ups/assets/14989943/77e9de3c-6cc1-4068-989e-ab98d844b2ed">

# Privilege Escalation
Now that we have access to the system with low level permissions, we need to determine how we can escalate privileges. I downloaded linpeas onto the target machine, and ran it.
<img width="1120" alt="linpeas file transfer" src="https://github.com/JustChief/Write-ups/assets/14989943/984c8fce-759b-4a89-bf9b-5a80d54f881d">

#tip Remember to update the linpeas.sh on the target machine to make it an executable
```bash
www-data@blackpearl:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@blackpearl:/tmp$ ./linpeas.sh
```
Once we run linpeas, we find the following key pieces of information

CVE-2021-3560
<img width="847" alt="CVE-2021-3560" src="https://github.com/JustChief/Write-ups/assets/14989943/54c29615-64a0-4a2e-a146-922f7e6d3278">

Back up files can potentially have config files, passwords, useful databases, etc
<img width="1196" alt="backup folders of interest" src="https://github.com/JustChief/Write-ups/assets/14989943/10d807ce-d0ec-4cf2-b2d3-2b03a81609b7">

<img width="1196" alt="passwd files of interest" src="https://github.com/JustChief/Write-ups/assets/14989943/32c3b6ea-3638-4e8b-975e-93abffdaba57">

<img width="1012" alt="users on blackpearl" src="https://github.com/JustChief/Write-ups/assets/14989943/60ad564e-0c77-4bdd-9695-a91e68a0b6c6">

Look for "Unknown SUID binaries" in the linpeas report. Looking for SUID, SGID, and the Stickybit. We're looking for binaries, that we (as a low level user) can run as the owner of the binary (root).
`-rwsr-xr--` SUID - Low level user can run as owner
`-rwxr-sr-x` SGID - Low level user can run as group owner

In this box, there is a command that provides a clearer picture for us. Essentially showing us permission settings for the binaries
`find / -type f -perm -4000 2>/dev/null`
<img width="1012" alt="folders with SUID permissions" src="https://github.com/JustChief/Write-ups/assets/14989943/dce6efe6-bd99-4657-b6cc-5ef7a7b3a9df">

Once we've identified the files, we do some online research in gtfobins, filtering on PHP. We chose the SUID exploit. 
(https://gtfobins.github.io/#+suid)
<img width="845" alt="PHP SUID exploit" src="https://github.com/JustChief/Write-ups/assets/14989943/e2793843-9f87-4be7-a5be-9c1cd569d74b">

Noting the php folder/version, we executed the command
`/usr/bin/php7.3 -r "pcntl_exec('bin/sh', ['-p']);"`
And with this command we gained root access
<img width="847" alt="getting root" src="https://github.com/JustChief/Write-ups/assets/14989943/e6a8fa01-d266-4126-950e-8f3a2eebd02e">


Completed, but maybe try an automated way? to be continued...

# Post Exploitation
cat /etc/passwd
