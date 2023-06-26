# Machine Details

| IP            | Hostname/Box | Operating System |
| ------------- | ------------ | ---------------- |
| 192.168.1.106 | Academy      | Linux 4.15 - 5.6 |

# Box Outline
This box was a stand-alone virtual machine that was used to host a test academy website. The website was centered on a student profile/registration. 3 ports were open: 21, 22 and 80. Port 21 allowed anonymous login and revealed a key note.txt, that contained credentials. Port 80 defaulted to an Apache server, and the actual academy website. The credentials found in the note were used to log into the student profile. Within the profile, there was a location where uploads were allowed. This field in the website was not sanitized or had controls in place. This allowed malicious code to be uploaded. A php reverse shell was used to exploit this vulnerability. Once in the system, further discovery revealed another user along with their credentials. This user had admin permissions. Using the information mentioned in note.txt, along with the newly found credentials, an ssh login was achieved. Recon was further conducted and discovered a backup.sh script that ran periodically. We leveraged this by altering the script to include our own script that would grant us escalated privileges. Once this was achieved, we obtained root and revealed contents of the flag.txt.

# Scanning and Enumeration
Had to find the new box on my network for Academy
Ran the following nmap scan
	`nmap -sS -A -O -T4 192.168.1.*`

We ran an nmap scan for open ports and services
![](nmap%20scan.png)

Target Box Details
	IP
		192.168.1.106
	OS
		Linux 4.15 - 5.6
	Open Ports & Services
		21 - ftp (allows anonymous FTP Login)
		22 - ssh (OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0))
		80 - http (Apache/2.4.38)

Searched for vulnerabilities for the versions listed above but no results found. Resources used:
	searchsploit
	metasploit

Findings

Port 21 allowed anonymous log in. We found a 'note.txt' and downloaded it to our attack box. It contained a message to Heath. Key notes, it contained student credentials a test website for a new academy.

![](anonymous%20login%20via%20ftp.png)

![](get%20note.txt%20via%20ftp.png)
![](note.txt.png)

Port 80 gave us an Apache Default Page via web browser. This reveals a lot of  information about the architecture. Attempted to navigate to a page that didn't exist and received a 404 error, however it provided the server version.
![](apache%20default%20webpage.png)

Since the note we found earlier indicated there was a website, and port 80 served up an Apache server, we decided to conduct directory discovery. A variety of tools can be used for directory discovery.
	Dirbuster
	FFUF
	DIRB

Dirbuster
![](dirbuster%20directory%20listing.png)

Point of interest: /academy/index.php brought up a login screen. I used the credentials found in the note.txt to log in. I used an online hash cracker to decode the hash
	StudentRegno: 10201321
	password: cd73502828457d15655bbd7a63fb0bc8
	Cracked Password: 'student'
#tip kali has a built in hash-identifier
![](student%20login%20screen.png)

![](student%20profile.png)

ffuf
#tip pipe results to a text file for comparison
![](ffuf%20directory%20listing%20results.png)
Dirb
![](dirb%20directory%20listing%20results.png)

# Exploitation

Looking at the student profile, there's a place that we can upload a profile picture. This is a potential location where we can upload a reverse shell. Searched google for php reverse shell and found 'https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php'
Steps
	1. Download and save the file
	2. Change the ip address (attacking box) and the port that will be used
	3. Setup a listener with port previously set up on attack box
		`nc -nvlp 1234`
	4. Upload the saved php-reverse-shell script to website
	5. Shell is established


![](php-reverse-shell.php%20file%20upload.png)

The shell was established as the user www-data. We tried to find sudo user, but could not locate it.
![](netcat%20listener.png)

# Privilege escalation
After exploiting the box, we began working towards escalating our privileges. To do this, we used LinPEAS (Linux Privilege Escalation Awesome Script. 
	LinPease description: LinPEAS is a script that searches for possible paths to escalate privileges on Linux/Unix*/MacOS hosts.
Steps
	1. Using the previously established shell, download linpeas.sh into the /tmp folder of the target box
	2. Change permissions to an executable
	3. Execute
![](linpeas%20upload.png)

LinPEAS returned the following key location, a username and password for that user

![](poi%20important%20config%20file%20for%20mysql%20db%20with%20password%20listed.png)

Taking note of this, we also decided to explore the /etc/passwd file. The final entry was 'grimmie', the same user previously found. The /etc/passwd file showed that this user had administrator privileges as well.
![](-etc-passwd%20file.png)

We ssh'd into grimmie's account with previously found credentials

![](ssh%20login%20for%20grimmie.png)

#tip commands to try in here,
	`sudo -l`
	`history`
	run linpeas for every user account from the /tmp folder because this folder's contents typically get deleted once the user logs off

# Post Exploitation

Once logged in, we found a file called backup.sh.
![](backup.sh%20file.png)
File explained
1. Remove /tmp/backup file
2. perform a backup for the website, and compress into a zip folder 
3. Update the permissions of the new zipped file
Basic Interpretation: periodic backups are occurring

#tip In terms of running processes (like backups) search the `crontab`, these are scheduled jobs that run periodically. You can also use `systemctl list-timers`

For this box, we used a tool called pspy
	PSPY Description: pspy is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute.
	Link: https://github.com/DominicBreuker/pspy

We confirmed our findings that the backups run every minute (every minute since it is ctf style)
![](backup%20process%20running%20every%20minute.png)

We further exploited this by setting up a reverse shell by using a one-liner and pasting it into the backup.sh. We did this because the file was already on the system. 
	Reverse-shell
	Link: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

![](reverse%20shell%20one%20liner.png)
We set up a netcat listener and executed the reverse shell via the backup.sh script. At this point, we achieved root privileges once the reverse shell executed. We captured the flag and exposed the contents of flag.txt as root.
![](achieved%20root%20access.png)
