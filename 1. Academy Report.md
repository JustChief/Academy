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

<img width="562" alt="nmap scan" src="https://github.com/JustChief/Academy/assets/14989943/ca33ce22-a15b-4ab3-a0b4-50fa75ca2b8d">

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

<img width="1131" alt="anonymous login via ftp" src="https://github.com/JustChief/Academy/assets/14989943/d526eb73-1b46-4aea-a5f2-816dd56e7c3c">

<img width="1131" alt="get note txt via ftp" src="https://github.com/JustChief/Academy/assets/14989943/03e76e49-3d46-42d4-97b3-33635e19d424">

<img width="1131" alt="note txt" src="https://github.com/JustChief/Academy/assets/14989943/71895c4c-8cdc-46af-88b7-202cb4e89ee7">

Port 80 gave us an Apache Default Page via web browser. This reveals a lot of  information about the architecture. Attempted to navigate to a page that didn't exist and received a 404 error, however it provided the server version.

<img width="1131" alt="apache default webpage" src="https://github.com/JustChief/Academy/assets/14989943/2bf62500-6628-4c47-9092-ced9eebd5531">


Since the note we found earlier indicated there was a website, and port 80 served up an Apache server, we decided to conduct directory discovery. A variety of tools can be used for directory discovery.
	Dirbuster
	FFUF
	DIRB

Dirbuster

<img width="772" alt="dirbuster directory listing" src="https://github.com/JustChief/Academy/assets/14989943/fbd35332-3986-4187-981f-d40d3766ae09">

Point of interest: /academy/index.php brought up a login screen. I used the credentials found in the note.txt to log in. I used an online hash cracker to decode the hash
	StudentRegno: 10201321
	password: cd73502828457d15655bbd7a63fb0bc8
	Cracked Password: 'student'
#tip kali has a built in hash-identifier
<img width="1131" alt="student login screen" src="https://github.com/JustChief/Academy/assets/14989943/2958481e-13de-453b-902a-8697ea42dc7e">
<img width="840" alt="student profile" src="https://github.com/JustChief/Academy/assets/14989943/87275b9f-0b48-4f45-aa9d-3863d9cc7beb">

ffuf
#tip pipe results to a text file for comparison
<img width="875" alt="ffuf directory listing results" src="https://github.com/JustChief/Academy/assets/14989943/b9f2f115-0e3a-432d-8b50-711a46a9527b">

Dirb

<img width="875" alt="dirb directory listing results" src="https://github.com/JustChief/Academy/assets/14989943/64518fe3-0f6e-4739-b698-a192b72d0fab">

# Exploitation

Looking at the student profile, there's a place that we can upload a profile picture. This is a potential location where we can upload a reverse shell. Searched google for php reverse shell and found 'https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php'
Steps
	1. Download and save the file
	2. Change the ip address (attacking box) and the port that will be used
	3. Setup a listener with port previously set up on attack box
		`nc -nvlp 1234`
	4. Upload the saved php-reverse-shell script to website
	5. Shell is established

<img width="423" alt="php-reverse-shell php file upload" src="https://github.com/JustChief/Academy/assets/14989943/255ed12f-86b4-42c3-8722-90daa6e3de34">

The shell was established as the user www-data. We tried to find sudo user, but could not locate it.
<img width="700" alt="netcat listener" src="https://github.com/JustChief/Academy/assets/14989943/868eb754-9e8e-4047-879c-39c2ed99c3ec">

# Privilege escalation
After exploiting the box, we began working towards escalating our privileges. To do this, we used LinPEAS (Linux Privilege Escalation Awesome Script. 
	LinPease description: LinPEAS is a script that searches for possible paths to escalate privileges on Linux/Unix*/MacOS hosts.
Steps
	1. Using the previously established shell, download linpeas.sh into the /tmp folder of the target box
	2. Change permissions to an executable
	3. Execute

<img width="693" alt="linpeas upload" src="https://github.com/JustChief/Academy/assets/14989943/9dfd5aea-8499-40ef-ab93-a1d8711e87a5">

LinPEAS returned the following key location, a username and password for that user
<img width="986" alt="poi important config file for mysql db with password listed" src="https://github.com/JustChief/Academy/assets/14989943/398edbf0-228d-4d95-97b3-4a7edfd31a6e">

Taking note of this, we also decided to explore the /etc/passwd file. The final entry was 'grimmie', the same user previously found. The /etc/passwd file showed that this user had administrator privileges as well.
<img width="725" alt="-etc-passwd file" src="https://github.com/JustChief/Academy/assets/14989943/20a79f1e-7da2-4986-843c-e0cb2f6197ff">

We ssh'd into grimmie's account with previously found credentials
<img width="649" alt="ssh login for grimmie" src="https://github.com/JustChief/Academy/assets/14989943/ffb02d10-853a-4442-a3ba-197640052ed0">

#tip commands to try in here,
	`sudo -l`
	`history`
	run linpeas for every user account from the /tmp folder because this folder's contents typically get deleted once the user logs off

# Post Exploitation

Once logged in, we found a file called backup.sh.

<img width="438" alt="backup sh file" src="https://github.com/JustChief/Academy/assets/14989943/90dc5e57-921a-4de4-8211-8ff4ddd31f0c">

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
<img width="694" alt="backup process running every minute" src="https://github.com/JustChief/Academy/assets/14989943/ed591a35-8ae7-44ab-9817-a2f129e7fcdd">


We further exploited this by setting up a reverse shell by using a one-liner and pasting it into the backup.sh. We did this because the file was already on the system. 
	Reverse-shell
	Link: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
<img width="458" alt="reverse shell one liner" src="https://github.com/JustChief/Academy/assets/14989943/cbba448c-bc5f-45d9-8b8d-a3c92761d975">

We set up a netcat listener and executed the reverse shell via the backup.sh script. At this point, we achieved root privileges once the reverse shell executed. We captured the flag and exposed the contents of flag.txt as root.
<img width="645" alt="achieved root access" src="https://github.com/JustChief/Academy/assets/14989943/7bdff6c2-9563-4686-8a40-eee4c48cf7ef">

