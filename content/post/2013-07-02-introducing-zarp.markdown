---
categories:
- zarp
- projects
comments: false
date: "2013-07-02T22:37:15Z"
title: introducing zarp
---

I've been quietly developing a local network attack tool for quite a while now, and it's approaching a state I deem 'presentable'.  Bugs are still being ironed out, and tons of features are still planned, but I've gotten some great feedback over the past few months and decided it was time for an official introductory post.  This post serves as an introduction into the current capabilities of the framework, as well as a timeline for future development and goals.

[zarp](https://github.com/hatRiot/zarp) is a local network attack toolkit that emphasizes absolute control over local networks.  It's end goal is to provide a very clean, modular, well-defined interface into a network, handing absolute control over to the user.  Over the course of several months, I discovered myself having to harness one too many tools to perform very basic, and what should be, simple network exploitation.  Mind you, zarp is not about exploiting hosts.  It is merely about the manipulation of any and all traffic present on the local network, and allowing the user the ability to view it, manipulate it, and save it in any manner they desire.  I would align zarp more with Ettercap than Metasploit.

zarp is written in Python and makes an attempt to be as modular as possible while maintaining a high level of independence.  As of now, three things are required to run zarp: Python 2.7.x, Linux, and Scapy.  Because of Scapy's age, I've had to modify the source code explicitly for zarp, and thus Scapy comes packaged with zarp.  I'm currently working to replace Scapy entirely and move to Python 3, but this won't be for awhile.  Zarp modules are dynamically loaded at runtime, and a very basic, but useable, interface has been defined.  It is incredibly easy to write a zarp module and get them loaded up into the framework.

zarp's predominant interface is a CLI-driven GUI, as shown:

```
bryan@devbox:~/zarp$ sudo ./zarp.py 
[!] Loaded 35 modules.
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)
        [Version 0.1.3]            
    [1] Poisoners        [5] Parameter
    [2] DoS Attacks      [6] Services 
    [3] Sniffers         [7] Sessions 
    [4] Scanners   

0) Back
> 
```

Each module is loaded into one of six buckets.  These buckets define the traits of the module and its intended use.  Sessions [7] are how sessions are managed.  Zarp allows a user to poison, sniff, and scan as many hosts as your system allows.  This means that all of your network poisoning and sniffing can be performed all in one spot.

```
> 0 7
    [Running sessions]
[1] ARP Spoof
    [0] 192.168.1.219
    [1] 192.168.1.49
[2] Password Sniffer
    [0] 192.168.1.49
    |--> Logging to  /tmp/passwords_49.txt
[3] HTTP Server
    [0] HTTP Server
[4] DNS Spoof
    [0] 192.168.1.219
    |-> [0] facebook.* -> 192.168.1.42


    [1] Stop session
    [2] View session
    [3] Start session logger
    [4] Stop session logger

0) 
```

As shown, many sessions can be managed from this interface at once.  Each module defines how output is displayed when the user is 'viewing' the session; it could be network traffic, passwords, HTTP requests, and more.  Various sniffers built in allow easy parsing and logging. 

Below are some of the built-in modules.

```
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)
        [Version 0.1.3]            
    [1] Poisoners        [5] Parameter
    [2] DoS Attacks      [6] Services 
    [3] Sniffers         [7] Sessions 
    [4] Scanners   

0) Back
> 1
    [1] ARP Spoof
    [2] DNS Spoof
    [3] DHCP Spoof
    [4] NBNS Poison
    [5] LLMNR Spoofer
    [6] ICMP Redirection

0) Back
> 0 2
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)
        [Version 0.1.3]            
    [1] DHCP Starvation
    [2] LAND DoS
    [3] IPv6 Neighbor Discovery Protocol RA DoS
    [4] Nestea DoS
    [5] SMB2 DoS
    [6] TCP SYN
    [7] IPv6 Neighbor Unreachability Detection DoS
    [8] Linux 2.6.36 - 3.2.1 IGMP DoS
    [9] MS13-018 Win7/8 DoS

0) Back
> 0 3
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)
        [Version 0.1.3]            
    [1] HTTP Sniffer
    [2] Password Sniffer
    [3] Traffic Sniffer
    [4] Database Sniffer
    [5] Packet Modifier

0) Back
> 
```

Also included are various router exploits, switch flooding, ARP shells, access point cracking, and more.  Zarp also allows modules to set CLI options, which can be used like any regular CLI application:

```
bryan@devbox:~/zarp$ sudo ./zarp.py --help
[!] Loaded 35 modules.
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)
        [Version 0.1.3]            
usage: zarp.py [-h] [-q FILTER] [--update] [--wap] [--ftp] [--http] [--smb]
               [--ssh] [--telnet] [-w] [-s] [--service-scan]

optional arguments:
  -h, --help      show this help message and exit
  -q FILTER       Generic network sniff
  --update        Update Zarp

Services:
  --wap           Wireless access point
  --ftp           FTP server
  --http          HTTP Server
  --smb           SMB Service
  --ssh           SSH Server
  --telnet        Telnet server

Scanners:
  -w              Wireless AP Scan
  -s              Network scanner
  --service-scan  Service scanner
bryan@devbox:~/zarp$ sudo ./zarp.py --ssh
[!] Loaded 35 modules.
     ____   __   ____  ____
    (__  ) / _\ (  _ \(  _ '
     / _/ /    \ )   / ) __/
    (____)\_/\_/(__\_)(__)
        [Version 0.1.3]            
[!] Starting SSH Server...
```

The idea behind services is this: honeypots are scary effective at what they do because they exploit a certain trust a user has in a system, or address.  But, if I'm able to DoS a web server, ARPP/DNS spoof the host into redirecting it to me, I can fetch credentials off them just by presenting a login.  These can be leveraged in any number of ways, including spoofing, social engineering, etc. 

I realize that many of these attacks are not bleeding-edge; that's okay, for now.  I needed a solid foundation full of tried-and-true attacks that I can then expand upon; for this reason, I've gone for breadth over depth, initially.  Modules are still being actively developed and features piled on.  zarp is currently lacking a few key features, such as packet modification and ssl stripping, but these are currently in development.  Moxie's sslstrip is fantastic, but I would prefer a native implementation without relying on twisted.

Now comes the future; what's the end-goal for zarp.  I see zarp as a master control system for a local network.  Plug it in and watch it grow.  Recently I've added a database logging tool that formats certain key bits, username/passwords, hosts, logs, etc., and inserts them into a local sqlite3 database.  This will be expanded to eventually allow connections to postgresql/mysql servers for remote work and collaboration.  The idea behind this is to allow a web application the ability to aggregate everything zarp spits out and organize, analyze, and display this in a very powerful way.  This web application presents network topologies, host relationships, active connections, man-in-the-middle attacks, and more.  The television to zarp's remote control.

Though ambitious, I feel this could be an incredibly powerful tool that provides pentesters an invaluable service.  I'm hoping this post garners a few users who can provide solid usage feedback and help iron out bugs or develop features; if you like what you've seen, please check out the wiki or send me an email (drone AT ballastsecurity DOT net) or tweet (@dronesec).  Any and all feedback, including suggestions/bugs/questions, are welcome.
