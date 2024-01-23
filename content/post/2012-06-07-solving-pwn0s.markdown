---
categories:
- vulnhub
- walkthrough
comments: true
date: "2012-06-07T00:15:10Z"
title: solving pwn0s
---

pwnOS is a vulnerable VM used in penetration testing and vulnerability assessment.  I thought this one was pretty fun, so I've decided to do a little write up in the various ways it can be attacked.  The VM for it can be found on forums.hackingdojo.com; you need an account to access the forums, but it's worth it. 

The VM comes packaged as a split vmdk, so just loading up the vmx sets everything up.  Booting it up and flipping over to BackTrack, a quick nmap scan gives us a few immediate vectors of attack:

{{< figure src="/images/posts/2012/scan.jpg" title="image" alt="images" >}}

So there's a few notable things here; the OpenSSH version, specifically that Debian build, is known to generate weak, predictable SSH keys.  This vulnerability is due to a side-effect of removing a bit of code that effected the initial seeding for the PRNG; instead of seeding it with true, random data, it instead only used a process ID. There are a total of 32,768 process ID's available, meaning, only 32,768 potential seeds to the PRNG.  We can attack this by generating a 2048 bit key (that's the bit size of the RSA key, according to nmap) 32,768 times with the number as a seed.  We'll set this aside, for now, and come back to it.

There's an HTTP server up with some plaintext HTML on it, but nothing worthy of any web-side exploits.  That version of Apache has some DoS vulnerabilities, but that doesn't do much for us.

The next interesting port is actually on 10000; MiniServ is a fairly obscure, hyperminimal web server written in C.  It's barely supported and has a very low exposure level.  On the frontend runs WebMin, a PHP interface for HTTP servers.  As it happens to turn out, there's a vulnerability allowing an attacker to retrieve unauthorized remote files.  This will work harmoniously with our OpenSSH vulnerability above!  I pulled some perl code from [here](http://www.exploit-db.com/exploits/2017/) and dumped a few things:

{{< figure src="/images/posts/2012/webmin.jpg" title="image" alt="images" >}}

Oh boy users!  Lets back up for a minute and take a look at this exploit.  If we pop open the perl code, we see a little bit of this:

```
 $temp="/..%01" x 40;

        if ($tar == '0')
           { my $url= "http://". $target. ":" . $port ."/unauthenticated/".$temp . $filename;
            $content=get $url;

            print("\n FILE CONTENT STARTED");
            print("\n -----------------------------------\n");

            print("$content");
            print("\n -------------------------------------\n");
            }
```

That's about as easy as it gets when it comes to exploits; we're filling up the url with /..%01.  It does this 40 times until the buffer is full, then appends the filename onto the end.    I dug into the Webmin source code to see exactly what was going on; diffing 1.28 and 1.29, I found this:

{{< figure src="/images/posts/2012/diff.jpg" title="image" alt="images" >}}

Essentially it was checking for a directory traversal in the path, but only checking "..".  In our exploit, we're appending a %01, which is the ASCII Start of Header.  This final, encoded ASCII code can be any control code; that's %00 - %1F ([codes](http://www.w3schools.com/tags/ref_urlencode.asp)).  This works because these codes have no purpose in the URL and do not decode to anything useful; they merely throw off the $b eq ".." check by doing nothing.  The remainder of the code is left as an exercise for the reader.

Now that we've got a few names, we can run through RSA keys and see if we get a match.  HD Moore of Metasploit has already generated and distributed the keys, and can be retrieved [here](http://metasploit.com/users/hdm/tools/debian-openssl/).  Got 'em?  Cool; now we can test keys against the usernames in the file.  I used [this](http://www.exploit-db.com/exploits/5632/) to iterate through them, but it shouldn't be too hard to code it up yourself.  Essentially we just want to connect to the server with one of the usernames with the generated keys; when we pop a shell, we know we're in:

{{< figure src="/images/posts/2012/brute.jpg" title="image" alt="images" >}}

So now we've got ourselves a private RSA key for account 'obama'.  Testing it out, and...

{{< figure src="/images/posts/2012/ssh.jpg" title="image" alt="images" >}}

Success!  So now we've got a valid account on the box.  We see it's an x86 Ubuntu machine on the 2.6.22 kernel.  What can we do?  Well, immediately I recognize a major vulnerability in the kernel version.  A bit of googling will turn up the vmsplice exploit.  The exploit itself is in fact a chaining of three separate, now patched, vulnerabilities in the fs/splice.c module.  I will let the fantastic article at [lwn](https://lwn.net/Articles/268783/) describe the vulnerability in more detail, and instead put it to some use here:

{{< figure src="/images/posts/2012/vmsplice_root.jpg" title="image" alt="images" >}}

And just like that we've got root on the box. 

Other avenues of attack could be sticking Medusa/Hydra on the SSH port and letting it brute force the accounts, exploiting remote uploads to MiniServ, or the local ftruncate root exploit.  Though fairly easy and straightforward (I didn't have to write a line of code), this VM was fun to toy around with.
