---
categories:
- windows
- red team
- code injection
comments: false
date: "2021-05-12T15:10:04Z"
title: the fanciful allure and utility of syscalls
---

So over the years I've had a number of conversations about the utility of using syscalls in shellcode, C2s, or loaders in offsec tooling and red team ops. For reasons likely related to the increasing maturity of EDRs and their totalitarian grip in enterprise environments, I've seen an uptick in projects and blogs championing "raw syscalls" as a technique for evading AV/SIEM technologies. This post is an attempt to describe why I think the technique's efficacy has been overstated and its utility stretched thin.

This diatribe is not meant to denigrate any one project or its utility; if your tool or payload uses syscalls instead of ntdll, great. The technique is useful under certain circumstances and can be valuable in attempts at evading EDR, particularly when combined with other strategies. What it's not, however, is a silver bullet. It is not going to grant you any particularly interesting capability by virtue of evading a vendor data sink. Determining its efficacy in context of the execution chain is difficult, ambiguous at best. Your C2 is not advanced in EDR evasion by including a few ntdll stubs.

Note that when I'm talking about EDRs, I'm speaking specifically to modern samples with online and cloud-based machine learning capabilities, both attended and unattended. Crowdstrike Falcon, Cylance, CybeReason, Endgame, Carbon Black, and others have a wide array of ML strategies of varying quality. This post is not an analysis of these vendors' user mode hooking capabilities.

Finally, this discussion's perspective is that of post-exploitation, necessary for an attacker to issue a syscall anyway. User mode hooks can provide useful telemetry on user behavior prior to code execution (phishing stages), but once that's achieved, all bets of process integrity are off. 

## syscalling

Very briefly, using raw syscalls is an old technique that obviates the need to use sanctioned APIs and instead uses assembly to execute certain functions exposed to user mode from the kernel. For example, if you wanted to read memory of another process, you might use `NtReadVirtualMemory`:

```
NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
```

This function is exported by NTDLL; at runtime, the PE loader loads every DLL in its import directory table, then resolves all of the import address table (IAT) function pointers. When we call `NtReadVirtualMemory` our pointers are fixed up based on the resolved address of the function, bringing us to execute:

```
00007ffb`1676d4f0 4c8bd1           mov     r10, rcx
00007ffb`1676d4f3 b83f000000       mov     eax, 3Fh
00007ffb`1676d4f8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)], 1
00007ffb`1676d500 7503             jne     ntdll!NtReadVirtualMemory+0x15 (00007ffb`1676d505)
00007ffb`1676d502 0f05             syscall 
00007ffb`1676d504 c3               ret     
00007ffb`1676d505 cd2e             int     2Eh
00007ffb`1676d507 c3               ret 
```

This stub, implemented in NTDLL, moves the syscall number (0x3f) into EAX and uses `syscall` or `int 2e`, depending on the system bitness, to transition to the kernel. At this point the kernel begins executing the routine tied to code `0x3f`. There are plenty of resources on how the process works and what happens on the way back, so [please](https://www.geoffchappell.com/studies/windows/km/cpu/sep.htm) [refer](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/glimpse-into-ssdt-in-windows-x64-kernel) [elsewhere](https://scorpiosoftware.net/2019/11/). 

Modern EDRs will typically inject hooks, or detours, into the implementation of the function. This allows them to capture additional information about the context of the call for further analysis. In some cases the call can be outright blocked. As a red team, we obviously want to stymie this.

With that, I want to detail a few shortcomings with this technique that I've seen in many of the public implementations. Let me once again stress here that I'm not trying to denigrate these tools; they provide utility and have their use cases that cannot be ignored, which I hope to highlight below.

### syscall values are not consistent

j00ru maintains the go-to source for both [nt](https://j00ru.vexillium.org/syscalls/nt/64/) and [win32k](https://j00ru.vexillium.org/syscalls/win32k/64/), and by blindly searching around on here you can see the shift in values between functions. Windows 10 alone currently has *eleven* columns for the different major builds of Win10, some functions shifting 4 or 5 times. This means that we either need to know ahead of time what build the victim is running and tailor the syscall stubs specifically (at worst cumbersome in a post-exp environment), or we need to dynamically generate the syscall number at runtime.

There are several proposed solutions to discovering the syscall at runtime: sorting Zw exports, reading the stubs directly out of the mapped NTDLL, querying j00ru's [Github repository](https://github.com/j00ru/windows-syscalls) (lol), or actually baking every potential code into the payload and selecting the correct one at runtime. These are all usable options, but everything here is either cumbersome or an unnecessary risk in raising our threat profile with the EDRs ML model.

Let's say you attempt to read NTDLL off disk to discover the stubs; that requires issuing `CreateFile` and `ReadFile` calls, both triggering minifilter and ETW events, and potentially executing already established EDR hooks. Maybe that raises your threat profile a few percentage points, but you're still golden. You then need to copy that stub out into an executable section, setup the stack/registers, and invoke. Optionally, you could use the already mapped NTDLL; that requires either `GetProcAddress`, walking PEB, or parsing out the IAT. Are these events surrounding the resolution of the stub more or less likely to increase the threat profile than just calling the NTDLL function itself? 

The least-bad option of these is baking the codes into your payload and switching at runtime based on the detection of the system version. In memory this is going to look like an s-box switch, but there are no extraneous calls to in-memory or on-disk files or stumbles up or down the PEB. This is great, but cumbersome if you need to support a range of languages and execution environments, particularly those with on-demand or dynamic requirements.

### syscall's miss useful/critical functionality

In addition to ease of use in C/C++, user mode APIs provide additional functionality prior to hitting the kernel. This could be setting up/formatting arguments, exception or edge-case handling, SxS/activation contexts, etc. Without using these APIs and instead syscalling yourself, you're missing out on this, for better or for worse. In some cases it means porting that behavior directly to your assembler stub or setting up the environment pre/post execution.

In some cases, like [`WriteProcessMemory`](http://theevilbit.blogspot.com/2018/08/about-writeprocessmemory.html) or `CreateRemoteThreadEx`, it's more "helpful" than actually necessary. In others, like `CreateEnclave` or `CallEnclave`, it's virtually a requirement. If you're angling to use only a specific set of functions (`NtReadVirtualMemory/NtWriteVirtualMemory/etc`) this might not be much of an issue, but expanding beyond that comes with great caveat. 

### the spooky functions are probably being called anyway

In general, syscalling is used to evade the use of some function known or suspected to be hooked in user mode. In certain scenarios we can guarantee that the syscall is the only way that hooked function is going to execute. In others, however, such as a more feature rich stage 0 or C2, we can't guarantee this. Consider the following (pseudo-code):

```
UseSysCall(NtOpenProcess, ...)
UseSysCall(NtAllocateVirtualMemory, ...)
UseSysCall(NtWriteVirtualMemory, ...)
UseSysCall(NtCreateThreadEx, ...)
```

In the above we've opened a writable process handle, created a blob of memory, written into it, and started a thread to execute it. A very common process injection strategy. Setting aside the tsunami of information this feeds into the kernel, only dynamic instrumentation of the runtime would detect something like this. Any IAT or inline hooks are evaded. 

But say your loader does a few other things, makes a few other calls to user32, dnsapi, kernel32, etc. Do you know that those functions don't make calls into the very functions you're attempting to avoid using? Now you could argue that by evading the hooks for more sensitive functionality (process injection), you've lowered your threat score with the EDR. This isn't entirely true though because EDR isn't blind to your remote thread (`PsSetCreateThreadNotifyRoutine`) or your writable process handle (`ObRegisterCallbacks`) or even your cross process memory write. So what you've really done is avoided sending contextualized telemetry to the kernel of the cross process injection -- is that enough to avoid heightened scrutiny? Maybe. 

Additionally, modern EDRs hook a ton of stuff (or at least some do). Most syscall projects and research focus on NTDLL; what about kernel32, user32, advapi32, wininet, etc? None of the syscall evasion is going to work here because, naturally, a majority of those don't need to syscall into the kernel (or do via other ntdll functions...). For evasion coverage, then, you may need to both bolt on raw syscall support as well as a generic unhooking strategy for the other modules. 

### syscall's are partially effective at escaping UM data sinks

Many user mode hooks themselves do not have proactive defense capabilities baked in. By and large they are used to gather telemetry on the call context to provide to the kernel driver or system service for additional analysis. This analysis, paired with what it's gathered via ETW, kernel mode hooks, and other data sinks, forms a composite picture of the process since birth. 

Let's take the example of cross process code injection referenced above. Let's also give your loader the benefit of the doubt and assume it's triggered nothing and emitted little telemetry on its way to execution. When the following is run:

```
UseSysCall(NtOpenProcess, ...)
UseSysCall(NtAllocateVirtualMemory, ...)
UseSysCall(NtWriteVirtualMemory, ...)
UseSysCall(NtCreateThreadEx, ...)
```

We are firing off a *ton* of telemetry to the kernel and any listening drivers. Without a single user mode hook we would know:

1. Process A opened a handle to Process B with X permissions (`ObRegisterCallbacks`)
2. Process A allocated memory in Process B with X permissions (`EtwTi`)
3. Process A wrote data into Process B VAS (`EtwTi`)
4. Process A created a remote thread in Process B (`PsSetCreateThreadNotifyRoutine`, `Etw`)

It is true that `EtwTi` is newish and doesn't capture everything, hence the partial effectiveness. But that argument grows thin overtime as adoption of the feed grows and the API matures.

A strong argument for syscalls here is that it evades custom data sinks. Up until now we've only considered what Microsoft provides, not what the vendor themselves might include in their hook routine, and how that telemetry might influence their agent's model. Some vendors, for performance reasons, prefer to extract thread information at call time. Some capture all parameters and pack them into more consumable binary blobs for consumption in the kernel. Depending on what exactly the hook does, and its criticality to the bayesian model, this might be a great reason to use them.

### your testing isn't comprehensive or indicative of the general case

This is a more general gripe with some of the conversation on modern EDR evasion. Modern EDRs use a variety of learning heuristics to determine if an unknown binary is malicious or not; sometimes successfully, sometimes not. This model is initially trained on some set of data (depending on the vendor), but continues to grow based on its observations of the environment and data shared amongst nodes. This is generally known as online learning. On large deploys of new EDRs there is typically a learning or passive phase; that allows the model to collect baseline metrics of what is normal and, hopefully, identify anomalies or deviations thereafter.  

Effectively then, given a long enough timeline, one enterprise's agent model might be *significantly* different from another. This has a few implications. The first being, of course, that your lab environment is not an accurate representation of the client. While your syscall stub might work fine in the lab, unless it's particularly novel, it's entirely possible it's been observed elsewhere. 

This also means that pinpointing the reason why your payload works or doesn't work is a bit of dark art. If your payload with the syscall evasion ends up working in a client environment, does that mean the evasion is successful, or would it have worked regardless of whether you used ntdll or not? If on the other hand your payload was blocked, can you identify the syscalls as the problem? Furthermore, if you add in evasion stubs and successfully execute, can we definitively point to the syscall evasion as the threat score culprit? 

At this point, then, it's a game of risk. You risk allowing the agent's model to continue aggregating telemetry and improving its heuristic, and thereby the entire network's model. Repeated testing taints the analysis chain as it grows to identify portions of your code as malicious or not; a fuzzy match, regardless of the function or assembler changes made. You also risk exposing the increased telemetry and details to the cloud which is then in the hands of both automated and manual tooling and analysis. If you disabled this portion, then, you also lack an accurate representation of detection capabilities.

In short, much of the testing we do against these new EDR solutions is rather unscientific. That's largely a result of our inability to both peer into the state of an agent's model while also deterministically assessing its capabilities. Testing in a limped state (ie. offline, with cloud connectivity blackholed, etc.) and restarting VMs after every test provides some basic insight but we lose a significant chunk of EDR capability. Isolation is difficult.

## anyway

These things, when taken together, motivate my reluctance to embrace the strategy in much of my tooling. I've found scant cases in which a raw syscall was preferable to some other technique and I've become *exhausted* by the veracity of some tooling claims. The EDRs today are not the EDRs of our red teaming forefathers; testing is complicated, telemetry insight is improving, and data sets and enterprise security budgets are growing. We've got to get better at quantifying and substantiating our tool testing/analysis, and we need to improve the conversation surrounding the technologies. 

I have a few brief, unsolicited thoughts for both red teams and EDR vendors based on my years of experience in this space. I'd love to hear others.

### for EDR 

Do not rely on user mode hooks and, more importantly, do not implicitly *trust* it. Seriously. Even if you're monitoring hook integrity from the kernel, there are too many variables and too many opportunities for malicious code to tamper with or otherwise corrupt the hook or the integrity of the incoming data. Consider this from a performance perspective if you need to. I know you think you're being cute by:

1. Monitoring your hot patches for modification
2. Encrypting telemetry 
3. Transmitting telemetry via clandestine/obscure methods (I see you `NtQuerySystemInformation`)
4. "Validating" client processes

The fact is anything emitted from an unsigned, untrusted, user mode process can be corrupted. Put your efforts into consuming ETW and registering callbacks on all important routines, PPL'ing your user mode services, and locking down your IPC and general communication channels. Consume AMSI if you must, with the same caveat as user mode hooks: it is a data sink, and not necessarily one of truth.

The more you can consume in the kernel (maybe a trustlet some day?), the more difficult you are to tamper with. There is of course the ability for red team to wormhole into the kernel and attack your driver, but this is another hurdle for an attacker to leap, and yet another opportunity to catch them.

### for red team

Using raw syscalls is but a small component of a greater system -- evasion is less a set of techniques and more a system of behaviors. Consider that the *hooks* themselves are not the problem, but rather what the hooks do. I had to edit myself several times here to not reference the spoon quote from the Matrix, but it's apt, if cliche. 

There are also more effective methods of evading user mode hooks than raw syscalling. I've discussed some of them publicly [in the past](https://twitter.com/dronesec/status/1355587781825683457), but urge you to investigate the machinations of the EDR hooks themselves. I'd argue even IAT/inline unhooking is more effective, in some cases.

Cloud capabilities are the truly scary expansion. Sample submission, cloud telemetry aggregation and analysis, and manual/automatic hunting services change the landscape of threat analysis. Not only can your telemetry be correlated or bolstered amongst nodes, it can be retroactively hunted and analyzed. This retroactive capability, often provided by backend automation or threat hunting teams (hi Overwatch!) can be quite effective at improving an enterprises agent models. And not only one enterprises model; consider the fact that these data points are shared amongst *all* vendor subscribers, used to subsequently improve those agent models. Burning a technique is no longer isolated to a technology or a client.
