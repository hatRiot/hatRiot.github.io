---
categories:
- windows
- elevation of privilege
comments: false
date: "2018-08-22T15:10:04Z"
title: Dell Digital Delivery - CVE-2018-11072 - Local Privilege Escalation
---

Back in March or April I began reversing a slew of Dell applications installed
on a laptop I had. Many of them had privileged services or processes running
and seemed to perform a lot of different complex actions. I previously
disclosed a LPE in SupportAssist[0], and identified another in their Digital
Delivery platform. This post will detail a Digital Delivery vulnerability and 
how it can be exploited. This was privately discovered and disclosed, and no 
known active exploits are in the wild. Dell has issued a security advisory for
this issue, which can be found here[4].

I'll have another follow-up post detailing the internals of this application
and a few others to provide any future researchers with a starting point. 
Both applications are rather complex and expose a large attack surface. 
If you're interested in bug hunting LPEs in large C#/C++ applications, it's
a fine place to begin.

Dell's Digital Delivery[1] is a platform for buying and installing system
software. It allows users to purchase or manage software packages and reinstall
them as necessary. Once again, it comes "..preinstalled on most Dell
systems."[1]

## Bug

The Digital Delivery service runs as SYSTEM under the name DeliveryService,
which runs the DeliveryService.exe binary. A userland binary, DeliveryTray.exe,
is the user-facing component that allows users to view installed applications
or reinstall previously purchased ones.

Communication from DeliveryTray to DeliveryService is performed via a 
Windows Communication Foundation (WCF) named pipe. If you're unfamiliar with
WCF, it's essentially a standard methodology for exchanging data between two
endpoints[2]. It allows a service to register a processing endpoint and expose
functionality, similar to a web server with a REST API.

For those following along at home, you can find the initialization of the WCF
pipe in `Dell.ClientFulfillmentService.Controller.Initialize`:

```
this._host = WcfServiceUtil.StandupServiceHost(typeof(UiWcfSession),
                                typeof(IClientFulfillmentPipeService),
                                "DDDService");
```

This invokes `Dell.NamedPipe.StandupServiceHost`:

```
ServiceHost host = null;
string apiUrl = "net.pipe://localhost/DDDService/IClientFulfillmentPipeService";
Uri realUri = new Uri("net.pipe://localhost/" + Guid.NewGuid().ToString());
Tryblock.Run(delegate
{
  host = new ServiceHost(classType, new Uri[]
  {
    realUri
  });
  host.AddServiceEndpoint(interfaceType, WcfServiceUtil.CreateDefaultBinding(), string.Empty);
  host.Open();
}, null, null);
AuthenticationManager.Singleton.RegisterEndpoint(apiUrl, realUri.AbsoluteUri);
```

The endpoint is thus registered and listening and the AuthenticationManager
singleton is responsible for handling requests. Once a request comes in, the
AuthenticationManager passes this off to the AuthPipeWorker function which,
among other things, performs the following authentication:

```
string execuableByProcessId = AuthenticationManager.GetExecuableByProcessId(processId);
bool flag2 = !FileUtils.IsSignedByDell(execuableByProcessId);
if (!flag2)
{
    ...
```

If the process on the other end of the request is backed by a signed Dell
binary, the request is allowed and a connection may be established. If not, the
request is denied.

I noticed that this is new behavior, added sometime between 3.1 (my original
testing) and 3.5 (latest version at the time, 3.5.1001.0), so I assume Dell is
aware of this as a potential attack vector. Unfortunately, this is an
inadequate mitigation to sufficiently protect the endpoint. I was able to get
around this by simply spawning an executable signed by Dell (DeliveryTray.exe,
for example) and injecting code into it. Once code is injected, the WCF API
exposed by the privileged service is accessible.

The endpoint service itself is implemented by `Dell.NamedPipe`, and exposes a
dozen or so different functions. Those include:

```
ArchiveAndResetSettings
EnableEntitlements
EnableEntitlementsAsync
GetAppSetting
PingTrayApp
PollEntitlementService
RebootMachine
ReInstallEntitlement
ResumeAllOperations
SetAppSetting
SetAppState
SetEntitlementList
SetUserDownloadChoice
SetWallpaper
ShowBalloonTip
ShutDownApp
UpdateEntitlementUiState
```

Digital Delivery calls application install packages "entitlements", so the
references to installation/reinstallation are specific to those packages either
available or presently installed.

One of the first functions I investigated was `ReInstallEntitlement`, which
allows one to initiate a reinstallation process of an installed entitlement.
This code performs the following:

```
private static void ReInstallEntitlementThreadStart(object reInstallArgs)
{
    PipeServiceClient.ReInstallArgs ra = (PipeServiceClient.ReInstallArgs)reInstallArgs;
    PipeServiceClient.TryWcfCall(delegate
    {
        PipeServiceClient._commChannel.ReInstall(ra.EntitlementId, ra.RunAsUser);
    }, string.Concat(new object[]
    {
        "ReInstall ",
        ra.EntitlementId,
        " ",
        ra.RunAsUser.ToString()
    }));
}

```

This builds the arguments from the request and invokes a WCF call, which is
sent to the WCF endpoint. The `ReInstallEntitlement` call takes two arguments:
an entitlement ID and a RunAsUser flag. These are both controlled by the
caller.

On the server side, `Dell.ClientFulfillmentService.Controller` handles
implementation of these functions, and  `OnReInstall` handles the entitlement
reinstallation process. It does a couple sanity checks, validates the package
signature, and hits the `InstallationManager` to queue the install request. The
`InstallationManager` has a job queue and background thread (`WorkingThread`)
that occasionally polls for new jobs and, when it receives the install job,
kicks off `InstallSoftware`.

Because we're reinstalling an entitlement, the package is cached to disk and
ready to be installed. I'm going to gloss over a few installation steps
here because it's frankly standard and menial. 

The installation packages are located in 
`C:\ProgramData\Dell\DigitalDelivery\Downloads\Software\` and are first
unzipped, followed by an installation of the software. In my case, I was
triggering the installation of `Dell Data Protection - Security Tools v1.9.1`,
and if you follow along in procmon, you'll see it startup an install process:

```
"C:\ProgramData\Dell\Digital Delivery\Downloads\Software\Dell Data Protection _
Security Tools v1.9.1\STSetup.exe" -y -gm2 /S /z"\"CIRRUS_INSTALL,
SUPPRESSREBOOT=1\""
```

The run user for this process is determined by the controllable RunAsUser flag
and, if set to False, runs as `SYSTEM` out of the `%ProgramData%` directory.

During process launch of the `STSetup` process, I noticed the following in
procmon:

```
C:\ProgramData\Dell\Digital Delivery\Downloads\Software\Dell Data Protection _ Security Tools v1.9.1\VERSION.dll
C:\ProgramData\Dell\Digital Delivery\Downloads\Software\Dell Data Protection _ Security Tools v1.9.1\UxTheme.dll
C:\ProgramData\Dell\Digital Delivery\Downloads\Software\Dell Data Protection _ Security Tools v1.9.1\PROPSYS.dll
C:\ProgramData\Dell\Digital Delivery\Downloads\Software\Dell Data Protection _ Security Tools v1.9.1\apphelp.dll
C:\ProgramData\Dell\Digital Delivery\Downloads\Software\Dell Data Protection _ Security Tools v1.9.1\Secur32.dll
C:\ProgramData\Dell\Digital Delivery\Downloads\Software\Dell Data Protection _ Security Tools v1.9.1\api-ms-win-downlevel-advapi32-l2-1-0.dll
```

Of interest here is that the parent directory, `%ProgramData%\Dell\Digital
Delivery\Downloads\Software` is not writable by any system user, but the
entitlement package folders, `Dell Data Protection - Security Tools` in this
case, is.

This allows non-privileged users to drop arbitrary files into this
directory, granting us a DLL hijacking opportunity. 

## Exploitation

Exploiting this requires several steps:

1. Drop a DLL under the appropriate `%ProgramData%` software package directory
2. Launch a new process running an executable signed by Dell
3. Inject C# into this process (which is running unprivileged in userland)
4. Connect to the WCF named pipe from within the injected process
5. Trigger ReInstallEntitlement

Steps 4 and 5 can be performed using the following:

```
PipeServiceClient client = new PipeServiceClient();
client.Initialize();

while (PipeServiceClient.AppState == AppState.Initializing)
  System.Threading.Thread.Sleep(1000);

EntitlementUiWrapper entitle = PipeServiceClient.EntitlementList[0];
PipeServiceClient.ReInstallEntitlement(entitle.ID, false);
System.Threading.Thread.Sleep(30000);

PipeServiceClient.CloseConnection();
```

The classes used above are imported from `NamedPipe.dll`. Note that we're
simply choosing the first entitlement available and reinstalling it. You may
need to iterate over entitlements to identify the correct package pointing to
where you dropped your DLL.

I've provided a PoC on my Github here[3], and Dell has additionally released 
a security advisory, which can be found here[4].

## Timeline

05/24/18 - Vulnerability initially reported  
05/30/18 - Dell requests further information  
06/26/18 - Dell provides update on review and remediation  
07/06/18 - Dell provides internal tracking ID and update on progress  
07/24/18 - Update request  
07/30/18 - Dell confirms they will issue a security advisory and associated CVE  
08/07/18 - 90 day disclosure reminder provided  
08/10/18 - Dell confirms 8/22 disclosure date alignment  
08/22/18 - Public disclosure  

## References
[0] http://hatriot.github.io/blog/2018/05/17/dell-supportassist-local-privilege-escalation/<br/>
[1] https://www.dell.com/learn/us/en/04/flatcontentg/dell-digital-delivery<br/>
[2] https://docs.microsoft.com/en-us/dotnet/framework/wcf/whats-wcf<br/>
[3] https://github.com/hatRiot/bugs<br/>
[4] https://www.dell.com/support/article/us/en/04/SLN313559<br/>
