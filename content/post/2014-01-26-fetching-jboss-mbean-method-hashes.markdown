---
categories:
- jboss
- clusterd
comments: false
date: "2014-01-26T01:24:19Z"
title: Fetching JBoss MBean method hashes
---

Matasano published [one](http://www.matasano.com/research/OWASP3011_Luca.pdf) of [two](https://www.redteam-pentesting.de/en/publications/jboss/-bridging-the-gap-between-the-enterprise-and-you-or-whos-the-jboss-now) canonical papers on JBoss exploitation.  While working on a fresh new tool, I came across the JMXInvokerServlet technique, which uses serialized Java requests to deploy to remote MBeans.  This uses a specific object hash to route the JMX request to the correct MBean; in our case, the gold is jboss.jmx:name=Invoker.

In this paper, Matasano provides the hash for JBoss 4.0.3SP1, but does not list any others, nor show how it derived this.  After perusing the code, however, I found it to be quite simple, and have developed a simple method for fetching hashes of not only the Invoker MBean, but any listed in the JBoss registry.

To extract these values, we simply deploy a WAR file that dumps the entirety of the Registry, which is used for hash lookups when routing requests.  This can can be seen below:

```
<%@ page import="org.jboss.system.Registry"%>
<%@ page import="java.io.*"%>
<%@ page import="java.util.Map"%>
<%@ page import="java.util.Iterator"%>
<%
    Iterator it = Registry.entries.entrySet().iterator();
    while (it.hasNext()){
        Map.Entry pairs = (Map.Entry)it.next();
        out.println(pairs.getKey() + " = " + pairs.getValue() + "<br/>");
        it.remove();
    }
%>
```

When deployed and executed on my local 4.0.5.GA JBoss server, we get:

{{< figure class="center" src="/images/posts/2014/jb_hash.jpg" >}}

With this, we've fetched the hash for the Invoker MBean as well as every other invokable MBean in the registry.  This value appears to be common across all 3.x and 4.x JBoss instances.  However, when run against JBoss 5.x/6.x instances, the following is returned:

{{< figure class="center" src="/images/posts/2014/jb_hash_6x.jpg" >}}

This change is due to the way look-ups are performed in 5.x; instead of the key being an Integer (hash), the key is now an Object, as shown below:

```
public static Map<Object, Object> entries = new ConcurrentHashMap<Object, Object>();
```

To further enumerate this, we can iterate over the class methods and pull all of their hashes and hash codes:

```
<%@ page import="java.io.*"%>
<%@ page import="java.util.Map"%>
<%@ page import="java.util.Iterator"%>
<%@ page import="java.lang.reflect.Method"%>
<%@ page import="org.jboss.system.Registry"%>
<%@ page import="javax.management.ObjectName"%>
<%@ page import="org.jboss.invocation.MarshalledInvocation"%>
<%
    Iterator it = Registry.entries.entrySet().iterator();
    while (it.hasNext()){
        Map.Entry pairs = (Map.Entry)it.next();
        out.println(pairs.getKey() + " = " + pairs.getValue() + "<br/>");

        // check for ObjectName
        if (pairs.getKey() instanceof ObjectName){
            Long hash;
            Method[] methods = pairs.getValue().getClass().getMethods();
            for (int m = 0; m < methods.length; ++m){
                Method method = methods[m];
                hash = new Long(MarshalledInvocation.calculateHash(method));
                out.println("Method: " + method + "  Hash: " + hash + " (" + method.hashCode() + ")" + "<br/>");
            }
        }

        out.println("Key class: " + pairs.getKey().getClass() + "<br/>");
        it.remove();
    }
%>
```

Which gives us:

{{< figure class="center" src="/images/posts/2014/jb_6x_methods.jpg" >}}

Judging by this information, it doesn't appear that we can remotely invoke the same way we did with 3.x/4.x.  This is the fundamental issue with several of the available open source JBoss tools (Metasploit); none of them take into account the changes between different versions of JBoss.

Although I have yet to discover a way to map requests to the invoker (I'm not entirely sure its possible) in these later versions, I have a suspicion that we may be able to map these requests by serializing objects out.  More on this, and my exploitation tool, soon.
