---
categories:
- ibm
- tealeaf
- command injection
- lfi
comments: false
date: "2014-03-26T22:51:11Z"
title: IBM Tealeaf CX (v8 Release 8) Remote OS Command Injection / LFI
---

Tealeaf Technologies was [purchased](http://techcrunch.com/2012/05/02/ibm-acquires-tealeaf-to-add-customer-buying-analytics-to-smarter-commerce-products/) by IBM in May of 2012, and is a customer buying analytics application.  Essentially, an administrator will configure a Tealeaf server that accepts analytic data from remote servers, which it then generates various models, graphs, reports, etc based on the aggregate of data. 
Their analytics status/server monitoring application is vulnerable to a fairly trivial OS command injection vulnerability, as well as local file inclusion.  This vulnerability was discovered on a PCI engagement against a large retailer; the LFI was used to pull PHP files and hunt for RCE.

The entire application is served up by default on port 8080 and is developed in PHP.  Authentication by default is disabled, however, support for Basic Auth appears to exist.  This interface allows administrators access to statistics, logs, participating servers, and more.  Contained therein is the ability to obtain application logs, such as configuration, maintenance, access, and more.  The log parameter is vulnerable to LFI:

```
if(array_key_exists("log", $params))
$path = $config->logfiledir() . "/" . $params["log"];


$file = basename($path);
$size = filesize($path);

// Set the cache-control and expiration date so that the file expires
// immediately after download.
//
$rfc1123date = gmdate('D, d M Y H:i:s T', 1);
header('Cache-Control: max-age=0, must-revalidate, post-check=0, pre-check=0');
header("Expires: " . $rfc1123date);

header("Content-Type: application/octet-stream");
header("Content-Disposition: attachment; filename=$file;");
header("Content-Length: $size;");

readfile($path);
```

The URL then is `http://host:8080/download.php?log=../../../etc/passwd`

Tealeaf also suffers from a rather trivial remote OS command injection vulnerability.  Under the Delivery tab, there exists the option to ping remote servers that send data back to the mothership.  Do you see where this is going?

```
if ($_POST["perform_action"] == "testconn") {
    $host = $_POST["testconn_host"];
    $port = $_POST["testconn_port"];
    $use_t = strtolower($_POST["testconn_t"]) == "true" ? true : false;
    $command = $GLOBALS["config"]->testconn_program() . ' ';
    if($use_t)
    $output = trim(shell_command_output($command . $host . " -p " . $port . " -t"));
    else
    $output = trim(shell_command_output($command . $host . " -p " . $port));

    if($output != "") {
        $alert_function = "alert('" . str_replace("\n", "\\n",
        htmlentities($output, ENT_QUOTES)) . "')";
    }

    $_SESSION['delivery']->pending_changes = $orig_pending_changes;
}
```

And shell_command_output:

```
function shell_command_output($command) {
    $result = `$command 2>&1`;
    if (strlen($result) > 0)
    return $result;
}
```

Harnessing the `$host` variable, we can inject arbitrary commands to run under the context of the process user, which by default is `ctccap`.  In order to exploit this without hanging processes or goofing up flow, I injected the following as the host variable: `8.8.8.8 -c 1 ; whoami ; ping 8.8.8.8 -c 1`.  

<h3>Timeline</h3>
+ 11/08/2013: IBM vulnerability submitted
+ 11/09/2013: IBM acknowledge vulnerability and assign internal advisory ID
+ 12/05/2013: Request for status update
+ 01/06/2014: Second request for status update
+ 01/23/2014: IBM responds with a target patch date set for "another few months"
+ 03/26/2014: IBM posts advisory, assigns CVE-2013-6719 and CVE-2013-6720

[Advisory](http://www-01.ibm.com/support/docview.wss?uid=swg21667630)  
[exploit-db PoC](http://www.exploit-db.com/exploits/32546/)
