SLIRP4NETNS 1 "July 2018" "Rootless Containers" "User Commands"
==================================================

# NAME

slirp4netns - User-mode networking for unprivileged network namespaces

# SYNOPSIS

slirp4netns [OPTION]... PID TAPNAME

# DESCRIPTION

slirp4netns provides user-mode networking ("slirp") for network namespaces.

Unlike **veth**(4), slirp4netns does not require the root privileges on the host.

Default configuration:

* Gateway: 10.0.2.2, fd00::2
* DNS: 10.0.2.3, fd00::3
* Host: 10.0.2.2, 10.0.2.3, fd00::2, fd00::3

# OPTIONS

**-c**, **--configure**
bring up the interface. IP will be set to 10.0.2.100. IPv6 will be set to a random address.

**-e**, **--exit-fd=FD**
specify the FD for terminating slirp4netns.

**-r**, **--ready-fd=FD**
specify the FD to write to when the network is configured.

**-m**, **--mtu=MTU**
specify MTU (default=1500, max=65521).

**-a**, **--api-socket**
API socket path

**-6**, **--enable-ipv6**
enable IPv6 (experimental).

# EXAMPLE

Terminal 1: Create user/network/mount namespaces
```console
$ unshare --user --map-root-user --net --mount
unshared$ echo $$ > /tmp/pid
```

Terminal 2: Start slirp4netns
```console
$ slirp4netns --configure --mtu=65520 $(cat /tmp/pid) tap0
starting slirp, MTU=65520
...
```

Terminal 1: Make sure **tap0** is configured and connected to the Internet
```console
unshared$ ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
3: tap0: <BROADCAST,UP,LOWER_UP> mtu 65520 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether c2:28:0c:0e:29:06 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.100/24 brd 10.0.2.255 scope global tap0
       valid_lft forever preferred_lft forever
    inet6 fe80::c028:cff:fe0e:2906/64 scope link 
       valid_lft forever preferred_lft forever
unshared$ echo "nameserver 10.0.2.3" > /tmp/resolv.conf
unshared$ mount --bind /tmp/resolv.conf /etc/resolv.conf
unshared$ curl https://example.com
```

Bind-mounting **/etc/resolv.conf** is only needed when **/etc/resolv.conf** on
the host refers to loopback addresses (**127.0.0.X**, typically because of
**dnsmasq**(8) or **systemd-resolved.service**(8)) that cannot be accessed from
the namespace.

If your **/etc/resolv.conf** on the host is managed by **networkmanager**(8)
or **systemd-resolved.service**(8), you might need to mount a new filesystem on
**/etc** instead, so as to prevent the new **/etc/resolv.conf** from being
unmounted unexpectedly when **/etc/resolv.conf** on the host is regenerated.

```console
unshared$ mkdir /tmp/a /tmp/b
unshared$ mount --rbind /etc /tmp/a
unshared$ mount --rbind /tmp/b /etc
unshared$ mkdir /etc/.ro
unshared$ mount --move /tmp/a /etc/.ro
unshared$ cd /etc
unshared$ for f in .ro/*; do ln -s $f $(basename $f); done
unshared$ rm resolv.conf
unshared$ echo "nameserver 10.0.2.3" > /tmp/resolv.conf
unshared$ curl https://example.com
```

# ROUTING PING PACKETS

To route ping packets, you need to set up **net.ipv4.ping_group_range** properly
as the root.

e.g.
```console
$ sudo sh -c "echo 0   2147483647  > /proc/sys/net/ipv4/ping_group_range"
```

# API SOCKET

slirp4netns can provide QMP-like API server over an UNIX socket file:

```console
$ slirp4netns --api-socket /tmp/slirp4netns.sock ...
```

**add_hostfwd**: Expose a port

```console
$ json='{"execute": "add_hostfwd", "arguments": {"proto": "tcp", "host_addr": "0.0.0.0", "host_port": 8080, "guest_addr": "10.0.2.100", "guest_port": 80}}'
$ echo -n $json | nc -U /tmp/slirp4netns.sock
{ "return": {"id": 42}}
```

**list_hostfwd**: List exposed ports

```console
$ json='{"execute": "list_hostfwd"}'
$ echo -n $json | nc -U /tmp/slirp4netns.sock
{ "return": {"entries": [{"id": 42, "proto": "tcp", "host_addr": "0.0.0.0", "host_port": 8080, "guest_addr": "10.0.2.100", "guest_port": 80}]}}
```

**remove_hostfwd**: Remove an exposed port

```console
$ json='{"execute": "remove_hostfwd", "arguments": {"id": 42}}'
$ echo -n $json | nc -U /tmp/slirp4netns.sock
{ "return": {}}
```

Remarks:

* Client needs to **shutdown** the socket with **SHUT_WR** after sending every request.
  i.e. No support for keep-alive and timeout.
* slirp4netns "stops the world" during processing API requests.
* A request must be less than 4095 bytes.
* JSON responses may contain **error** instead of **return**.
* **add_hostfwd** is not tested with IPv6.

# SEE ALSO

**network_namespaces**(7), **user_namespaces**(7), **veth**(4)

# AVAILABILITY

The slirp4netns command is available from **https://github.com/rootless-containers/slirp4netns** under GNU GENERAL PUBLIC LICENSE Version 2.
