# slirp4netns: User-mode networking for unprivileged network namespaces 

slirp4netns provides user-mode networking ("slirp") for unprivileged network namespaces.

## Motivation

Starting with Linux 3.8, unprivileged users can create [`network_namespaces(7)`](http://man7.org/linux/man-pages/man7/network_namespaces.7.html) along with [`user_namespaces(7)`](http://man7.org/linux/man-pages/man7/user_namespaces.7.html).
However, unprivileged network namespaces had not been very useful, because creating [`veth(4)`](http://man7.org/linux/man-pages/man4/veth.4.html) pairs across the host and network namespaces still requires the root privileges. (i.e. No internet connection)

slirp4netns allows connecting a network namespace to the Internet in a completely unprivileged way, by connecting a TAP device in a network namespace to the usermode TCP/IP stack ("slirp").

## Projects using slirp4netns

* [Usernetes](https://github.com/rootless-containers/usernetes) (via RootlessKit)
* [Podman](https://github.com/containers/libpod)

* [RootlessKit](https://github.com/rootless-containers/rootlesskit)
* [become-root](https://github.com/giuseppe/become-root)

## Quick start

### Install from source

```console
$ ./autogen.sh
$ ./configure --prefix=/usr
$ make
$ sudo make install
```

* To build `slirp4netns` as a static binary, please run `./configure` with `LDFLAGS=-static`.
* If you set `--prefix` to `$HOME`, you don't need to run `make install` with `sudo`.

### Install from binary

[Fedora](https://src.fedoraproject.org/rpms/slirp4netns):

```console
$ sudo dnf install slirp4netns
```

### Usage

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

Terminal 1: Make sure the `tap0` is configured and connected to the Internet
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

See [`slirp4netns.1.md`](slirp4netns.1.md) for further information.

## Benchmarks

### iperf3 (netns -> host)

Aug 28, 2018, on [RootlessKit](https://github.com/rootless-containers/rootlesskit) Travis: https://github.com/rootless-containers/rootlesskit/pull/16

Implementation |  MTU=1500  |  MTU=4000  |  MTU=16384  |  MTU=65520
---------------|------------|------------|-------------|------------
vde_plug       |  763 Mbps  |Unsupported | Unsupported | Unsupported
VPNKit         |  514 Mbps  |  526 Mbps  |   540 Mbps  | Unsupported
slirp4netns    | 1.07 Gbps  | 2.78 Gbps  |  4.55 Gbps  |  9.21 Gbps

slirp4netns is faster than [vde_plug](https://github.com/rd235/vdeplug_slirp) and [VPNKit](https://github.com/moby/vpnkit) because slirp4netns is optimized to avoid copying packets across the namespaces.

The latest revision of slirp4netns is regularly benchmarked (`make benchmark`) on Travis: https://travis-ci.org/rootless-containers/slirp4netns

## Acknowledgement

* The files under [`qemu`](./qemu) directory were forked from [QEMU](https://github.com/qemu/qemu/commit/c447afd5783b9237fa51b7a85777007d8d568bfc).
* The files under [`rd235_libslirp`](./rd235_libslirp) directory were forked from [rd235/libslirp](https://github.com/rd235/libslirp/commit/37fd650ad7fba7eb0360b1e1d0abf69cac6eb403).
* The files under [`parson`](./parson) directory were copied from [kgabis/parson](https://github.com/kgabis/parson/commit/0a1896939faff5f69e179637fc49f678ff0128ba) without any modification.
