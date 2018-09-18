#!/bin/bash
set -xeuo pipefail

. $(dirname $0)/../tests/common.sh

iperf3 -s > /dev/null &

unshare -r -n sleep infinity &
child=$!

wait_for_network_namespace $child

mtu=${MTU:=1500}
tmpdir=$(mktemp -d /tmp/slirp4netns-bench.XXXXXXXXXX)
apisocket=${tmpdir}/slirp4netns.sock
slirp4netns -c --mtu $mtu --api-socket $apisocket $child tun11 &
slirp_pid=$!

wait_for_network_device $child tun11
wait_for_ping_connectivity $child 10.0.2.2

nsenter --preserve-credentials -U -n --target=$child iperf3 -s -p 15201 > /dev/null &
iperf3_pid=$!

expose_tcp $apisocket 15201 15201

function cleanup {
    kill -9 $iperf3_pid $child $slirp_pid
    rm -rf $tmpdir
}
trap cleanup EXIT

iperf3 -c 127.0.0.1 -p 15201 -t 60
