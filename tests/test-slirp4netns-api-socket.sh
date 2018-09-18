#!/bin/bash
set -xeuo pipefail

. $(dirname $0)/common.sh

unshare -r -n sleep infinity &
child=$!

wait_for_network_namespace $child

tmpdir=$(mktemp -d /tmp/slirp4netns-bench.XXXXXXXXXX)
apisocket=${tmpdir}/slirp4netns.sock
slirp4netns -c $child --api-socket $apisocket tun11 &
slirp_pid=$!

wait_for_network_device $child tun11

function cleanup {
    kill -9 $child $slirp_pid
    rm -rf $tmpdir
}
trap cleanup EXIT


result=$(echo 'badjson' | nc -U $apisocket)
echo $result | jq .error.desc | grep "bad request: cannot parse JSON"

result=$(echo '{"unexpectedjson": 42}' | nc -U $apisocket)
echo $result | jq .error.desc | grep "bad request: no execute found"

result=$(echo '{"execute": "bad"}' | nc -U $apisocket)
echo $result | jq .error.desc | grep "bad request: unknown execute"

result=$(echo '{"execute": "add_hostfwd", "arguments":{"proto": "bad"}}' | nc -U $apisocket)
echo $result | jq .error.desc | grep "bad request: add_hostfwd: bad arguments.proto"

set +e
result=$(cat /dev/urandom | nc -U $apisocket)
set set -e
echo $result | jq .error.desc | grep "bad request: too large message"

# see also: benchmarks/benchmark-iperf3-reverse.sh
