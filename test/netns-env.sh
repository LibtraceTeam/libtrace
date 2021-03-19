#!/bin/bash

# This script sets up the netns env and then runs
# the given argument which does the actual tests

NS="libtrace_testing"
EXEC="ip netns exec $NS"

if [ "$(id -u)" != "0" ]; then
   echo "WARNING: this test most likely needs to be run as ROOT!" 1>&2
fi

if [ "$#" -eq 0 ]; then
    echo "Expects at least one argument, the test with arguments to run in the network namespace"
    echo "    e.g. $0 ./do-live-tests.sh"
    exit 1
fi



# Setup a netns this is isolated from kernel interference
# such as trying to respond to ping ARPs etc
# Turns out the kernel will still try to setup IPv6 link
# addresses so disable IPv6 on them also
ip netns add $NS > /dev/null 2>&1

$EXEC ip link delete veth0 > /dev/null 2>&1
$EXEC ip link add veth0 type veth peer name veth1

$EXEC sysctl -w net.ipv6.conf.veth0.autoconf=0 > /dev/null 2>&1

$EXEC sysctl -w net.ipv6.conf.veth1.autoconf=0 > /dev/null 2>&1

$EXEC sysctl -w net.ipv6.conf.veth0.accept_ra=0 > /dev/null 2>&1

$EXEC sysctl -w net.ipv6.conf.veth1.accept_ra=0 > /dev/null 2>&1

$EXEC sysctl -w net.ipv6.conf.veth0.disable_ipv6=1 > /dev/null 2>&1

$EXEC sysctl -w net.ipv6.conf.veth1.disable_ipv6=1 > /dev/null 2>&1


$EXEC ip link set veth0 up
$EXEC ip link set veth1 up

# We now have the interfaces veth0 and veth1 connected
# together as if by a cable.


GOT_NETNS=1 $EXEC "$@"


#cleanup - deleting veth0 impilies veth1 also since these are
# linked together
$EXEC ip link delete veth0
ip netns delete $NS
