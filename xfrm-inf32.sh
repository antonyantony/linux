#!/bin/bash -ue
set -e

stop=${1-'no'}
fwd=${fwd-'yes'}
in=${in-'no'}

function stop () {
	set +ue
	for i in $(seq 1 2); do
		h="host${i}"
		j=$((i + 1))
		ip netns | grep ${h} > /dev/null || continue
		if [ $i -lt 6 ]; then
			ip -netns ${h} x s f
			ip -netns ${h} x p f
			ip -netns ${h} link set eth0 down 2>/dev/null
			ip -netns ${h} link del eth0 2>/dev/null
			ip -netns ${h} link set eth1 down 2>/dev/null
			ip -netns ${h} link del eth1 2>/dev/null
			# ip -netns ${h} link
		fi
		ip netns del ${h}
	done
	set -ue
}

# |host1 eth0|---|eth1 host2|
# |host1 10.1.1.1|---|10.1.1.2 host2|
# ping from host1 to host2

if [ "${stop}" = "stop" ]; then
 stop
 exit
fi

IP1=10.1.1.1
IP2=10.1.1.2
M=${M-2}

h1="host1"
h2="host2"
# ip -netns ${h1} xfrm s f; ip -netns ${h1} xfrm p f; ip -netns ${h2} xfrm s f; ip -netns ${h2} xfrm p f; ip -netns ${h1} xfrm s f; ip -netns ${h1} xfrm p f; ip -netns ${h2} xfrm s f; ip -netns ${h2} xfrm p f;

h=${h1}
ip netns add ${h}
ip -netns ${h} link set lo up
ip netns exec ${h} sysctl -wq net.ipv4.ip_forward=1
ip -netns ${h} link add eth0 type veth peer name eth1
ip -netns ${h} addr add "${IP1}/24" dev eth0
ip -netns ${h} link set up dev eth0
ip netns exec ${h} sysctl -w net.core.xfrm_aevent_rseqth=0
ip netns exec ${h} sysctl -w net.core.xfrm_aevent_etime=0

h=${h2}
ip netns add ${h}
ip -netns ${h} link set lo up
ip netns exec ${h} sysctl -wq net.ipv4.ip_forward=1
ip -netns ${h1} link set eth1 netns ${h2}
ip -netns ${h} link set eth1 name eth0
ip -netns ${h} link set up dev eth0
ip -netns ${h} addr add "${IP2}/24" dev eth0
ip netns exec ${h} sysctl -w net.core.xfrm_aevent_rseqth=0
ip netns exec ${h} sysctl -w net.core.xfrm_aevent_etime=0

# before the IPsec tunnel up
ip netns exec ${h1} ping -q -W 2 -w 1 -c 1 ${IP2} 2>&1>/dev/null

ip -netns ${h1} xfrm policy add src ${IP1} dst ${IP2} dir out \
	tmpl src ${IP1} dst ${IP2} proto esp reqid 1 mode tunnel

ip -netns ${h1} xfrm policy add src ${IP2} dst ${IP1} dir in \
	tmpl src ${IP2} dst ${IP1} proto esp reqid 2 mode tunnel

ip -netns ${h1} xfrm state add src ${IP1} dst ${IP2} proto esp spi 1 \
	reqid 1 mode tunnel cur packets 0xfffffffc aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src ${IP1} dst ${IP2}
ip -netns ${h1} xfrm state add src ${IP2} dst ${IP1} proto esp spi 2 \
	reqid 2 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96 \
	sel src ${IP2} dst ${IP1}

ip -netns ${h2} xfrm policy add src ${IP1} dst ${IP2} dir in \
	tmpl src ${IP1} dst ${IP2} proto esp reqid 1 mode tunnel

ip -netns ${h2} xfrm policy add src ${IP2} dst ${IP1} dir out \
	tmpl src ${IP2} dst ${IP1} proto esp reqid 2 mode tunnel

ip -netns ${h2} xfrm state add src ${IP1} dst ${IP2} proto esp spi 1 \
	reqid 1 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src ${IP1} dst ${IP2}
ip -netns ${h2} xfrm state add src ${IP2} dst ${IP1} proto esp spi 2 \
	reqid 2 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96 \
	sel src ${IP2} dst ${IP1}

# XfrmOutStateSeqError    	2
