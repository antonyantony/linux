#!/bin/bash -ue
set -e

stop=${1-'no'}
fwd=${fwd-'yes'}
in=${in-'yes'}

function stop () {
	set +ue
	for i in $(seq 1 6); do
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

# |host1 eth0|---|eth1 host2 eth0|==IPsec==|eth1 host3 eth0|===|eth1 host4 eth0|---|eth1 host5 eth0|--|eth1 host6|
# |host1 10.1.1.1|---|10.1.1.2 host2 10.1.2.1|===|10.1.2.2 host3 10.1.3.1|===|10.1.3.2 host 4 10.1.4.1|---|10.1.4.2 host5 10.1.5.1|---|10.1.5.2 host6|
# host2 and host4 are the IPsec gateways. tunnel between 10.2.1.2===10.1.3.2
# 10.1.0.0/24--|host2 10.1.2.2|===|10.1.3.2 host4|--10.1.5.0/24
# ping from host1 to host6
# host 3 in the middle. It block all ICMP.

if [ "${stop}" = "stop" ]; then
 stop
 exit
fi

AB="10.1"
M=${M-6}
mtu=${mtu-1500}
mtu0=${mtu}
for i in $(seq 1 ${M}); do
	h="host${i}"
	ip netns add ${h}
	ip -netns ${h} link set lo up
	ip netns exec ${h} sysctl -wq net.ipv4.ip_forward=1
	if [ $i -lt ${M} ]; then
		ip -netns ${h} link add eth0 type veth peer name eth10${i}
		ip -netns ${h} addr add "${AB}.${i}.1/24" dev eth0
		ip -netns ${h} link set up dev eth0
		ip -netns ${h} link set mtu ${mtu} dev eth0
		mtu=$((mtu - 20))
	fi
done

mtu=${mtu0}

for i in $(seq 1 ${M}); do
	h="host${i}"
	p=$((i - 1))
	ph="host${p}"
	# connect to previous host
	if [ $i -gt 1 ]; then
		ip -netns ${ph} link set eth10${p} netns ${h}
		ip -netns ${h} link set eth10${p} name eth1
		ip -netns ${h} link set up dev eth1
		ip -netns ${h} addr add "${AB}.${p}.2/24" dev eth1
		ip -netns ${h} link set mtu ${mtu} dev eth1
		mtu=$((mtu - 20))
	fi
	# add forward routes
	for k in $(seq ${i} $((M - 1))); do
		ip -netns ${h} route 2>/dev/null | (grep "${AB}.${k}.0" 2>/dev/null) || \
		ip -netns ${h} route add "${AB}.${k}.0/24" via "${AB}.${i}.2" 2>/dev/nul
	done

	# add reverse routes
	for k in $(seq 1 $((i - 2))); do
		ip -netns ${h} route 2>/dev/null | grep "${AB}.${k}.0" 2>/dev/null || \
		ip -netns ${h} route add "${AB}.${k}.0/24" via "${AB}.${p}.1" 2>/dev/nul
	done
done

# before the IPsec tunnels are up
ip netns exec host1 ping -q -W 2 -w 1 -c 1 10.1.5.2 2>&1>/dev/null
ip netns exec host1 traceroute -m 7 -nnn 10.1.5.2 || (echo FAILED && exit 1)
ip -netns host1 route flush cache

# blcok ping in the middle. Only allowed through the tunnel
ip netns exec host3 nft add table inet filter
ip netns exec host3 nft add chain inet filter FORWARD { type filter hook forward priority filter\; policy drop \; }
ip netns exec host3 nft add rule inet filter FORWARD counter ip protocol icmp drop
ip netns exec host3 nft add rule inet filter FORWARD counter ip protocol esp accept
ip netns exec host3 nft add rule inet filter FORWARD counter drop
ip netns exec host1 traceroute -m 7 -nnn 10.1.5.2 || echo success

ip -netns host2 xfrm policy add src 10.1.1.0/24 dst 10.1.5.0/24 dir out \
	flag icmp tmpl src 10.1.2.1 dst 10.1.3.2 proto esp reqid 1 mode tunnel

if [ "${in}" = "yes" ]; then
	ip -netns host2 xfrm policy add src 10.1.5.0/24 dst 10.1.1.0/24 dir in \
		tmpl src 10.1.3.2 dst 10.1.2.1 proto esp reqid 2 mode tunnel
fi

if [ "${fwd}" = "yes" ]; then
	ip -netns host2 xfrm policy add src 10.1.5.0/24 dst 10.1.1.0/24 dir fwd \
		flag icmp tmpl src 10.1.3.2 dst 10.1.2.1 proto esp reqid 2 mode tunnel
fi

ip -netns host2 xfrm state add src 10.1.2.1 dst 10.1.3.2 proto esp spi 1 \
	reqid 1 replay-window 1  mode tunnel aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src 10.1.1.0/24 dst 10.1.5.0/24

ip -netns host2 xfrm state add src 10.1.3.2 dst 10.1.2.1 proto esp spi 2 \
	flag icmp reqid 2 replay-window 10 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96

ip -netns host4 xfrm policy add src 10.1.5.0/24 dst 10.1.1.0/24 dir out \
	flag icmp tmpl src 10.1.3.2 dst 10.1.2.1 proto esp reqid 1 mode tunnel

if [ "${in}" = "yes" ]; then
	ip -netns host4 xfrm policy add src 10.1.1.0/24 dst 10.1.5.0/24 dir in \
		tmpl src 10.1.2.1 dst 10.1.3.2 proto esp reqid 2  mode tunnel
fi

if [ "${fwd}" = "yes" ]; then
	ip -netns host4 xfrm policy add src 10.1.1.0/24 dst 10.1.5.0/24 dir fwd \
		flag icmp tmpl src 10.1.2.1 dst 10.1.3.2 proto esp reqid 2 mode tunnel
fi

ip -netns host4 xfrm state add src 10.1.3.2 dst 10.1.2.1 proto esp spi 2 \
	reqid 1 replay-window 1 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96

ip -netns host4 xfrm state add src 10.1.2.1 dst 10.1.3.2 proto esp spi 1 \
	reqid 2 replay-window 20 flag icmp  mode tunnel aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src 10.1.1.0/24 dst 10.1.5.0/24

ip -netns host1 route flush cache
# ip -netns host2 x s
# ip -netns host2 x p
# ping ttl 3 will be dropped at host5 10.1.4.2
# From 10.1.4.2 icmp_seq=1 Time to live exceeded
ip netns exec host1 ping -W 2 -c 1 -t 3 10.1.5.2 && echo "ERROR" || echo "success expected 100% packet loss"
sleep 2
# both seq and oseq should be 0x1
# anti-replay context: seq 0x1, oseq 0x0, bitmap 0x00000001
# anti-replay context: seq 0x0, oseq 0x1, bitmap 0x00000000
# anti-replay context: seq 0x1, oseq 0x0, bitmap 0x00000001
# anti-replay context: seq 0x0, oseq 0x1, bitmap 0x00000000
h2=$(ip -netns host2 x s | grep "seq 0x1"|wc -l)
h4=$(ip -netns host2 x s | grep "seq 0x1"|wc -l)
s=$((h2 + h4))
if [ ${s} = 4 ] ; then
	echo "success"
else
	echo "fail"
fi
ip netns exec host1 traceroute -m 8 -nnn 10.1.5.2
ip netns exec host1 tracepath -nnn 10.1.5.2
echo "should have response from 10.1.4.2"
ip -netns host2 x s | grep seq
ip -netns host4 x s | grep seq

ip netns exec host2 grep -vw 0  /proc/net/xfrm_stat
ip netns exec host4 grep -vw 0  /proc/net/xfrm_stat
echo end
