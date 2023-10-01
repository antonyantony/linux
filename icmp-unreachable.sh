#!/bin/bash -ue
set -e
M=${M-5}
stop=${stop:-"no"}

function stop () {
	set +ue
	for i in $(seq 1 ${M}); do
		h="host${i}"
		j=$((i + 1))
		ip netns | grep ${h} > /dev/null || continue
		if [ $i -lt 5 ]; then
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

# |host1 eth0|---|eth1 host2 eth0|==IPsec==|eth1 host3 eth0|===|eth1 host4 eth0|---|eth1 host5 eth0|
# |host1 10.1.1.1|---|10.1.1.2 host2 10.1.2.1|===|10.1.2.2 host3 10.1.3.1|===|10.1.3.2 host 4 10.1.4.1|---|10.1.4.2 host5|
# host2 and host4 are the IPsec gateways. tunnel end points 10.2.1.2===10.1.3.2
# Tunneled network 10.1.0.0/24--|host2 10.1.2.2|===|10.1.3.2 host4|--10.1.4.0/24
# ping from host1 to host5 will go through the tunnel
# ping from host1 to 10.1.4.3 would generate host unreachable from host4
# host 3 in the middle blocks all ICMP.

if [ "${stop}" = "stop" ]; then
 stop
 exit
fi

AB="10.1"
for i in 1 2 3 4 5; do
	h="host${i}"
	ip netns add ${h}
	ip -netns ${h} link set lo up
	ip netns exec ${h} sysctl -wq net.ipv4.ip_forward=1
	if [ $i -lt ${M} ]; then
		ip -netns ${h} link add eth0 type veth peer name eth10${i}
		ip -netns ${h} addr add "${AB}.${i}.1/24" dev eth0
		ip -netns ${h} link set up dev eth0
	fi
done

for i in 1 2 3 4 5; do
	h="host${i}"
	p=$((i - 1))
	ph="host${p}"
	# connect to previous host
	if [ $i -gt 1 ]; then
		ip -netns ${ph} link set eth10${p} netns ${h}
		ip -netns ${h} link set eth10${p} name eth1
		ip -netns ${h} link set up dev eth1
		ip -netns ${h} addr add "${AB}.${p}.2/24" dev eth1
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
ip netns exec host1 ping -q -W 2 -w 1 -c 1 10.1.4.2 2>&1>/dev/null && echo "success 10.1.4.2 reachable" || echo "ERROR"
ip netns exec host1 ping -W 9 -w 5 -c 1 10.1.4.3 || echo  "note the source address of unreachble"
ip -netns host1 route flush cache

# blcok ping/icmp in the middle. Only allowed through the tunnel
# ip netns exec host3 nft add table inet filter
# ip netns exec host3 nft add chain inet filter FORWARD { type filter hook forward priority filter\; policy drop \; }
# ip netns exec host3 nft add rule inet filter FORWARD counter ip protocol icmp drop
# ip netns exec host3 nft add rule inet filter FORWARD counter ip protocol esp accept
# ip netns exec host3 nft add rule inet filter FORWARD counter drop

ip -netns host2 xfrm policy add src 10.1.1.0/24 dst 10.1.4.0/24 dir out \
	flag icmp tmpl src 10.1.2.1 dst 10.1.3.2 proto esp reqid 1 mode tunnel

ip -netns host2 xfrm policy add src 10.1.4.0/24 dst 10.1.1.0/24 dir in \
	tmpl src 10.1.3.2 dst 10.1.2.1 proto esp reqid 2 mode tunnel

ip -netns host2 xfrm policy add src 10.1.4.0/24 dst 10.1.1.0/24 dir fwd \
	flag icmp tmpl src 10.1.3.2 dst 10.1.2.1 proto esp reqid 2 mode tunnel

ip -netns host2 xfrm state add src 10.1.2.1 dst 10.1.3.2 proto esp spi 1 \
	reqid 1 replay-window 1  mode tunnel aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src 10.1.1.0/24 dst 10.1.4.0/24

ip -netns host2 xfrm state add src 10.1.3.2 dst 10.1.2.1 proto esp spi 2 \
	flag icmp reqid 2 replay-window 10 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96

ip -netns host4 xfrm policy add src 10.1.4.0/24 dst 10.1.1.0/24 dir out \
	flag icmp tmpl src 10.1.3.2 dst 10.1.2.1 proto esp reqid 1 mode tunnel

ip -netns host4 xfrm policy add src 10.1.1.0/24 dst 10.1.4.0/24 dir in \
	tmpl src 10.1.2.1 dst 10.1.3.2 proto esp reqid 2  mode tunnel

ip -netns host4 xfrm policy add src 10.1.1.0/24 dst 10.1.4.0/24 dir fwd \
		flag icmp tmpl src 10.1.2.1 dst 10.1.3.2 proto esp reqid 2 mode tunnel

ip -netns host4 xfrm state add src 10.1.3.2 dst 10.1.2.1 proto esp spi 2 \
	reqid 1 replay-window 1 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96

ip -netns host4 xfrm state add src 10.1.2.1 dst 10.1.3.2 proto esp spi 1 \
	reqid 2 replay-window 20 flag icmp  mode tunnel aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src 10.1.1.0/24 dst 10.1.4.0/24

ip netns exec host1 ping -W 5 -c 1 10.1.4.2 2>&1 > /dev/null && echo ""
ip netns exec host1 ping -W 5 -c 1 10.1.4.3 && echo "succes" || echo "note source address"
