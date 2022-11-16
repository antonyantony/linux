#!/bin/bash -ue
set -e
stop=${1-'no'}

verbose=${verbose-''}
if [ "${verbose}" = "yes" ]; then
        set -x
fi

usage() {
	echo "Usage: $0 [--stop | --help] [--verbose]"
	echo "    Create a test network using namespaces and veth"

	echo "   |sam eth1|---||eth0 huckred xfrm0|heukblack eth0||===IPsec===| eth1 moritzblack | xfrm0 moritz red eth0|---|eth1 tiffy|"
	echo "   huck and moritz are the IPsec gateways. Tunnel is between 10.1.2.1===10.1.2.2"
	echo "   10.1.1.2/24 sam|---|10.1.1.1 huckred xfrm0|| huckblack 10.1.2.1|==IPsec Tunnrel===|10.1.2.2 moritzblack ||xfrm0 moritzred 10.1.3.1|---|10.1.3.2 tiffy|"
	echo "   ping from sam to tiffy will go through the IPsec tunnel"
	echo ""
	echo "   ip netns exec sam ping 10.1.3.1"
	echo "   To run iperf"
	echo "   ip netns exec tiffy iperf -i 2 -u -s & # start the server on tiffy"
	echo "   ip netns exec sam iperf -i 2 -u -c 10.1.3.1"

	echo "   --stop : remove the veth devices, clean the xfrm polices and namespaces";
	echo "   --verbose : to execute with set -x\n"
}

OPTIONS=$(getopt -o hs: --long verbose,stop,help, -- "$@")
if (( $? != 0 )); then
    err 4 "Error calling getopt"
fi

eval set -- "$OPTIONS"
while true; do
	case "$1" in
		-h | --help )
			usage
			exit 0
			;;
		-s | --stop )
			stop=stop
			shift
			;;
		-v | --verbose )
			verbose=yes
			set -x
			shift
			;;
		-- ) shift; break ;;
		* )
		shift
		break
		;;
	esac
done

function stop () {
	set +ue
	for h in sam huckred huckblack moritzred moritzblack tiffy  ; do
		ip netns | grep ${h} > /dev/null || continue
		ip -netns ${h} x s f
		ip -netns ${h} x p f
		ip -netns ${h} link set eth0 down 2>/dev/null
		ip -netns ${h} link del eth0 2>/dev/null
		ip -netns ${h} link set eth1 down 2>/dev/null
		ip -netns ${h} link del eth1 2>/dev/null
		# ip -netns ${h} link
		ip netns del ${h}
	done
	set -ue
}

if [ "${stop}" = "stop" ]; then
 stop
 exit
fi

AB="10.1"
mtu=${mtu-1500}
mtu0=${mtu}
for h in sam huckred huckblack moritzred moritzblack tiffy; do
	ip netns add ${h}
	ip -netns ${h} link set lo up
	ip netns exec ${h} sysctl -wq net.ipv4.ip_forward=1
done

i=1
for h in huckred huckblack moritzred; do
	ip -netns ${h} link add eth0 type veth peer name eth10${i}
	ip -netns ${h} addr add "${AB}.${i}.1/24" dev eth0
	ip -netns ${h} link set up dev eth0
	i=$((i + 1))
done

ip -netns huckred link set eth101 netns sam
ip -netns huckblack link set eth102 netns moritzblack
ip -netns moritzred link set eth103 netns tiffy

ip -netns sam link set eth101 name eth1
ip -netns moritzblack link set eth102 name eth1
ip -netns tiffy link set eth103 name eth1

ip -netns sam link set eth1 up
ip -netns moritzblack link set eth1 up
ip -netns tiffy link set eth1 up

ip -netns huckblack link add xfrm0 type xfrm if_id 1
ip -netns moritzblack link add xfrm0 type xfrm if_id 1

ip -netns huckblack link set xfrm0 netns huckred
ip -netns moritzblack link set xfrm0 netns moritzred
ip -netns moritzred link set xfrm0 up
ip -netns huckred link set xfrm0 up

ip -netns sam addr add 10.1.1.2/24 dev eth1
ip -netns moritzblack addr add 10.1.2.2/24 dev eth1
ip -netns tiffy  addr add 10.1.3.2/24 dev  eth1

ip -netns sam route add 10.1.2.0/24 via 10.1.1.1
ip -netns sam route add 10.1.3.0/24 via 10.1.1.1

ip -netns tiffy route add 10.1.1.0/24 via 10.1.3.1
ip -netns tiffy route add 10.1.2.0/24 via 10.1.3.1

ip -netns moritzred route add 10.1.1.0/24 dev xfrm0
ip -netns huckred route add 10.1.3.0/24 dev xfrm0

ip -netns huckblack xfrm policy add src 10.1.1.0/24 dst 10.1.3.0/24 dir out \
	tmpl src 10.1.2.1 dst 10.1.2.2 proto esp reqid 1 mode tunnel if_id 0x1
ip -netns huckblack xfrm policy add src 10.1.3.0/24 dst 10.1.1.0/24 dir in \
	tmpl src 10.1.2.2 dst 10.1.2.1 proto esp reqid 2 mode tunnel if_id 0x1
ip -netns huckblack xfrm policy add src 10.1.3.0/24 dst 10.1.1.0/24 dir fwd \
	tmpl src 10.1.2.2 dst 10.1.2.1 proto esp reqid 2 mode tunnel

ip -netns huckblack xfrm state add src 10.1.2.1 dst 10.1.2.2 proto esp spi 1 \
	if_id 0x1 reqid 1 replay-window 1  mode tunnel aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src 10.1.1.0/24 dst 10.1.3.0/24

ip -netns huckblack xfrm state add src 10.1.2.2 dst 10.1.2.1 proto esp spi 2 \
	if_id 0x1 reqid 2 replay-window 10 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96

ip -netns moritzblack xfrm policy add src 10.1.3.0/24 dst 10.1.1.0/24 dir out \
	tmpl src 10.1.2.2 dst 10.1.2.1 proto esp reqid 1 mode tunnel if_id 0x1

ip -netns moritzblack xfrm policy add src 10.1.1.0/24 dst 10.1.3.0/24 dir in \
	tmpl src 10.1.2.1 dst 10.1.2.2 proto esp reqid 2  mode tunnel if_id 0x1

ip -netns moritzblack xfrm policy add src 10.1.1.0/24 dst 10.1.3.0/24 dir fwd \
	tmpl src 10.1.2.1 dst 10.1.2.2 proto esp reqid 2 mode tunnel

ip -netns moritzblack xfrm state add src 10.1.2.2 dst 10.1.2.1 proto esp spi 2 \
	if_id 0x1 reqid 1 replay-window 1 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x2222222222222222222222222222222222222222 96

ip -netns moritzblack xfrm state add src 10.1.2.1 dst 10.1.2.2 proto esp spi 1 \
	if_id 0x1 reqid 2 replay-window 20 mode tunnel aead 'rfc4106(gcm(aes))' \
	0x1111111111111111111111111111111111111111 96 \
	sel src 10.1.1.0/24 dst 10.1.3.0/24

# ping from sam to tiffy
ip netns exec sam ping -c 4 10.1.3.1
# ip netns exec tiffy iperf -i 2 -u -s &
# ip netns exec sam iperf -i 2 -u -c 10.1.3.1
ip -netns huckblack x s
ip -netns moritzblack x s
ip -netns huckred -s link show dev xfrm0
ip -netns moritzred -s link show dev xfrm0
