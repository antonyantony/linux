#!/bin/bash -ue
set -e

stop=${1-'no'}

verbose=${verbose-''}
if [ "${verbose}" = "yes" ]; then
        set -x
fi

usage() {
	echo "Usage: $0 [--stop | --help] [--verbose]"
	echo "    Create tx ONLY path to offload code "
	echo "   |eth1|---||xfrm0 h|=== ESP IPsec === via dummy0>"
}

OPTIONS=$(getopt -o ht:r:s: --long verbose,stop,tx,rx,help, -- "$@")
if (( $? != 0 )); then
    err 4 "Error calling getopt"
fi

rx=""
tx="yes"

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
		-t | --tx )
			tx=yes
			shift
			;;
		-r | --rx )
			rx=yes
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
		ip x s f
		ip x p f
		ip link set xfrm0 down 2>/dev/null
		ip link set dummy0 down 2>/dev/null
		ip addr flush dev dummy0 2>/dev/null
		ip link del xfrm0 2>/dev/null
	done
	set -ue
}

tx() {
	echo 1 > /proc/sys/net/ipv4/ip_forward
	modprobe dummy numdummies=1 2>/dev/null|| echo  "no module found CONFIG_DUMMY=y in this kernel?"
	ip link set up dev dummy0 || (echo "can not set dummy0" exit 1)

	ip link add xfrm0 type xfrm if_id 0x1
	ip link set up dev xfrm0
	ip route add 198.18.0.0/24 dev xfrm0
	ip addr add 10.1.6.1/24 dev dummy0

	ip xfrm policy add src 192.168.2.0/24 dst 198.18.0.0/24 dir out \
		tmpl src  10.1.6.1 dst  10.1.6.2 proto esp reqid 1 mode tunnel if_id 0x1

	ip xfrm state add src  10.1.6.1 dst  10.1.6.2 proto esp spi 1 \
		if_id 0x1 reqid 1 replay-window 1  mode tunnel aead 'rfc4106(gcm(aes))' \
		0x1111111111111111111111111111111111111111 96 \
		sel src 192.168.2.0/24 dst 198.18.0.0/24

	DEST_IP="198.18.0.11" DST_MAC=52:54:00:a1:43:45 BURST= APPEND= IP6=  DELAY= F_THREAD= THREADS= PKT_SIZE= DST_PORT=444 APPEND= VERBOSE= DEBUG= bash -eu samples/pktgen//pktgen_bench_xmit_mode_netif_receive.sh -i eth2 -n 1 -m 52:54:00:a1:43:45 -s 1000 -f 1 -t 1 -w 0 -d 198.18.0.11 -b 0
	ip -s link show dev xfrm0
}

if [ "${stop}" = "stop" ]; then
 stop
 exit
fi

if [ "${tx}" = "yes" ]; then
 tx
elif [ "${rx}" = "yes" ]; then
 rx
fi
