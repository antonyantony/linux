echo 1 > /proc/sys/net/ipv4/ip_forward
ip link set up dev dummy0 || echo ""
ip ro add 198.18.0.0/24 dev dummy0 scope link || echo ""
nft flush ruleset
N=15000000

# IP6=  DST_PORT=444 APPEND= VERBOSE= DEBUG= bash -eu samples/pktgen//pktgen_bench_xmit_mode_netif_receive.sh -i eth2 -n $N -m 52:54:00:a1:43:45 -s 1000 -f 1 -t 1 -w 0 -d 198.18.0.11 -b 0
nft -f samples/pktgen/bulk/flow.nft

N=1 IP6=  DST_PORT=444 APPEND= VERBOSE= DEBUG= bash -eu samples/pktgen//pktgen_bench_xmit_mode_netif_receive.sh -i eth2 -n $N -m 52:54:00:a1:43:45 -s 1000 -f 1 -t 1 -w 0 -d 198.18.0.11 -b 0
