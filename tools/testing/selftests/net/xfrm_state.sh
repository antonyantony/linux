#!/bin/bash -e
# SPDX-License-Identifier: GPL-2.0
#
# xfrm/IPsec tests.
# Currently implemented:
# - ICMP error source address verification (IETF RFC 4301 section 6)
# - ICMP MTU exceeded handling over IPsec tunnels.
#
# Addresses and topology:
# IPv4 prefix 10.1.c.d IPv6 prefix fc00:c::d/64 where c is the segment number
# and d is the interface identifier.
# IPv6 uses the same c:d as IPv4, and start with IPv6 prefix instead ipv4 prefix
#
# Network topology default: ns_set_v4 or ns_set_v6
#   1.1   1.2   2.1   2.2   3.1   3.2   4.1   4.2   5.1   5.2  6.1  6.2
#  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1 eth0  eth1
# a -------- r1 -------- s1 -------- r2 -------- s2 -------- r3 -------- b
# a, b = Alice and Bob hosts without IPsec.
# r1, r2, r3 routers, without IPsec
# s1, s2, IPsec gateways/routers that setup tunnel(s).

# Network topology x: IPsec gateway that generates ICMP response - ns_set_v4x or ns_set_v6x
#   1.1   1.2   2.1   2.2   3.1   3.2   4.1   4.2   5.1   5.2
#  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1
# a -------- r1 -------- s1 -------- r2 -------- s2 -------- b

# Network topology: h for IPsec host-to-host : ns_set_v4h or ns_set_v6h
#   1.1   1.2   2.1   2.2
#  eth0  eth1  eth0  eth1
# a -------- r1 -------- b

. lib.sh

EXIT_ON_TEST_FAIL=no
PAUSE=no
VERBOSE=${VERBOSE:-0}
DEBUG=1

MTU=1500

#	Name				Description
tests="
	migrate_basic			MIGRATE: move SA to new endpoint, policy updated
	migrate_notfound		MIGRATE: non-matching policy selector fails
	migrate_ipv6			MIGRATE: IPv6 SA and policy migration
	migrate_transport		MIGRATE_STATE: transport mode with UPDATE_H2H_SEL
	migrate_in			MIGRATE: inbound direction migration
	unreachable_ipv4		IPv4 unreachable from router r3
	unreachable_ipv6		IPv6 unreachable from router r3
	unreachable_gw_ipv4		IPv4 unreachable from IPsec gateway s2
	unreachable_gw_ipv6		IPv6 unreachable from IPsec gateway s2
	mtu_ipv4_s2			IPv4 MTU exceeded from IPsec gateway s2
	mtu_ipv6_s2			IPv6 MTU exceeded from IPsec gateway s2
	mtu_ipv4_r2			IPv4 MTU exceeded from ESP router r2
	mtu_ipv6_r2			IPv6 MTU exceeded from ESP router r2
	mtu_ipv4_r3			IPv4 MTU exceeded from router r3
	mtu_ipv6_r3			IPv6 MTU exceeded from router r3
	ipv4_beet			IPv4 host-to-host BEET mode
	ipv4_iptfs			IPv4 host-to-host IPTFS mode RFC 9347
	migrate_state_set_mark		MIGRATE_STATE: change output-mark (set-mark)
	migrate_state_mark_add		MIGRATE_STATE: add SA mark (none to value)
	migrate_state_mark_remove	MIGRATE_STATE: remove SA mark (value to zero)
	migrate_state_mark_preserve	MIGRATE_STATE: mark preserved when no new-mark
	migrate_state_mark_eexist	MIGRATE_STATE: mark collision detected (EEXIST)
	migrate_state_mark_broad	MIGRATE_STATE: broad mask must not match wrong SA
	migrate_state_new_dst		MIGRATE_STATE: migrate SA to new destination address
	migrate_state_reqid		MIGRATE_STATE: change reqid
	migrate_state_ipv6		MIGRATE_STATE: IPv6 SA migration to new destination
	migrate_state_v6_to_v4		MIGRATE_STATE: cross-family migration IPv6->IPv4
	migrate_state_encap_remove	MIGRATE_STATE: UDP encap dropped without encap attr
	migrate_state_offload_none	MIGRATE_STATE: offload none sentinel
	migrate_state_notfound		MIGRATE_STATE: migrate non-existent SA fails
	migrate_state_cross_family	MIGRATE_STATE: cross-family migration IPv4->IPv6"

prefix4="10.1"
prefix6="fc00"

run_cmd_err() {
	cmd="$*"

	if [ "$VERBOSE" -gt 0 ]; then
		printf "  COMMAND: %s\n" "$cmd"
	fi

	out="$($cmd 2>&1)" && rc=0 || rc=$?
	if [ "$VERBOSE" -gt 1 ] && [ -n "$out" ]; then
		echo "  $out"
		echo
	fi
	return 0
}

run_cmd() {
	run_cmd_err "$@" || exit 1
}

run_test() {
	# If errexit is set, unset it for sub-shell and restore after test
	errexit=0
	if [[ $- =~ "e" ]]; then
		errexit=1
		set +e
	fi

	(
		unset IFS

		# shellcheck disable=SC2030 # fail is read by trap/cleanup within this subshell
		fail="yes"

		# Since cleanup() relies on variables modified by this sub shell,
		# it has to run in this context.
		trap 'log_test_error $?; cleanup' EXIT INT TERM

		if [ "$VERBOSE" -gt 0 ]; then
			printf "\n#############################################################\n\n"
		fi

		ret=0
		case "${name}" in
		# can't use eval and test names shell check will complain about unused code
		migrate_basic)        test_migrate_basic ;;
		migrate_notfound)     test_migrate_notfound ;;
		migrate_ipv6)         test_migrate_ipv6 ;;
		migrate_transport)    test_migrate_transport ;;
		migrate_in)           test_migrate_in ;;
		unreachable_ipv4)    test_unreachable_ipv4 ;;
		unreachable_ipv6)    test_unreachable_ipv6 ;;
		unreachable_gw_ipv4) test_unreachable_gw_ipv4 ;;
		unreachable_gw_ipv6) test_unreachable_gw_ipv6 ;;
		mtu_ipv4_s2)         test_mtu_ipv4_s2 ;;
		mtu_ipv6_s2)         test_mtu_ipv6_s2 ;;
		mtu_ipv4_r2)         test_mtu_ipv4_r2 ;;
		mtu_ipv6_r2)         test_mtu_ipv6_r2 ;;
		mtu_ipv4_r3)         test_mtu_ipv4_r3 ;;
		mtu_ipv6_r3)         test_mtu_ipv6_r3 ;;
		ipv4_beet)                    test_ipv4_beet ;;
		ipv4_iptfs)                   test_ipv4_iptfs ;;
		migrate_state_set_mark)       test_migrate_state_set_mark ;;
		migrate_state_mark_add)       test_migrate_state_mark_add ;;
		migrate_state_mark_remove)    test_migrate_state_mark_remove ;;
		migrate_state_mark_preserve)  test_migrate_state_mark_preserve ;;
		migrate_state_mark_eexist)    test_migrate_state_mark_eexist ;;
		migrate_state_mark_broad)     test_migrate_state_mark_broad ;;
		migrate_state_new_dst)        test_migrate_state_new_dst ;;
		migrate_state_reqid)          test_migrate_state_reqid ;;
		migrate_state_ipv6)           test_migrate_state_ipv6 ;;
		migrate_state_v6_to_v4)       test_migrate_state_v6_to_v4 ;;
		migrate_state_encap_remove)   test_migrate_state_encap_remove ;;
		migrate_state_offload_none)   test_migrate_state_offload_none ;;
		migrate_state_notfound)       test_migrate_state_notfound ;;
		migrate_state_cross_family)   test_migrate_state_cross_family ;;
		esac
		ret=$?

		if [ $ret -eq 0 ]; then
			fail="no"

			if [ "$VERBOSE" -gt 1 ]; then
				show_icmp_filter
			fi

			printf "TEST: %-60s [ PASS ]\n" "${desc}"
		elif [ $ret -eq "$ksft_skip" ]; then
			fail="no"
			printf "TEST: %-60s [SKIP]\n" "${desc}"
		fi

		return $ret
	)
	ret=$?

	[ $errexit -eq 1 ] && set -e

	case $ret in
	0)
		all_skipped=false
		[ "$exitcode" -eq "$ksft_skip" ] && exitcode=0
		;;
	"$ksft_skip")
		[ $all_skipped = true ] && exitcode=$ksft_skip
		;;
	*)
		all_skipped=false
		exitcode=1
		;;
	esac

	return 0 # don't trigger errexit (-e); actual status in exitcode
}

setup_namespaces() {
	local namespaces=""

	NS_A=""
	NS_B=""
	NS_R1=""
	NS_R2=""
	NS_R3=""
	NS_S1=""
	NS_S2=""

	for ns in ${ns_set}; do
		namespaces="$namespaces NS_${ns^^}"
	done

	# shellcheck disable=SC2086 # setup_ns expects unquoted list
	setup_ns $namespaces

	ns_active= #ordered list of namespaces for this test.

	[ -n "${NS_A}" ] && ns_a=(ip netns exec "${NS_A}") && ns_active="${ns_active} $NS_A"
	[ -n "${NS_R1}" ] && ns_active="${ns_active} $NS_R1"
	[ -n "${NS_S1}" ] && ns_s1=(ip netns exec "${NS_S1}") && ns_active="${ns_active} $NS_S1"
	[ -n "${NS_R2}" ] && ns_r2=(ip netns exec "${NS_R2}") && ns_active="${ns_active} $NS_R2"
	[ -n "${NS_S2}" ] && ns_s2=(ip netns exec "${NS_S2}") && ns_active="${ns_active} $NS_S2"
	[ -n "${NS_R3}" ] && ns_r3=(ip netns exec "${NS_R3}") && ns_active="${ns_active} $NS_R3"
	[ -n "${NS_B}" ] && ns_active="${ns_active} $NS_B"

	return 0
}

addr_add() {
	local -a ns_cmd=(ip netns exec "$1")
	local addr="$2"
	local dev="$3"

	run_cmd "${ns_cmd[@]}" ip addr add "${addr}" dev "${dev}"
	run_cmd "${ns_cmd[@]}" ip link set up "${dev}"
}

veth_add() {
	local ns=$2
	local pns=$1
	local -a ns_cmd=(ip netns exec "${pns}")
	local ln="eth0"
	local rn="eth1"
	local mtu=""

	[ "${MTU}" -ne 1500 ] && mtu="mtu ${MTU}"

	run_cmd "${ns_cmd[@]}" ip link add "${ln}" type veth peer name "${rn}" netns "${ns}" "$mtu"

	if [ -n "$mtu" ]; then
		run_cmd "${ns_cmd[@]}" ip link set "${ln}" "${mtu}"
	fi
}

show_icmp_filter() {
	run_cmd "${ns_r2[@]}" nft list ruleset
	echo "$out"
}

setup_icmp_filter() {
	run_cmd "${ns_r2[@]}" nft add table inet filter
	run_cmd "${ns_r2[@]}" nft add chain inet filter FORWARD \
		'{ type filter hook forward priority filter; policy drop ; }'
	run_cmd "${ns_r2[@]}" nft add rule inet filter FORWARD counter ip protocol esp \
		counter log accept
	run_cmd "${ns_r2[@]}" nft add rule inet filter FORWARD counter ip protocol \
		icmp counter log drop

	if [ "$VERBOSE" -gt 0 ]; then
		run_cmd "${ns_r2[@]}" nft list ruleset
		echo "$out"
	fi
}

setup_icmpv6_filter() {
	run_cmd "${ns_r2[@]}" nft add table inet filter
	run_cmd "${ns_r2[@]}" nft add chain inet filter FORWARD \
		'{ type filter hook forward priority filter; policy drop ; }'
	run_cmd "${ns_r2[@]}" nft add rule inet filter FORWARD ip6 nexthdr \
		ipv6-icmp icmpv6 type echo-request counter log drop
	run_cmd "${ns_r2[@]}" nft add rule inet filter FORWARD ip6 nexthdr esp \
		counter log accept
	run_cmd "${ns_r2[@]}" nft add rule inet filter FORWARD ip6 nexthdr \
		ipv6-icmp icmpv6 type \
		'{nd-neighbor-solicit,nd-neighbor-advert,nd-router-solicit,nd-router-advert}' \
		counter log drop
	if [ "$VERBOSE" -gt 0 ]; then
		run_cmd "${ns_r2[@]}" nft list ruleset
		echo "$out"
	fi
}

set_xfrm_params() {
	s1_src=${src}
	s1_dst=${dst}
	s1_src_net=${src_net}
	s1_dst_net=${dst_net}
}

setup_ns_set_v4() {
	ns_set="a r1 s1 r2 s2 r3 b"    # Network topology default
	imax=$(echo "$ns_set" | wc -w) # number of namespaces in this topology

	src="10.1.3.1"
	dst="10.1.4.2"
	src_net="10.1.1.0/24"
	dst_net="10.1.6.0/24"

	prefix=${prefix4}
	prefix_len=24
	s="."
	S="."

	set_xfrm_params
}

setup_ns_set_v4x() {
	ns_set="a r1 s1 r2 s2 b"       # Network topology: x
	imax=$(echo "$ns_set" | wc -w) # number of namespaces in this topology
	prefix=${prefix4}
	s="."
	S="."
	src="10.1.3.1"
	dst="10.1.4.2"
	src_net="10.1.1.0/24"
	dst_net="10.1.5.0/24"
	prefix_len=24

	set_xfrm_params
}

setup_ns_set_simple() {
	ns_set="a"
	imax=1
	src="10.1.1.1"
	dst="10.1.1.2"
	src_net="10.1.0.0/24"
	dst_net="10.2.0.0/24"
	new_dst="10.1.1.3"

	set_xfrm_params
}

setup_ns_set_v4h() {
        ns_set="a r1 b"       # Network topology: host-to-host v4h
        imax=$(echo "$ns_set" | wc -w) # number of namespaces in this topology
        prefix=${prefix4}
        s="."
        S="."
        src="10.1.1.1"
        dst="10.1.2.2"
        src_net="10.1.1.1/32"
        dst_net="10.1.2.2/32"
        prefix_len=24
        b=10.1.2.2
        b1=10.1.2.23 # an unreachable host in the dst network

        set_xfrm_params
}

setup_ns_set_v6() {
	ns_set="a r1 s1 r2 s2 r3 b"    # Network topology default
	imax=$(echo "$ns_set" | wc -w) # number of namespaces in this topology
	prefix=${prefix6}
	s=":"
	S="::"
	src="fc00:3::1"
	dst="fc00:4::2"
	src_net="fc00:1::0/64"
	dst_net="fc00:6::0/64"
	prefix_len=64

	set_xfrm_params
}

setup_ns_set_v6x() {
	ns_set="a r1 s1 r2 s2 b" # Network topology: x
	imax=$(echo "$ns_set" | wc -w)
	prefix=${prefix6}
	s=":"
	S="::"
	src="fc00:3::1"
	dst="fc00:4::2"
	src_net="fc00:1::0/64"
	dst_net="fc00:5::0/64"
	prefix_len=64

	set_xfrm_params
}

setup_network() {
	# Create veths and add addresses
	local -a ns_cmd
	i=1
	p=""
	for ns in ${ns_active}; do
		ns_cmd=(ip netns exec "${ns}")

		if [ "${i}" -ne 1 ]; then
			# Create veth between previous and current namespace
			veth_add "${p}" "${ns}"
			# Add addresses: previous gets .1 on eth0, current gets .2 on eth1
			addr_add "${p}" "${prefix}${s}$((i-1))${S}1/${prefix_len}" eth0
			addr_add "${ns}" "${prefix}${s}$((i-1))${S}2/${prefix_len}" eth1
		fi

		# Enable forwarding
		run_cmd "${ns_cmd[@]}" sysctl -q net/ipv4/ip_forward=1
		run_cmd "${ns_cmd[@]}" sysctl -q net/ipv6/conf/all/forwarding=1
		run_cmd "${ns_cmd[@]}" sysctl -q net/ipv6/conf/default/accept_dad=0

		p=${ns}
		i=$((i + 1))
	done

	# Add routes (needs all addresses to exist first)
	i=1
	for ns in ${ns_active}; do
		ns_cmd=(ip netns exec "${ns}")

		# Forward routes to networks beyond this node
		if [ "${i}" -ne "${imax}" ]; then
			nhf="${prefix}${s}${i}${S}2" # nexthop forward
			for j in $(seq $((i + 1)) "${imax}"); do
				run_cmd "${ns_cmd[@]}" ip route replace \
				       	"${prefix}${s}${j}${S}0/${prefix_len}" via "${nhf}"
			done
		fi

		# Reverse routes to networks before this node
		if [ "${i}" -gt 1 ]; then
			nhr="${prefix}${s}$((i-1))${S}1" # nexthop reverse
			for j in $(seq 1 $((i - 2))); do
				run_cmd "${ns_cmd[@]}" ip route replace \
					"${prefix}${s}${j}${S}0/${prefix_len}" via "${nhr}"
			done
		fi

		i=$((i + 1))
	done
}

setup_xfrm_mode() {
	local MODE=${1:-tunnel}
	if [ "${MODE}" != "tunnel" ] && [ "${MODE}" != "beet" ] && [ "${MODE}" != "iptfs" ] ; then
		echo "xfrm mode ${MODE} not supported"
		log_test_error
		return 1
	fi

	run_cmd "${ns_s1[@]}" ip xfrm policy add src "${s1_src_net}" dst "${s1_dst_net}" dir out \
		tmpl src "${s1_src}" dst "${s1_dst}" proto esp reqid 1 mode "${MODE}"

	# no "input" policies. we are only doing forwarding so far

	run_cmd "${ns_s1[@]}" ip xfrm policy add src "${s1_dst_net}" dst "${s1_src_net}" dir fwd \
		flag icmp tmpl src "${s1_dst}" dst "${s1_src}" proto esp reqid 2 mode "${MODE}"

	run_cmd "${ns_s1[@]}" ip xfrm state add src "${s1_src}" dst "${s1_dst}" proto esp spi 1 \
		reqid 1 mode "${MODE}" aead 'rfc4106(gcm(aes))' \
		0x1111111111111111111111111111111111111111 96 \
		sel src "${s1_src_net}" dst "${s1_dst_net}" dir out

	run_cmd "${ns_s1[@]}" ip xfrm state add src "${s1_dst}" dst "${s1_src}" proto esp spi 2 \
		reqid 2 flag icmp replay-window 8 mode "${MODE}" aead 'rfc4106(gcm(aes))' \
		0x2222222222222222222222222222222222222222 96 \
		sel src "${s1_dst_net}" dst "${s1_src_net}" dir in

	run_cmd "${ns_s2[@]}" ip xfrm policy add src "${s1_dst_net}" dst "${s1_src_net}" dir out \
		flag icmp tmpl src "${s1_dst}" dst "${s1_src}" proto esp reqid 2 mode "${MODE}"

	run_cmd "${ns_s2[@]}" ip xfrm policy add src "${s1_src_net}" dst "${s1_dst_net}" dir fwd \
		tmpl src "${s1_src}" dst "${s1_dst}" proto esp reqid 1 mode "${MODE}"

	run_cmd "${ns_s2[@]}" ip xfrm state add src "${s1_dst}" dst "${s1_src}" proto esp spi 2 \
		reqid 2 mode "${MODE}" aead 'rfc4106(gcm(aes))' \
		0x2222222222222222222222222222222222222222 96 \
		sel src "${s1_dst_net}" dst "${s1_src_net}" dir out

	run_cmd "${ns_s2[@]}" ip xfrm state add src "${s1_src}" dst "${s1_dst}" proto esp spi 1 \
		reqid 1 flag icmp replay-window 8 mode "${MODE}" aead 'rfc4106(gcm(aes))' \
		0x1111111111111111111111111111111111111111 96 \
		sel src "${s1_src_net}" dst "${s1_dst_net}" dir in
}

setup_xfrm() {
	setup_xfrm_mode tunnel
}

setup_xfrm_beet() {
        setup_xfrm_mode beet
}

setup_xfrm_iptfs() {
        setup_xfrm_mode iptfs
}


setup() {
	[ "$(id -u)" -ne 0 ] && echo "  need to run as root" && return "$ksft_skip"

	for arg; do
		case "${arg}" in
		ns_set_v4)     setup_ns_set_v4 ;;
		ns_set_v4x)    setup_ns_set_v4x ;;
		ns_set_v6)     setup_ns_set_v6 ;;
		ns_set_v6x)    setup_ns_set_v6x ;;
		ns_set_v4h)    setup_ns_set_v4h ;;
		ns_set_simple) setup_ns_set_simple ;;
		namespaces)    setup_namespaces ;;
		network)       setup_network ;;
		xfrm)          setup_xfrm ;;
		xfrm_beet)     setup_xfrm_beet ;;
		xfrm_iptfs)    setup_xfrm_iptfs ;;
		icmp_filter)   setup_icmp_filter ;;
		icmpv6_filter) setup_icmpv6_filter ;;
		*) echo "  ${arg} not supported"; return 1 ;;
		esac || return 1
	done
}

# shellcheck disable=SC2317 # called via trap
pause() {
	echo
	echo "Pausing. Hit enter to continue"
	read -r _
}

# shellcheck disable=SC2317 # called via trap
log_test_error() {
	# shellcheck disable=SC2031 # fail is set in subshell, read via trap
	if [ "${fail}" = "yes" ] && [ -n "${desc}" ]; then
		if [ "$VERBOSE" -gt 0 ] && [ -n "${NS_R2}" ]; then
			show_icmp_filter
		fi
		printf "TEST: %-60s [ FAIL ]  %s\n" "${desc}" "${name}"
		[ -n "${cmd}" ] && printf '%s\n\n' "${cmd}"
		[ -n "${out}" ] && printf '%s\n\n' "${out}"
	fi
}

# shellcheck disable=SC2317 # called via trap
cleanup() {
	# shellcheck disable=SC2031 # fail is set in subshell, read via trap
	[[ "$PAUSE" = "always" || ( "$PAUSE" = "fail" && "$fail" = "yes" ) ]] && pause
	cleanup_all_ns
	# shellcheck disable=SC2031 # fail is set in subshell, read via trap
	[ "${EXIT_ON_TEST_FAIL}" = "yes" ] && [ "${fail}" = "yes" ] && exit 1
}

test_unreachable_ipv6() {
	setup ns_set_v6 namespaces network xfrm icmpv6_filter || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 fc00:6::2
	run_cmd_err "${ns_a[@]}" ping -W 5 -w 4 -c 1 fc00:6::3
	rc=0
	echo -e "$out" | grep -q -E 'From fc00:5::2 icmp_seq.* Destination' || rc=1
	return "${rc}"
}

test_unreachable_gw_ipv6() {
	setup ns_set_v6x namespaces network xfrm icmpv6_filter || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 fc00:5::2
	run_cmd_err "${ns_a[@]}" ping -W 5 -w 4 -c 1 fc00:5::3
	rc=0
	echo -e "$out" | grep -q -E 'From fc00:4::2 icmp_seq.* Destination' || rc=1
	return "${rc}"
}

test_unreachable_ipv4() {
	setup ns_set_v4 namespaces network icmp_filter xfrm || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.6.2
	run_cmd_err "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.6.3
	rc=0
	echo -e "$out" | grep -q -E 'From 10.1.5.2 icmp_seq.* Destination' || rc=1
	return "${rc}"
}

test_unreachable_gw_ipv4() {
	setup ns_set_v4x namespaces network icmp_filter xfrm || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.5.2
	run_cmd_err "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.5.3
	rc=0
	echo -e "$out" | grep -q -E 'From 10.1.4.2 icmp_seq.* Destination' || rc=1
	return "${rc}"
}

test_mtu_ipv4_r2() {
	setup ns_set_v4 namespaces network icmp_filter xfrm || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.6.2
	run_cmd "${ns_r2[@]}" ip route replace 10.1.3.0/24 dev eth1 src 10.1.3.2 mtu 1300
	run_cmd "${ns_r2[@]}" ip route replace 10.1.4.0/24 dev eth0 src 10.1.4.1 mtu 1300
	# shellcheck disable=SC1010 # -M do: do = dont-fragment, not shell keyword
	run_cmd "${ns_a[@]}" ping -M do -s 1300 -W 5 -w 4 -c 1 10.1.6.2 || true
	rc=0
	echo -e "$out" | grep -q -E "From 10.1.2.2 icmp_seq=.* Frag needed and DF set" || rc=1
	return "${rc}"
}

test_mtu_ipv6_r2() {
	setup ns_set_v6 namespaces network xfrm icmpv6_filter || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 fc00:6::2
	run_cmd "${ns_r2[@]}" ip -6 route replace fc00:3::/64 \
		dev eth1 metric 256 src fc00:3::2 mtu 1300
	run_cmd "${ns_r2[@]}" ip -6 route replace fc00:4::/64 \
		dev eth0 metric 256 src fc00:4::1 mtu 1300
	# shellcheck disable=SC1010 # -M do: do = dont-fragment, not shell keyword
	run_cmd "${ns_a[@]}" ping -M do -s 1300 -W 5 -w 4 -c 1 fc00:6::2 || true
	rc=0
	echo -e "$out" | grep -q -E "From fc00:2::2 icmp_seq=.* Packet too big: mtu=1230" || rc=1
	return "${rc}"
}

test_mtu_ipv4_r3() {
	setup ns_set_v4 namespaces network icmp_filter xfrm || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.6.2
	run_cmd "${ns_r3[@]}" ip route replace 10.1.6.0/24 dev eth0 mtu 1300
	# shellcheck disable=SC1010 # -M do: do = dont-fragment, not shell keyword
	run_cmd "${ns_a[@]}" ping -M do -s 1350 -W 5 -w 4 -c 1 10.1.6.2 || true
	rc=0
	echo -e "$out" | grep -q -E "From 10.1.5.2 .* Frag needed and DF set \(mtu = 1300\)" || rc=1
	return "${rc}"
}

test_mtu_ipv4_s2() {
	setup ns_set_v4x namespaces network icmp_filter xfrm || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.5.2
	run_cmd "${ns_s2[@]}" ip route replace 10.1.5.0/24 dev eth0 src 10.1.5.1 mtu 1300
	# shellcheck disable=SC1010 # -M do: do = dont-fragment, not shell keyword
	run_cmd "${ns_a[@]}" ping -M do -s 1350 -W 5 -w 4 -c 1 10.1.5.2 || true
	rc=0
	echo -e "$out" | grep -q -E "From 10.1.4.2.*Frag needed and DF set \(mtu = 1300\)" || rc=1
	return "${rc}"
}

test_mtu_ipv6_s2() {
	setup ns_set_v6x namespaces network xfrm icmpv6_filter || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 fc00:5::2
	run_cmd "${ns_s2[@]}" ip -6 route replace fc00:5::/64 dev eth0 metric 256 mtu 1300
	# shellcheck disable=SC1010 # -M do: do = dont-fragment, not shell keyword
	run_cmd "${ns_a[@]}" ping -M do -s 1350 -W 5 -w 4 -c 1 fc00:5::2 || true
	rc=0
	echo -e "$out" | grep -q -E "From fc00:4::2.*Packet too big: mtu=1300" || rc=1
	return "${rc}"
}

test_mtu_ipv6_r3() {
	setup ns_set_v6 namespaces network xfrm icmpv6_filter || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 fc00:6::2
	run_cmd "${ns_r3[@]}" ip -6 route replace fc00:6::/64 dev eth1 metric 256 mtu 1300
	# shellcheck disable=SC1010 # -M do: do = dont-fragment, not shell keyword
	run_cmd "${ns_a[@]}" ping -M do -s 1300 -W 5 -w 4 -c 1 fc00:6::2 || true
	rc=0
	echo -e "$out" | grep -q -E "From fc00:5::2 icmp_seq=.* Packet too big: mtu=1300" || rc=1
	return "${rc}"
}

test_ipv4_beet () {
        setup ns_set_v4h namespaces network icmp_filter xfrm_beet || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.2.2
        rc=0
        echo -e "$out" | grep -q -E "64 bytes from 10.1.2.2: icmp_seq=" || rc=1
        return "${rc}"
}

test_ipv4_iptfs () {
	MTU=9000
        setup ns_set_v4h namespaces network icmp_filter xfrm_iptfs || return "$ksft_skip"
	run_cmd "${ns_a[@]}" ping -W 5 -w 4 -c 1 10.1.2.2
	run_cmd "${ns_a[@]}" ping -s 9500 -W 5 -w 4 -c 1 10.1.2.2
        rc=0
        echo -e "$out" | grep -q -E "bytes from 10.1.2.2: icmp_seq=" || rc=1
        return "${rc}"
}

require_migrate_state_support() {
	ip xfrm state help 2>&1 | grep -q "migrate" || return "$ksft_skip"
	ip xfrm state migrate dst 127.0.0.1 proto esp spi 0xdead \
		new-dst 127.0.0.1 new-src 127.0.0.2 new-reqid 1 2>&1 | \
		grep -qi "not supported" && return "$ksft_skip"
	return 0
}

migrate_old_policy_add() {
	run_cmd "${ns_a[@]}" ip xfrm policy add \
		src "${src_net}" dst "${dst_net}" dir out \
		tmpl src "${src}" dst "${dst}" \
		proto esp reqid 100 mode tunnel
}

migrate_old_do() {
	run_cmd "${ns_a[@]}" ip xfrm migrate \
		src "${src_net}" dst "${dst_net}" dir out \
		reqid 100 \
		old-src "${src}" old-dst "${dst}" \
		new-src "${src}" new-dst "${new_dst}" \
		"$@"
}

test_migrate_basic() {
	setup ns_set_simple namespaces || return "$ksft_skip"
	local result=0

	migrate_state_sa_add
	migrate_old_policy_add

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${dst}" || result=1
	run_cmd_err "${ns_a[@]}" ip xfrm policy show
	echo "$out" | grep -q "dst ${dst}" || result=1

	migrate_old_do

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${dst}" && result=1
	echo "$out" | grep -q "dst ${new_dst}" || result=1
	run_cmd_err "${ns_a[@]}" ip xfrm policy show
	echo "$out" | grep -q "${new_dst}" || result=1

	return "${result}"
}

test_migrate_notfound() {
	setup ns_set_simple namespaces || return "$ksft_skip"

	run_cmd_err "${ns_a[@]}" ip xfrm migrate \
		src "192.0.2.0/24" dst "198.51.100.0/24" dir out \
		reqid 100 \
		old-src "${src}" old-dst "${dst}" \
		new-src "${src}" new-dst "${new_dst}"
	[ "${rc}" -ne 0 ] || return 1
}

test_migrate_ipv6() {
	setup ns_set_simple namespaces || return "$ksft_skip"
	local ipv6_src="fc00:1::1"
	local ipv6_dst="fc00:1::2"
	local ipv6_new_dst="fc00:1::3"
	local ipv6_src_net="fc00:1::/64"
	local ipv6_dst_net="fc00:2::/64"
	local result=0

	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${ipv6_src}" dst "${ipv6_dst}" proto esp spi 0x1000 \
		reqid 100 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96
	run_cmd "${ns_a[@]}" ip xfrm policy add \
		src "${ipv6_src_net}" dst "${ipv6_dst_net}" dir out \
		tmpl src "${ipv6_src}" dst "${ipv6_dst}" \
		proto esp reqid 100 mode tunnel

	run_cmd "${ns_a[@]}" ip xfrm migrate \
		src "${ipv6_src_net}" dst "${ipv6_dst_net}" dir out \
		reqid 100 \
		old-src "${ipv6_src}" old-dst "${ipv6_dst}" \
		new-src "${ipv6_src}" new-dst "${ipv6_new_dst}"
	[ "${rc}" -eq 0 ] || result=1

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${ipv6_dst}" && result=1
	echo "$out" | grep -q "dst ${ipv6_new_dst}" || result=1
	run_cmd_err "${ns_a[@]}" ip xfrm policy show
	echo "$out" | grep -q "${ipv6_new_dst}" || result=1

	return "${result}"
}

test_migrate_transport() {
	# Transport mode SA migration via XFRM_MSG_MIGRATE_STATE.
	# XFRM_MIGRATE_STATE_UPDATE_H2H_SEL updates the H2H selector
	# automatically when dst changes, as strongswan does.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	local result=0

	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${src}" dst "${dst}" proto esp spi 0x1000 \
		reqid 100 mode transport \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96 \
		sel src "${src}/32" dst "${dst}/32"

	run_cmd_err "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0x1000 \
		new-dst "${new_dst}" new-src "${src}" new-reqid 100 \
		update-h2h-sel
	[ "${rc}" -eq 0 ] || result=1

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${dst}" && result=1
	echo "$out" | grep -q "dst ${new_dst}" || result=1
	echo "$out" | grep -q "sel.*dst ${new_dst}" || result=1

	return "${result}"
}

test_migrate_in() {
	setup ns_set_simple namespaces || return "$ksft_skip"
	local result=0

	# Inbound SA: src/dst are swapped relative to outbound.
	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${dst}" dst "${src}" proto esp spi 0x2000 \
		reqid 100 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96
	run_cmd "${ns_a[@]}" ip xfrm policy add \
		src "${dst_net}" dst "${src_net}" dir in \
		tmpl src "${dst}" dst "${src}" \
		proto esp reqid 100 mode tunnel

	run_cmd "${ns_a[@]}" ip xfrm migrate \
		src "${dst_net}" dst "${src_net}" dir in \
		reqid 100 \
		old-src "${dst}" old-dst "${src}" \
		new-src "${new_dst}" new-dst "${src}"
	[ "${rc}" -eq 0 ] || result=1

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "src ${dst} " && result=1
	echo "$out" | grep -q "src ${new_dst}" || result=1
	run_cmd_err "${ns_a[@]}" ip xfrm policy show
	echo "$out" | grep -q "${new_dst}" || result=1

	return "${result}"
}

# Add a basic ESP SA used by migrate state tests.
# Usage: migrate_state_sa_add [mark MARK [mask MASK]]
migrate_state_sa_add() {
	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${src}" dst "${dst}" proto esp spi 0x1000 \
		reqid 100 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96 \
		"$@"
}

# Run ip xfrm state migrate keeping same dst/src/reqid, pass extra options.
# Usage: migrate_state_run [extra options...]
migrate_state_run() {
	run_cmd "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0x1000 \
		new-dst "${dst}" new-src "${src}" new-reqid 100 \
		"$@"
}

# Show the SA and capture output for grepping.
migrate_state_show() {
	run_cmd_err "${ns_a[@]}" ip xfrm state show \
		src "${src}" dst "${dst}" proto esp spi 0x1000 \
		"$@"
}

test_migrate_state_set_mark() {
	# Test XFRMA_SET_MARK: change output-mark (none → value, value → value).
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add
	local result=0

	migrate_state_show
	echo "$out" | grep -q "output-mark" && result=1

	migrate_state_run set-mark 0x100
	migrate_state_show
	echo "$out" | grep -q "output-mark 0x100" || result=1

	migrate_state_run set-mark 0x200
	migrate_state_show
	echo "$out" | grep -q "output-mark 0x200" || result=1

	return "${result}"
}

test_migrate_state_mark_add() {
	# Test XFRMA_MARK via new-mark: add SA mark (none → value).
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add
	local result=0

	# Verify no mark initially.
	migrate_state_show
	echo "$out" | grep -q "mark" && result=1

	migrate_state_run new-mark 0x200 mask 0xffffffff
	[ "${rc}" -eq 0 ] || result=1

	# SA moved to a new mark bucket; list all SAs to find it.
	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "mark 0x200/0xffffffff" || result=1

	return "${result}"
}

test_migrate_state_mark_remove() {
	# Test XFRMA_MARK via new-mark: remove SA mark (value → 0/0).
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add mark 0x300 mask 0xffffffff
	local result=0

	# Verify mark is present.
	migrate_state_show
	echo "$out" | grep -q "mark 0x300" || result=1

	run_cmd "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0x1000 \
		mark 0x300 mask 0xffffffff \
		new-dst "${dst}" new-src "${src}" new-reqid 100 \
		new-mark 0 mask 0

	migrate_state_show
	echo "$out" | grep -q "mark 0x300" && result=1

	return "${result}"
}

test_migrate_state_mark_preserve() {
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add mark 0 mask 0xff
	local result=0

	migrate_state_show
	echo "$out" | grep -q "mark 0/0xff" || result=1

	migrate_state_run
	migrate_state_show
	echo "$out" | grep -q "mark 0/0xff" || result=1

	return "${result}"
}

test_migrate_state_mark_eexist() {
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	local result=0

	migrate_state_sa_add mark 0x1 mask 0xff
	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${src}" dst "${dst}" proto esp spi 0x1000 \
		reqid 100 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96 \
		mark 0x2 mask 0xff

	run_cmd_err "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0x1000 \
		mark 0x1 mask 0xff \
		new-dst "${dst}" new-src "${src}" new-reqid 100 \
		new-mark 0x2 mask 0xff
	[ "${rc}" -ne 0 ] || result=1

	return "${result}"
}

test_migrate_state_mark_broad() {
	# A broad-mask SA {0,0} matches any lookup key via (key & 0x0 == 0x0).
	# A migrate request with old_mark={0x1,0xff} (key=1) must not find and
	# migrate the match-all SA {0,0} instead of the intended SA.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	local result=0

	# Add a match-all SA (mark 0/0).
	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${src}" dst "${dst}" proto esp spi 0x1000 \
		reqid 100 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96 \
		mark 0 mask 0

	# Migrate with old_mark={0x1,0xff}: lookup key=1 matches the {0,0} SA
	# via broad mask, but the marks do not match exactly. Must return error.
	run_cmd_err "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0x1000 \
		mark 0x1 mask 0xff \
		new-dst "${dst}" new-src "${src}" new-reqid 100
	[ "${rc}" -ne 0 ] || result=1

	return "${result}"
}

test_migrate_state_new_dst() {
	# Basic SA migration: change destination address IPv4 -> IPv4.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add
	local result=0

	migrate_state_show
	echo "$out" | grep -q "dst ${dst}" || result=1

	run_cmd "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0x1000 \
		new-dst "${new_dst}" new-src "${src}" new-reqid 100
	[ "${rc}" -eq 0 ] || result=1

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${dst}" && result=1
	echo "$out" | grep -q "dst ${new_dst}" || result=1

	return "${result}"
}

test_migrate_state_reqid() {
	# Change reqid on an existing SA, keep same endpoints.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add
	local result=0

	migrate_state_show
	echo "$out" | grep -q "reqid 100" || result=1

	migrate_state_run new-reqid 200
	[ "${rc}" -eq 0 ] || result=1

	migrate_state_show
	echo "$out" | grep -q "reqid 200" || result=1
	echo "$out" | grep -q "reqid 100" && result=1

	return "${result}"
}

test_migrate_state_ipv6() {
	# Pure IPv6 SA migration: change destination address IPv6 -> IPv6.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	local ipv6_src="fc00:1::1"
	local ipv6_dst="fc00:1::2"
	local ipv6_new_dst="fc00:1::3"
	local result=0

	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${ipv6_src}" dst "${ipv6_dst}" proto esp spi 0x1000 \
		reqid 100 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${ipv6_dst}" || result=1

	run_cmd "${ns_a[@]}" ip xfrm state migrate \
		dst "${ipv6_dst}" proto esp spi 0x1000 \
		new-dst "${ipv6_new_dst}" new-src "${ipv6_src}" new-reqid 100
	[ "${rc}" -eq 0 ] || result=1

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${ipv6_dst}" && result=1
	echo "$out" | grep -q "dst ${ipv6_new_dst}" || result=1

	return "${result}"
}

test_migrate_state_v6_to_v4() {
	# Cross-family migration: IPv6 SA -> IPv4 destination.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	local ipv6_src="fc00:1::1"
	local ipv6_dst="fc00:1::2"
	local result=0

	run_cmd "${ns_a[@]}" ip xfrm state add \
		src "${ipv6_src}" dst "${ipv6_dst}" proto esp spi 0x1000 \
		reqid 100 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x1111111111111111111111111111111111111111 96

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${ipv6_dst}" || result=1

	run_cmd "${ns_a[@]}" ip xfrm state migrate \
		dst "${ipv6_dst}" proto esp spi 0x1000 \
		new-dst "${dst}" new-src "${src}" new-reqid 100
	[ "${rc}" -eq 0 ] || result=1

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${ipv6_dst}" && result=1
	echo "$out" | grep -q "dst ${dst}" || result=1

	return "${result}"
}

test_migrate_state_encap_remove() {
	# encap none sentinel must remove UDP encap from the migrated SA.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add encap espinudp 4500 4500 0.0.0.0
	local result=0

	migrate_state_show
	echo "$out" | grep -q "espinudp" || result=1

	migrate_state_run encap none
	migrate_state_show
	echo "$out" | grep -q "espinudp" && result=1

	return "${result}"
}

test_migrate_state_offload_none() {
	# Test offload none sentinel: migrate on non-offloaded SA succeeds.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"
	migrate_state_sa_add
	local result=0

	migrate_state_run offload none
	migrate_state_show
	echo "$out" | grep -q "spi 0x" || result=1

	return "${result}"
}

test_migrate_state_notfound() {
	# Test that migrating a non-existent SA (wrong SPI) returns an error.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"

	run_cmd_err "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0xdead \
		new-dst "${dst}" new-src "${src}" new-reqid 100

	[ "${rc}" -ne 0 ] || return 1
}

test_migrate_state_cross_family() {
	# misroute through xfrm_state_insert() due to a missing family guard.
	setup ns_set_simple namespaces || return "$ksft_skip"
	require_migrate_state_support || return "$ksft_skip"

	local ipv6_src="fc00:1::1"
	local ipv6_dst="fc00:1::2"
	local result=0

	migrate_state_sa_add

	migrate_state_show
	echo "$out" | grep -q "dst ${dst}" || result=1

	run_cmd "${ns_a[@]}" ip xfrm state migrate \
		dst "${dst}" proto esp spi 0x1000 \
		new-dst "${ipv6_dst}" new-src "${ipv6_src}" new-reqid 100
	[ "${rc}" -eq 0 ] || result=1

	run_cmd_err "${ns_a[@]}" ip xfrm state show
	echo "$out" | grep -q "dst ${dst}" && result=1
	echo "$out" | grep -q "dst ${ipv6_dst}" || result=1

	return "${result}"
}

################################################################################
#
usage() {
	echo
	echo "$0 [OPTIONS] [TEST]..."
	echo "If no TEST argument is given, all tests will be run."
	echo
	echo -e "\t-p Pause on fail. Namespaces are kept for diagnostics"
	echo -e "\t-P Pause after the test. Namespaces are kept for diagnostics"
	echo -e "\t-v Verbose output. Show commands; -vv Show output and nft rules also"
	echo "Available tests${tests}"
	exit 1
}

################################################################################
#
exitcode=0
all_skipped=true
out=
cmd=

while getopts :epPv o; do
	case $o in
	e) EXIT_ON_TEST_FAIL=yes ;;
	P) PAUSE=always ;;
	p) PAUSE=fail ;;
	v) VERBOSE=$((VERBOSE + 1)) ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

IFS=$'\t\n'

for arg; do
	# Check first that all requested tests are available before running any
	command -v "test_${arg}" >/dev/null || {
		echo "=== Test ${arg} not found"
		usage
	}
done

name=""
desc=""
fail="no"

for t in ${tests}; do
	[ "${name}" = "" ] && name="${t}" && continue
	[ "${desc}" = "" ] && desc="${t}"

	run_this=1
	for arg; do
		[ "${arg}" = "${name}" ] && run_this=1 && break
		run_this=0
	done
	if [ $run_this -eq 1 ]; then
		run_test
	fi
	name=""
	desc=""
done

exit ${exitcode}
