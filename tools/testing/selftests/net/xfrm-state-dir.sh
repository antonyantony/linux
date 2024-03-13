#!/bin/bash -u
# SPDX-License-Identifier: GPL-2.0
#
# Checks for xfrm/ESP/IPsec tunnel.
# The unreachable tests are for icmp error handling.
# As specified in IETF RFC 4301 section 6.
#
# See "test=" for the implemented tests.
#
# Network toplogy default
# 10.1.c.d or IPv6 fc00:c::d/64
#   1.1   1.2   2.1   2.2   3.1   3.2   4.1   4.2   5.1   5.2  6.1  6.2
#  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1 eth0  eth1
# a -------- r1 -------- s1 -------- r2 -------- s2 -------- r3 -------- b
# a, b = Alice and Bob hosts
# r1, r2, r3 routers without IPsec
# s1, s2, IPsec gateways/routers
#
# Network topology: x for IPsec gateway generatte ICMP response.
## 10.1.c.d
#   1.1   1.2   2.1   2.2   3.1   3.2   4.1   4.2   5.1   5.2
#  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1  eth0  eth1
# a -------- r1 -------- s1 -------- r2 -------- s2 -------- b
# With IPv6

source lib.sh

PAUSE_ON_FAIL=no
VERBOSE=0
TRACING=0

# Assumes ping support ping6 without any switches.

#               Name                          Description
tests="
	ip_xfrm_dir_in			xfrm: add dir in
	ip_xfrm_dir_out			xfrm: add dir out
	ip_xfrm_dir_out_esn		xfrm: add dir out ESN
	ip_xfrm_dir_in_exception	xfrm: add dir in offload exception
	ip_xfrm_dir_out_exception	xfrm: add dir out with replay
	ip_xfrm_dir_out_replay_exception	xfrm: add dir out replay exception
	ip_xfrm_dir_out_esn_replay_exception	xfrm: add dir out ESN replay exception"

# 	unreachable_v4			unreachable IPv4 from router r3
#	unreachable_v6			unreachable IPv6 from router r3
#	unreachable_v4_gw		unreachable IPv4 from IPsec gateway s2
#	unreachable_v6_gw		unreachable IPv6 from IPsec gateway s2"

test_out=""
imax=6

ns_set="a r1 s1 r2 s2 r3 b" #default network topology
prefix4="10.1"
prefix6="fc00"

err_buf=
tcpdump_pids=
nettest_pids=
socat_pids=

err() {
	err_buf="${err_buf}${1}
"
}

err_flush() {
	echo -n "${err_buf}"
	err_buf=
}

run_cmd() {
	cmd="$*"

	if [ "$VERBOSE" = "1" ]; then
		printf "    COMMAND: $cmd\n"
	fi

	out="$($cmd 2>&1)"
	rc=$?
	if [ "$VERBOSE" = "1" -a -n "$out" ]; then
		echo "    $out"
		echo
	else
		test_out="${test_out}${cmd}\n"
		[ -n "${out}" ] && test_out="${test_out}${out}\n"
	fi
	return $rc
}

run_cmd_bg() {
	cmd="$*"

	if [ "$VERBOSE" = "1" ]; then
		printf "    COMMAND: %s &\n" "${cmd}"
	fi

	$cmd 2>&1 &
}

run_test() {
	(
	tname="$1"
	tdesc="$2"

	unset IFS

	fail=0
	test_out=""

	# Since cleanup() relies on variables modified by this subshell, it
	# has to run in this context.
	trap cleanup EXIT

	if [ "$VERBOSE" = "1" ]; then
		printf "\n##########################################################################\n\n"
	fi

	eval test_${tname}
	ret=$?

	if [ $ret -eq 0 ]; then
		printf "TEST: %-60s  [ OK ]\n" "${tdesc}"
	elif [ $ret -eq 1 ]; then
		printf "TEST: %-60s  [FAIL]\n" "${tdesc}"
		if [ -n "${test_out}" ]; then
			echo "##########################################################################"
			# printf "${test_out}"
			echo -e "${test_out}"
			echo "##########################################################################"
		fi
		if [ "${PAUSE_ON_FAIL}" = "yes" ]; then
			echo
			echo "Pausing. Hit enter to continue"
			read a
		fi
		err_flush
		exit 1
	elif [ $ret -eq $ksft_skip ]; then
		printf "TEST: %-60s  [SKIP]\n" "${tdesc}"
		err_flush
	fi

	return $ret
	)
	ret=$?
	case $ret in
		0)
			all_skipped=false
			[ $exitcode -eq $ksft_skip ] && exitcode=0
		;;
		$ksft_skip)
			[ $all_skipped = true ] && exitcode=$ksft_skip
		;;
		*)
			all_skipped=false
			exitcode=1
		;;
	esac

	return $ret
}

# Find the auto-generated name for this namespace
nsname() {
	eval echo ns_$1
}

nscmd() {
	eval echo "ip netns exec $(nsname $1)"
}

setup_namespace() {
	setup_ns NS_A
	ns_a="ip netns exec ${NS_A}"
}

setup_namespaces() {
	local namespaces="";

	NS_R3=""
	for ns in ${ns_set}; do
		n=$(nsname ${ns})
		n=$(echo $n | tr '[:lower:]' '[:upper:]')
		namespaces="$namespaces ${n}"
	done

	setup_ns $namespaces

	[ -n NS_A ] && ns_a="ip netns exec ${NS_A}"
	[ -n NS_B ] && ns_b="ip netns exec ${NS_B}"
	[ -n NS_S1 ] && ns_s1="ip netns exec ${NS_S1}"
	[ -n NS_S2 ] && ns_s2="ip netns exec ${NS_S2}"
	[ -n NS_R1 ] && ns_r1="ip netns exec ${NS_R1}"
	[ -n NS_R2 ] && ns_r2="ip netns exec ${NS_R2}"
	[ -n NS_R3 ] && ns_r3="ip netns exec ${NS_R3}"
}

setup_addr_add() {
	local ns_cmd=$(nscmd $1)
	local ip0="$2"
	local ip1="$3"

	if [ -n "${ip0}" ]; then
	       run_cmd ${ns_cmd} ip addr add ${ip0} dev eth0
	       run_cmd ${ns_cmd} ip link set up eth0
	fi
	if [ -n "${ip1}" ]; then
		run_cmd ${ns_cmd} ip addr add ${ip1} dev eth1
		run_cmd ${ns_cmd} ip link set up eth1
	fi
	run_cmd ${ns_cmd} sysctl -q net/ipv4/ip_forward=1
	run_cmd ${ns_cmd} sysctl -q net/ipv6/conf/all/forwarding=1

	# Disable DAD, so that we don't have to wait to use the
	# configured IPv6 addresses
	run_cmd ${ns_cmd} sysctl -q net/ipv6/conf/default/accept_dad=0
}

route_add() {
	local ns_cmd=$(nscmd $1)
	local nhf=$2
	local nhr=$3
	local i=$4

	if [ -n "${nhf}" ]; then
		# add forward routes
		for j in $(seq $((i + 1)) $imax); do
			local route="${prefix}${s}${j}${S}0/${prefix_len}"
			run_cmd ${ns_cmd} ip route replace "${route} via ${nhf}"
		done
	fi

	if [ -n "${nhr}" ]; then
		# add reverse routes
		for j in $(seq 1 $((i - 2))); do
			local route="${prefix}${s}${j}${S}0/${prefix_len}"
			run_cmd ${ns_cmd} ip route replace "${route} via ${nhr}"
		done
	fi
}

veth_add() {
	local ns_cmd=$(nscmd $1)
	local ln=${2:-eth0}
	local tn="veth${1}1"
	run_cmd ${ns_cmd} ip link add ${ln} type veth peer name ${tn}
}

veth_mv() {
	local ns_cmd=$(nscmd $1)
	local p=$2
	local rn=${3:-eth1}
	local tn="veth${p}1"
	local ns=$(nsname $1)

	run_cmd "$(nscmd ${p})" ip link set ${tn} netns ${ns}
	run_cmd "$(nscmd $1)" ip link set ${tn} name ${rn}
}

vm_set() {
	s1_src=${src}
	s1_dst=${dst}
	s1_src_net=${src_net}
	s1_dst_net=${dst_net}

	s2_src=${dst}
	s2_dst=${src}
	s2_src_net=${dst_net}
	s2_dst_net=${src_net}
}

setup_vm_set_v4() {
	src="10.1.3.1"
	dst="10.1.4.2"
	src_net="10.1.1.0/24"
	dst_net="10.1.6.0/24"

	prefix=${prefix4}
	prefix_len=24
	s="."
	S="."

	vm_set
}

setup_vm_set_v4x() {
	ns_set="a r1 s1 r2 s2 b" # topology without r3
	imax=5
	prefix=${prefix4}
	s="."
	S="."
	src="10.1.3.1"
	dst="10.1.4.2"
	src_net="10.1.1.0/24"
	dst_net="10.1.5.0/24"
	prefix_len=24

	vm_set
}

setup_vm_set_v6() {
	imax=6
	prefix=${prefix6}
	s=":"
	S="::"
	src="fc00:3::1"
	dst="fc00:4::2"
	src_net="fc00:1::0/64"
	dst_net="fc00:6::0/64"
	prefix_len=64

	vm_set
}

setup_vm_set_v6x() {
	ns_set="a r1 s1 r2 s2 b" # topology without r3
	imax=5
	prefix=${prefix6}
	s=":"
	S="::"
	src="fc00:3::1"
	dst="fc00:4::2"
	src_net="fc00:1::0/64"
	dst_net="fc00:5::0/64"
	prefix_len=64

	vm_set
}

setup_veths() {
	for ns in ${ns_set}; do
		[ "${ns}" == b ] && continue
		veth_add ${ns}
	done

	p=a
	for ns in ${ns_set}; do
		[ "${ns}" == a ] && continue
		veth_mv ${ns} "${p}"
		p=${ns}
	done
}

setup_routes() {
	ip1=""
	i=1
	for ns in ${ns_set}; do
		# 10.1.C.1/24
		ip0="${prefix}${s}${i}${S}1/${prefix_len}"
		[ "${ns}" == b ] && ip0=""
		setup_addr_add ${ns} "${ip0}" "${ip1}"
		# 10.1.C.2/24
		ip1="${prefix}${s}${i}${S}2/${prefix_len}"
		i=$((i + 1))
	done

	i=1
	nhr=""
	for ns in ${ns_set}; do
		nhf="${prefix}${s}${i}${S}2"
		[ "${ns}" == b ] && nhf=""
		route_add ${ns} "${nhf}" "${nhr}" ${i}
		nhr="${prefix}${s}${i}${S}1"
		i=$((i + 1))
	done
}

setup_xfrm() {

	run_cmd ${ns_s1} ip xfrm policy add src ${s1_src_net} dst ${s1_dst_net} dir out \
		tmpl src ${s1_src} dst ${s1_dst} proto esp reqid 1 mode tunnel

	# no "dir in" policies.
	# run_cmd ${ns_s1} ip xfrm policy add src ${s1_dst_net} dst ${s1_src_net} dir in \
	#	flag icmp tmpl src ${s1_dst} dst ${s1_src} proto esp reqid 2 mode tunnel

	run_cmd ${ns_s1} ip xfrm policy add src ${s1_dst_net} dst ${s1_src_net} dir fwd \
		flag icmp tmpl src ${s1_dst} dst ${s1_src} proto esp reqid 2 mode tunnel

	run_cmd ${ns_s1} ip xfrm state add src ${s1_src} dst ${s1_dst} proto esp spi 1 \
        	reqid 1 mode tunnel aead 'rfc4106(gcm(aes))' \
        	0x1111111111111111111111111111111111111111 96 \
        	sel src ${s1_src_net} dst ${s1_dst_net}

	run_cmd ${ns_s1} ip xfrm state add src ${s1_dst} dst ${s1_src} proto esp spi 2 \
        	reqid 2 flag icmp replay-window 8 mode tunnel aead 'rfc4106(gcm(aes))' \
        	0x2222222222222222222222222222222222222222 96 \
        	sel src ${s1_dst_net} dst ${s1_src_net}

	run_cmd ${ns_s2} ip xfrm policy add src ${s1_dst_net} dst ${s1_src_net} dir out \
        	flag icmp tmpl src ${s1_dst} dst ${s1_src} proto esp reqid 2 mode tunnel

	run_cmd ${ns_s2} ip xfrm policy add src ${s1_src_net} dst ${s1_dst_net} dir fwd \
		tmpl src ${s1_src} dst ${s1_dst} proto esp reqid 1 mode tunnel

	run_cmd ${ns_s2} ip xfrm state add src ${s1_dst} dst ${s1_src} proto esp spi 2 \
        	reqid 2 mode tunnel aead 'rfc4106(gcm(aes))' \
        	0x2222222222222222222222222222222222222222 96 \
        	sel src ${s1_dst_net} dst ${s1_src_net}

	run_cmd ${ns_s2} ip xfrm state add src ${s1_src} dst ${s1_dst} proto esp spi 1 \
        	reqid 1 flag icmp replay-window 8 mode tunnel aead 'rfc4106(gcm(aes))' \
        	0x1111111111111111111111111111111111111111 96 \
        	sel src ${s1_src_net} dst ${s1_dst_net}
}

setup() {
	[ "$(id -u)" -ne 0 ] && echo "  need to run as root" && return $ksft_skip

	for arg do
		eval setup_${arg} || { echo "  ${arg} not supported"; return 1; }
	done
}

trace() {
	[ $TRACING -eq 0 ] && return

	for arg do
		[ "${ns_cmd}" = "" ] && ns_cmd="${arg}" && continue
		${ns_cmd} tcpdump --immediate-mode -s 0 -i "${arg}" -w "${name}_${arg}.pcap" 2> /dev/null &
		tcpdump_pids="${tcpdump_pids} $!"
		ns_cmd=
	done
	sleep 1
}

cleanup() {
	for pid in ${tcpdump_pids}; do
		kill ${pid}
	done
	tcpdump_pids=

	cleanup_all_ns
}

mtu() {
	ns_cmd="${1}"
	dev="${2}"
	mtu="${3}"

	${ns_cmd} ip link set dev ${dev} mtu ${mtu}
}

mtu_parse() {
	input="${1}"

	next=0
	for i in ${input}; do
		[ ${next} -eq 1 -a "${i}" = "lock" ] && next=2 && continue
		[ ${next} -eq 1 ] && echo "${i}" && return
		[ ${next} -eq 2 ] && echo "lock ${i}" && return
		[ "${i}" = "mtu" ] && next=1
	done
}

link_get() {
	ns_cmd="${1}"
	name="${2}"

	${ns_cmd} ip link show dev "${name}"
}

link_get_mtu() {
	ns_cmd="${1}"
	name="${2}"

	mtu_parse "$(link_get "${ns_cmd}" ${name})"
}

test_ip_xfrm_dir_in() {
	setup namespace || return $ksft_skip
	run_cmd ${ns_a} ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 reqid 2 replay-window 10 mode tunnel dir in aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11
	run_cmd ${ns_a} ip xfrm state
	echo $out | grep -q 'dir in' || fail=1
	return ${fail}
}

test_ip_xfrm_dir_in_exception () {
	setup namespace || return $ksft_skip
	run_cmd ${ns_a} ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 reqid 2 replay-window 10 mode tunnel dir in aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11 offload dev tunl0 dir out || true
	echo ${out} | grep -q 'Mismatched SA and offload direction'
}

test_ip_xfrm_dir_out_exception () {
	setup namespace || return $ksft_skip
	run_cmd ${ns_a} ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 reqid 2 mode tunnel dir out aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11 offload dev tunl0 dir in || true
	echo ${out} | grep -q 'Mismatched SA and offload direction'
}

test_ip_xfrm_dir_out_replay_exception() {
	setup namespace || return $ksft_skip
	run_cmd ${ns_a} ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 reqid 2 replay-window 10 mode tunnel dir out aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 || true
	echo ${out} | grep -q 'Replay window should be 0 for output SA'
}

test_ip_xfrm_dir_out() {
	setup namespace || return $ksft_skip
	run_cmd ${ns_a} ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 reqid 2 mode tunnel dir out aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11
	run_cmd ${ns_a} ip xfrm state
	echo $out | grep -q 'dir out'
}

test_ip_xfrm_dir_out_esn() {
	setup namespace || return $ksft_skip
	run_cmd ${ns_a} ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 reqid 2 mode tunnel dir out flag esn aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 if_id 11
	run_cmd ${ns_a} ip xfrm state
	echo $out | grep -q 'dir out'
}

test_ip_xfrm_dir_out_esn_replay_exception() {
	setup namespace || return $ksft_skip
	run_cmd ${ns_a} ip xfrm state add src 10.1.3.4 dst 10.1.2.3 proto esp spi 3 reqid 2 replay-window 10 mode tunnel dir out aead 'rfc4106(gcm(aes))' 0x2222222222222222222222222222222222222222 96 flag esn || true
	echo ${out} | grep -q 'Error: Replay window should be 0 for output SA'
}



test_unreachable_v6() {
	setup vm_set_v6 namespaces veths routes xfrm || return $ksft_skip
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 fc00:5::2
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 fc00:5::3 || true
	rc=0
	echo -e "$out" | grep -q -E 'From fc00:4::2 icmp_seq.* Destination' || rc=1
	return ${rc}
}

test_unreachable_v6_gw() {
	setup vm_set_v6x namespaces veths routes xfrm || return $ksft_skip
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 fc00:5::2
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 fc00:5::3 || true
	rc=0
	echo -e "$out" | grep -q -E 'From fc00:4::2 icmp_seq.* Destination' || rc=1
	return ${rc}
}

test_unreachable_v4_gw() {
	setup vm_set_v4x  namespaces veths routes xfrm || return $ksft_skip
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 10.1.5.2
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 10.1.5.3 || true
	rc=0
	echo -e "$out" | grep -q -E 'From 10.1.4.2 icmp_seq.* Destination' || rc=1
	return ${rc}
}

test_unreachable_v4() {
	setup vm_set_v4 namespaces veths routes xfrm || return $ksft_skip
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 10.1.6.2
	run_cmd ${ns_a} ping -W 5 -w 4 -c 1 10.1.6.3 || true
	rc=0
	echo -e "$out" | grep -q -E 'From 10.1.5.2 icmp_seq.* Destination' || rc=1
	return ${rc}
}

################################################################################
#
usage() {
	echo
	echo "$0 [OPTIONS] [TEST]..."
	echo "If no TEST argument is given, all tests will be run."
	echo
	echo "Available tests${tests}"
	exit 1
}

################################################################################
#
exitcode=0
desc=0
all_skipped=true

while getopts :ptv o
do
	case $o in
	p) PAUSE_ON_FAIL=yes;;
	v) VERBOSE=1;;
	t) if which tcpdump > /dev/null 2>&1; then
		TRACING=1
	   else
		echo "=== tcpdump not available, tracing disabled"
	   fi
	   ;;
	*) usage;;
	esac
done
shift $(($OPTIND-1))

IFS="	
"

for arg do
	# Check first that all requested tests are available before running any
	command -v > /dev/null "test_${arg}" || { echo "=== Test ${arg} not found"; usage; }
done

trap cleanup EXIT

# start clean
cleanup

name=""
desc=""
for t in ${tests}; do
	[ "${name}" = "" ]	&& name="${t}"	&& continue
	[ "${desc}" = "" ]	&& desc="${t}"

	run_this=1
	for arg do
		[ "${arg}" != "${arg#--*}" ] && continue
		[ "${arg}" = "${name}" ] && run_this=1 && break
		run_this=0
	done
	if [ $run_this -eq 1 ]; then
		run_test "${name}" "${desc}"
	fi
	name=""
	desc=""
done

exit ${exitcode}
