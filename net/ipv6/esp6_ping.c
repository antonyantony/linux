// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv6 support for "ESP-PING" sockets
 *		(draft-ietf-ipsecme-esp-ping-01 /
 *		draft-ietf-ipsecme-encrypted-esp-ping).
 *
 * Based on ipv6/ping.c code (IPv6 support for ICMP "ping" sockets), mirrored
 * onto ipv4/esp_ping.c's IPv4 "ESP-PING" socket the same way ipv6/ping.c
 * mirrors ipv4/ping.c: bind/hash/recvmsg/queue_rcv_skb/etc. are already
 * family-agnostic and live in esp_ping.c; this file only adds what's
 * genuinely IPv6-specific -- the sendmsg path (route/dst lookup, IPv6
 * header/flow setup) and AF_INET6 protocol registration.
 */

#include <linux/bpf-cgroup.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/proc_fs.h>
#include <net/addrconf.h>
#include <net/esp_ping.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/udp.h>
#include <net/xfrm.h>

/* Compatibility glue so we can support IPv6 when it's compiled as a module */
static void dummy_ip6_datagram_recv_ctl(struct sock *sk, struct msghdr *msg,
					struct sk_buff *skb)
{
}

static int dummy_ipv6_chk_addr(struct net *net, const struct in6_addr *addr,
			       const struct net_device *dev, int strict)
{
	return 0;
}

static int esp_ping_v6_pre_connect(struct sock *sk, struct sockaddr_unsized *uaddr,
				   int addr_len)
{
	/* This check is replicated from __ip6_datagram_connect() and
	 * intended to prevent BPF program called below from accessing
	 * bytes that are out of the bound specified by user in addr_len.
	 */
	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	return BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr, &addr_len);
}

/* IPv6 mirror of esp_ping_v4_sendmsg() in esp_ping.c: builds and sends
 * ESP(SPI=spi_out)|esp_echo_hdr|data over an established or pinned SA.
 *
 * Unlike esp_ping_v4_sendmsg(), this doesn't yet support IP_PKTINFO/SO_MARK
 * per-call cmsg overrides (esp_ping_cmsg_send()'s IPv6 equivalent) -- the
 * socket's own bound source/oif/mark are used as-is. Add
 * ip6_datagram_send_ctl() handling here if a per-call override is needed.
 */
static int esp_ping_v6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct net *net = sock_net(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct esp_ping_sock *psk = esp_ping_sk(sk);
	__be32 send_spi = psk ? psk->spi_out : 0;
	struct esp_echo_hdr user_hdr;
	struct xfrm_state *x;
	struct dst_entry *dst;
	struct dst_entry *route;
	struct sk_buff *skb;
	struct esp_echo_hdr *eh;
	struct in6_addr *daddr;
	struct flowi6 fl6;
	int oif = 0;
	u16 data_len;
	int payload_len;
	int err;

	err = esp_ping_common_sendmsg(msg, len, &user_hdr, &send_spi);
	if (err < 0)
		return err;

	data_len = ntohs(user_hdr.data_len);

	memset(&fl6, 0, sizeof(fl6));

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_in6 *, usin, msg->msg_name);

		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin6_family != AF_INET6)
			return -EAFNOSUPPORT;
		daddr = &usin->sin6_addr;
		if (__ipv6_addr_needs_scope_id(ipv6_addr_type(daddr)))
			oif = usin->sin6_scope_id;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = &sk->sk_v6_daddr;
	}

	if (!oif)
		oif = sk->sk_bound_dev_if;
	if (!oif)
		oif = np->sticky_pktinfo.ipi6_ifindex;
	if (!oif)
		oif = READ_ONCE(np->ucast_oif);

	fl6.flowi6_oif   = oif;
	fl6.flowi6_proto = IPPROTO_ESP;
	fl6.flowi6_mark  = READ_ONCE(sk->sk_mark);
	fl6.flowi6_uid   = sk_uid(sk);
	fl6.saddr        = np->saddr;
	fl6.daddr        = *daddr;

	security_sk_classify_flow(sk, flowi6_to_flowi_common(&fl6));

	if (send_spi) {
		xfrm_address_t xdaddr = { .in6 = *daddr };

		/* Pinned SA: look up state directly, bypass SPD. send_spi is
		 * either the ESP_PING_SEND_SPI cmsg override for this call,
		 * or the socket's sticky spi_out.
		 */
		x = xfrm_state_lookup(net, fl6.flowi6_mark, &xdaddr,
				      send_spi, IPPROTO_ESP, AF_INET6);
		if (!x)
			return -ENOENT;

		/* Plain route to SA peer — no XFRM policy involvement. */
		route = ip6_route_output(net, sk, &fl6);
		if (route->error) {
			err = route->error;
			dst_release(route);
			xfrm_state_put(x);
			return err;
		}

		/* Build 1-SA xfrm_dst; steals refs to x and route on success. */
		dst = xfrm_dst_create_for_state(net, x, route,
						flowi6_to_flowi(&fl6));
		if (IS_ERR(dst)) {
			xfrm_state_put(x);
			dst_release(route);
			return PTR_ERR(dst);
		}
		x = dst->xfrm;
	} else {
		/* SPD path: ip6_dst_lookup_flow() calls xfrm_lookup_route(). */
		dst = ip6_dst_lookup_flow(net, sk, &fl6, NULL);
		if (IS_ERR(dst))
			return PTR_ERR(dst);
		x = dst->xfrm;
		if (!x || !x->mode_cbs) {
			err = -EINVAL;
			goto put_dst;
		}
	}

	err = -EPERM;
	if (!(x->props.extra_flags & XFRM_SA_XFLAG_ESP_PING))
		goto put_dst;

	payload_len = sizeof(struct esp_echo_hdr)
		    + ((user_hdr.flags & ESP_ECHO_FLAG_R) ? sizeof(__be32) : 0)
		    + data_len;

	err = -ENOMEM;
	skb = alloc_skb(LL_RESERVED_SPACE(dst->dev) + dst->header_len
			+ payload_len + x->props.trailer_len, GFP_KERNEL);
	if (!skb)
		goto put_dst;

	skb_reserve(skb, LL_RESERVED_SPACE(dst->dev) + dst->header_len);
	skb_dst_set(skb, dst);

	eh = skb_put(skb, sizeof(*eh));
	eh->sub_type = user_hdr.sub_type;
	eh->flags    = user_hdr.flags;
	eh->data_len = user_hdr.data_len;
	/* requests get our own port; responses keep the requester's id */
	eh->id       = user_hdr.sub_type == ESP_ECHO_RESPONSE ?
			user_hdr.id : inet->inet_sport;
	eh->seq      = user_hdr.seq;

	err = -EFAULT;
	if (user_hdr.flags & ESP_ECHO_FLAG_R) {
		__be32 return_spi;

		if (memcpy_from_msg(&return_spi, msg, sizeof(return_spi)))
			goto free_skb;
		skb_put_data(skb, &return_spi, sizeof(return_spi));
	}
	if (data_len && !copy_from_iter_full(skb_put(skb, data_len), data_len,
					     &msg->msg_iter))
		goto free_skb;

	skb->protocol = htons(ETH_P_IPV6);
	err = xfrm_output(sk, skb);
	if (err)
		return err;
	return len;

free_skb:
	kfree_skb(skb);
	return err;
put_dst:
	dst_release(dst);
	return err;
}

struct proto esp_ping_v6_prot = {
	.name		= "ESP-PINGv6",
	.owner		= THIS_MODULE,
	.init		= esp_ping_init_sock,
	.close		= esp_ping_close,
	.pre_connect	= esp_ping_v6_pre_connect,
	.connect	= ip6_datagram_connect_v6_only,
	.disconnect	= __udp_disconnect,
	.setsockopt	= ipv6_setsockopt,
	.getsockopt	= ipv6_getsockopt,
	.sendmsg	= esp_ping_v6_sendmsg,
	.recvmsg	= esp_ping_recvmsg,
	.bind		= esp_ping_bind,
	.backlog_rcv	= esp_ping_queue_rcv_skb,
	.hash		= esp_ping_hash,
	.unhash		= esp_ping_unhash,
	.get_port	= esp_ping_get_port,
	.put_port	= esp_ping_unhash,
	.obj_size	= sizeof(struct raw6_sock),
	.ipv6_pinfo_offset = offsetof(struct raw6_sock, inet6),
};
EXPORT_SYMBOL_GPL(esp_ping_v6_prot);

static struct inet_protosw esp_ping_v6_protosw = {
	.type      = SOCK_DGRAM,
	.protocol  = IPPROTO_ESP,
	.prot      = &esp_ping_v6_prot,
	.ops       = &inet6_sockraw_ops,
	.flags     = INET_PROTOSW_REUSE,
};

#ifdef CONFIG_PROC_FS
static void *esp_ping_v6_seq_start(struct seq_file *seq, loff_t *pos)
{
	return esp_ping_seq_start(seq, pos, AF_INET6);
}

static void esp_ping_v6_format_sock(struct sock *sp, struct seq_file *f, int bucket)
{
	const struct in6_addr *dest = &sp->sk_v6_daddr;
	const struct in6_addr *src  = &sp->sk_v6_rcv_saddr;
	__u16 destp = ntohs(inet_sk(sp)->inet_dport);
	__u16 srcp  = ntohs(inet_sk(sp)->inet_sport);

	seq_printf(f, "%5d: %pI6c:%04X %pI6c:%04X %02X %08X:%08X %02X:%08lX %08X %5u %8d %llu %d %pK %u",
		   bucket, src, srcp, dest, destp, sp->sk_state,
		sk_wmem_alloc_get(sp),
		sk_rmem_alloc_get(sp),
		0, 0L, 0,
		from_kuid_munged(seq_user_ns(f), sock_net_uid(sock_net(sp), sp)),
		0, sock_i_ino(sp),
		refcount_read(&sp->sk_refcnt), sp,
		atomic_read(&sp->sk_drops));
}

static int esp_ping_v6_seq_show(struct seq_file *seq, void *v)
{
	seq_setwidth(seq, 127);
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, IPV6_SEQ_DGRAM_HEADER);
	} else {
		struct esp_ping_iter_state *state = seq->private;

		esp_ping_v6_format_sock(v, seq, state->bucket);
	}
	seq_pad(seq, '\n');
	return 0;
}

static const struct seq_operations esp_ping_v6_seq_ops = {
	.start		= esp_ping_v6_seq_start,
	.show		= esp_ping_v6_seq_show,
	.next		= esp_ping_seq_next,
	.stop		= esp_ping_seq_stop,
};

static int __net_init esp_ping_v6_proc_init_net(struct net *net)
{
	if (!proc_create_net("esp6", 0444, net->proc_net, &esp_ping_v6_seq_ops,
			     sizeof(struct esp_ping_iter_state)))
		return -ENOMEM;
	return 0;
}

static void __net_exit esp_ping_v6_proc_exit_net(struct net *net)
{
	remove_proc_entry("esp6", net->proc_net);
}

static struct pernet_operations esp_ping_v6_net_ops = {
	.init = esp_ping_v6_proc_init_net,
	.exit = esp_ping_v6_proc_exit_net,
};
#endif

int __init esp_pingv6_init(void)
{
#ifdef CONFIG_PROC_FS
	int ret = register_pernet_subsys(&esp_ping_v6_net_ops);

	if (ret)
		return ret;
#endif
	esp_pingv6_ops.ip6_datagram_recv_common_ctl = ip6_datagram_recv_common_ctl;
	esp_pingv6_ops.ip6_datagram_recv_specific_ctl =
		ip6_datagram_recv_specific_ctl;
	esp_pingv6_ops.ipv6_chk_addr = ipv6_chk_addr;
	return inet6_register_protosw(&esp_ping_v6_protosw);
}

/* This never gets called because it's not possible to unload the ipv6
 * module, but just in case.
 */
void esp_pingv6_exit(void)
{
	esp_pingv6_ops.ip6_datagram_recv_common_ctl = dummy_ip6_datagram_recv_ctl;
	esp_pingv6_ops.ip6_datagram_recv_specific_ctl = dummy_ip6_datagram_recv_ctl;
	esp_pingv6_ops.ipv6_chk_addr = dummy_ipv6_chk_addr;
#ifdef CONFIG_PROC_FS
	unregister_pernet_subsys(&esp_ping_v6_net_ops);
#endif
	inet6_unregister_protosw(&esp_ping_v6_protosw);
}
