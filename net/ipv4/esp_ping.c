// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		"Ping" sockets
 *
 * Based on ipv4/udp.c code.
 *
 * Authors:	Vasiliy Kulikov / Openwall (for Linux 2.6),
 *		Pavel Kankovsky (for Linux 2.4.32)
 *
 * Pavel gave all rights to bugs to Vasiliy,
 * none of the bugs are Pavel's now.
 */

#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/export.h>
#include <linux/bpf-cgroup.h>
#include <net/sock.h>
#include <net/esp_ping.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/inet_common.h>
#include <net/checksum.h>
#include <net/ip_fib.h>
#include <net/l3mdev.h>
#include <net/xfrm.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <linux/in6.h>
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/transp_v6.h>
#endif

struct esp_ping_table {
	struct hlist_head	hash[ESP_PING_HTABLE_SIZE];
	spinlock_t		lock;	/* protects hash */
};

static struct esp_ping_table esp_ping_table;
struct esp_pingv6_ops esp_pingv6_ops;
EXPORT_SYMBOL_GPL(esp_pingv6_ops);

static u16 esp_ping_port_rover;

static inline u32 esp_ping_hashfn(const struct net *net, u32 num, u32 mask)
{
	u32 res = (num + net_hash_mix(net)) & mask;

	pr_debug("hash(%u) = %u\n", num, res);
	return res;
}

static inline struct hlist_head *esp_ping_hashslot(struct esp_ping_table *table,
						   struct net *net, unsigned int num)
{
	return &table->hash[esp_ping_hashfn(net, num, ESP_PING_HTABLE_MASK)];
}

int esp_ping_get_port(struct sock *sk, unsigned short ident)
{
	struct inet_sock *isk, *isk2;
	struct hlist_head *hlist;
	struct sock *sk2 = NULL;

	isk = inet_sk(sk);
	spin_lock(&esp_ping_table.lock);
	if (ident == 0) {
		u32 i;
		u16 result = esp_ping_port_rover + 1;

		for (i = 0; i < (1L << 16); i++, result++) {
			if (!result)
				result++; /* avoid zero */
			hlist = esp_ping_hashslot(&esp_ping_table, sock_net(sk),
						  result);
			sk_for_each(sk2, hlist) {
				isk2 = inet_sk(sk2);

				if (isk2->inet_num == result)
					goto next_port;
			}

			/* found */
			esp_ping_port_rover = result;
			ident = result;
			break;
next_port:
			;
		}
		if (i >= (1L << 16))
			goto fail;
	} else {
		hlist = esp_ping_hashslot(&esp_ping_table, sock_net(sk), ident);
		sk_for_each(sk2, hlist) {
			isk2 = inet_sk(sk2);

			/* BUG? Why is this reuse and not reuseaddr? esp_.c
			 * doesn't turn off SO_REUSEADDR, and it doesn't expect
			 * that other esp_ processes can steal its packets.
			 */
			if (isk2->inet_num == ident &&
			    sk2 != sk &&
			    (!sk2->sk_reuse || !sk->sk_reuse))
				goto fail;
		}
	}

	pr_debug("found port/ident = %d\n", ident);
	isk->inet_num = ident;
	if (sk_unhashed(sk)) {
		pr_debug("was not hashed\n");
		sk_add_node_rcu(sk, hlist);
		sock_set_flag(sk, SOCK_RCU_FREE);
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	}
	spin_unlock(&esp_ping_table.lock);
	return 0;

fail:
	spin_unlock(&esp_ping_table.lock);
	return -EADDRINUSE;
}
EXPORT_SYMBOL_GPL(esp_ping_get_port);

int esp_ping_hash(struct sock *sk)
{
	pr_debug("%s(sk->port=%u)\n", __func__, inet_sk(sk)->inet_num);
	WARN_ON_ONCE(1); /* "Please do not press this button again." */

	return 0;
}
EXPORT_SYMBOL_GPL(esp_ping_hash);

void esp_ping_unhash(struct sock *sk)
{
	struct inet_sock *isk = inet_sk(sk);

	pr_debug("%s(isk=%p,isk->num=%u)\n", __func__, isk, isk->inet_num);
	spin_lock(&esp_ping_table.lock);
	if (sk_del_node_init_rcu(sk)) {
		isk->inet_num = 0;
		isk->inet_sport = 0;
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	}
	spin_unlock(&esp_ping_table.lock);
}
EXPORT_SYMBOL_GPL(esp_ping_unhash);

/* Called under rcu_read_lock() */
static struct sock *esp_ping_lookup(struct net *net, struct sk_buff *skb, u16 ident)
{
	struct hlist_head *hslot = esp_ping_hashslot(&esp_ping_table, net, ident);
	struct sock *sk = NULL;
	struct inet_sock *isk;
	int dif, sdif;

	if (skb->protocol == htons(ETH_P_IP)) {
		dif = inet_iif(skb);
		sdif = inet_sdif(skb);
		pr_debug("try to find: num = %d, daddr = %pI4, dif = %d\n",
			 (int)ident, &ip_hdr(skb)->daddr, dif);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		dif = inet6_iif(skb);
		sdif = inet6_sdif(skb);
		pr_debug("try to find: num = %d, daddr = %pI6c, dif = %d\n",
			 (int)ident, &ipv6_hdr(skb)->daddr, dif);
#endif
	} else {
		return NULL;
	}

	sk_for_each_rcu(sk, hslot) {
		isk = inet_sk(sk);

		pr_debug("iterate\n");
		if (isk->inet_num != ident)
			continue;

		if (skb->protocol == htons(ETH_P_IP) &&
		    sk->sk_family == AF_INET) {
			pr_debug("found: %p: num=%d, daddr=%pI4, dif=%d\n", sk,
				 (int)isk->inet_num, &isk->inet_rcv_saddr,
				 sk->sk_bound_dev_if);

			if (isk->inet_rcv_saddr &&
			    isk->inet_rcv_saddr != ip_hdr(skb)->daddr)
				continue;
#if IS_ENABLED(CONFIG_IPV6)
		} else if (skb->protocol == htons(ETH_P_IPV6) &&
			   sk->sk_family == AF_INET6) {
			pr_debug("found: %p: num=%d, daddr=%pI6c, dif=%d\n", sk,
				 (int)isk->inet_num,
				 &sk->sk_v6_rcv_saddr,
				 sk->sk_bound_dev_if);

			if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr) &&
			    !ipv6_addr_equal(&sk->sk_v6_rcv_saddr,
					     &ipv6_hdr(skb)->daddr))
				continue;
#endif
		} else {
			continue;
		}

		if (sk->sk_bound_dev_if && sk->sk_bound_dev_if != dif &&
		    sk->sk_bound_dev_if != sdif)
			continue;

		goto exit;
	}

	sk = NULL;
exit:

	return sk;
}

static void inet_get_esp_ping_group_range_net(struct net *net, kgid_t *low,
					      kgid_t *high)
{
	kgid_t *data = net->ipv4.esp_ping_group_range.range;
	unsigned int seq;

	do {
		seq = read_seqbegin(&net->ipv4.esp_ping_group_range.lock);

		*low = data[0];
		*high = data[1];
	} while (read_seqretry(&net->ipv4.esp_ping_group_range.lock, seq));
}

int esp_ping_init_sock(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct group_info *group_info;
	kgid_t group = current_egid();
	struct esp_ping_sock *psk;
	kgid_t low, high;
	int ret = 0;
	int i;

	psk = kzalloc_obj(*psk, GFP_KERNEL);
	if (!psk)
		return -ENOMEM;
	sk->sk_user_data = psk;

	if (sk->sk_family == AF_INET6)
		sk->sk_ipv6only = 1;

	if (ns_capable(net->user_ns, CAP_NET_RAW))
		return 0;

	inet_get_esp_ping_group_range_net(net, &low, &high);
	if (gid_lte(low, group) && gid_lte(group, high))
		return 0;

	group_info = get_current_groups();
	for (i = 0; i < group_info->ngroups; i++) {
		kgid_t gid = group_info->gid[i];

		if (gid_lte(low, gid) && gid_lte(gid, high))
			goto out_release_group;
	}

	ret = -EACCES;

out_release_group:
	put_group_info(group_info);
	if (ret) {
		kfree(psk);
		sk->sk_user_data = NULL;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(esp_ping_init_sock);

void esp_ping_close(struct sock *sk, long timeout)
{
	pr_debug("%s(sk=%p,sk->num=%u)\n", __func__,
		 inet_sk(sk), inet_sk(sk)->inet_num);
	pr_debug("isk->refcnt = %d\n", refcount_read(&sk->sk_refcnt));

	kfree(sk->sk_user_data);
	sk->sk_user_data = NULL;
	sk_common_release(sk);
}
EXPORT_SYMBOL_GPL(esp_ping_close);

static int esp_ping_pre_connect(struct sock *sk, struct sockaddr_unsized *uaddr,
				int addr_len)
{
	/* This check is replicated from __ip4_datagram_connect() and
	 * intended to prevent BPF program called below from accessing bytes
	 * that are out of the bound specified by user in addr_len.
	 */
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	return BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr, &addr_len);
}

/* Checks the bind address and possibly modifies sk->sk_bound_dev_if. */
static int esp_ping_check_bind_addr(struct sock *sk, struct inet_sock *isk,
				    struct sockaddr_unsized *uaddr, int addr_len)
{
	struct net *net = sock_net(sk);

	if (sk->sk_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
		u32 tb_id = RT_TABLE_LOCAL;
		int chk_addr_ret;

		if (addr_len < sizeof(*addr))
			return -EINVAL;

		if (addr->sin_family != AF_INET &&
		    !(addr->sin_family == AF_UNSPEC &&
		      addr->sin_addr.s_addr == htonl(INADDR_ANY)))
			return -EAFNOSUPPORT;

		pr_debug("%s(sk=%p,addr=%pI4,port=%d)\n", __func__,
			 sk, &addr->sin_addr.s_addr, ntohs(addr->sin_port));

		if (addr->sin_addr.s_addr == htonl(INADDR_ANY))
			return 0;

		tb_id = l3mdev_fib_table_by_index(net, sk->sk_bound_dev_if) ? : tb_id;
		chk_addr_ret = inet_addr_type_table(net, addr->sin_addr.s_addr, tb_id);

		if (chk_addr_ret == RTN_MULTICAST ||
		    chk_addr_ret == RTN_BROADCAST ||
		    (chk_addr_ret != RTN_LOCAL &&
		     !inet_can_nonlocal_bind(net, isk)))
			return -EADDRNOTAVAIL;

#if IS_ENABLED(CONFIG_IPV6)
	} else if (sk->sk_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)uaddr;
		int addr_type, scoped, has_addr;
		struct net_device *dev = NULL;

		if (addr_len < sizeof(*addr))
			return -EINVAL;

		if (addr->sin6_family != AF_INET6)
			return -EAFNOSUPPORT;

		pr_debug("%s(sk=%p,addr=%pI6c,port=%d)\n", __func__,
			 sk, addr->sin6_addr.s6_addr, ntohs(addr->sin6_port));

		addr_type = ipv6_addr_type(&addr->sin6_addr);
		scoped = __ipv6_addr_needs_scope_id(addr_type);
		if ((addr_type != IPV6_ADDR_ANY &&
		     !(addr_type & IPV6_ADDR_UNICAST)) ||
		    (scoped && !addr->sin6_scope_id))
			return -EINVAL;

		rcu_read_lock();
		if (addr->sin6_scope_id) {
			dev = dev_get_by_index_rcu(net, addr->sin6_scope_id);
			if (!dev) {
				rcu_read_unlock();
				return -ENODEV;
			}
		}

		if (!dev && sk->sk_bound_dev_if) {
			dev = dev_get_by_index_rcu(net, sk->sk_bound_dev_if);
			if (!dev) {
				rcu_read_unlock();
				return -ENODEV;
			}
		}
		has_addr = esp_pingv6_ops.ipv6_chk_addr(net, &addr->sin6_addr,
							dev, scoped);
		rcu_read_unlock();

		if (!(ipv6_can_nonlocal_bind(net, isk) || has_addr ||
		      addr_type == IPV6_ADDR_ANY))
			return -EADDRNOTAVAIL;

		if (scoped)
			sk->sk_bound_dev_if = addr->sin6_scope_id;
#endif
	} else {
		return -EAFNOSUPPORT;
	}
	return 0;
}

static void esp_ping_set_saddr(struct sock *sk, struct sockaddr_unsized *saddr)
{
	if (saddr->sa_family == AF_INET) {
		struct inet_sock *isk = inet_sk(sk);
		struct sockaddr_in *addr = (struct sockaddr_in *)saddr;

		isk->inet_rcv_saddr = addr->sin_addr.s_addr;
		isk->inet_saddr = addr->sin_addr.s_addr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (saddr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)saddr;
		struct ipv6_pinfo *np = inet6_sk(sk);

		sk->sk_v6_rcv_saddr = addr->sin6_addr;
		np->saddr = addr->sin6_addr;
#endif
	}
}

/*
 * We need our own bind because there are no privileged id's == local ports.
 * Moreover, we don't allow binding to multi- and broadcast addresses.
 */

int esp_ping_bind(struct sock *sk, struct sockaddr_unsized *uaddr, int addr_len)
{
	struct inet_sock *isk = inet_sk(sk);
	unsigned short snum;
	int err;
	int dif = sk->sk_bound_dev_if;

	err = esp_ping_check_bind_addr(sk, isk, uaddr, addr_len);
	if (err)
		return err;

	lock_sock(sk);

	err = -EINVAL;
	if (isk->inet_num != 0)
		goto out;

	err = -EADDRINUSE;
	snum = ntohs(((struct sockaddr_in *)uaddr)->sin_port);
	if (esp_ping_get_port(sk, snum) != 0) {
		/* Restore possibly modified sk->sk_bound_dev_if by esp_ping_check_bind_addr(). */
		sk->sk_bound_dev_if = dif;
		goto out;
	}
	esp_ping_set_saddr(sk, uaddr);

	pr_debug("after bind(): num = %u, dif = %d\n",
		 isk->inet_num,
		 sk->sk_bound_dev_if);

	err = 0;
	if (sk->sk_family == AF_INET && isk->inet_rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6 && !ipv6_addr_any(&sk->sk_v6_rcv_saddr))
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
#endif

	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	isk->inet_sport = htons(isk->inet_num);
	isk->inet_daddr = 0;
	isk->inet_dport = 0;

#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		memset(&sk->sk_v6_daddr, 0, sizeof(sk->sk_v6_daddr));
#endif

	sk_dst_reset(sk);
out:
	release_sock(sk);
	pr_debug("esp_ping_v4_bind -> %d\n", err);
	return err;
}
EXPORT_SYMBOL_GPL(esp_ping_bind);

/* draft-ietf-ipsecme-esp-ping-01: build IP|ESP(SPI=8)|esp_echo_hdr|data reply */
static void esp_ping_plain_ipv4_reply(struct sk_buff *req,
				      const struct esp_echo_hdr *rh,
				      const u8 *req_data, u16 data_len)
{
	struct net *net = dev_net(req->dev);
	int payload = sizeof(struct ip_esp_hdr) + sizeof(struct esp_echo_hdr)
		      + data_len;
	struct flowi4 fl4 = {
		.daddr        = ip_hdr(req)->saddr,
		.saddr        = fib_compute_spec_dst(req),
		.flowi4_proto = IPPROTO_ESP,
		.flowi4_mark  = IP4_REPLY_MARK(net, req->mark),
		.flowi4_oif   = l3mdev_master_ifindex(req->dev),
	};
	struct rtable *rt;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct ip_esp_hdr *esph;
	struct esp_echo_hdr *eh;

	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return;

	skb = alloc_skb(LL_RESERVED_SPACE(rt->dst.dev)
			+ sizeof(*iph) + payload, GFP_ATOMIC);
	if (!skb)
		goto put_rt;

	skb_reserve(skb, LL_RESERVED_SPACE(rt->dst.dev));
	skb_dst_set(skb, &rt->dst);
	skb_reset_network_header(skb);

	iph = skb_put_zero(skb, sizeof(*iph));
	iph->version  = 4;
	iph->ihl      = 5;
	iph->ttl      = READ_ONCE(net->ipv4.sysctl_ip_default_ttl);
	iph->protocol = IPPROTO_ESP;
	iph->saddr    = fl4.saddr;
	iph->daddr    = fl4.daddr;
	iph->tot_len  = htons(sizeof(*iph) + payload);
	ip_send_check(iph);

	esph = skb_put(skb, sizeof(*esph));
	esph->spi    = htonl(ESP_PING_SPI_REPLY);
	esph->seq_no = 0;

	eh = skb_put(skb, sizeof(*eh));
	eh->sub_type = ESP_ECHO_RESPONSE;
	eh->flags    = 0;
	eh->data_len = rh->data_len;
	eh->id       = rh->id;
	eh->seq      = rh->seq;

	skb_put_data(skb, req_data, data_len);

	icmp_global_consume(net);
	ip_local_out(net, NULL, skb);
	return;
put_rt:
	ip_rt_put(rt);
}

#if IS_ENABLED(CONFIG_IPV6)
/* draft-ietf-ipsecme-esp-ping-01: build IP6|ESP(SPI=8)|esp_echo_hdr|data reply */
static void esp_ping_plain_ipv6_reply(struct sk_buff *req,
				      const struct esp_echo_hdr *rh,
				      const u8 *req_data, u16 data_len)
{
	struct net *net = dev_net(req->dev);
	int payload = sizeof(struct ip_esp_hdr) + sizeof(struct esp_echo_hdr)
		      + data_len;
	struct flowi6 fl6 = {
		.daddr        = ipv6_hdr(req)->saddr,
		.saddr        = ipv6_hdr(req)->daddr,
		.flowi6_proto = IPPROTO_ESP,
		.flowi6_mark  = IP6_REPLY_MARK(net, req->mark),
		.flowi6_oif   = l3mdev_master_ifindex(req->dev),
	};
	struct dst_entry *dst;
	struct sk_buff *skb;
	struct ipv6hdr *ip6h;
	struct ip_esp_hdr *esph;
	struct esp_echo_hdr *eh;

	dst = ip6_route_output(net, NULL, &fl6);
	if (dst->error)
		goto put_dst;

	skb = alloc_skb(LL_RESERVED_SPACE(dst->dev)
			+ sizeof(*ip6h) + payload, GFP_ATOMIC);
	if (!skb)
		goto put_dst;

	skb_reserve(skb, LL_RESERVED_SPACE(dst->dev));
	skb_dst_set(skb, dst);
	skb_reset_network_header(skb);

	ip6h = skb_put_zero(skb, sizeof(*ip6h));
	ip6_flow_hdr(ip6h, 0, 0);
	ip6h->payload_len = htons(payload);
	ip6h->nexthdr     = IPPROTO_ESP;
	ip6h->hop_limit   = READ_ONCE(net->ipv6.devconf_all->hop_limit);
	ip6h->saddr       = fl6.saddr;
	ip6h->daddr       = fl6.daddr;

	esph = skb_put(skb, sizeof(*esph));
	esph->spi    = htonl(ESP_PING_SPI_REPLY);
	esph->seq_no = 0;

	eh = skb_put(skb, sizeof(*eh));
	eh->sub_type = ESP_ECHO_RESPONSE;
	eh->flags    = 0;
	eh->data_len = rh->data_len;
	eh->id       = rh->id;
	eh->seq      = rh->seq;

	skb_put_data(skb, req_data, data_len);

	icmp_global_consume(net);
	ip6_local_out(net, NULL, skb);
	return;
put_dst:
	dst_release(dst);
}
#endif

/* draft-ietf-ipsecme-esp-ping-01: handle incoming SPI=7 request */
void esp_ping_plain_rcv(struct sk_buff *skb)
{
	unsigned int hdr_off = skb_transport_offset(skb) + sizeof(struct ip_esp_hdr);
	struct esp_echo_hdr *h;
	u16 r_skip, data_len;

	if (!pskb_may_pull(skb, hdr_off + sizeof(struct esp_echo_hdr)))
		goto drop;

	h = (struct esp_echo_hdr *)(skb->data + hdr_off);

	if (h->sub_type != ESP_ECHO_REQUEST)
		goto drop;

	/* skip return_spi if sender set R=1; R flag is not used for plain ping */
	r_skip   = (h->flags & ESP_ECHO_FLAG_R) ? sizeof(__be32) : 0;
	data_len = ntohs(h->data_len);

	if (!pskb_may_pull(skb, hdr_off + sizeof(*h) + r_skip + data_len))
		goto drop;

	if (!icmp_global_allow(dev_net(skb->dev)))
		goto drop;

	if (skb->protocol == htons(ETH_P_IP)) {
		esp_ping_plain_ipv4_reply(skb, h, (u8 *)(h + 1) + r_skip, data_len);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		esp_ping_plain_ipv6_reply(skb, h, (u8 *)(h + 1) + r_skip, data_len);
#endif
	}
	kfree_skb(skb);
	return;
drop:
	kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(esp_ping_plain_rcv);

/*
 * Handle IP_PKTINFO (source address + oif override) and SOL_SOCKET cmsgs
 * (SO_MARK via __sock_cmsg_send(), already permission-checked) on send,
 * same as every other IPv4 protocol's sendmsg (see ip_cmsg_send(), used by
 * ping.c/raw.c/udp.c). Deliberately narrower than ip_cmsg_send() itself:
 * it also handles IP_RETOPTS, which allocates ipc->opt and would need
 * cleanup on every one of esp_ping_v4_sendmsg()'s several early-return
 * paths for a feature (IP source routing) esp-ping has no use for. Nothing
 * here allocates, so callers don't need to free anything.
 */
static int esp_ping_cmsg_send(struct sock *sk, struct msghdr *msg,
			      struct ipcm_cookie *ipc)
{
	struct in_pktinfo *info;
	struct cmsghdr *cmsg;
	int err;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level == SOL_SOCKET) {
			err = __sock_cmsg_send(sk, cmsg, &ipc->sockc);
			if (err)
				return err;
			continue;
		}

		if (cmsg->cmsg_level != SOL_IP)
			continue;

		if (cmsg->cmsg_type != IP_PKTINFO)
			return -EINVAL;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(*info)))
			return -EINVAL;

		info = (struct in_pktinfo *)CMSG_DATA(cmsg);
		if (info->ipi_ifindex)
			ipc->oif = info->ipi_ifindex;
		ipc->addr = info->ipi_spec_dst.s_addr;
	}
	return 0;
}

static int esp_ping_v4_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct net *net = sock_net(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct ipcm_cookie ipc;
	struct esp_echo_hdr user_hdr;
	struct xfrm_state *x;
	struct sk_buff *skb;
	struct esp_echo_hdr *eh;
	struct rtable *rt;
	__be32 daddr, saddr;
	struct flowi4 fl4;
	u16 data_len;
	int payload_len;
	int err;

	if (len < sizeof(user_hdr))
		return -EINVAL;
	if (memcpy_from_msg(&user_hdr, msg, sizeof(user_hdr)))
		return -EFAULT;
	if (user_hdr.sub_type != ESP_ECHO_REQUEST &&
	    user_hdr.sub_type != ESP_ECHO_RESPONSE)
		return -EINVAL;

	data_len = ntohs(user_hdr.data_len);

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);

		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET)
			return -EAFNOSUPPORT;
		daddr = usin->sin_addr.s_addr;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
	}

	ipcm_init_sk(&ipc, inet);

	/* IP_PKTINFO/SO_MARK cmsg override addr/oif/mark for this call only,
	 * same as ping.c/raw.c/udp.c's sendmsg (see esp_ping_cmsg_send()).
	 */
	if (msg->msg_controllen) {
		err = esp_ping_cmsg_send(sk, msg, &ipc);
		if (err)
			return err;
	}
	saddr = ipc.addr;

	/* fl4 carries saddr (from bind/-I <ip>/IP_PKTINFO) and oif (from
	 * SO_BINDTODEVICE/-I <dev>/IP_PKTINFO, falling back to IP_UNICAST_IF)
	 * so both the SPD path and the pinned-SA path honour -I.
	 */
	flowi4_init_output(&fl4, ipc.oif ?: READ_ONCE(inet->uc_index),
			   ipc.sockc.mark,
			   ipc.tos & INET_DSCP_MASK, RT_SCOPE_UNIVERSE,
			   IPPROTO_ESP, inet_sk_flowi_flags(sk),
			   daddr, saddr, 0, 0, sk_uid(sk));

	security_sk_classify_flow(sk, flowi4_to_flowi_common(&fl4));
	rt = ip_route_output_flow(net, &fl4, sk);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	err = -EINVAL;
	x = rt->dst.xfrm;
	if (!x || !x->mode_cbs)
		goto put_rt;

	err = -EPERM;
	if (!(x->props.extra_flags & XFRM_SA_XFLAG_ESP_PING))
		goto put_rt;

	payload_len = sizeof(struct esp_echo_hdr)
		    + ((user_hdr.flags & ESP_ECHO_FLAG_R) ? sizeof(__be32) : 0)
		    + data_len;

	err = -ENOMEM;
	skb = alloc_skb(LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
			+ payload_len + x->props.trailer_len, GFP_KERNEL);
	if (!skb)
		goto put_rt;

	skb_reserve(skb, LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len);
	skb_dst_set(skb, &rt->dst);

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

	skb->protocol = htons(ETH_P_IP);
	return xfrm_output(sk, skb);

free_skb:
	kfree_skb(skb);
	return err;
put_rt:
	ip_rt_put(rt);
	return err;
}

int esp_ping_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	struct inet_sock *isk = inet_sk(sk);
	int family = sk->sk_family;
	struct sk_buff *skb;
	int copied, err;

	pr_debug("%s(sk=%p,sk->num=%u)\n", __func__, isk, isk->inet_num);

	err = -EOPNOTSUPP;
	if (flags & MSG_OOB)
		goto out;

	if (flags & MSG_ERRQUEUE)
		return inet_recv_error(sk, msg, len);

	skb = skb_recv_datagram(sk, flags, &err);
	if (!skb)
		goto out;

	copied = skb->len;
	if (copied > len) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	/* Don't bother checking the checksum */
	err = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (err)
		goto done;

	sock_recv_timestamp(msg, sk, skb);

	/* Copy the address and add cmsg data. */
	if (family == AF_INET) {
		DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);

		if (sin) {
			sin->sin_family = AF_INET;
			sin->sin_port = 0 /* skb->h.uh->source */;
			sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
			memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
			msg->msg_namelen = sizeof(*sin);
		}

		if (inet_cmsg_flags(isk))
			ip_cmsg_recv(msg, skb);

#if IS_ENABLED(CONFIG_IPV6)
	} else if (family == AF_INET6) {
		struct ipv6hdr *ip6 = ipv6_hdr(skb);
		DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, msg->msg_name);

		if (sin6) {
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = 0;
			sin6->sin6_addr = ip6->saddr;
			sin6->sin6_flowinfo = 0;
			if (inet6_test_bit(SNDFLOW, sk))
				sin6->sin6_flowinfo = ip6_flowinfo(ip6);
			sin6->sin6_scope_id =
				ipv6_iface_scope_id(&sin6->sin6_addr,
						    inet6_iif(skb));
			msg->msg_namelen = sizeof(*sin6);
		}

		if (inet6_sk(sk)->rxopt.all)
			esp_pingv6_ops.ip6_datagram_recv_common_ctl(sk, msg, skb);
		if (skb->protocol == htons(ETH_P_IPV6) &&
		    inet6_sk(sk)->rxopt.all)
			esp_pingv6_ops.ip6_datagram_recv_specific_ctl(sk, msg, skb);
		else if (skb->protocol == htons(ETH_P_IP) &&
			 inet_cmsg_flags(isk))
			ip_cmsg_recv(msg, skb);
#endif
	} else {
		WARN_ON_ONCE(1);
	}

	err = copied;

done:
	skb_free_datagram(sk, skb);
out:
	pr_debug("%s -> %d\n", __func__, err);
	return err;
}
EXPORT_SYMBOL_GPL(esp_ping_recvmsg);

static enum skb_drop_reason __esp_ping_queue_rcv_skb(struct sock *sk,
						     struct sk_buff *skb)
{
	enum skb_drop_reason reason;

	pr_debug("esp_ping_queue_rcv_skb(sk=%p,sk->num=%d,skb=%p)\n",
		 inet_sk(sk), inet_sk(sk)->inet_num, skb);
	reason = sock_queue_rcv_skb_reason(sk, skb);
	if (reason != SKB_NOT_DROPPED_YET) {
		sk_skb_reason_drop(sk, skb, reason);
		pr_debug("esp_ping_queue_rcv_skb -> failed\n");
		return reason;
	}
	return SKB_NOT_DROPPED_YET;
}

int esp_ping_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return __esp_ping_queue_rcv_skb(sk, skb) ? -1 : 0;
}
EXPORT_SYMBOL_GPL(esp_ping_queue_rcv_skb);

/* draft-ietf-ipsecme-esp-ping-01: deliver an incoming SPI=8 reply to its socket */
enum skb_drop_reason esp_ping_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	unsigned int hdr_off = skb_transport_offset(skb) + sizeof(struct ip_esp_hdr);
	struct esp_echo_hdr *h;
	struct sock *sk;

	if (!pskb_may_pull(skb, hdr_off + sizeof(struct esp_echo_hdr))) {
		kfree_skb_reason(skb, SKB_DROP_REASON_PKT_TOO_SMALL);
		return SKB_DROP_REASON_PKT_TOO_SMALL;
	}

	h = (struct esp_echo_hdr *)(skb->data + hdr_off);
	if (h->sub_type != ESP_ECHO_RESPONSE) {
		kfree_skb_reason(skb, SKB_DROP_REASON_INVALID_PROTO);
		return SKB_DROP_REASON_INVALID_PROTO;
	}

	sk = esp_ping_lookup(net, skb, ntohs(h->id));
	if (sk)
		return __esp_ping_queue_rcv_skb(sk, skb);

	kfree_skb_reason(skb, SKB_DROP_REASON_NO_SOCKET);
	return SKB_DROP_REASON_NO_SOCKET;
}
EXPORT_SYMBOL_GPL(esp_ping_rcv);

/* draft-ietf-ipsecme-esp-ping-01: dispatch a state-less ESP ping packet
 * (outer SPI 7 request or SPI 8 reply) that didn't match any SA.
 * Returns false if @spi is neither, leaving the packet untouched.
 */
bool esp_recv(struct sk_buff *skb, __be32 spi)
{
	switch (ntohl(spi)) {
	case ESP_PING_SPI_REQUEST:
		esp_ping_plain_rcv(skb);
		return true;
	case ESP_PING_SPI_REPLY:
		esp_ping_rcv(skb);
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(esp_recv);

struct proto esp_ping_prot = {
	.name =		"ESP-PING",
	.owner =	THIS_MODULE,
	.init =		esp_ping_init_sock,
	.close =	esp_ping_close,
	.pre_connect =	esp_ping_pre_connect,
	.connect =	ip4_datagram_connect,
	.disconnect =	__udp_disconnect,
	.setsockopt =	ip_setsockopt,
	.getsockopt =	ip_getsockopt,
	.sendmsg =	esp_ping_v4_sendmsg,
	.recvmsg =	esp_ping_recvmsg,
	.bind =		esp_ping_bind,
	.backlog_rcv =	esp_ping_queue_rcv_skb,
	.release_cb =	ip4_datagram_release_cb,
	.hash =		esp_ping_hash,
	.unhash =	esp_ping_unhash,
	.get_port =	esp_ping_get_port,
	.put_port =	esp_ping_unhash,
	.obj_size =	sizeof(struct inet_sock),
};
EXPORT_SYMBOL(esp_ping_prot);

#ifdef CONFIG_PROC_FS

static struct sock *esp_ping_get_first(struct seq_file *seq, int start)
{
	struct sock *sk;
	struct esp_ping_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	for (state->bucket = start; state->bucket < ESP_PING_HTABLE_SIZE;
	     ++state->bucket) {
		struct hlist_head *hslot;

		hslot = &esp_ping_table.hash[state->bucket];

		if (hlist_empty(hslot))
			continue;

		sk_for_each(sk, hslot) {
			if (net_eq(sock_net(sk), net) &&
			    sk->sk_family == state->family)
				goto found;
		}
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *esp_ping_get_next(struct seq_file *seq, struct sock *sk)
{
	struct esp_ping_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	do {
		sk = sk_next(sk);
	} while (sk && (!net_eq(sock_net(sk), net)));

	if (!sk)
		return esp_ping_get_first(seq, state->bucket + 1);
	return sk;
}

static struct sock *esp_ping_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = esp_ping_get_first(seq, 0);

	if (sk)
		while (pos && (sk = esp_ping_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

void *esp_ping_seq_start(struct seq_file *seq, loff_t *pos, sa_family_t family)
	__acquires(esp_ping_table.lock)
{
	struct esp_ping_iter_state *state = seq->private;

	state->bucket = 0;
	state->family = family;

	spin_lock(&esp_ping_table.lock);

	return *pos ? esp_ping_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}
EXPORT_SYMBOL_GPL(esp_ping_seq_start);

static void *esp_ping_v4_seq_start(struct seq_file *seq, loff_t *pos)
{
	return esp_ping_seq_start(seq, pos, AF_INET);
}

void *esp_ping_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == SEQ_START_TOKEN)
		sk = esp_ping_get_idx(seq, 0);
	else
		sk = esp_ping_get_next(seq, v);

	++*pos;
	return sk;
}
EXPORT_SYMBOL_GPL(esp_ping_seq_next);

void esp_ping_seq_stop(struct seq_file *seq, void *v)
	__releases(esp_ping_table.lock)
{
	spin_unlock(&esp_ping_table.lock);
}
EXPORT_SYMBOL_GPL(esp_ping_seq_stop);

static void esp_ping_v4_format_sock(struct sock *sp, struct seq_file *f,
				    int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->inet_daddr;
	__be32 src = inet->inet_rcv_saddr;
	__u16 destp = ntohs(inet->inet_dport);
	__u16 srcp = ntohs(inet->inet_sport);

	seq_printf(f, "%5d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX %08X %5u %8d %llu %d %pK %u",
		   bucket, src, srcp, dest, destp, sp->sk_state,
		sk_wmem_alloc_get(sp),
		sk_rmem_alloc_get(sp),
		0, 0L, 0,
		from_kuid_munged(seq_user_ns(f), sock_net_uid(sock_net(sp), sp)),
		0, sock_i_ino(sp),
		refcount_read(&sp->sk_refcnt), sp,
		atomic_read(&sp->sk_drops));
}

static int esp_ping_v4_seq_show(struct seq_file *seq, void *v)
{
	seq_setwidth(seq, 127);
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, " sl spi rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops");
	} else {
		struct esp_ping_iter_state *state = seq->private;

		esp_ping_v4_format_sock(v, seq, state->bucket);
	}
	seq_pad(seq, '\n');
	return 0;
}

static const struct seq_operations esp_ping_v4_seq_ops = {
	.start		= esp_ping_v4_seq_start,
	.show		= esp_ping_v4_seq_show,
	.next		= esp_ping_seq_next,
	.stop		= esp_ping_seq_stop,
};

static int __net_init esp_ping_v4_proc_init_net(struct net *net)
{
	if (!proc_create_net("esp", 0444, net->proc_net, &esp_ping_v4_seq_ops,
			     sizeof(struct esp_ping_iter_state)))
		return -ENOMEM;
	return 0;
}

static void __net_exit esp_ping_v4_proc_exit_net(struct net *net)
{
	remove_proc_entry("esp", net->proc_net);
}

static struct pernet_operations esp_ping_v4_net_ops = {
	.init = esp_ping_v4_proc_init_net,
	.exit = esp_ping_v4_proc_exit_net,
};

int __init esp_ping_proc_init(void)
{
	return register_pernet_subsys(&esp_ping_v4_net_ops);
}

void esp_ping_proc_exit(void)
{
	unregister_pernet_subsys(&esp_ping_v4_net_ops);
}

#endif

void __init esp_ping_init(void)
{
	int i;

	for (i = 0; i < ESP_PING_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&esp_ping_table.hash[i]);
	spin_lock_init(&esp_ping_table.lock);
	proto_register(&esp_ping_prot, 1);
}
