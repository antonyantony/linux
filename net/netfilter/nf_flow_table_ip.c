// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/rhashtable.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/neighbour.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_conntrack_acct.h>
/* For layer 4 checksum field offset. */
#include <linux/tcp.h>
#include <linux/udp.h>

static int nf_flow_state_check(struct flow_offload *flow, int proto,
			       struct sk_buff *skb, unsigned int thoff)
{
	struct tcphdr *tcph;

	if (proto != IPPROTO_TCP)
		return 0;

	tcph = (void *)(skb_network_header(skb) + thoff);
	if (unlikely(tcph->fin || tcph->rst)) {
		flow_offload_teardown(flow);
		return -1;
	}

	return 0;
}

static void nf_flow_nat_ip_tcp(struct sk_buff *skb, unsigned int thoff,
			       __be32 addr, __be32 new_addr)
{
	struct tcphdr *tcph;

	tcph = (void *)(skb_network_header(skb) + thoff);
	inet_proto_csum_replace4(&tcph->check, skb, addr, new_addr, true);
}

static void nf_flow_nat_ip_udp(struct sk_buff *skb, unsigned int thoff,
			       __be32 addr, __be32 new_addr)
{
	struct udphdr *udph;

	udph = (void *)(skb_network_header(skb) + thoff);
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace4(&udph->check, skb, addr,
					 new_addr, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}
}

static void nf_flow_nat_ip_l4proto(struct sk_buff *skb, struct iphdr *iph,
				   unsigned int thoff, __be32 addr,
				   __be32 new_addr)
{
	switch (iph->protocol) {
	case IPPROTO_TCP:
		nf_flow_nat_ip_tcp(skb, thoff, addr, new_addr);
		break;
	case IPPROTO_UDP:
		nf_flow_nat_ip_udp(skb, thoff, addr, new_addr);
		break;
	}
}

static void nf_flow_snat_ip(const struct flow_offload *flow,
			    struct sk_buff *skb, struct iphdr *iph,
			    unsigned int thoff, enum flow_offload_tuple_dir dir)
{
	__be32 addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v4.s_addr;
		iph->saddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v4.s_addr;
		iph->daddr = new_addr;
		break;
	}
	csum_replace4(&iph->check, addr, new_addr);

	nf_flow_nat_ip_l4proto(skb, iph, thoff, addr, new_addr);
}

static void nf_flow_dnat_ip(const struct flow_offload *flow,
			    struct sk_buff *skb, struct iphdr *iph,
			    unsigned int thoff, enum flow_offload_tuple_dir dir)
{
	__be32 addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr;
		iph->daddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v4.s_addr;
		iph->saddr = new_addr;
		break;
	}
	csum_replace4(&iph->check, addr, new_addr);

	nf_flow_nat_ip_l4proto(skb, iph, thoff, addr, new_addr);
}

static void nf_flow_nat_ip(const struct flow_offload *flow, struct sk_buff *skb,
			  unsigned int thoff, enum flow_offload_tuple_dir dir,
			  struct iphdr *iph)
{
	if (test_bit(NF_FLOW_SNAT, &flow->flags)) {
		nf_flow_snat_port(flow, skb, thoff, iph->protocol, dir);
		nf_flow_snat_ip(flow, skb, iph, thoff, dir);
	}
	if (test_bit(NF_FLOW_DNAT, &flow->flags)) {
		nf_flow_dnat_port(flow, skb, thoff, iph->protocol, dir);
		nf_flow_dnat_ip(flow, skb, iph, thoff, dir);
	}
}

static bool ip_has_options(unsigned int thoff)
{
	return thoff != sizeof(struct iphdr);
}

static void nf_flow_tuple_encap(struct sk_buff *skb,
				struct flow_offload_tuple *tuple)
{
	struct vlan_ethhdr *veth;
	struct pppoe_hdr *phdr;
	int i = 0;

	if (skb_vlan_tag_present(skb)) {
		tuple->encap[i].id = skb_vlan_tag_get(skb);
		tuple->encap[i].proto = skb->vlan_proto;
		i++;
	}
	switch (skb->protocol) {
	case htons(ETH_P_8021Q):
		veth = (struct vlan_ethhdr *)skb_mac_header(skb);
		tuple->encap[i].id = ntohs(veth->h_vlan_TCI);
		tuple->encap[i].proto = skb->protocol;
		break;
	case htons(ETH_P_PPP_SES):
		phdr = (struct pppoe_hdr *)skb_mac_header(skb);
		tuple->encap[i].id = ntohs(phdr->sid);
		tuple->encap[i].proto = skb->protocol;
		break;
	}
}

static int nf_flow_tuple_ip(struct sk_buff *skb, const struct net_device *dev,
			    struct flow_offload_tuple *tuple, u32 *hdrsize,
			    u32 offset)
{
	struct flow_ports *ports;
	unsigned int thoff;
	struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof(*iph) + offset))
		return -1;

	iph = (struct iphdr *)(skb_network_header(skb) + offset);
	thoff = (iph->ihl * 4);

	if (ip_is_fragment(iph) ||
	    unlikely(ip_has_options(thoff)))
		return -1;

	thoff += offset;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		*hdrsize = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		*hdrsize = sizeof(struct udphdr);
		break;
	default:
		return -1;
	}

	if (iph->ttl <= 1)
		return -1;

	if (!pskb_may_pull(skb, thoff + *hdrsize))
		return -1;

	iph = (struct iphdr *)(skb_network_header(skb) + offset);
	ports = (struct flow_ports *)(skb_network_header(skb) + thoff);

	tuple->src_v4.s_addr	= iph->saddr;
	tuple->dst_v4.s_addr	= iph->daddr;
	tuple->src_port		= ports->source;
	tuple->dst_port		= ports->dest;
	tuple->l3proto		= AF_INET;
	tuple->l4proto		= iph->protocol;
	tuple->iifidx		= dev->ifindex;
	nf_flow_tuple_encap(skb, tuple);

	return 0;
}

/* Based on ip_exceeds_mtu(). */
static bool nf_flow_exceeds_mtu(const struct sk_buff *skb, unsigned int mtu)
{
	if (skb->len <= mtu)
		return false;

	if (skb_is_gso(skb) && skb_gso_validate_network_len(skb, mtu))
		return false;

	return true;
}

static unsigned int nf_flow_xmit_xfrm(struct sk_buff *skb,
				      const struct nf_hook_state *state,
				      struct dst_entry *dst)
{
	skb_orphan(skb);
	skb_dst_set_noref(skb, dst);
	dst_output(state->net, state->sk, skb);
	return NF_STOLEN;
}

static inline __be16 nf_flow_pppoe_proto(const struct sk_buff *skb)
{
	__be16 proto;

	proto = *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +
			     sizeof(struct pppoe_hdr)));
	switch (proto) {
	case htons(PPP_IP):
		return htons(ETH_P_IP);
	case htons(PPP_IPV6):
		return htons(ETH_P_IPV6);
	}

	return 0;
}

static bool nf_flow_skb_encap_protocol(const struct sk_buff *skb, __be16 proto,
				       u32 *offset)
{
	struct vlan_ethhdr *veth;

	switch (skb->protocol) {
	case htons(ETH_P_8021Q):
		veth = (struct vlan_ethhdr *)skb_mac_header(skb);
		if (veth->h_vlan_encapsulated_proto == proto) {
			*offset += VLAN_HLEN;
			return true;
		}
		break;
	case htons(ETH_P_PPP_SES):
		if (nf_flow_pppoe_proto(skb) == proto) {
			*offset += PPPOE_SES_HLEN;
			return true;
		}
		break;
	}

	return false;
}

static void nf_flow_encap_pop(struct sk_buff *skb,
			      struct flow_offload_tuple_rhash *tuplehash)
{
	struct vlan_hdr *vlan_hdr;
	int i;

	for (i = 0; i < tuplehash->tuple.encap_num; i++) {
		if (skb_vlan_tag_present(skb)) {
			__vlan_hwaccel_clear_tag(skb);
			continue;
		}
		switch (skb->protocol) {
		case htons(ETH_P_8021Q):
			vlan_hdr = (struct vlan_hdr *)skb->data;
			__skb_pull(skb, VLAN_HLEN);
			vlan_set_encap_proto(skb, vlan_hdr);
			skb_reset_network_header(skb);
			break;
		case htons(ETH_P_PPP_SES):
			skb->protocol = nf_flow_pppoe_proto(skb);
			skb_pull(skb, PPPOE_SES_HLEN);
			skb_reset_network_header(skb);
			break;
		}
	}
}

static unsigned int nf_flow_queue_xmit(struct net *net, struct sk_buff *skb,
				       const struct flow_offload_tuple_rhash *tuplehash,
				       unsigned short type)
{
	struct net_device *outdev;

	outdev = dev_get_by_index_rcu(net, tuplehash->tuple.out.ifidx);
	if (!outdev)
		return NF_DROP;

	skb->dev = outdev;
	dev_hard_header(skb, skb->dev, type, tuplehash->tuple.out.h_dest,
			tuplehash->tuple.out.h_source, skb->len);
	dev_queue_xmit(skb);

	return NF_STOLEN;
}

int nft_bulk_receive_list(struct sk_buff *p, struct sk_buff *skb)
{
	NFT_BULK_CB(p)->last->next = skb;
	NFT_BULK_CB(p)->last = skb;
	NFT_BULK_CB(skb)->same_flow = 1;

	return 0;
}

static void nft_bulk_receive(struct list_head *head, struct sk_buff *skb)
{
	const struct iphdr *iph;
	struct sk_buff *p;
	struct dst_entry *dst;
	struct rtable *rt;
	struct xfrm_state *x;
	int proto;
	__be32 daddr;

	iph = ip_hdr(skb);
	dst = skb_dst(skb);
	/* dst must be present from the flowtable
	if (!dst) {
		goto out;
	}
	*/

	rt = (struct rtable *)dst;
	daddr = rt_nexthop(rt, iph->daddr);
	x = dst_xfrm(dst);
	proto = iph->protocol;

	list_for_each_entry(p, head, list) {
		struct dst_entry *dst2;
		struct rtable *rt2;
		struct iphdr *iph2;
		__be32 daddr2;

		if (!NFT_BULK_CB(p)->same_flow)
			continue;

		dst2 = skb_dst(p);
		rt2 = (struct rtable *)dst2;
		if (dst->dev != dst2->dev) {
			NFT_BULK_CB(p)->same_flow = 0;
			continue;
		}

		iph2 = ip_hdr(p);
		daddr2 = rt_nexthop(rt2, iph2->daddr);
		if (daddr != daddr2) {
			NFT_BULK_CB(p)->same_flow = 0;
			continue;
		}

		if (x != dst_xfrm(dst2)) {
			NFT_BULK_CB(p)->same_flow = 0;
			continue;
		}

		goto found;
	}

	goto out;

found:
	if (NFT_BULK_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		NFT_BULK_CB(p)->last->next = skb;

	NFT_BULK_CB(p)->last = skb;
	NFT_BULK_CB(skb)->same_flow = 1;

	return;
out:
	/* First skb */
	NFT_BULK_CB(skb)->last = skb;
	NFT_BULK_CB(skb)->same_flow = 1;
	list_add_tail(&skb->list, head);

	return;
}

unsigned int
__nf_flow_offload_ip_hook(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	struct flow_offload_tuple tuple = {};
	enum flow_offload_tuple_dir dir;
	struct flow_offload *flow;
	u32 hdrsize, offset = 0;
	unsigned int thoff, mtu;
	struct iphdr *iph;
	struct dst_entry *dst;

	skb_reset_network_header(skb);
	if (!skb_transport_header_was_set(skb))
		skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);

	if (skb->protocol != htons(ETH_P_IP) &&
	    !nf_flow_skb_encap_protocol(skb, htons(ETH_P_IP), &offset))
		return 0;

	if (nf_flow_tuple_ip(skb, state->in, &tuple, &hdrsize, offset) < 0)
		return 0;

	tuplehash = flow_offload_lookup(flow_table, &tuple);
	if (tuplehash == NULL)
		return 0;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	mtu = flow->tuplehash[dir].tuple.mtu + offset;
	if (unlikely(nf_flow_exceeds_mtu(skb, mtu)))
		return 0;

	iph = (struct iphdr *)(skb_network_header(skb) + offset);
	thoff = (iph->ihl * 4) + offset;
	if (nf_flow_state_check(flow, iph->protocol, skb, thoff))
		return 0;

	if (skb_try_make_writable(skb, thoff + hdrsize))
		return -1;
	
	memset(skb->cb, 0, sizeof(struct nft_bulk_cb));
	NFT_BULK_CB(skb)->tuplehash = tuplehash;

	dst = tuplehash->tuple.dst_cache;
	skb_dst_set_noref(skb, dst);

	flow_offload_refresh(flow_table, flow);

	nf_flow_encap_pop(skb, tuplehash);
	thoff -= offset;

	iph = ip_hdr(skb);
	nf_flow_nat_ip(flow, skb, thoff, dir, iph);

	ip_decrease_ttl(iph);
	skb->tstamp = 0;

	if (flow_table->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_update(flow->ct, tuplehash->tuple.dir, skb->len);

	return 1;
}

unsigned int
nf_flow_offload_ip_hook_list(void *priv, struct sk_buff *unused,
			const struct nf_hook_state *state)
{
	struct nf_flowtable *flow_table = priv;
		struct net_device *outdev;
	struct rtable *rt;
	__be32 nexthop;
	int ret, cpu;
	struct sk_buff *skb, *n;
	struct list_head bulk_list;
	struct list_head acc_list;
	struct list_head *bulk_head;
	struct list_head *head = state->skb_list;

	cpu = get_cpu();

	INIT_LIST_HEAD(&bulk_list);
	INIT_LIST_HEAD(&acc_list);

	bulk_head = per_cpu_ptr(flow_table->bulk_list, cpu);

	list_for_each_entry_safe(skb, n, head, list) {

		skb_list_del_init(skb);
		ret = __nf_flow_offload_ip_hook(priv, skb, state);
		if (ret == 0)
			list_add_tail(&skb->list, &acc_list);
		else if (ret == 1)
			list_add_tail(&skb->list, &bulk_list);
		/* ret == -1: Packet dropped! */
		else if (ret == -1)
			kfree_skb(skb);

	}

	list_splice_init(&acc_list, head);

	list_for_each_entry_safe(skb, n, &bulk_list, list) {
		skb_list_del_init(skb);
		nft_bulk_receive(bulk_head, skb);
	}

	list_for_each_entry_safe(skb, n, bulk_head, list) {

		list_del_init(&skb->list);

		skb->next = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;

		while (skb) {
			struct flow_offload_tuple_rhash *tuplehash;
			enum flow_offload_tuple_dir dir;
			struct flow_offload *flow;
			struct sk_buff *next;


			next = skb->next;
			skb_mark_not_on_list(skb);
			tuplehash = NFT_BULK_CB(skb)->tuplehash;

			switch (tuplehash->tuple.xmit_type) {
			case FLOW_OFFLOAD_XMIT_NEIGH:
				rt = (struct rtable *)skb_dst(skb);
				outdev = rt->dst.dev;
				skb->dev = outdev;
				nexthop = rt_nexthop(rt, ip_hdr(skb)->saddr);
				neigh_xmit(NEIGH_ARP_TABLE, outdev, &nexthop, skb);
				break;
			case FLOW_OFFLOAD_XMIT_DIRECT:
				dir = tuplehash->tuple.dir;
				flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
				ret = nf_flow_queue_xmit(state->net, skb, tuplehash, ETH_P_IP);
				if (ret == NF_DROP)
					flow_offload_teardown(flow);
				break;
			case FLOW_OFFLOAD_XMIT_XFRM:
				memset(skb->cb, 0, sizeof(struct inet_skb_parm));
				IPCB(skb)->iif = skb->dev->ifindex;
				IPCB(skb)->flags = IPSKB_FORWARDED;
				nf_flow_xmit_xfrm(skb, state, skb_dst(skb));
				break;
			}

			skb = next;
		}
	}

	put_cpu();

	BUG_ON(!list_empty(bulk_head));

	/* XXX: What to return here? */
	return NF_STOLEN;
}
EXPORT_SYMBOL_GPL(nf_flow_offload_ip_hook_list);


unsigned int
nf_flow_offload_ip_hook(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	enum flow_offload_tuple_dir dir;
	struct flow_offload *flow;
	struct net_device *outdev;
	struct rtable *rt;
	__be32 nexthop;
	int ret;

	ret = __nf_flow_offload_ip_hook(priv, skb, state);
	if (ret == 0)
		return NF_ACCEPT;	
	else if (ret == -1)
		return NF_DROP;	

	tuplehash = NFT_BULK_CB(skb)->tuplehash;

	if (unlikely(tuplehash->tuple.xmit_type == FLOW_OFFLOAD_XMIT_XFRM)) {
		rt = (struct rtable *)tuplehash->tuple.dst_cache;
		memset(skb->cb, 0, sizeof(struct inet_skb_parm));
		IPCB(skb)->iif = skb->dev->ifindex;
		IPCB(skb)->flags = IPSKB_FORWARDED;
		return nf_flow_xmit_xfrm(skb, state, &rt->dst);
	}

	switch (tuplehash->tuple.xmit_type) {
	case FLOW_OFFLOAD_XMIT_NEIGH:
		rt = (struct rtable *)tuplehash->tuple.dst_cache;
		outdev = rt->dst.dev;
		skb->dev = outdev;
		nexthop = rt_nexthop(rt, flow->tuplehash[!dir].tuple.src_v4.s_addr);
		skb_dst_set_noref(skb, &rt->dst);
		neigh_xmit(NEIGH_ARP_TABLE, outdev, &nexthop, skb);
		ret = NF_STOLEN;
		break;
	case FLOW_OFFLOAD_XMIT_DIRECT:
		ret = nf_flow_queue_xmit(state->net, skb, tuplehash, ETH_P_IP);
		if (ret == NF_DROP)
			flow_offload_teardown(flow);
		break;
	}

	return NF_ACCEPT;
}
EXPORT_SYMBOL_GPL(nf_flow_offload_ip_hook);

static void nf_flow_nat_ipv6_tcp(struct sk_buff *skb, unsigned int thoff,
				 struct in6_addr *addr,
				 struct in6_addr *new_addr,
				 struct ipv6hdr *ip6h)
{
	struct tcphdr *tcph;

	tcph = (void *)(skb_network_header(skb) + thoff);
	inet_proto_csum_replace16(&tcph->check, skb, addr->s6_addr32,
				  new_addr->s6_addr32, true);
}

static void nf_flow_nat_ipv6_udp(struct sk_buff *skb, unsigned int thoff,
				 struct in6_addr *addr,
				 struct in6_addr *new_addr)
{
	struct udphdr *udph;

	udph = (void *)(skb_network_header(skb) + thoff);
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace16(&udph->check, skb, addr->s6_addr32,
					  new_addr->s6_addr32, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}
}

static void nf_flow_nat_ipv6_l4proto(struct sk_buff *skb, struct ipv6hdr *ip6h,
				     unsigned int thoff, struct in6_addr *addr,
				     struct in6_addr *new_addr)
{
	switch (ip6h->nexthdr) {
	case IPPROTO_TCP:
		nf_flow_nat_ipv6_tcp(skb, thoff, addr, new_addr, ip6h);
		break;
	case IPPROTO_UDP:
		nf_flow_nat_ipv6_udp(skb, thoff, addr, new_addr);
		break;
	}
}

static void nf_flow_snat_ipv6(const struct flow_offload *flow,
			      struct sk_buff *skb, struct ipv6hdr *ip6h,
			      unsigned int thoff,
			      enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v6;
		ip6h->saddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v6;
		ip6h->daddr = new_addr;
		break;
	}

	nf_flow_nat_ipv6_l4proto(skb, ip6h, thoff, &addr, &new_addr);
}

static void nf_flow_dnat_ipv6(const struct flow_offload *flow,
			      struct sk_buff *skb, struct ipv6hdr *ip6h,
			      unsigned int thoff,
			      enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6;
		ip6h->daddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v6;
		ip6h->saddr = new_addr;
		break;
	}

	nf_flow_nat_ipv6_l4proto(skb, ip6h, thoff, &addr, &new_addr);
}

static void nf_flow_nat_ipv6(const struct flow_offload *flow,
			     struct sk_buff *skb,
			     enum flow_offload_tuple_dir dir,
			     struct ipv6hdr *ip6h)
{
	unsigned int thoff = sizeof(*ip6h);

	if (test_bit(NF_FLOW_SNAT, &flow->flags)) {
		nf_flow_snat_port(flow, skb, thoff, ip6h->nexthdr, dir);
		nf_flow_snat_ipv6(flow, skb, ip6h, thoff, dir);
	}
	if (test_bit(NF_FLOW_DNAT, &flow->flags)) {
		nf_flow_dnat_port(flow, skb, thoff, ip6h->nexthdr, dir);
		nf_flow_dnat_ipv6(flow, skb, ip6h, thoff, dir);
	}
}

static int nf_flow_tuple_ipv6(struct sk_buff *skb, const struct net_device *dev,
			      struct flow_offload_tuple *tuple, u32 *hdrsize,
			      u32 offset)
{
	struct flow_ports *ports;
	struct ipv6hdr *ip6h;
	unsigned int thoff;

	thoff = sizeof(*ip6h) + offset;
	if (!pskb_may_pull(skb, thoff))
		return -1;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);

	switch (ip6h->nexthdr) {
	case IPPROTO_TCP:
		*hdrsize = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		*hdrsize = sizeof(struct udphdr);
		break;
	default:
		return -1;
	}

	if (ip6h->hop_limit <= 1)
		return -1;

	if (!pskb_may_pull(skb, thoff + *hdrsize))
		return -1;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);
	ports = (struct flow_ports *)(skb_network_header(skb) + thoff);

	tuple->src_v6		= ip6h->saddr;
	tuple->dst_v6		= ip6h->daddr;
	tuple->src_port		= ports->source;
	tuple->dst_port		= ports->dest;
	tuple->l3proto		= AF_INET6;
	tuple->l4proto		= ip6h->nexthdr;
	tuple->iifidx		= dev->ifindex;
	nf_flow_tuple_encap(skb, tuple);

	return 0;
}

unsigned int
nf_flow_offload_ipv6_hook(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	struct flow_offload_tuple tuple = {};
	enum flow_offload_tuple_dir dir;
	const struct in6_addr *nexthop;
	struct flow_offload *flow;
	struct net_device *outdev;
	unsigned int thoff, mtu;
	u32 hdrsize, offset = 0;
	struct ipv6hdr *ip6h;
	struct rt6_info *rt;
	int ret;

	if (skb->protocol != htons(ETH_P_IPV6) &&
	    !nf_flow_skb_encap_protocol(skb, htons(ETH_P_IPV6), &offset))
		return NF_ACCEPT;

	if (nf_flow_tuple_ipv6(skb, state->in, &tuple, &hdrsize, offset) < 0)
		return NF_ACCEPT;

	tuplehash = flow_offload_lookup(flow_table, &tuple);
	if (tuplehash == NULL)
		return NF_ACCEPT;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	mtu = flow->tuplehash[dir].tuple.mtu + offset;
	if (unlikely(nf_flow_exceeds_mtu(skb, mtu)))
		return NF_ACCEPT;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);
	thoff = sizeof(*ip6h) + offset;
	if (nf_flow_state_check(flow, ip6h->nexthdr, skb, thoff))
		return NF_ACCEPT;

	if (skb_try_make_writable(skb, thoff + hdrsize))
		return NF_DROP;

	flow_offload_refresh(flow_table, flow);

	nf_flow_encap_pop(skb, tuplehash);

	ip6h = ipv6_hdr(skb);
	nf_flow_nat_ipv6(flow, skb, dir, ip6h);

	ip6h->hop_limit--;
	skb->tstamp = 0;

	if (flow_table->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_update(flow->ct, tuplehash->tuple.dir, skb->len);

	if (unlikely(tuplehash->tuple.xmit_type == FLOW_OFFLOAD_XMIT_XFRM)) {
		rt = (struct rt6_info *)tuplehash->tuple.dst_cache;
		memset(skb->cb, 0, sizeof(struct inet6_skb_parm));
		IP6CB(skb)->iif = skb->dev->ifindex;
		IP6CB(skb)->flags = IP6SKB_FORWARDED;
		return nf_flow_xmit_xfrm(skb, state, &rt->dst);
	}

	switch (tuplehash->tuple.xmit_type) {
	case FLOW_OFFLOAD_XMIT_NEIGH:
		rt = (struct rt6_info *)tuplehash->tuple.dst_cache;
		outdev = rt->dst.dev;
		skb->dev = outdev;
		nexthop = rt6_nexthop(rt, &flow->tuplehash[!dir].tuple.src_v6);
		skb_dst_set_noref(skb, &rt->dst);
		neigh_xmit(NEIGH_ND_TABLE, outdev, nexthop, skb);
		ret = NF_STOLEN;
		break;
	case FLOW_OFFLOAD_XMIT_DIRECT:
		ret = nf_flow_queue_xmit(state->net, skb, tuplehash, ETH_P_IPV6);
		if (ret == NF_DROP)
			flow_offload_teardown(flow);
		break;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(nf_flow_offload_ipv6_hook);
