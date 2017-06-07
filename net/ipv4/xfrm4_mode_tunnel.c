/*
 * xfrm4_mode_tunnel.c - Tunnel mode encapsulation for IPv4.
 *
 * Copyright (c) 2004-2006 Herbert Xu <herbert@gondor.apana.org.au>
 */

#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/stringify.h>
#include <net/dst.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/xfrm.h>

static inline void ipip_ecn_decapsulate(struct sk_buff *skb)
{
	struct iphdr *inner_iph = ipip_hdr(skb);

	if (INET_ECN_is_ce(XFRM_MODE_SKB_CB(skb)->tos))
		IP_ECN_set_ce(inner_iph);
}

/* AA_217_05 DEBUG stuff remove it */
static unsigned int xfrmaddr_to_sockaddr(const xfrm_address_t *xa, __be16 port,
                unsigned short family, struct sockaddr *sa)
{
        switch (family) {
        case AF_INET:
                {
                        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
                        sin->sin_family = AF_INET;
                        sin->sin_port = port;
                        sin->sin_addr.s_addr = xa->a4;
                        memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
                        return 32;
                }
#if IS_ENABLED(CONFIG_IPV6)
        case AF_INET6:
                {
                        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
                        sin6->sin6_family = AF_INET6;
                        sin6->sin6_port = port;
                        sin6->sin6_flowinfo = 0;
                        sin6->sin6_addr = xa->in6;
                        sin6->sin6_scope_id = 0;
                        return 128;
                }
#endif
        }
        return 0;
}

static void cat_dbug(struct xfrm_state *x,  bool dir_in)
{
	struct sockaddr caddr;
	struct sockaddr daddr;

	xfrmaddr_to_sockaddr(&x->id.daddr,  0, AF_INET, &daddr);

	if (x->print_cat == 0) { //print only once per flow. Only the first packet
		x->print_cat = 1;
		if (x->caddr == NULL)  {
			printk("AA_2017_05 caddr is NULL for this state %pISc dir %s", &daddr, dir_in ? "in" : "out");
		}  else  {
			xfrmaddr_to_sockaddr(x->caddr,  0, AF_INET, &caddr);
			printk("AA_2017_05 flow caddr %pISc %pISc dir %s", &caddr,
					&daddr, dir_in ? "in" : "out");
		}
	}
}

static void cat_translate_dbug(struct xfrm_state *x,
		xfrm_address_t *caddr, struct iphdr *iph, struct
		iphdr *iphb, bool dir_in,  __sum16 check_b,  __sum16 check_a)
{
	struct sockaddr s_caddr;
	struct sockaddr s_baddr;
	struct sockaddr s_paddr;
	xfrm_address_t paddr;
	xfrm_address_t baddr;


	// if (x->print_cat == 0 || x->print_cat == 1) { // only once fist  packet
		/* for tcp/udp checksum debugging you need to print for every packet */
		x->print_cat++;
		if (dir_in) {
			paddr.a4 = iph->daddr;
			baddr.a4 = iphb->daddr;
		} else {
			paddr.a4 = iph->saddr;
			baddr.a4 = iphb->saddr;
		}

		xfrmaddr_to_sockaddr(caddr,  0, AF_INET, &s_caddr);
		xfrmaddr_to_sockaddr(&paddr,  0, AF_INET, &s_paddr);
		xfrmaddr_to_sockaddr(&baddr,  0, AF_INET, &s_baddr);

		printk("AA_2017_05 packet caddr %pISc paddr %pISc baddr %pISc dir %s %04x %04x other order %04x %04x",
				&s_caddr, &s_paddr, &s_baddr,
				dir_in ? "in" : "out",
				check_b, check_a, ntohs(check_b), ntohs(check_a));
	//}
}

static void xfrm_cat_manip_pkt(struct xfrm_state *x, /* only for debug */
		struct sk_buff
		*skb, xfrm_address_t *caddr,
		bool dir_in)
{
	struct iphdr *iph;
	struct iphdr baddr;
	__sum16 check_b;
	__sum16 check_a;

	if (dir_in) {
		iph  = ipip_hdr(skb);
		baddr = *iph;
		iph->daddr = caddr->a4;
	} else {
		iph  = ip_hdr(skb);
		baddr = *iph;
		iph->saddr = caddr->a4;
	}

	check_b = iph->check;

	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	check_a = iph->check;

	cat_translate_dbug(x, caddr, iph, &baddr, dir_in, check_b, check_a);
}

/* Add encapsulation header.
 *
 * The top IP header will be constructed per RFC 2401.
 */
static int xfrm4_mode_tunnel_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct iphdr *top_iph;
	int flags;

	cat_dbug(x, false);
	if (x->caddr != NULL)
		xfrm_cat_manip_pkt(x, skb, x->caddr, false);

	skb_set_inner_network_header(skb, skb_network_offset(skb));
	skb_set_inner_transport_header(skb, skb_transport_offset(skb));

	skb_set_network_header(skb, -x->props.header_len);
	skb->mac_header = skb->network_header +
			  offsetof(struct iphdr, protocol);
	skb->transport_header = skb->network_header + sizeof(*top_iph);
	top_iph = ip_hdr(skb);

	top_iph->ihl = 5;
	top_iph->version = 4;

	top_iph->protocol = xfrm_af2proto(skb_dst(skb)->ops->family);

	/* DS disclosing depends on XFRM_SA_XFLAG_DONT_ENCAP_DSCP */
	if (x->props.extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)
		top_iph->tos = 0;
	else
		top_iph->tos = XFRM_MODE_SKB_CB(skb)->tos;
	top_iph->tos = INET_ECN_encapsulate(top_iph->tos,
					    XFRM_MODE_SKB_CB(skb)->tos);

	flags = x->props.flags;
	if (flags & XFRM_STATE_NOECN)
		IP_ECN_clear(top_iph);

	top_iph->frag_off = (flags & XFRM_STATE_NOPMTUDISC) ?
		0 : (XFRM_MODE_SKB_CB(skb)->frag_off & htons(IP_DF));

	top_iph->ttl = ip4_dst_hoplimit(dst->child);

	top_iph->saddr = x->props.saddr.a4;
	top_iph->daddr = x->id.daddr.a4;
	ip_select_ident(dev_net(dst->dev), skb, NULL);

	return 0;
}

static int xfrm4_mode_tunnel_input(struct xfrm_state *x, struct sk_buff *skb)
{
	int err = -EINVAL;

	if (XFRM_MODE_SKB_CB(skb)->protocol != IPPROTO_IPIP)
		goto out;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto out;

	err = skb_unclone(skb, GFP_ATOMIC);
	if (err)
		goto out;

	if (x->props.flags & XFRM_STATE_DECAP_DSCP)
		ipv4_copy_dscp(XFRM_MODE_SKB_CB(skb)->tos, ipip_hdr(skb));
	if (!(x->props.flags & XFRM_STATE_NOECN))
		ipip_ecn_decapsulate(skb);

	cat_dbug(x, true);
	if (x->caddr != NULL)
		xfrm_cat_manip_pkt(x, skb, x->caddr, true /* daddr */);

	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);

	err = 0;

out:
	return err;
}

static struct sk_buff *xfrm4_mode_tunnel_gso_segment(struct xfrm_state *x,
						     struct sk_buff *skb,
						     netdev_features_t features)
{
	__skb_push(skb, skb->mac_len);
	return skb_mac_gso_segment(skb, features);

}

static void xfrm4_mode_tunnel_xmit(struct xfrm_state *x, struct sk_buff *skb)
{
	struct xfrm_offload *xo = xfrm_offload(skb);

	if (xo->flags & XFRM_GSO_SEGMENT) {
		skb->network_header = skb->network_header - x->props.header_len;
		skb->transport_header = skb->network_header +
					sizeof(struct iphdr);
	}

	skb_reset_mac_len(skb);
	pskb_pull(skb, skb->mac_len + x->props.header_len);
}

static struct xfrm_mode xfrm4_tunnel_mode = {
	.input2 = xfrm4_mode_tunnel_input,
	.input = xfrm_prepare_input,
	.output2 = xfrm4_mode_tunnel_output,
	.output = xfrm4_prepare_output,
	.gso_segment = xfrm4_mode_tunnel_gso_segment,
	.xmit = xfrm4_mode_tunnel_xmit,
	.owner = THIS_MODULE,
	.encap = XFRM_MODE_TUNNEL,
	.flags = XFRM_MODE_FLAG_TUNNEL,
};

static int __init xfrm4_mode_tunnel_init(void)
{
	return xfrm_register_mode(&xfrm4_tunnel_mode, AF_INET);
}

static void __exit xfrm4_mode_tunnel_exit(void)
{
	int err;

	err = xfrm_unregister_mode(&xfrm4_tunnel_mode, AF_INET);
	BUG_ON(err);
}

module_init(xfrm4_mode_tunnel_init);
module_exit(xfrm4_mode_tunnel_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS_XFRM_MODE(AF_INET, XFRM_MODE_TUNNEL);
