// SPDX-License-Identifier: GPL-2.0
/*
 * XFRM helpers for encrypted ESP ping (draft-ietf-ipsecme-encrypted-esp-ping).
 *
 * Builds a 1-SA xfrm_dst from a pinned XFRM state and a plain route,
 * bypassing the SPD.  Used by esp_ping_v4_sendmsg() when IP_ESP_PING_SPI
 * pins a specific SA and no policy covers the gateway-to-gateway flow.
 */

#include <linux/kernel.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/xfrm.h>
#include "xfrm_internal.h"

/**
 * xfrm_dst_create_for_state() - build a 1-SA xfrm_dst from a pinned state
 *     and a plain (non-XFRM) route, without consulting the SPD.
 *
 * @net: network namespace
 * @x:   XFRM state; caller's reference is transferred to the dst on success
 * @rt:  plain rtable to the SA peer; dst reference is stolen on success
 * @fl:  flow key for xfrm_fill_dst() AF-specific initialisation
 *
 * Returns the new dst_entry (refcount 1) or ERR_PTR.  On error the caller
 * must release @x and @rt itself.
 */
struct dst_entry *
xfrm_dst_create_for_state(struct net *net, struct xfrm_state *x,
			  struct rtable *rt, const struct flowi *fl)
{
	const struct xfrm_state_afinfo *afinfo;
	struct dst_entry *inner = &rt->dst;
	struct dst_entry *dst1;
	struct xfrm_dst *xdst;
	int err;

	xdst = xfrm_alloc_dst(net, x->props.family);
	if (IS_ERR(xdst))
		return ERR_CAST(xdst);
	dst1 = &xdst->u.dst;

	/* route: one ref stolen from rt; released by xfrm_dst_destroy() */
	dst_hold(inner);
	xdst->route = inner;
	dst_copy_metrics(dst1, inner);

	/* child/path: second ref; consumed by dst_clone() in skb_dst_pop() */
	dst_hold(inner);
	xfrm_dst_set_child(xdst, inner);
	xdst->path = inner;

	dst1->xfrm = x;		/* ref transferred from caller */
	xdst->xfrm_genid = x->genid;
	dst1->obsolete = DST_OBSOLETE_FORCE_CHK;
	dst1->lastuse  = jiffies;
	dst1->input    = dst_discard;

	if (x->mode_cbs && x->mode_cbs->output) {
		dst1->output = x->mode_cbs->output;
	} else {
		rcu_read_lock();
		afinfo = xfrm_state_afinfo_get_rcu(x->inner_mode.family);
		dst1->output = likely(afinfo) ? afinfo->output : dst_discard_out;
		rcu_read_unlock();
	}

	dst1->header_len  = x->props.header_len;
	dst1->trailer_len = x->props.trailer_len;

	xfrm_init_path(xdst, inner, 0);

	err = -ENODEV;
	if (!inner->dev)
		goto free_dst;

	err = xfrm_fill_dst(xdst, inner->dev, fl);
	if (err)
		goto free_dst;

	return dst1;

free_dst:
	dst1->xfrm = NULL;	/* prevent xfrm_dst_destroy() double-put */
	xfrm_state_put(x);
	dst_release(dst1);	/* drops route + child refs via destroy */
	return ERR_PTR(err);
}
EXPORT_SYMBOL(xfrm_dst_create_for_state);
