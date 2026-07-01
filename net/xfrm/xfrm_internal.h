/* SPDX-License-Identifier: GPL-2.0 */
/* Internal helpers shared within net/xfrm/ — not for use outside. */
#ifndef _NET_XFRM_INTERNAL_H
#define _NET_XFRM_INTERNAL_H

#include <net/xfrm.h>

struct xfrm_dst *xfrm_alloc_dst(struct net *net, int family);
void xfrm_init_path(struct xfrm_dst *path, struct dst_entry *dst,
		    int nfheader_len);
int xfrm_fill_dst(struct xfrm_dst *xdst, struct net_device *dev,
		  const struct flowi *fl);

#endif /* _NET_XFRM_INTERNAL_H */
