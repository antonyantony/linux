/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the "esp_ping" module.
 */
#ifndef _ESP_PING_H
#define _ESP_PING_H

#include <net/netns/hash.h>

struct xfrm_state;
struct esp_echo_hdr;

/* ESP_PING_HTABLE_SIZE must be power of 2 */
#define ESP_PING_HTABLE_SIZE	64
#define ESP_PING_HTABLE_MASK	(ESP_PING_HTABLE_SIZE-1)

#define GID_T_MAX (((gid_t)~0U) - 1)

/* Compatibility glue so we can support IPv6 when it's compiled as a module */
struct esp_pingv6_ops {
	void (*ip6_datagram_recv_common_ctl)(struct sock *sk,
					     struct msghdr *msg,
					     struct sk_buff *skb);
	void (*ip6_datagram_recv_specific_ctl)(struct sock *sk,
					       struct msghdr *msg,
					       struct sk_buff *skb);
	int (*ipv6_chk_addr)(struct net *net, const struct in6_addr *addr,
			     const struct net_device *dev, int strict);
};

struct esp_ping_sock {
	__be32   spi_out;      /* 0 = use SPD; non-zero = pinned SA SPI */

	/* Receive-only listener (responder/monitor): gets inbound
	 * echo-request fan-out. Set via IP_ESP_PING_LISTEN; independent of
	 * spi_out.
	 *   n_listen_spi <  0: not a listener (default)
	 *   n_listen_spi == 0: listener, no filter — receives all SAs
	 *   n_listen_spi >  0: listener, filtered to listen_spi[] only
	 */
	__be32  *listen_spi;
	int      n_listen_spi;
};

static inline struct esp_ping_sock *esp_ping_sk(const struct sock *sk)
{
	return (struct esp_ping_sock *)sk->sk_user_data;
}

struct esp_ping_skb_cb {
	__be32  spi;   /* SPI of the decrypting SA */
};
#define ESP_PING_SKB_CB(skb) ((struct esp_ping_skb_cb *)((skb)->cb))

struct esp_ping_iter_state {
	struct seq_net_private  p;
	int			bucket;
	sa_family_t		family;
};

extern struct proto esp_ping_prot;
#if IS_ENABLED(CONFIG_IPV6)
extern struct esp_pingv6_ops esp_pingv6_ops;
extern struct proto esp_ping_v6_prot;
#endif

int  esp_ping_get_port(struct sock *sk, unsigned short ident);
int esp_ping_hash(struct sock *sk);
void esp_ping_unhash(struct sock *sk);

int  esp_ping_init_sock(struct sock *sk);
void esp_ping_close(struct sock *sk, long timeout);
int  esp_ping_bind(struct sock *sk, struct sockaddr_unsized *uaddr, int addr_len);
int  esp_ping_common_sendmsg(struct msghdr *msg, size_t len,
			     struct esp_echo_hdr *user_hdr, __be32 *send_spi);
int  esp_ping_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		      int flags);
int  esp_ping_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);
enum skb_drop_reason esp_ping_rcv(struct sk_buff *skb);
void esp_ping_plain_rcv(struct sk_buff *skb);
bool esp_recv(struct sk_buff *skb, __be32 spi);
void esp_ping_deliver_request(struct net *net, struct xfrm_state *x,
			      struct sk_buff *skb);
void esp_ping_deliver_response(struct net *net, struct xfrm_state *x,
			       struct sk_buff *skb);

#ifdef CONFIG_PROC_FS
void *esp_ping_seq_start(struct seq_file *seq, loff_t *pos, sa_family_t family);
void *esp_ping_seq_next(struct seq_file *seq, void *v, loff_t *pos);
void esp_ping_seq_stop(struct seq_file *seq, void *v);

int __init esp_ping_proc_init(void);
void esp_ping_proc_exit(void);
#endif

void __init esp_ping_init(void);
int  __init esp_pingv6_init(void);
void esp_pingv6_exit(void);

#endif /* _ESP_PING_H */
