/*
 * Extend ipv6 fragment function
 */

#ifndef _EX_IPV6_FRAGMENT_H
#define _EX_IPV6_FRAGMENT_H

#define EX_FRAG_ERR 0

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0))
#define DST_NOPEER 0x0040
static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}
#endif

extern int ex_ip6_fragment(struct sk_buff *,
			int (*)(struct sk_buff *), unsigned int);
extern int ex_ipv6_frag_rcv(struct sk_buff *);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
extern struct sk_buff *ex_ndisc_build_skb(struct net_device *dev,
                                const struct in6_addr *daddr,
                                const struct in6_addr *saddr,
                                struct icmp6hdr *icmp6h,
                                const struct in6_addr *target,
                                int llinfo);
#endif
#endif /* _EX_IPV6_FRAGMENT_H */
