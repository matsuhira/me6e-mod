/*
 * Extend ipv6 fragment function
 */

#include <linux/module.h>
#include <linux/version.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ip.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
#include <net/inet_ecn.h>
#endif
#include "ex_ipv6_fragment.h"

MODULE_DESCRIPTION("extend ipv6 fragment function");
MODULE_LICENSE("GPL");

struct ip6frag_skb_cb {
	struct inet6_skb_parm	h;
	int			offset;
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0))
struct ctl_path net_ipv6_ctl_path[] = {
	{ .procname = "net", },
	{ .procname = "ipv6", },
	{ },
};
#endif


#define FRAG6_CB(skb)	((struct ip6frag_skb_cb *)((skb)->cb))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
/*
 *	Equivalent of ipv4 struct ipq
 */

struct frag_queue {
	struct inet_frag_queue	q;

	__be32			id;		/* fragment id		*/
	u32			user;
	struct in6_addr		saddr;
	struct in6_addr		daddr;

	int			iif;
	unsigned int		csum;
	__u16			nhoffset;
};
#endif

static struct inet_frags ip6_frags;

static int ip6_frag_reasm(struct frag_queue *fq, struct sk_buff *prev,
			  struct net_device *dev);

/*
 * callers should be careful not to use the hash value outside the ipfrag_lock
 * as doing so could race with ipfrag_hash_rnd being recalculated.
 */
static unsigned int ex_inet6_hash_frag(__be32 id, const struct in6_addr *saddr,
                             const struct in6_addr *daddr, u32 rnd)
{
	u32 c;

	c = jhash_3words((__force u32)saddr->s6_addr32[0],
			 (__force u32)saddr->s6_addr32[1],
			 (__force u32)saddr->s6_addr32[2],
			 rnd);

	c = jhash_3words((__force u32)saddr->s6_addr32[3],
			 (__force u32)daddr->s6_addr32[0],
			 (__force u32)daddr->s6_addr32[1],
			 c);

	c =  jhash_3words((__force u32)daddr->s6_addr32[2],
			 (__force u32)daddr->s6_addr32[3],
			 (__force u32)id,
			 c);

	return c & (INETFRAGS_HASHSZ - 1);
}

static unsigned int ip6_hashfn(struct inet_frag_queue *q)
{
	struct frag_queue *fq;

	fq = container_of(q, struct frag_queue, q);
	return ex_inet6_hash_frag(fq->id, &fq->saddr, &fq->daddr, ip6_frags.rnd);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 4, 0))
static bool ex_ip6_frag_match(struct inet_frag_queue *q, void *a)
#else
static int ex_ip6_frag_match(struct inet_frag_queue *q, void *a)
#endif
{
	struct frag_queue *fq;
	struct ip6_create_arg *arg = a;

	fq = container_of(q, struct frag_queue, q);
	return  fq->id == arg->id &&
		fq->user == arg->user &&
		ipv6_addr_equal(&fq->saddr, arg->src) &&
		ipv6_addr_equal(&fq->daddr, arg->dst);
}

static void ex_ip6_frag_init(struct inet_frag_queue *q, void *a)
{
	struct frag_queue *fq = container_of(q, struct frag_queue, q);
	struct ip6_create_arg *arg = a;

	fq->id = arg->id;
	fq->user = arg->user;
	fq->saddr = *arg->src;
	fq->daddr = *arg->dst;
}

/* Destruction primitives. */
static __inline__ void fq_put(struct frag_queue *fq)
{
	inet_frag_put(&fq->q, &ip6_frags);
}

/* Kill fq entry. It is not destroyed immediately,
 * because caller (and someone more) holds reference count.
 */
static __inline__ void fq_kill(struct frag_queue *fq)
{
	inet_frag_kill(&fq->q, &ip6_frags);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
static void ip6_evictor(struct net *net, struct inet6_dev *idev)
{
	int evicted;

	evicted = inet_frag_evictor(&net->ipv6.frags, &ip6_frags);
	if (evicted)
		IP6_ADD_STATS_BH(net, idev, IPSTATS_MIB_REASMFAILS, evicted);
}
#endif

static void ip6_frag_expire(unsigned long data)
{
	struct frag_queue *fq;
	struct net_device *dev = NULL;
	struct net *net;

	fq = container_of((struct inet_frag_queue *)data, struct frag_queue, q);

	spin_lock(&fq->q.lock);

	if (fq->q.last_in & INET_FRAG_COMPLETE)
		goto out;

	fq_kill(fq);

	net = container_of(fq->q.net, struct net, ipv6.frags);
	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, fq->iif);
	if (!dev)
		goto out_rcu_unlock;

	IP6_INC_STATS_BH(net, __in6_dev_get(dev), IPSTATS_MIB_REASMTIMEOUT);
	IP6_INC_STATS_BH(net, __in6_dev_get(dev), IPSTATS_MIB_REASMFAILS);

	/* Don't send error if the first segment did not arrive. */
	if (!(fq->q.last_in & INET_FRAG_FIRST_IN) || !fq->q.fragments)
		goto out_rcu_unlock;

	/*
	   But use as source device on which LAST ARRIVED
	   segment was received. And do not use fq->dev
	   pointer directly, device might already disappeared.
	 */
	fq->q.fragments->dev = dev;
	/* send to src frag expire info */
	/* icmpv6_send(fq->q.fragments, ICMPV6_TIME_EXCEED,
	 *		ICMPV6_EXC_FRAGTIME, 0);
	 */
out_rcu_unlock:
	rcu_read_unlock();
out:
	spin_unlock(&fq->q.lock);
	fq_put(fq);
}

static __inline__ struct frag_queue *
fq_find(struct net *net, __be32 id, const struct in6_addr *src,
					const struct in6_addr *dst)
{
	struct inet_frag_queue *q;
	struct ip6_create_arg arg;
	unsigned int hash;

	arg.id = id;
	arg.user = IP6_DEFRAG_LOCAL_DELIVER;
	arg.src = src;
	arg.dst = dst;

	read_lock(&ip6_frags.lock);
	hash = ex_inet6_hash_frag(id, src, dst, ip6_frags.rnd);

	q = inet_frag_find(&net->ipv6.frags, &ip6_frags, &arg, hash);
	if (q == NULL)
		return NULL;

	return container_of(q, struct frag_queue, q);
}

static void sae6_icmpv6_param_prob(struct sk_buff *skb, u8 code, int pos)
{
	icmpv6_send(skb, ICMPV6_PARAMPROB, code, pos);
	kfree_skb(skb);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
static inline u8 ip6_frag_ecn(const struct ipv6hdr *ipv6h)
{
        return 1 << (ipv6_get_dsfield(ipv6h) & INET_ECN_MASK);
}
#endif

static int ip6_frag_queue(struct frag_queue *fq, struct sk_buff *skb,
			   struct frag_hdr *fhdr, int nhoff)
{
	struct sk_buff *prev, *next;
	struct net_device *dev;
	int offset, end;
	struct net *net = dev_net(skb_dst(skb)->dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
    u8 ecn;
#endif

	if (fq->q.last_in & INET_FRAG_COMPLETE)
		goto err;

	offset = ntohs(fhdr->frag_off) & ~0x7;
	end = offset + (ntohs(ipv6_hdr(skb)->payload_len) -
			((u8 *)(fhdr + 1) - (u8 *)(ipv6_hdr(skb) + 1)));

	if ((unsigned int)end > IPV6_MAXPLEN) {
		IP6_INC_STATS_BH(net, ip6_dst_idev(skb_dst(skb)),
				 IPSTATS_MIB_INHDRERRORS);
		sae6_icmpv6_param_prob(skb, ICMPV6_HDR_FIELD,
				  ((u8 *)&fhdr->frag_off -
				   skb_network_header(skb)));
		return -1;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
    ecn = ip6_frag_ecn(ipv6_hdr(skb));
#endif

	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		const unsigned char *nh = skb_network_header(skb);
		skb->csum = csum_sub(skb->csum,
				     csum_partial(nh, (u8 *)(fhdr + 1) - nh,
						  0));
	}

	/* Is this the final fragment? */
	if (!(fhdr->frag_off & htons(IP6_MF))) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrupted.
		 */
		if (end < fq->q.len ||
		    ((fq->q.last_in & INET_FRAG_LAST_IN) && end != fq->q.len))
			goto err;
		fq->q.last_in |= INET_FRAG_LAST_IN;
		fq->q.len = end;
	} else {
		/* Check if the fragment is rounded to 8 bytes.
		 * Required by the RFC.
		 */
		if (end & 0x7) {
			/* RFC2460 says always send parameter problem in
			 * this case. -DaveM
			 */
			IP6_INC_STATS_BH(net, ip6_dst_idev(skb_dst(skb)),
					 IPSTATS_MIB_INHDRERRORS);
			sae6_icmpv6_param_prob(skb, ICMPV6_HDR_FIELD,
				offsetof(struct ipv6hdr, payload_len));
			return -1;
		}
		if (end > fq->q.len) {
			/* Some bits beyond end -> corruption. */
			if (fq->q.last_in & INET_FRAG_LAST_IN)
				goto err;
			fq->q.len = end;
		}
	}

	if (end == offset)
		goto err;

	/* Point into the IP datagram 'data' part. */
	if (!pskb_pull(skb, (u8 *) (fhdr + 1) - skb->data))
		goto err;

	if (pskb_trim_rcsum(skb, end - offset))
		goto err;

	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment, right?
	 */
	prev = fq->q.fragments_tail;
	if (!prev || FRAG6_CB(prev)->offset < offset) {
		next = NULL;
		goto found;
	}
	prev = NULL;
	for (next = fq->q.fragments; next != NULL; next = next->next) {
		if (FRAG6_CB(next)->offset >= offset)
			break;	/* bingo! */
		prev = next;
	}

found:
	/* RFC5722, Section 4, amended by Errata ID : 3089
	 *                          When reassembling an IPv6 datagram, if
	 *   one or more its constituent fragments is determined to be an
	 *   overlapping fragment, the entire datagram (and any constituent
	 *   fragments) MUST be silently discarded.
	 */

	/* Check for overlap with preceding fragment. */
	if (prev &&
	    (FRAG6_CB(prev)->offset + prev->len) > offset)
		goto discard_fq;

	/* Look for overlap with succeeding segment. */
	if (next && FRAG6_CB(next)->offset < end)
		goto discard_fq;

	FRAG6_CB(skb)->offset = offset;

	/* Insert this fragment in the chain of fragments. */
	skb->next = next;
	if (!next)
		fq->q.fragments_tail = skb;
	if (prev)
		prev->next = skb;
	else
		fq->q.fragments = skb;

	dev = skb->dev;
	if (dev) {
		fq->iif = dev->ifindex;
		skb->dev = NULL;
	}
	fq->q.stamp = skb->tstamp;
	fq->q.meat += skb->len;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
	atomic_add(skb->truesize, &fq->q.net->mem);
#else
	fq->ecn |= ecn;
        add_frag_mem_limit(&fq->q, skb->truesize);
#endif // atomic_add -> add_frag_mem_limit

	/* The first fragment.
	 * nhoffset is obtained from the first fragment, of course.
	 */
	if (offset == 0) {
		fq->nhoffset = nhoff;
		fq->q.last_in |= INET_FRAG_FIRST_IN;
	}

	if (fq->q.last_in == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    fq->q.meat == fq->q.len)
		return ip6_frag_reasm(fq, prev, dev);

	write_lock(&ip6_frags.lock);
	list_move_tail(&fq->q.lru_list, &fq->q.net->lru_list);
	write_unlock(&ip6_frags.lock);
	return -1;

discard_fq:
	fq_kill(fq);
err:
	IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
		      IPSTATS_MIB_REASMFAILS);
	kfree_skb(skb);
	return -1;
}

/*
 *	Check if this packet is complete.
 *	Returns NULL on failure by any reason, and pointer
 *	to current nexthdr field in reassembled frame.
 *
 *	It is called with locked fq, and caller must check that
 *	queue is eligible for reassembly i.e. it is not COMPLETE,
 *	the last and the first frames arrived and all the bits are here.
 */
static int ip6_frag_reasm(struct frag_queue *fq, struct sk_buff *prev,
			  struct net_device *dev)
{
	struct net *net = container_of(fq->q.net, struct net, ipv6.frags);
	struct sk_buff *fp, *head = fq->q.fragments;
	int    payload_len;
	unsigned int nhoff;
	int sum_truesize;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
    u8 ecn;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	inet_frag_kill(&fq->q, &ip6_frags);

    ecn = ip_frag_ecn_table[fq->ecn];
    if (unlikely(ecn == 0xff))
        goto out_fail;
#else
	fq_kill(fq);
#endif

	/* Make the one we just received the head. */
	if (prev) {
		head = prev->next;
		fp = skb_clone(head, GFP_ATOMIC);

		if (!fp)
			goto out_fail;

		fp->next = head->next;
		if (!fp->next)
			fq->q.fragments_tail = fp;
		prev->next = fp;

		skb_morph(head, fq->q.fragments);
		head->next = fq->q.fragments->next;

		consume_skb(fq->q.fragments);
		fq->q.fragments = head;
	}

	WARN_ON(head == NULL);
	WARN_ON(FRAG6_CB(head)->offset != 0);

	/* Unfragmented part is taken from the first segment. */
	payload_len = ((head->data - skb_network_header(head)) -
		       sizeof(struct ipv6hdr) + fq->q.len -
		       sizeof(struct frag_hdr));
	if (payload_len > IPV6_MAXPLEN)
		goto out_fail;

	/* Head of list must not be cloned. */
	if (skb_cloned(head) && pskb_expand_head(head, 0, 0, GFP_ATOMIC))
		goto out_fail;

	/* If the first fragment is fragmented itself, we split
	 * it to two chunks: the first with data and paged part
	 * and the second, holding only fragments. */
	if (skb_has_frag_list(head)) {
		struct sk_buff *clone;
		int i, plen = 0;

		clone = alloc_skb(0, GFP_ATOMIC);
		if (clone == NULL)
			goto out_fail;
		clone->next = head->next;
		head->next = clone;
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;
		skb_frag_list_init(head);
		for (i = 0; i < skb_shinfo(head)->nr_frags; i++)
			plen += skb_frag_size(&skb_shinfo(head)->frags[i]);
		clone->len = clone->data_len = head->data_len - plen;
		head->data_len -= clone->len;
		head->len -= clone->len;
		clone->csum = 0;
		clone->ip_summed = head->ip_summed;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
		add_frag_mem_limit(&fq->q, clone->truesize);
#else
		atomic_add(clone->truesize, &fq->q.net->mem);
#endif
	}

	/* We have to remove fragment header from datagram and to relocate
	 * header in order to calculate ICV correctly. */
	nhoff = fq->nhoffset;
	skb_network_header(head)[nhoff] = skb_transport_header(head)[0];
	memmove(head->head + sizeof(struct frag_hdr), head->head,
		(head->data - head->head) - sizeof(struct frag_hdr));
	head->mac_header += sizeof(struct frag_hdr);
	head->network_header += sizeof(struct frag_hdr);

	skb_reset_transport_header(head);
	skb_push(head, head->data - skb_network_header(head));

	sum_truesize = head->truesize;
	for (fp = head->next; fp;) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 4, 0))
		bool headstolen;
		int delta;
#endif
		struct sk_buff *next = fp->next;

		sum_truesize += fp->truesize;
		if (head->ip_summed != fp->ip_summed)
			head->ip_summed = CHECKSUM_NONE;
		else if (head->ip_summed == CHECKSUM_COMPLETE)
			head->csum = csum_add(head->csum, fp->csum);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 4, 0))
		if (skb_try_coalesce(head, fp, &headstolen, &delta)) {
			kfree_skb_partial(fp, headstolen);
		} else {
			if (!skb_shinfo(head)->frag_list)
				skb_shinfo(head)->frag_list = fp;
			head->data_len += fp->len;
			head->len += fp->len;
			head->truesize += fp->truesize;
		}
#else
		if (!skb_shinfo(head)->frag_list)
			skb_shinfo(head)->frag_list = fp;
		head->data_len += fp->len;
		head->len += fp->len;
		head->truesize += fp->truesize;
#endif
		fp = next;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	sub_frag_mem_limit(&fq->q, sum_truesize);
#else
	atomic_sub(sum_truesize, &fq->q.net->mem);
#endif

	head->next = NULL;
	head->dev = dev;
	head->tstamp = fq->q.stamp;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	ipv6_change_dsfield(ipv6_hdr(head), 0xff, ecn);
#endif
	ipv6_hdr(head)->payload_len = htons(payload_len);
	IP6CB(head)->nhoff = nhoff;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	IP6CB(head)->flags |= IP6SKB_FRAGMENTED;
#endif

	/* Yes, and fold redundant checksum back. 8) */
	if (head->ip_summed == CHECKSUM_COMPLETE)
		head->csum = csum_partial(skb_network_header(head),
					  skb_network_header_len(head),
					  head->csum);

	rcu_read_lock();
	IP6_INC_STATS_BH(net, __in6_dev_get(dev), IPSTATS_MIB_REASMOKS);
	rcu_read_unlock();
	fq->q.fragments = NULL;
	fq->q.fragments_tail = NULL;
	return 1;

out_fail:
	rcu_read_lock();
	IP6_INC_STATS_BH(net, __in6_dev_get(dev), IPSTATS_MIB_REASMFAILS);
	rcu_read_unlock();
	return -1;
}

int ex_ipv6_frag_rcv(struct sk_buff *skb)
{
	struct frag_hdr *fhdr;
	struct frag_queue *fq;
	const struct ipv6hdr *hdr = ipv6_hdr(skb);
	struct net *net = dev_net(skb_dst(skb)->dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	int evicted;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	if (IP6CB(skb)->flags & IP6SKB_FRAGMENTED)
                goto fail_hdr;
#endif

	IP6_INC_STATS_BH(net, ip6_dst_idev(skb_dst(skb)),
				IPSTATS_MIB_REASMREQDS);

	/* Jumbo payload inhibits frag. header */
	if (hdr->payload_len == 0)
		goto fail_hdr;

	if (!pskb_may_pull(skb, (skb_transport_offset(skb) +
				 sizeof(struct frag_hdr))))
		goto fail_hdr;

	hdr = ipv6_hdr(skb);
	fhdr = (struct frag_hdr *)skb_transport_header(skb);

	if (!(fhdr->frag_off & htons(0xFFF9))) {
		/* It is not a fragmented frame */
		skb->transport_header += sizeof(struct frag_hdr);
		IP6_INC_STATS_BH(net, ip6_dst_idev(skb_dst(skb)),
					IPSTATS_MIB_REASMOKS);

		IP6CB(skb)->nhoff = (u8 *)fhdr - skb_network_header(skb);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
		IP6CB(skb)->flags |= IP6SKB_FRAGMENTED;
#endif
		return 1;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
        evicted = inet_frag_evictor(&net->ipv6.frags, &ip6_frags, false);
        if (evicted)
                IP6_ADD_STATS_BH(net, ip6_dst_idev(skb_dst(skb)),
                                 IPSTATS_MIB_REASMFAILS, evicted);
#else
	if (atomic_read(&net->ipv6.frags.mem) > net->ipv6.frags.high_thresh)
		ip6_evictor(net, ip6_dst_idev(skb_dst(skb)));
#endif

	fq = fq_find(net, fhdr->identification, &hdr->saddr, &hdr->daddr);
	if (fq != NULL) {
		int ret;

		spin_lock(&fq->q.lock);

		ret = ip6_frag_queue(fq, skb, fhdr, IP6CB(skb)->nhoff);

		spin_unlock(&fq->q.lock);
		fq_put(fq);
		return ret;
	}

	IP6_INC_STATS_BH(net, ip6_dst_idev(skb_dst(skb)),
					IPSTATS_MIB_REASMFAILS);
	kfree_skb(skb);
	return -1;

fail_hdr:
	IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)), IPSTATS_MIB_INHDRERRORS);
	sae6_icmpv6_param_prob(skb, ICMPV6_HDR_FIELD,
				skb_network_header_len(skb));
	return -1;
}
EXPORT_SYMBOL(ex_ipv6_frag_rcv);

#ifdef CONFIG_SYSCTL
static struct ctl_table ip6_frags_ns_ctl_table[] = {
	{
		.procname	= "sae6_ip6frag_high_thresh",
		.data		= &init_net.ipv6.frags.high_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "sae6_ip6frag_low_thresh",
		.data		= &init_net.ipv6.frags.low_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "sae6_ip6frag_time",
		.data		= &init_net.ipv6.frags.timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{ }
};

static struct ctl_table ip6_frags_ctl_table[] = {
	{
		.procname	= "sae6_ip6frag_secret_interval",
		.data		= &ip6_frags.secret_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{ }
};

static int __net_init ip6_frags_ns_sysctl_register(struct net *net)
{
	struct ctl_table *table;
	struct ctl_table_header *hdr;

	table = ip6_frags_ns_ctl_table;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(ip6_frags_ns_ctl_table),
						GFP_KERNEL);
		if (table == NULL)
			goto err_alloc;

		table[0].data = &net->ipv6.frags.high_thresh;
		table[1].data = &net->ipv6.frags.low_thresh;
		table[2].data = &net->ipv6.frags.timeout;
	}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 4, 0))
	hdr = register_net_sysctl(net, "net/ipv6", table);
#else
	hdr = register_net_sysctl_table(net,
		net_ipv6_ctl_path, table);
#endif
	if (hdr == NULL)
		goto err_reg;

	net->ipv6.sysctl.frags_hdr = hdr;
	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static void __net_exit ip6_frags_ns_sysctl_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net->ipv6.sysctl.frags_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->ipv6.sysctl.frags_hdr);
	if (!net_eq(net, &init_net))
		kfree(table);
}

static struct ctl_table_header *ip6_ctl_header;

static int ip6_frags_sysctl_register(void)
{
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 4, 0))
	ip6_ctl_header = register_net_sysctl(&init_net, "net/ipv6",
			ip6_frags_ctl_table);
#else
	ip6_ctl_header = register_net_sysctl_table(&init_net,
			net_ipv6_ctl_path,
			ip6_frags_ctl_table);
#endif
	return ip6_ctl_header == NULL ? -ENOMEM : 0;
}

static void ip6_frags_sysctl_unregister(void)
{
	unregister_net_sysctl_table(ip6_ctl_header);
}
#else
static inline int ip6_frags_ns_sysctl_register(struct net *net)
{
	return 0;
}

static inline void ip6_frags_ns_sysctl_unregister(struct net *net)
{
}

static inline int ip6_frags_sysctl_register(void)
{
	return 0;
}

static inline void ip6_frags_sysctl_unregister(void)
{
}
#endif

static int __net_init ipv6_frags_init_net(struct net *net)
{
	net->ipv6.frags.high_thresh = IPV6_FRAG_HIGH_THRESH;
	net->ipv6.frags.low_thresh = IPV6_FRAG_LOW_THRESH;
	net->ipv6.frags.timeout = IPV6_FRAG_TIMEOUT;

	inet_frags_init_net(&net->ipv6.frags);

	return ip6_frags_ns_sysctl_register(net);
}

static void __net_exit ipv6_frags_exit_net(struct net *net)
{
	ip6_frags_ns_sysctl_unregister(net);
	inet_frags_exit_net(&net->ipv6.frags, &ip6_frags);
}

static struct pernet_operations ip6_frags_ops = {
	.init = ipv6_frags_init_net,
	.exit = ipv6_frags_exit_net,
};

static int __init ex_ipv6_frag_init(void)
{
	int ret;

	ret = ip6_frags_sysctl_register();
	if (ret)
		goto err_sysctl;

	ret = register_pernet_subsys(&ip6_frags_ops);
	if (ret)
		goto err_pernet;

	ip6_frags.hashfn = ip6_hashfn;
	ip6_frags.constructor = ex_ip6_frag_init;
	ip6_frags.destructor = NULL;
	ip6_frags.skb_free = NULL;
	ip6_frags.qsize = sizeof(struct frag_queue);
	ip6_frags.match = ex_ip6_frag_match;
	ip6_frags.frag_expire = ip6_frag_expire;
	ip6_frags.secret_interval = 10 * 60 * HZ;
	inet_frags_init(&ip6_frags);
out:
	return ret;

err_pernet:
	ip6_frags_sysctl_unregister();
err_sysctl:
	goto out;
}

static void ex_ipv6_frag_exit(void)
{
	inet_frags_fini(&ip6_frags);
	ip6_frags_sysctl_unregister();
	unregister_pernet_subsys(&ip6_frags_ops);
}

static int ex_ip6_find_1stfragopt(struct sk_buff *skb, u8 **nexthdr)
{
	u16 offset = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr *exthdr =
			(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
	unsigned int packet_len = skb->tail - skb->network_header;
	int found_rhdr = 0;
	*nexthdr = &ipv6_hdr(skb)->nexthdr;

	while (offset + 1 <= packet_len) {

		switch (**nexthdr) {

		case NEXTHDR_HOP:
			break;
		case NEXTHDR_ROUTING:
			found_rhdr = 1;
			break;
		case NEXTHDR_DEST:
#if defined(CONFIG_IPV6_MIP6) || defined(CONFIG_IPV6_MIP6_MODULE)
			if (ipv6_find_tlv(skb, offset, IPV6_TLV_HAO) >= 0)
				break;
#endif
			if (found_rhdr)
				return offset;
			break;
		default:
			return offset;
		}

		offset += ipv6_optlen(exthdr);
		*nexthdr = &exthdr->nexthdr;
		exthdr = (struct ipv6_opt_hdr *)(skb_network_header(skb) +
								offset);
	}

	return offset;
}

static void ex_ipv6_select_ident(struct frag_hdr *fhdr, struct rt6_info *rt)
{
	static u32 ip6_idents_hashrnd __read_mostly;
	static bool hashrnd_initialized = false;
	u32 hash, id;

	if (unlikely(!hashrnd_initialized)) {
		hashrnd_initialized = true;
		get_random_bytes(&ip6_idents_hashrnd, sizeof(ip6_idents_hashrnd));
	}
	hash = __ipv6_addr_jhash(&rt->rt6i_dst.addr, ip6_idents_hashrnd);
	hash = __ipv6_addr_jhash(&rt->rt6i_src.addr, hash);

	id = ip_idents_reserve(hash, 1);
	fhdr->identification = htonl(id);
}

static void copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	skb_dst_drop(to);
	skb_dst_set(to, dst_clone(skb_dst(from)));
	to->dev = from->dev;
	to->mark = from->mark;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
	defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	to->nf_trace = from->nf_trace;
#endif
	skb_copy_secmark(to, from);
}

int ex_ip6_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *),
					unsigned int org_mtu)
{
	struct sk_buff *frag;
	struct rt6_info *rt = (struct rt6_info *)skb_dst(skb);
	struct ipv6_pinfo *np = skb->sk ? inet6_sk(skb->sk) : NULL;
	struct frag_hdr *fh;
	unsigned int mtu, hlen, left, len;
	int hroom, troom;
	__be32 frag_id = 0;
	int ptr, offset = 0, err = 0, frag_cnt = 0;
	u8 *prevhdr, nexthdr = 0;
	struct net *net = dev_net(skb_dst(skb)->dev);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	struct ethhdr *src, *dst;
#endif

	hlen = ex_ip6_find_1stfragopt(skb, &prevhdr);
	nexthdr = *prevhdr;

// PMTU fix
//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
//	mtu = ip6_skb_dst_mtu(skb);
//#else
	mtu = org_mtu;
//#endif

#if 0
	/* We must not fragment if the socket is set to force MTU discovery
	 * or if the skb it not generated by a local socket.
	 */
	if (unlikely(!skb->local_df && skb->len > mtu)) {
		if (skb->sk && dst_allfrag(skb_dst(skb)))
			sk_nocaps_add(skb->sk, NETIF_F_GSO_MASK);

		skb->dev = skb_dst(skb)->dev;
		t->encap_send_icmp++;	/* todo icmp6 */
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
		kfree_skb(skb);
		return 0;	/* todo -EMSGSIZE */
	}
#endif /* return packet too big */

	if (np && np->frag_size < mtu) {
		if (np->frag_size)
			mtu = np->frag_size;
	}
	mtu -= hlen + sizeof(struct frag_hdr);

	if (skb_has_frag_list(skb)) {
		printk(KERN_INFO "ex_ipv6_fragment: skb_has_frag_list = 0x%08x\n",
						skb_has_frag_list(skb));
	}

	if ((skb->ip_summed == CHECKSUM_PARTIAL) &&
		skb_checksum_help(skb)) {
			kfree_skb(skb);
			return 0;
	}

	left = skb->len - hlen;         /* Space per frame */
	ptr = hlen;                     /* Where to start from */

	/*
	 *      Fragment the datagram.
	 */

	*prevhdr = NEXTHDR_FRAGMENT;
	hroom = LL_RESERVED_SPACE(rt->dst.dev);
	troom = rt->dst.dev->needed_tailroom;

	/*
	 *      Keep copying data until we run out.
	 */
	while (left > 0) {
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending up to and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)
			len &= ~7;
		/*
		 *      Allocate buffer.
		 */

		frag = alloc_skb(len + hlen + sizeof(struct frag_hdr) +
					hroom + troom, GFP_ATOMIC);
		if (frag == NULL) {
			printk(KERN_INFO "ex_ipv6_fragment: no memory for new fragment!.\n");
			IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
						      IPSTATS_MIB_FRAGFAILS);
			kfree_skb(skb);
			err = -ENOMEM;
			return 0;
		}

		/*
		 *      Set up data on packet
		 */

		copy_metadata(frag, skb);
		skb_reserve(frag, hroom);
		skb_put(frag, len + hlen + sizeof(struct frag_hdr));
		skb_reset_network_header(frag);
		fh = (struct frag_hdr *)(skb_network_header(frag) + hlen);
		frag->transport_header = (frag->network_header + hlen +
						sizeof(struct frag_hdr));

		/*
		 *      Charge the memory for the fragment to any owner
		 *      it might possess
		 */
		if (skb->sk)
			skb_set_owner_w(frag, skb->sk);

		/*
		 *      Copy the packet header into the new buffer.
		 */
		skb_copy_from_linear_data(skb, skb_network_header(frag), hlen);

		/*
		 *      Build fragment header.
		 */
		fh->nexthdr = nexthdr;
		fh->reserved = 0;
		if (!frag_id) {
			ex_ipv6_select_ident(fh, rt);
			frag_id = fh->identification;
		} else
			fh->identification = frag_id;

		/*
		 *      Copy a block of the IP datagram.
		 */
		if (skb_copy_bits(skb, ptr, skb_transport_header(frag), len))
			BUG();
		left -= len;

		fh->frag_off = htons(offset);
		if (left > 0)
			fh->frag_off |= htons(IP6_MF);
		ipv6_hdr(frag)->payload_len = htons(frag->len -
							sizeof(struct ipv6hdr));

		ptr += len;
		offset += len;

		/*
		 *      Put this fragment into the sending queue.
		 */
		skb_set_mac_header(frag, -14);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
		src = (struct ethhdr *)skb_mac_header(skb);
		dst = (struct ethhdr *)skb_mac_header(frag);
		memcpy(dst, src, sizeof(struct ethhdr));
#else
		memcpy(frag->mac_header, skb->mac_header,
					sizeof(struct ethhdr));
#endif

		err = output(frag);
		if (err) {
			kfree_skb(skb);
			/* printk(KERN_INFO "ex_ipv6_fragment:
			 *		fragment packet tx = %d\n", err);
			 */
			return EX_FRAG_ERR;
		}

		frag_cnt++;

		IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
					      IPSTATS_MIB_FRAGCREATES);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
		dst_release(&rt->dst);
#endif

	}
	IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
		      IPSTATS_MIB_FRAGOKS);
	consume_skb(skb);
	return frag_cnt;
}
EXPORT_SYMBOL(ex_ip6_fragment);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
int ip6_nd_hdr(struct sock *sk, struct sk_buff *skb, struct net_device *dev,
               const struct in6_addr *saddr, const struct in6_addr *daddr,
               int proto, int len)
{
        struct ipv6_pinfo *np = inet6_sk(sk);
        struct ipv6hdr *hdr;

        skb->protocol = htons(ETH_P_IPV6);
        skb->dev = dev;

        skb_reset_network_header(skb);
        skb_put(skb, sizeof(struct ipv6hdr));
        hdr = ipv6_hdr(skb);

        *(__be32*)hdr = htonl(0x60000000);

        hdr->payload_len = htons(len);
        hdr->nexthdr = proto;
        hdr->hop_limit = np->hop_limit;

        hdr->saddr = *saddr;
        hdr->daddr = *daddr;

        return 0;
}

static u8 *ndisc_fill_addr_option(u8 *opt, int type, void *data, int data_len,
                                  unsigned short addr_type)
{
        int space = NDISC_OPT_SPACE(data_len);
        int pad   = ndisc_addr_option_pad(addr_type);

        opt[0] = type;
        opt[1] = space>>3;

        memset(opt + 2, 0, pad);
        opt   += pad;
        space -= pad;

        memcpy(opt+2, data, data_len);
        data_len += 2;
        opt += data_len;
        if ((space -= data_len) > 0)
                memset(opt, 0, space);
        return opt + space;
}

struct sk_buff *ex_ndisc_build_skb(struct net_device *dev,
                                const struct in6_addr *daddr,
                                const struct in6_addr *saddr,
                                struct icmp6hdr *icmp6h,
                                const struct in6_addr *target,
                                int llinfo)
{

        struct net *net = dev_net(dev);
        struct sock *sk = net->ipv6.ndisc_sk;
        struct sk_buff *skb;
        struct icmp6hdr *hdr;
        int hlen = LL_RESERVED_SPACE(dev);
        int tlen = dev->needed_tailroom;
        int len;
        int err;
        u8 *opt;

        if (!dev->addr_len)
                llinfo = 0;

        len = sizeof(struct icmp6hdr) + (target ? sizeof(*target) : 0);
        if (llinfo)
                len += ndisc_opt_addr_space(dev, NDISC_NEIGHBOUR_ADVERTISEMENT);

        skb = sock_alloc_send_skb(sk,
                                  (MAX_HEADER + sizeof(struct ipv6hdr) +
                                   len + hlen + tlen),
                                  1, &err);
        if (!skb) {
                return NULL;
        }

        skb_reserve(skb, hlen);
        ip6_nd_hdr(sk, skb, dev, saddr, daddr, IPPROTO_ICMPV6, len);

        skb->transport_header = skb->tail;
        skb_put(skb, len);

        hdr = (struct icmp6hdr *)skb_transport_header(skb);
        memcpy(hdr, icmp6h, sizeof(*hdr));

        opt = skb_transport_header(skb) + sizeof(struct icmp6hdr);
        if (target) {
                *(struct in6_addr *)opt = *target;
                opt += sizeof(*target);
        }

        if (llinfo)
                ndisc_fill_addr_option(opt, llinfo, dev->dev_addr,
                                       dev->addr_len, dev->type);

        hdr->icmp6_cksum = csum_ipv6_magic(saddr, daddr, len,
                                           IPPROTO_ICMPV6,
                                           csum_partial(hdr,
                                                        len, 0));

        return skb;

}
EXPORT_SYMBOL(ex_ndisc_build_skb);
#endif

module_init(ex_ipv6_frag_init);
module_exit(ex_ipv6_frag_exit);
