/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 * tamagawa        <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * Changes:
 * 2013.12.10 tamagawa new
 * 2016.6.14  tamagawa pr add
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/arp.h>
#include "ex_ipv6_fragment.h"
#include "me6e.h"

MODULE_DESCRIPTION("Stateless Automatic Ethernet over IPv6 tunneling device");
MODULE_LICENSE("GPL v2");

static int me6_pmtu_set(struct in6_addr, __be32, uint32_t);

/* ME6E Path MTU Discovery */
static int timerstop = 0;
static rwlock_t me6_pmtu_tbl_lock;
static struct timer_list me6_pmtu_timer;
static struct me6_pmtu_entry *me6_pmtu_tbl[ME6_PMTU_HASH_SIZE];
static struct me6_pmtu_info me6_pmtu_info;

static void me6_dev_setup(struct net_device *);

/* ME6E arp table */
static struct me6_arp_entry *me6_arp_tbl[ME6_ARP_HASH_SIZE];
static struct me6_arp_info me6_arp_info;

/* ME6E ndp table */
static struct me6_ndp_entry *me6_ndp_tbl[ME6_NDP_HASH_SIZE];
static struct me6_ndp_info me6_ndp_info;

/* ME6E stub ndp table */
static struct me6_ndp_entry *me6_stub_ndp_tbl[ME6_NDP_HASH_SIZE];
static struct me6_ndp_info me6_stub_ndp_info;

/* ME6E device table */
static struct me6_dev_entry *me6_dev_tbl;
static struct me6_dev_info me6_dev_info;

/* ME6E pr table */
static struct me6_pr_entry *me6_pr_tbl[ME6_PR_HASH_SIZE];
static struct me6_pr_info me6_pr_info;

/* ME6E IPsec table */
static struct me6_ipsec_info me6_ipsec_info;

/* ME6E iif table */
static struct me6_iif_entry *me6_iif_tbl[ME6_PR_HASH_SIZE];
static struct me6_iif_info me6_iif_info;

static inline uint32_t me6_hash(uint32_t key, uint32_t mask, uint32_t size)
{

	return jhash_1word((__force u32)(__be32)(key & inet_make_mask(mask)),
				mask) & (size - 1);
}

#if 0
static inline u32 me6_ipv6_addr_hash(const struct in6_addr *a)
{
        return (__force u32)(a->s6_addr32[0] ^ a->s6_addr32[1] ^
                             a->s6_addr32[2] ^ a->s6_addr32[3]);
}
#else
static inline u32 me6_ipv6_addr_hash(const struct in6_addr *a, const u32 size)
{
#if 0
        u32 v = (__force u32)a->s6_addr32[0] ^ (__force u32)a->s6_addr32[1];

        return jhash_3words(v,
                            (__force u32)a->s6_addr32[2],
                            (__force u32)a->s6_addr32[3],
                            initval);
#else
	u32 key = (__force u32)a->s6_addr32[0] ^ (__force u32)a->s6_addr32[1]
		^ (__force u32)a->s6_addr32[2] ^ (__force u32)a->s6_addr32[3];

	return jhash_1word((__force u32)(__be32)(key),128) & (size - 1);
#endif
}
#endif

static inline uint32_t me6_hash_ch(char *key, uint32_t tbl_size,
					uint32_t v_size)
{
	int hashval = 0;
	int i;

	for (i = 0; i < v_size; i++)
		hashval += *key++;

	return hashval % tbl_size;
}

static int me6_dst_set(struct sk_buff *skb)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct rt6_info *rt;
	struct flowi6 fl6 = {
		.flowi6_oif = skb->sk ? skb->sk->sk_bound_dev_if : 0,
		.flowi6_mark = skb->mark,
		.daddr = ipv6h->daddr,
		.saddr = ipv6h->saddr,
	};

	rt = (struct rt6_info *)ip6_route_output(dev_net(skb->dev),
							skb->sk, &fl6);
	if (rt->dst.error) {
		printk(KERN_INFO "me6e: route not found.\n");
		dst_release(&rt->dst);
		return -EINVAL;
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);

	return 0;
}

static u32 me6_get_mtu(struct sk_buff *skb, struct net_device *dev)
{
        struct ipv6hdr *ipv6h = ipv6_hdr(skb);
        struct me6_pmtu_entry *ent;
        u32 index, mtu = dev->mtu;

        read_lock_bh(&me6_pmtu_tbl_lock);
        index = me6_ipv6_addr_hash(&ipv6h->daddr, ME6_PMTU_HASH_SIZE);
        for (ent = me6_pmtu_tbl[index]; ent != NULL; ent = ent->next) {
		if (!(strcmp(ipv6h->daddr.s6_addr, ent->v6_host_addr.s6_addr))) {
                        mtu = ent->me6_mtu;
                        break;
                }
        }
        read_unlock_bh(&me6_pmtu_tbl_lock);

        return mtu;
}

static int me6_encap_send(struct sk_buff *skb, struct net_device *dev, __be16 protocol)
{
	struct sa46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	int len = skb->len, ret = 0, frag_cnt = 0;
	u32 me6_mtu;

	me6_mtu = me6_get_mtu(skb, dev);

#if 0
	if (me6_ipsec_info.ipsec_flag != ME6_IPSEC_OFF) {
		me6_mtu = ME6_IPV6_MTU_MIN;
	}
#endif // PMTU

	if ((skb->len > me6_mtu)) {
		ret = me6_dst_set(skb);
		if (ret < 0)
			return -1;

		frag_cnt = ex_ip6_fragment(skb, netif_rx_ni, me6_mtu);
		if (frag_cnt == ME6_FRAGMENT_ERR) {
			stats->tx_fifo_errors++;
			stats->tx_dropped++;
			t->encap_fragment_tx_error++;
			/* skb already free */
			return 0;
		}
		stats->tx_packets += frag_cnt;
		t->encap_fragment_tx_packet += frag_cnt;
		t->encap_cnt += frag_cnt;
	} else {
		if (netif_rx_ni(skb) != NET_RX_SUCCESS) {
			stats->tx_fifo_errors++;
			stats->tx_dropped++;
			t->encap_tx_errors++;
			/* todo printk */
			/* printk(KERN_INFO "me6e: netif_rx_ni() = %d\n",
								 err); */
			/* skb already free */
			return 0;
		}
		stats->tx_packets++;
		t->encap_cnt++;
	}

	stats->tx_bytes += len;

	return 0;
}

static struct inet6_ifaddr *me6_ifaddr_search(struct net_device *dev)
{
	struct inet6_dev *idev = (struct inet6_dev *)dev->ip6_ptr;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 35))
	struct inet6_ifaddr *ifaddr;
#else
	struct inet6_ifaddr *ifaddr = (struct inet6_ifaddr *)idev->addr_list;
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 35))
	list_for_each_entry(ifaddr, &idev->addr_list, if_list) {
#else
	for (; ifaddr; ifaddr = ifaddr->if_next) {
#endif
		if (ipv6_addr_src_scope(&ifaddr->addr)
				== IPV6_ADDR_SCOPE_GLOBAL) {
			return ifaddr;
		}
	}
	return NULL;
}

static void me6_make_ethhdr(struct sk_buff *skb, struct net_device *dev,
				struct ethhdr *ehdr)
{
	struct ethhdr *v6ehdr;

	/* make eth hdr */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
	v6ehdr = (struct ethhdr *)skb->mac_header;
#else
	v6ehdr = (struct ethhdr *)skb_mac_header(skb);
#endif
	memcpy(v6ehdr->h_dest, skb->dev->dev_addr, ETH_ALEN);
	memcpy(v6ehdr->h_source, ehdr->h_source, ETH_ALEN);
	v6ehdr->h_proto = htons(ETH_P_IPV6);

	return;
}

static inline int me6_make_ipv6hdr(struct sk_buff *skb, struct net_device *dev,
					int pay_len, struct ethhdr *ehdr)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	union me6_ethip_hdr_ac *ethip_hdr;
	struct inet6_ifaddr *ifaddr;
	struct me6_pr_entry *pr_ent;
	struct me6_iif_entry *iif_ent;
	uint32_t index, plane_id = 0;
	int hit = ME6_ENT_NOTHIT;

	ipv6h->version = 6;
	ipv6h->priority = 0;
	ipv6h->flow_lbl[0] = 0;
	ipv6h->flow_lbl[1] = 0;
	ipv6h->flow_lbl[2] = 0;
	ipv6h->payload_len = htons(pay_len + sizeof(struct me6_ethip_hdr));
	ipv6h->nexthdr = ME6_IPPROTO_ETHERIP;
	ipv6h->hop_limit = 0x80;

	ifaddr = me6_ifaddr_search(dev);
	if (!ifaddr) {
		printk(KERN_INFO "me6e: ifaddr search was not match.\n");
		return hit;
	}

	/* serch ifindex plane id */
	index = me6_hash(skb->skb_iif, 32, ME6_IIF_HASH_SIZE);
        for (iif_ent = me6_iif_tbl[index]; iif_ent != NULL
                ; iif_ent = iif_ent->next) {
		if (skb->skb_iif == iif_ent->iif) {
			plane_id = iif_ent->plane_id;
		}
	}

	/* search destination */
	index = me6_hash_ch(ehdr->h_dest, ME6_PR_HASH_SIZE, ETH_ALEN);
	for (pr_ent = me6_pr_tbl[index]; pr_ent != NULL
		; pr_ent = pr_ent->next) {

		if (strstr(ehdr->h_dest, pr_ent->hw_addr)) {
			if (plane_id != pr_ent->plane_id)
				continue;

			ipv6h->saddr = ifaddr->addr;
			memcpy(&ipv6h->saddr.s6_addr[10]
					, (__u8 *)ehdr->h_source, ETH_ALEN);
			ipv6h->daddr = pr_ent->me6_addr;
			memcpy(&ipv6h->daddr.s6_addr[10]
					, (__u8 *)ehdr->h_dest, ETH_ALEN);
			hit = ME6_ENT_HIT;
			break;
		}
	}

	/* default prefix */
	if (me6_pr_info.def_valid_flg && hit == ME6_ENT_NOTHIT) {
		ipv6h->saddr = ifaddr->addr;
		memcpy(&ipv6h->saddr.s6_addr[10]
				, (__u8 *)ehdr->h_source, ETH_ALEN);
		ipv6h->daddr = me6_pr_info.me6_def_pre;
		memcpy(&ipv6h->daddr.s6_addr[10]
				, (__u8 *)ehdr->h_dest, ETH_ALEN);
		hit = ME6_ENT_HIT;
	}

	ethip_hdr = (union me6_ethip_hdr_ac *)(ipv6h + 1);
	ethip_hdr->hdr.version = ME6_ETHIP_VERSION;
	ethip_hdr->hdr.reserved = 0x0;
	ethip_hdr->hdr_all = htons(ethip_hdr->hdr_all);

	skb->protocol = htons(ETH_P_IPV6);
	skb->pkt_type = PACKET_HOST;
	skb_dst_drop(skb);
	nf_reset(skb);

	return hit;
}

static inline int me6_encap(struct sk_buff *skb, struct net_device *dev, __be16 protocol)
{
	struct net_device *ndev;
	struct net *net = dev_net(dev);
	struct ethhdr *ehdr;
	int len = skb->len;

	DBGp("%s() start.", __func__);

	/* recive self packet. nothing todo. */
	ndev = dev_get_by_index(net, skb->skb_iif);
	if (ndev == NULL)
		return 0;

	if (skb_headroom(skb)
		< sizeof(struct ipv6hdr) + sizeof(struct me6_ethip_hdr)) {
		struct sk_buff *new_skb;
		printk(KERN_INFO "me6e: headroom not enough.\n");
		new_skb = skb_realloc_headroom(skb, sizeof(struct ipv6hdr)
					       + sizeof(struct me6_ethip_hdr));
		if (!new_skb) {
			printk(KERN_INFO "me6e: skb_realloc_headroom error.\n");
			return -1;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		kfree_skb(skb);
		skb = new_skb;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
	ehdr = (struct ethhdr *)skb->mac_header;
#else
	ehdr = (struct ethhdr *)skb_mac_header(skb);
#endif

	skb_push(skb, sizeof(struct ipv6hdr) + sizeof(struct me6_ethip_hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	skb_set_mac_header(skb, -ETH_HLEN);

	if (me6_make_ipv6hdr(skb, dev, len, ehdr))
		return -1;

	me6_make_ethhdr(skb, dev, ehdr);

	/* gard bridge table(dev me6e0 -> srcdev) */
	skb->dev = ndev;

	return me6_encap_send(skb, dev, protocol);

}

static int me6_decap_send(struct sk_buff *skb, struct net_device *dev)
{
	struct sa46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	uint32_t len;

	len = skb->len;

	if (netif_rx_ni(skb) != NET_RX_SUCCESS) {
		stats->tx_fifo_errors++;
		stats->tx_dropped++;
		t->decap_tx_errors++;
		/* todo printk */
		/* printk(KERN_INFO "me6e: netif_rx_ni() = %d\n", err); */
		/* skb already free */
		return 0;
	}

	stats->tx_bytes += len;
	stats->tx_packets++;
	t->decap_cnt++;
	return 0;
}

static int me6_decap_ethip(struct sk_buff *skb, struct net_device *dev)
{
	struct ethhdr *eth_hdr = NULL;

	skb_pull(skb, (sizeof(struct ipv6hdr) + ETH_HLEN
				+ sizeof(struct me6_ethip_hdr)));
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN);

	skb_pull(skb, ETH_HLEN);

	eth_hdr = (struct ethhdr *)skb_mac_header(skb);
	switch (htons(eth_hdr->h_proto)) {
	case ETH_P_IP:
		skb->protocol = htons(ETH_P_IP);
		break;
	case ETH_P_IPV6:
		skb->protocol = htons(ETH_P_IPV6);
		break;
	default:
		skb->protocol = htons(ETH_P_802_2);
	}

	skb->pkt_type = PACKET_HOST;
	skb_dst_drop(skb);
	nf_reset(skb);

	return me6_decap_send(skb, dev);
}

static int me6_ndisc_send(struct net_device *dev,
				const struct in6_addr *daddr,
				const struct in6_addr *saddr,
				struct icmp6hdr *icmp6h,
				const struct in6_addr *target,
				int llinfo)
{
	struct sa46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	struct sk_buff *skb;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
	skb = ndisc_build_skb(dev, daddr, saddr, icmp6h, target, llinfo);
#else
	skb = ex_ndisc_build_skb(dev, daddr, saddr, icmp6h, target, llinfo);
#endif
	if (!skb)
		return -1;

	/* todo don't look tcpdump */
	skb->pkt_type = PACKET_LOOPBACK;

	if (netif_rx_ni(skb) != NET_RX_SUCCESS) {
		stats->tx_fifo_errors++;
		stats->tx_dropped++;
		t->proxy_ndp_backbone_tx_errors++;
		/* todo printk */
		/* printk(KERN_INFO "me6e: netif_rx_ni()  = %d\n", err); */
		return -1;
	}

	stats->tx_packets++;
	t->proxy_ndp_backbone_tx_packet++;
	return 0;
}

static int me6_ndisc_send_na(struct sk_buff *skb)
{
	struct nd_msg *msg = (struct nd_msg *)skb_transport_header(skb);
	const struct in6_addr *daddr;
	const struct in6_addr *saddr;
	const struct in6_addr *solicited_addr;
	struct net_device *dev = skb->dev;
	struct icmp6hdr icmp6h = {
		.icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT,
		.icmp6_router = ME6_NDISC_RT_ON,
		.icmp6_solicited = ME6_NDISC_SOL_ON,
		.icmp6_override = ME6_NDISC_OVW_ON,
	};

	/* ndp packet addr set */
	daddr = &ipv6_hdr(skb)->saddr;
	solicited_addr = &msg->target;
	saddr = solicited_addr;

	if (me6_ndisc_send(dev, daddr, saddr, &icmp6h, solicited_addr,
				ND_OPT_TARGET_LL_ADDR))
		return -1;

	return 0;
}

static int me6_ndisc_send_encap_na(struct sk_buff *skb, unsigned char *hw_addr)
{
	struct sk_buff *new_skb = NULL;
	struct nd_msg *msg = (struct nd_msg *)skb_transport_header(skb);
	struct net_device *dev = skb->dev;
	struct sa46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	const struct in6_addr *daddr;
	const struct in6_addr *saddr;
	const struct in6_addr *solicited_addr;
	unsigned char *tmp_dev_addr;
	unsigned char tmp_addr_len;
	unsigned char *dst_lladdr;
	struct icmp6hdr icmp6h = {
		.icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT,
		.icmp6_router = ME6_NDISC_RT_ON,
		.icmp6_solicited = ME6_NDISC_SOL_ON,
		.icmp6_override = ME6_NDISC_OVW_ON,
	};

	daddr = &ipv6_hdr(skb)->saddr;
	solicited_addr = &msg->target;
	saddr = solicited_addr;

	/* temporarily overwrite dev_addr to set option target lladdr */
	tmp_dev_addr = dev->dev_addr;
	tmp_addr_len = dev->addr_len;
	dev->dev_addr = hw_addr;
	dev->addr_len = ETH_ALEN;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
	new_skb = ndisc_build_skb(dev, daddr, saddr, &icmp6h, solicited_addr,
			 ND_OPT_TARGET_LL_ADDR);
#else
	new_skb = ex_ndisc_build_skb(dev, daddr, saddr, &icmp6h, solicited_addr,
			 ND_OPT_TARGET_LL_ADDR);
#endif
	if (!new_skb)
		return -1;

	dev->dev_addr = tmp_dev_addr;
	dev->addr_len = tmp_addr_len;

	/* fill device header  */
	dst_lladdr = (unsigned char *)(((struct nd_opt_hdr *)msg->opt) + 1);
	if (dev_hard_header(new_skb, dev, ETH_P_IPV6,
#if 0
			dst_lladdr, hw_addr, skb->len) < 0){
#else
			dst_lladdr, me6_dev->dev_addr, skb->len) < 0){
#endif // src MAC ME6E
		kfree(new_skb);
		return -1;
	}
	skb_reset_mac_header(new_skb);
	skb_pull(new_skb, 14);

	if (netif_rx_ni(new_skb) != NET_RX_SUCCESS) {
		stats->tx_fifo_errors++;
		stats->tx_dropped++;
		t->proxy_ndp_stub_tx_errors++;
		return -1;
	}

	stats->tx_packets++;
	t->proxy_ndp_stub_tx_packet++;
	return 0;
}

static int me6_search_ndp_tbl(struct sk_buff *skb, unsigned char *v6addr)
{
	struct me6_ndp_entry *sne;
	uint32_t index;

	index = me6_hash_ch(&v6addr[10], ME6_NDP_HASH_SIZE, ETH_ALEN);

	for (sne = me6_ndp_tbl[index]; sne != NULL; sne = sne->next) {
		/* Compare MAC address */
		if (memcmp(&v6addr[10], &sne->hw_addr, ETH_ALEN) == 0) {
			/* Clear Control buffer */
			memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));
			if (me6_ndisc_send_na(skb))
				return -1;
			break;
		}
	}
	return 0;
}

static int me6_search_stub_ndp_tbl(struct sk_buff *skb, unsigned char *v6addr)
{
	struct me6_ndp_entry *sne;
	struct me6_iif_entry *iif_ent;
	uint32_t index, plane_id = 0;
	size_t in6addr_sz = sizeof(struct in6_addr);

	/* serch ifindex plane id */
	index = me6_hash(skb->skb_iif, 32, ME6_IIF_HASH_SIZE);
        for (iif_ent = me6_iif_tbl[index]; iif_ent != NULL
                ; iif_ent = iif_ent->next) {
		if (skb->skb_iif == iif_ent->iif) {
			plane_id = iif_ent->plane_id;
		}
	}

	index = me6_hash_ch(v6addr, ME6_NDP_HASH_SIZE, 16);

	for (sne = me6_stub_ndp_tbl[index]; sne != NULL; sne = sne->next) {
		/* Compare dst ipv6 address */
		if (memcmp(v6addr, &sne->daddr, in6addr_sz) == 0) {
			if (plane_id != sne->plane_id)
				continue;

			/* Clear Control buffer */
			memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));
			if (me6_ndisc_send_encap_na(skb, sne->hw_addr))
				return -1;
			break;
		}
	}
	return 0;
}

static int me6_ndisc_rcv(struct sk_buff *skb, bool is_stub)
{
	struct nd_msg *msg;
	unsigned char *v6addr;

	if (!pskb_may_pull(skb, skb->len))
		return -1;

	msg = (struct nd_msg *)skb_transport_header(skb);

	__skb_push(skb, skb->data - skb_transport_header(skb));

	if (ipv6_hdr(skb)->hop_limit != 255) {
		printk(KERN_INFO "me6e: invalid hop-limit = %d\n\n",
					ipv6_hdr(skb)->hop_limit);
		return -1;
	}

	if (msg->icmph.icmp6_code != 0) {
		printk(KERN_INFO "me6e: invalid ICMPv6 code = %d\n\n",
					msg->icmph.icmp6_code);
		return -1;
	}

	v6addr = (unsigned char *)&msg->target;

	if (is_stub) {
		if (me6_search_stub_ndp_tbl(skb, v6addr))
			return -1;
	} else {
		if (me6_search_ndp_tbl(skb, v6addr))
			return -1;
	}

	return 0;
}

static int me6_icmp6(struct sk_buff *skb, struct net_device *dev, bool is_stub, __be16 protocol)
{
	struct icmp6hdr *icmp6h = icmp6_hdr(skb);
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct sa46_tbl *t = netdev_priv(dev);
	int offset = 0;

	if (is_stub) {
		/* set transport header for bridged packet */
		offset += skb_network_offset(skb);
		offset += sizeof(struct ipv6hdr);
		skb_set_transport_header(skb, offset);
		icmp6h = icmp6_hdr(skb);
	}

	switch (icmp6h->icmp6_type) {
	case NDISC_NEIGHBOUR_SOLICITATION:
		if (me6_ndisc_rcv(skb, is_stub)) {

			if (is_stub)
				t->proxy_ndp_stub_tx_errors++;
			else
				t->proxy_ndp_backbone_tx_errors++;

			return -1;
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		/* update IPv6 header */
		ipv6h = (struct ipv6hdr *)(icmp6h + 1);
		if (me6_pmtu_set(ipv6h->daddr, ntohl(icmp6h->icmp6_mtu), 0) < 0) {
			//t->decap_pmtu_set_errors++;
			return -1;
		}
	default:
		if (is_stub) {
			return me6_encap(skb, dev, protocol);
		} else {
			t->decap_next_hdr_type_errors++;
			return -1;
		}
	}

	kfree_skb(skb);
	return 0;
}

static int me6_ip6_input_fragment(struct sk_buff *skb, struct net_device *dev)
{
	struct sa46_tbl *t = netdev_priv(dev);
	unsigned int nhoff;
	int nexthdr, ret = 0;

	ret = me6_dst_set(skb);
	if (ret < 0)
		return -1;

	/* rcu_read_lock(); */

	if (!pskb_pull(skb, skb_transport_offset(skb))) {
		printk(KERN_INFO "me6e: message is too short.\n");
		/* rcu_read_unlock(); */
		return -1;
	}

	nhoff = IP6CB(skb)->nhoff;
	nexthdr = skb_network_header(skb)[nhoff];

	ret = ex_ipv6_frag_rcv(skb);
	if (ret != 1) {
		/* reassemble incomplete */
		/* rcu_read_unlock(); */
		return 0;
	}

	/* rcu_read_unlock(); */

	t->fragment_reasm_packet++;

	skb_push(skb, ETH_HLEN);

	return me6_decap_ethip(skb, dev);

}

static inline int me6_ip6(struct sk_buff *skb, struct net_device *dev, __be16 protocol)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct sa46_tbl *t = netdev_priv(dev);
	union me6_ethip_hdr_ac *ethip_hdr;
	bool is_stub;
	int err;

	DBGp("%s() start.", __func__);

	/* check whether packet was transported
	 * by bridge(from stub network) or router(from backbone network)
	 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
        if (skb->network_header == skb->transport_header) {
#else
        if (skb->transport_header == ME6_TRANSPORT_HED_STUB_OFFSET) {
#endif
		/* stub */
		is_stub = true;
	} else {
		/* backbone */
		is_stub = false;
	}

	if (ipv6h->nexthdr == ME6_IPPROTO_ETHERIP) {
		ethip_hdr = (union me6_ethip_hdr_ac *)(ipv6h + 1);
		ethip_hdr->hdr_all = ntohs(ethip_hdr->hdr_all);
		if (ethip_hdr->hdr.version != ME6_ETHIP_VERSION
			|| ethip_hdr->hdr.reserved != 0x0) {
			t->decap_tx_errors++;
			return -1;
		}
		err = me6_decap_ethip(skb, dev);
		if (err < 0) {
			t->decap_tx_errors++;
			return err;
		}
	} else if (ipv6h->nexthdr == IPPROTO_FRAGMENT
			&& is_stub == false) {
		err = me6_ip6_input_fragment(skb, dev);
		if (err < 0) {
			t->decap_tx_errors++;
			return err;
		}
	} else if (ipv6h->nexthdr == NEXTHDR_ICMP) {
		err = me6_icmp6(skb, dev, is_stub, protocol);
		if (err < 0)
			return err;
	} else {
		err = me6_encap(skb, dev, protocol);
		if (err < 0) {
			t->encap_tx_errors++;
			return err;
		}
	}

	return 0;
}

static int me6_arp(struct sk_buff *skb, struct net_device *dev)
{
	struct sa46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	struct arphdr *arp = arp_hdr(skb);
	struct sk_buff *p;
	struct me6_arphdr *me6_arp;
	struct me6_arp_entry *sae;
	struct me6_iif_entry *iif_ent;
	__be32 saddr, daddr;
	uint32_t index, plane_id = 0;
#if 0
	uint32_t planeid;
#endif // planeID no check
	struct inet6_ifaddr *ifaddr;

	me6_arp = (struct me6_arphdr *)(arp + 1);

	if ((ntohs(arp->ar_op) != ARPOP_REQUEST)) {
		kfree(skb);
		return 0;
	}

	ifaddr = me6_ifaddr_search(dev);
	if (!ifaddr) {
		printk(KERN_INFO "me6e: ifaddr search was not match.\n");
		return -1;
	}

	/* serch ifindex plane id */
        index = me6_hash(skb->skb_iif, 32, ME6_IIF_HASH_SIZE);
        for (iif_ent = me6_iif_tbl[index]; iif_ent != NULL
                ; iif_ent = iif_ent->next) {
                if (skb->skb_iif == iif_ent->iif) {
                        plane_id = iif_ent->plane_id;
                }
        }

#if 0
	memcpy(&planeid, &ifaddr->addr.s6_addr16[3], sizeof(planeid));
	planeid = ntohl(planeid);
#endif // planeID no check

	memcpy(&saddr, &me6_arp->ar_tip, 4);
	index = me6_hash(saddr, 32, ME6_ARP_HASH_SIZE);

	for (sae = me6_arp_tbl[index]; sae != NULL; sae = sae->next) {
		if (memcmp(me6_arp->ar_tip, &sae->daddr, 4) == 0) {
# if 0
				&& sae->planeid == planeid) {
#endif // planeID no check

			if (plane_id != sae->planeid)
				continue;

			memcpy(&daddr, &me6_arp->ar_sip, 4);

#if 0
			p = arp_create(ARPOP_REPLY, ETH_P_ARP, daddr, dev,
					saddr, me6_arp->ar_sha, sae->hw_addr,
					sae->hw_addr);
#else
			p = arp_create(ARPOP_REPLY, ETH_P_ARP, daddr, dev,
                                        saddr, me6_arp->ar_sha, me6_dev->dev_addr,
                                        sae->hw_addr);
#endif // src MAC ME6E

			arp = arp_hdr(p);
			me6_arp = (struct me6_arphdr *)(arp + 1);

			memcpy(me6_arp->ar_sha, sae->hw_addr, ETH_ALEN);
			//memcpy(me6_arp->ar_sha, me6_dev->dev_addr, ETH_ALEN);

			skb_reset_mac_header(p);
			skb_pull(p, 14);

			if (netif_rx_ni(p) != NET_RX_SUCCESS) {
				stats->tx_fifo_errors++;
				stats->tx_dropped++;
				t->proxy_arp_tx_errors++;
				/* todo printk */
				/*
				 * printk(KERN_INFO "me6e:netif_rx_ni() =
				 * %d\n", err);
				 */
				return -1;
			}
			stats->tx_packets++;
			t->proxy_arp_tx_packet++;
			break;
		}
	}

	kfree(skb);
	return 0;
}

static netdev_tx_t me6_rcv(struct sk_buff *skb, struct net_device *dev)
{
	struct sa46_tbl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	int ret;

	stats->rx_packets++;
	stats->rx_bytes += skb->len;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ret = me6_encap(skb, dev, ETH_P_IP);
		break;
	case htons(ETH_P_IPV6):
		ret = me6_ip6(skb, dev, ETH_P_IPV6);
		break;
	case htons(ETH_P_ARP):
		ret = me6_arp(skb, dev);
		break;
	default:
		ret = me6_encap(skb, dev, 0);
		break;
	}

	if (ret < 0)
		goto err_proc;

	return 0;

err_proc:
	kfree_skb(skb);
	return 0;
}

static int me6_pr_entry_search(struct me6_pr_entry *spe)
{
        struct me6_pr_entry **p, *q;
        uint32_t index;

	index = me6_hash_ch(spe->hw_addr, ME6_PR_HASH_SIZE, ETH_ALEN);

        p = &me6_pr_tbl[index];
        q = me6_pr_tbl[index];
        if (!p)
                return 0;

        for (; q != NULL; p = &q->next, q = q->next) {
                if (memcmp(&spe->hw_addr, &q->hw_addr, ETH_ALEN) == 0) {
                        return -EEXIST;
                }
        }

        return 0;

}

static int me6_pr_entry_set(struct me6_pr_entry *spe)
{
	struct me6_pr_entry *p, *q;
	u32 index;

	p = kmalloc(sizeof(struct me6_pr_entry), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, spe, sizeof(struct me6_pr_entry));
	index = me6_hash_ch(p->hw_addr, ME6_PR_HASH_SIZE, ETH_ALEN);
	p->next = NULL;
	if (me6_pr_tbl[index] == NULL) {
		/* new */
		me6_pr_tbl[index] = p;
	} else {
		/* chain */
		q = me6_pr_tbl[index];
		for (; q->next != NULL; q = q->next)
			;
		q->next = p;
	}

	me6_pr_info.entry_num++;

	return 0;

}

static int me6_pr_entry_free(struct me6_pr_entry *spe)
{
	struct me6_pr_entry **p, *q;
	u32 index;
	int err = -ENOENT, i = 0;

	index = me6_hash_ch(spe->hw_addr, ME6_PR_HASH_SIZE, ETH_ALEN);

	p = &me6_pr_tbl[index];
	q = me6_pr_tbl[index];
	if (!p)
		return err;

	for (; q != NULL; p = &q->next, q = q->next, i++) {
		if (spe->plane_id != q->plane_id)
			continue;
		if (strstr(spe->hw_addr, q->hw_addr)) {
			*p = q->next;
			kfree(q);
			me6_pr_info.entry_num--;
			return 0;
		}
	}

	return err;
}

static int me6_pr_entry_get_all(int *p)
{
	struct me6_pr_entry *ent, *q;
	int i;

	q = (struct me6_pr_entry *)p;

	for (i = 0; i < ME6_PR_HASH_SIZE; i++) {
		ent = me6_pr_tbl[i];
		for (; ent != NULL; ent = ent->next, q++) {
			if (copy_to_user(q, ent, sizeof(struct me6_pr_entry)))
				return -EFAULT;
		}
	}
	return 0;
}

static void me6_pr_entry_free_all(void)
{
	struct me6_pr_entry *p, *q;
	int i, j;

	for (i = 0; i < ME6_PR_HASH_SIZE; i++) {
		for (p = me6_pr_tbl[i], j = 0; p != NULL; j++) {
			q = p->next;
			kfree(p);
			me6_pr_info.entry_num--;
			p = q;
		}
	}
}

static int me6_arp_entry_search(struct me6_arp_entry *sae)
{
	struct me6_arp_entry **p, *q;
	uint32_t index;

	index = me6_hash(sae->daddr.s_addr, 32, ME6_ARP_HASH_SIZE);

	p = &me6_arp_tbl[index];
	q = me6_arp_tbl[index];
	if (!p)
		return 0;

	for (; q != NULL; p = &q->next, q = q->next) {
		if (memcmp(&sae->daddr, &q->daddr, 4) == 0
			&& sae->planeid == q->planeid) {
			return -EEXIST;
		}
	}

	return 0;

}

static int me6_arp_entry_set(struct me6_arp_entry *sae)
{
	struct me6_arp_entry *p, *q;
	uint32_t index;

	index = me6_hash(sae->daddr.s_addr, 32, ME6_ARP_HASH_SIZE);

	p = kmalloc(sizeof(struct me6_arp_entry), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, sae, sizeof(struct me6_arp_entry));

	p->next = NULL;
	if (me6_arp_tbl[index] == NULL) {
		/* new */
		me6_arp_tbl[index] = p;
	} else {
		/* chain */
		q = me6_arp_tbl[index];
		for (; q->next != NULL; q = q->next)
			;
		q->next = p;
	}

	me6_arp_info.entry_num++;

	return 0;
}

static int me6_arp_entry_free(struct me6_arp_entry *sae)
{
	struct me6_arp_entry **p, *q;
	uint32_t index;
	int err = -ENOENT;

	index = me6_hash(sae->daddr.s_addr, 32, ME6_ARP_HASH_SIZE);

	p = &me6_arp_tbl[index];
	q = me6_arp_tbl[index];
	if (!p)
		return err;

	for (; q != NULL; p = &q->next, q = q->next) {
		if (memcmp(&sae->daddr, &q->daddr, 4) == 0
			&& sae->planeid == q->planeid) {
			*p = q->next;
			kfree(q);
			me6_arp_info.entry_num--;
			return 0;
		}
	}

	return err;
}

static int me6_arp_entry_get_all(int *p)
{
	struct me6_arp_entry *ent, *q;
	int i;

	q = (struct me6_arp_entry *)p;

	for (i = 0; i < ME6_ARP_HASH_SIZE; i++) {
		ent = me6_arp_tbl[i];
		for (; ent != NULL; ent = ent->next, q++) {
			if (copy_to_user(q, ent, sizeof(struct me6_arp_entry)))
				return -EFAULT;
		}
	}
	return 0;
}

static void me6_arp_entry_free_all(void)
{
	struct me6_arp_entry *p, *q;
	int i, j;

	for (i = 0; i < ME6_ARP_HASH_SIZE; i++) {
		for (p = me6_arp_tbl[i], j = 0; p != NULL; j++) {
			q = p->next;
			kfree(p);
			me6_arp_info.entry_num--;
			p = q;
		}
	}
}

static int me6_ndp_entry_search(struct me6_ndp_entry *sne)
{
	struct me6_ndp_entry **p, *q;
	uint32_t index;

	index = me6_hash_ch(sne->hw_addr, ME6_NDP_HASH_SIZE, ETH_ALEN);

	p = &me6_ndp_tbl[index];
	q = me6_ndp_tbl[index];
	if (!p)
		return 0;

	for (; q != NULL; p = &q->next, q = q->next) {
		if (memcmp(sne->hw_addr, q->hw_addr, ETH_ALEN) == 0)
			return -EEXIST;
	}

	return 0;
}

static int me6_ndp_entry_set(struct me6_ndp_entry *sne)
{
	struct me6_ndp_entry *p, *q;
	uint32_t index;

	index = me6_hash_ch(sne->hw_addr, ME6_NDP_HASH_SIZE, ETH_ALEN);

	p = kmalloc(sizeof(struct me6_ndp_entry), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, sne, sizeof(struct me6_ndp_entry));

	p->next = NULL;
	if (me6_ndp_tbl[index] == NULL) {
		/* new */
		me6_ndp_tbl[index] = p;
	} else {
		/* chain */
		q = me6_ndp_tbl[index];
		for (; q->next != NULL; q = q->next)
			;
		q->next = p;
	}

	me6_ndp_info.entry_num++;

	return 0;
}

static int me6_ndp_entry_free(struct me6_ndp_entry *sne)
{
	struct me6_ndp_entry **p, *q;
	uint32_t index;
	int err = -ENOENT;

	index = me6_hash_ch(sne->hw_addr, ME6_NDP_HASH_SIZE, ETH_ALEN);

	p = &me6_ndp_tbl[index];
	q = me6_ndp_tbl[index];
	if (!p)
		return err;

	for (; q != NULL; p = &q->next, q = q->next) {
		if (memcmp(sne->hw_addr, q->hw_addr, ETH_ALEN) == 0) {
			*p = q->next;
			kfree(q);
			me6_ndp_info.entry_num--;
			return 0;
		}
	}

	return err;
}

static int me6_ndp_entry_get_all(int *p)
{
	struct me6_ndp_entry *ent, *q;
	int i;

	q = (struct me6_ndp_entry *)p;

	for (i = 0; i < ME6_NDP_HASH_SIZE; i++) {
		ent = me6_ndp_tbl[i];
		for (; ent != NULL; ent = ent->next, q++) {
			if (copy_to_user(q, ent, sizeof(struct me6_ndp_entry)))
				return -EFAULT;
		}
	}
	return 0;
}

static void me6_ndp_entry_free_all(void)
{
	struct me6_ndp_entry *p, *q;
	int i, j;

	for (i = 0; i < ME6_NDP_HASH_SIZE; i++) {
		for (p = me6_ndp_tbl[i], j = 0; p != NULL; j++) {
			q = p->next;
			kfree(p);
			me6_ndp_info.entry_num--;
			p = q;
		}
	}
}

static int me6_stub_ndp_entry_search(struct me6_ndp_entry *sne)
{
	struct me6_ndp_entry **p, *q;
	uint32_t index;

	index = me6_hash_ch((unsigned char *)&sne->daddr,
				ME6_NDP_HASH_SIZE, 16);

	p = &me6_stub_ndp_tbl[index];
	q = me6_stub_ndp_tbl[index];
	if (!p)
		return 0;

	for (; q != NULL; p = &q->next, q = q->next) {
		if (memcmp(&sne->daddr, &q->daddr,
				sizeof(struct in6_addr)) == 0) {
			return -EEXIST;
		}
	}

	return 0;
}

static int me6_stub_ndp_entry_set(struct me6_ndp_entry *sne)
{
	struct me6_ndp_entry *p, *q;
	uint32_t index;

	index = me6_hash_ch((unsigned char *)&sne->daddr,
				ME6_NDP_HASH_SIZE, 16);

	p = kmalloc(sizeof(struct me6_ndp_entry), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, sne, sizeof(struct me6_ndp_entry));

	index = me6_hash_ch((unsigned char *)&p->daddr,
					ME6_NDP_HASH_SIZE, 16);

	p->next = NULL;
	if (me6_stub_ndp_tbl[index] == NULL) {
		/* new */
		me6_stub_ndp_tbl[index] = p;
	} else {
		/* chain */
		q = me6_stub_ndp_tbl[index];
		for (; q->next != NULL; q = q->next)
			;
		q->next = p;
	}

	me6_stub_ndp_info.entry_num++;

	return 0;
}

static int me6_stub_ndp_entry_free(struct me6_ndp_entry *sne)
{
	struct me6_ndp_entry **p, *q;
	uint32_t index;
	int err = -ENOENT;
	index = me6_hash_ch((unsigned char *)&sne->daddr,
					ME6_NDP_HASH_SIZE, 16);

	p = &me6_stub_ndp_tbl[index];
	q = me6_stub_ndp_tbl[index];
	if (!p)
		return err;

	for (; q != NULL; p = &q->next, q = q->next) {
		if (memcmp(&sne->daddr, &q->daddr,
					sizeof(struct in6_addr)) == 0) {
			*p = q->next;
			kfree(q);
			me6_stub_ndp_info.entry_num--;
			return 0;
		}
	}

	return err;
}

static int me6_stub_ndp_entry_get_all(int *p)
{
	struct me6_ndp_entry *ent, *q;
	int i;

	q = (struct me6_ndp_entry *)p;

	for (i = 0; i < ME6_NDP_HASH_SIZE; i++) {
		ent = me6_stub_ndp_tbl[i];
		for (; ent != NULL; ent = ent->next, q++) {
			if (copy_to_user(q, ent,
					sizeof(struct me6_ndp_entry)))
				return -EFAULT;
		}
	}
	return 0;
}

static void me6_stub_ndp_entry_free_all(void)
{
	struct me6_ndp_entry *p, *q;
	int i, j;

	for (i = 0; i < ME6_NDP_HASH_SIZE; i++) {
		for (p = me6_stub_ndp_tbl[i], j = 0; p != NULL; j++) {
			q = p->next;
			kfree(p);
			me6_stub_ndp_info.entry_num--;
			p = q;
		}
	}
}

static int me6_alloc_dev(struct me6_dev_entry *sde)
{
	int err;
	char str[IFNAMSIZ];

	memset(str, 0, sizeof(str));

	sprintf(str, "me6e%d", ++me6_dev_info.entry_num);

	sde->me6_dev = alloc_netdev(sizeof(struct sa46_tbl),  str,
			me6_dev_setup);

	if (!sde->me6_dev)
		return -ENOMEM;

	dev_hold(sde->me6_dev);

	err = register_netdevice(sde->me6_dev);
	if (err) {
		free_netdev(sde->me6_dev);
		return err;
	}

	if (sde->me6_dev->dev_addr)
		random_ether_addr(sde->me6_dev->dev_addr);

	return 0;
}

static int me6_dev_entry_set(void)
{
	struct me6_dev_entry *p, *q;
	int err;

	p = kmalloc(sizeof(struct me6_dev_entry), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	memset(p, 0, sizeof(struct me6_dev_entry));

	err = me6_alloc_dev(p);
	if (err) {
		printk(KERN_ERR "me6e: Alloc device failed.\n");
		kfree(p);
		return err;
	}

	p->next = NULL;
	if (me6_dev_tbl == NULL) {
		/* new */
		me6_dev_tbl = p;
	} else {
		/* chain */
		for (q = me6_dev_tbl; q->next != NULL; q = q->next)
			;
		q->next = p;
	}

	return 0;
}

static void me6_dev_entry_free_all(void)
{
	struct me6_dev_entry *p, *q;

	for (p = me6_dev_tbl; p != NULL; ) {
		q = p->next;
		dev_put(p->me6_dev);
		unregister_netdev(p->me6_dev);
		memset(p, 0, sizeof(struct me6_dev_entry));
		kfree(p);
		p = NULL;
		p = q;
	}
	me6_dev_tbl = NULL;
}

static int me6_iif_entry_search(struct me6_iif_entry *sie)
{
        struct me6_iif_entry **p, *q;
        uint32_t index;

        index = me6_hash(sie->iif, 32, ME6_IIF_HASH_SIZE);

        p = &me6_iif_tbl[index];
        q = me6_iif_tbl[index];
        if (!p)
                return 0;

        for (; q != NULL; p = &q->next, q = q->next) {
                if (sie->iif == q->iif) {
                        return -EEXIST;
                }
        }

        return 0;

}

static int me6_iif_entry_set(struct me6_iif_entry *sie)
{
        struct me6_iif_entry *p, *q;
        u32 index;

        index = me6_hash(sie->iif, 32, ME6_IIF_HASH_SIZE);

        p = kmalloc(sizeof(struct me6_iif_entry), GFP_KERNEL);
        if (p == NULL)
                return -ENOMEM;

        memcpy(p, sie, sizeof(struct me6_iif_entry));

        p->next = NULL;
        if (me6_iif_tbl[index] == NULL) {
                /* new */
                me6_iif_tbl[index] = p;
        } else {
                /* chain */
                q = me6_iif_tbl[index];
                for (; q->next != NULL; q = q->next)
                        ;
                q->next = p;
        }

        me6_iif_info.entry_num++;

        return 0;
}

static int me6_iif_entry_free(struct me6_iif_entry *sie)
{
        struct me6_iif_entry **p, *q;
        uint32_t index;
        int err = -ENOENT;

        index = me6_hash(sie->iif, 32, ME6_IIF_HASH_SIZE);

        p = &me6_iif_tbl[index];
        q = me6_iif_tbl[index];
        if (!p)
                return err;

        for (; q != NULL; p = &q->next, q = q->next) {
                if (sie->iif == q->iif) {
                        *p = q->next;
                        kfree(q);
                        me6_iif_info.entry_num--;
                        return 0;
                }
        }

        return err;
}

static int me6_iif_entry_get_all(int *p)
{
        struct me6_iif_entry *ent, *q;
        int i;

        q = (struct me6_iif_entry *)p;

        for (i = 0; i < ME6_IIF_HASH_SIZE; i++) {
                ent = me6_iif_tbl[i];
                for (; ent != NULL; ent = ent->next, q++) {
                        if (copy_to_user(q, ent, sizeof(struct me6_iif_entry)))
                                return -EFAULT;
                }
        }
        return 0;
}

static void me6_iif_entry_free_all(void)
{
        struct me6_iif_entry *p, *q;
        int i, j;

        for (i = 0; i < ME6_IIF_HASH_SIZE; i++) {
                for (p = me6_iif_tbl[i], j = 0; p != NULL; j++) {
                        q = p->next;
                        kfree(p);
                        me6_iif_info.entry_num--;
                        p = q;
                }
        }
}

static int me6_pmtu_entry_set(struct me6_pmtu_entry *ent)
{
	struct me6_pmtu_entry *p, *q;
	u32 index;

	p = kmalloc(sizeof(struct me6_pmtu_entry), GFP_ATOMIC);
	if (p == NULL)
		return -ENOMEM;

	memcpy(p, ent, sizeof(struct me6_pmtu_entry));
	write_lock_bh(&me6_pmtu_tbl_lock);
	index = me6_ipv6_addr_hash(&p->v6_host_addr, ME6_PMTU_HASH_SIZE);
	p->next = NULL;
	if (me6_pmtu_tbl[index] == NULL) {
		/* new */
		me6_pmtu_tbl[index] = p;
	} else {
		/* chain */
		q = me6_pmtu_tbl[index];

		for (;; q = q->next) {
			//if ((!(q->v6_host_addr ^ p->v6_host_addr)) {
			if (!(strcmp(q->v6_host_addr.s6_addr, p->v6_host_addr.s6_addr))) {
				if (q->pmtu_flags == ME6_PMTU_STATIC_ENTRY) {
					q->me6_mtu = p->me6_mtu;
					kfree(p);
					write_unlock_bh(&me6_pmtu_tbl_lock);
					return 0;
				}
				if (p->pmtu_flags != ME6_PMTU_STATIC_ENTRY) {
					/* because same entry, update mtu, expires */
					q->me6_mtu = p->me6_mtu;
					q->expires = get_jiffies_64() + me6_pmtu_info.timeout;
				} else {
					q->expires = 0;
				}
				q->pmtu_flags = p->pmtu_flags;
				kfree(p);
				write_unlock_bh(&me6_pmtu_tbl_lock);

				return 0;
			}
			if (q->next == NULL)
				break;
		}
		q->next = p;
	}

	/* New entry */
	if (p->pmtu_flags != ME6_PMTU_STATIC_ENTRY) {
		p->expires = get_jiffies_64() + me6_pmtu_info.timeout;
	}
	me6_pmtu_info.entry_num++;
	write_unlock_bh(&me6_pmtu_tbl_lock);

	return 0;
}

static int me6_pmtu_set(struct in6_addr daddr, __be32 mtu, uint32_t flags)
{
	struct me6_pmtu_entry ent;

	memset(&ent, 0, sizeof(struct me6_pmtu_entry));
	ent.v6_host_addr = daddr;
	ent.me6_mtu = mtu;
	ent.pmtu_flags = flags;

	return me6_pmtu_entry_set(&ent);
}

static int me6_pmtu_entry_free(struct me6_pmtu_entry *ent, u32 index)
{
	struct me6_pmtu_entry **p, *q;
	int err = -ENOENT;

	p = &me6_pmtu_tbl[index];
	q = me6_pmtu_tbl[index];

	for (; q != NULL; p = &q->next, q = q->next) {
		//if ((!(ent->v6_host_addr ^ q->v6_host_addr)) {
		if(!(strcmp(ent->v6_host_addr.s6_addr, q->v6_host_addr.s6_addr))) {
			*p = q->next;
			kfree(q);
			me6_pmtu_info.entry_num--;
			err = 0;
			break;
		}
	}

	return err;
}

static int me6_pmtu_free(struct me6_pmtu_entry *ent)
{
	u32 index;
	int err;

	index = me6_ipv6_addr_hash(&ent->v6_host_addr, ME6_PMTU_HASH_SIZE);

	write_lock_bh(&me6_pmtu_tbl_lock);
	err = me6_pmtu_entry_free(ent, index);
	write_unlock_bh(&me6_pmtu_tbl_lock);

	return err;
}

static int me6_pmtu_entry_get_all(int *p)
{
	struct me6_pmtu_entry *ent, *q;
	int i;

	q = (struct me6_pmtu_entry *)p;

	read_lock_bh(&me6_pmtu_tbl_lock);
	for (i = 0; i < ME6_PMTU_HASH_SIZE; i++) {
		ent = me6_pmtu_tbl[i];
		for (; ent != NULL; ent = ent->next, q++) {
			if (copy_to_user(q, ent, sizeof(struct me6_pmtu_entry))) {
				read_unlock_bh(&me6_pmtu_tbl_lock);
				return -EFAULT;
			}
		}
	}
	read_unlock_bh(&me6_pmtu_tbl_lock);
	return 0;
}

static void me6_pmtu_entry_free_all(void)
{
	struct me6_pmtu_entry *p, *q;
	int i;

	write_lock_bh(&me6_pmtu_tbl_lock);
	for (i = 0; i < ME6_PMTU_HASH_SIZE; i++) {
		for (p = me6_pmtu_tbl[i]; p != NULL; p = q) {
			q = p->next;
			kfree(p);
			me6_pmtu_info.entry_num--;
		}
	}
	write_unlock_bh(&me6_pmtu_tbl_lock);
}

static void me6_pmtu_timer_func(unsigned long data)
{
	struct me6_pmtu_entry *p, *q;
	int i;

	if (timerstop == 1)
		return;

	write_lock_bh(&me6_pmtu_tbl_lock);
	for (i = 0; i < ME6_PMTU_HASH_SIZE; i++) {
		for (p = me6_pmtu_tbl[i]; p != NULL; p = q) {
			q = p->next;
			if (p->pmtu_flags == ME6_PMTU_STATIC_ENTRY)
				continue;
			if (!time_after_eq64(p->expires, get_jiffies_64())) {
				if (me6_pmtu_entry_free(p, i) < 0)
					printk(KERN_ERR "me6e: pmtu table free error.\n");
			}
		}
	}
	write_unlock_bh(&me6_pmtu_tbl_lock);

	me6_pmtu_timer.entry.prev = NULL;
	me6_pmtu_timer.entry.next = NULL;
	me6_pmtu_timer.expires    = jiffies + ME6_PMTU_CYCLE_TIME;
	me6_pmtu_timer.data       = 0;
	me6_pmtu_timer.function   = me6_pmtu_timer_func;
	add_timer(&me6_pmtu_timer);
}

static int me6_ioctl_pmtu(struct ifreq *ifr)
{
	struct me6_pmtu_info pmtu_info;
	struct me6_pmtu_entry pmtu_ent;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case ME6_GETPMTUENTRYNUM:
		me6_pmtu_info.now = get_jiffies_64();
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &me6_pmtu_info,
				 sizeof(me6_pmtu_info)))
			return -EFAULT;
		break;
	case ME6_GETPMTUENTRY:
		err = me6_pmtu_entry_get_all(ifr->ifr_ifru.ifru_data);
		break;
	case ME6_SETPMTUENTRY:
		if (copy_from_user(&pmtu_ent, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pmtu_entry)))
			return -EFAULT;
		err = me6_pmtu_entry_set(&pmtu_ent);
		break;
	case ME6_FREEPMTUENTRY:
		if (copy_from_user(&pmtu_ent, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pmtu_entry)))
			return -EFAULT;
		err = me6_pmtu_free(&pmtu_ent);
		break;
	case ME6_SETPMTUTIME:
		if (copy_from_user(&pmtu_info, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pmtu_info)))
			return -EFAULT;
		me6_pmtu_info.timeout = pmtu_info.timeout * HZ;
		break;
	case ME6_SETPMTUINFO:
		if (copy_from_user(&pmtu_info, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pmtu_info)))
			return -EFAULT;
		me6_pmtu_info.force_fragment = pmtu_info.force_fragment;
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "me6_ioctl_pmtu() unknown command type(%d)\n", type);
		break;
	}
	return err;
}

static int me6_ioctl_dev(struct ifreq *ifr)
{
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case ME6_SETDEVENTRY:
		err = me6_dev_entry_set();
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "me6_ioctl() unknown command type(%d)\n",
					type);
		break;
	}
	return err;
}

static int me6_ioctl_ndp(struct ifreq *ifr)
{
	struct me6_ndp_entry sne;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case ME6_SETNDPENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_ndp_entry)))
			return -EFAULT;
		err = me6_ndp_entry_set(&sne);
		break;
	case ME6_FREENDPENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_ndp_entry)))
			return -EFAULT;
		err = me6_ndp_entry_free(&sne);
		break;
	case ME6_GETNDPENTRYINFO:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &me6_ndp_info,
				 sizeof(struct me6_ndp_info)))
			return -EFAULT;
		break;
	case ME6_GETNDPENTRY:
		err = me6_ndp_entry_get_all(ifr->ifr_ifru.ifru_data);
		break;
	case ME6_SEARCHNDPENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_ndp_entry)))
			return -EFAULT;
		err = me6_ndp_entry_search(&sne);
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "me6_ioctl() unknown command type(%d)\n",
					type);
		break;
	}
	return err;
}

static int me6_ioctl_stub_ndp(struct ifreq *ifr)
{
	struct me6_ndp_entry sne;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case ME6_STUB_SETNDPENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_ndp_entry)))
			return -EFAULT;
		err = me6_stub_ndp_entry_set(&sne);
		break;
	case ME6_STUB_FREENDPENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_ndp_entry)))
			return -EFAULT;
		err = me6_stub_ndp_entry_free(&sne);
		break;
	case ME6_STUB_GETNDPENTRYINFO:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &me6_stub_ndp_info,
				 sizeof(struct me6_ndp_info)))
			return -EFAULT;
		break;
	case ME6_STUB_GETNDPENTRY:
		err = me6_stub_ndp_entry_get_all(ifr->ifr_ifru.ifru_data);
		break;
	case ME6_STUB_SEARCHNDPENTRY:
		if (copy_from_user(&sne, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_ndp_entry)))
			return -EFAULT;
		err = me6_stub_ndp_entry_search(&sne);
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "me6_ioctl() unknown command type(%d)\n",
					type);
		break;
	}
	return err;
}

static int me6_ioctl_arp(struct ifreq *ifr)
{
	struct me6_arp_entry sae;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case ME6_SETARPENTRY:
		if (copy_from_user(&sae, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_arp_entry)))
			return -EFAULT;
		err = me6_arp_entry_set(&sae);
		break;
	case ME6_FREEARPENTRY:
		if (copy_from_user(&sae, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_arp_entry)))
			return -EFAULT;
		err = me6_arp_entry_free(&sae);
		break;
	case ME6_GETARPENTRYINFO:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &me6_arp_info,
				 sizeof(struct me6_arp_info)))
			return -EFAULT;
		break;
	case ME6_GETARPENTRY:
		err = me6_arp_entry_get_all(ifr->ifr_ifru.ifru_data);
		break;
	case ME6_SEARCHARPENTRY:
		if (copy_from_user(&sae, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_arp_entry)))
			return -EFAULT;
		err = me6_arp_entry_search(&sae);
		break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "me6_ioctl() unknown command type(%d)\n",
					type);
		break;
	}
	return err;
}

static int me6_ioctl_pr(struct ifreq *ifr)
{
	struct me6_pr_entry spe;
	struct me6_pr_info spi;
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case ME6_SETPRENTRY:
		if (copy_from_user(&spe, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pr_entry)))
			return -EFAULT;
		err = me6_pr_entry_set(&spe);
		break;
	case ME6_FREEPRENTRY:
		if (copy_from_user(&spe, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pr_entry)))
			return -EFAULT;
		err = me6_pr_entry_free(&spe);
		break;
	case ME6_GETPRENTRYNUM:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &me6_pr_info,
				 sizeof(struct me6_pr_info)))
			return -EFAULT;
		break;
	case ME6_GETPRENTRY:
		err = me6_pr_entry_get_all(ifr->ifr_ifru.ifru_data);
		break;
	case ME6_SETDEFPREFIX:
		if (copy_from_user(&spi, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pr_info)))
			return -EFAULT;
		me6_pr_info.def_valid_flg = 1;
		memcpy(&me6_pr_info.me6_def_pre, &spi.me6_def_pre,
		       sizeof(spi.me6_def_pre));
		break;
	case ME6_FREEDEFPREFIX:
		if (copy_from_user(&spi, ifr->ifr_ifru.ifru_data,
				   sizeof(struct me6_pr_info)))
			return -EFAULT;
		me6_pr_info.def_valid_flg = 0;
		ipv6_addr_set(&me6_pr_info.me6_def_pre, 0, 0, 0, 0);
		break;
        case ME6_SEARCHPRENTRY:
                if (copy_from_user(&spe, ifr->ifr_ifru.ifru_data,
                                   sizeof(struct me6_pr_entry)))
                        return -EFAULT;
                err = me6_pr_entry_search(&spe);
                break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "me6_ioctl() unknown command type(%d)\n"
			, type);
		break;
	}
	return err;
}

static int me6_ioctl_ipsec(struct ifreq *ifr)
{
	uint32_t type;
	int err = 0;

	if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
		return -EFAULT;

	switch (type) {
	case ME6_IPSEC_FLAG:
		if (me6_ipsec_info.ipsec_flag == ME6_IPSEC_OFF) {
                        me6_ipsec_info.ipsec_flag = ME6_IPSEC_ON;
                } else {
                        me6_ipsec_info.ipsec_flag = ME6_IPSEC_OFF;
                }
		break;
        case ME6_GETIPSECENTRYINFO:
                if (copy_to_user(ifr->ifr_ifru.ifru_data, &me6_ipsec_info,
                                 sizeof(struct me6_ipsec_info)))
                        return -EFAULT;
                break;
	default:
		err = -EINVAL;
		printk(KERN_ERR "me6_ioctl() unknown command type(%d)\n"
			, type);
		break;
	}
	return err;
}

static int me6_ioctl_iif(struct ifreq *ifr)
{
        struct me6_iif_entry sie;
        uint32_t type;
        int err = 0;

        if (copy_from_user(&type, ifr->ifr_ifru.ifru_data, sizeof(uint32_t)))
                return -EFAULT;

        switch (type) {
        case ME6_SETIIFENTRY:
                if (copy_from_user(&sie, ifr->ifr_ifru.ifru_data,
                                   sizeof(struct me6_iif_entry)))
                        return -EFAULT;
                err = me6_iif_entry_set(&sie);
                break;
        case ME6_FREEIIFENTRY:
                if (copy_from_user(&sie, ifr->ifr_ifru.ifru_data,
                                   sizeof(struct me6_iif_entry)))
                        return -EFAULT;
                err = me6_iif_entry_free(&sie);
                break;
        case ME6_GETIIFENTRYINFO:
                if (copy_to_user(ifr->ifr_ifru.ifru_data, &me6_iif_info,
                                 sizeof(struct me6_iif_info)))
                        return -EFAULT;
                break;
        case ME6_GETIIFENTRY:
                err = me6_iif_entry_get_all(ifr->ifr_ifru.ifru_data);
                break;
        case ME6_SEARCHIIFENTRY:
                if (copy_from_user(&sie, ifr->ifr_ifru.ifru_data,
                                   sizeof(struct me6_iif_entry)))
                        return -EFAULT;
                err = me6_iif_entry_search(&sie);
                break;
        default:
                err = -EINVAL;
                printk(KERN_ERR "me6_ioctl() unknown command type(%d)\n",
                                        type);
                break;
        }
	return err;
}

static int me6_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct sa46_tbl *t = netdev_priv(dev);
	int err = 0;

	switch (cmd) {
	case ME6_GETSTATISTICS:
		if (copy_to_user(ifr->ifr_ifru.ifru_data, t,
					sizeof(struct sa46_tbl)))
			return -EFAULT;
		break;
	case ME6_ARP:
		err = me6_ioctl_arp(ifr);
		break;
	case ME6_NDP:
		err = me6_ioctl_ndp(ifr);
		break;
	case ME6_STUB_NDP:
		err = me6_ioctl_stub_ndp(ifr);
		break;
	case ME6_DEV:
		err = me6_ioctl_dev(ifr);
		break;
	case ME6_PR:
		err = me6_ioctl_pr(ifr);
		break;
	case ME6_IPSEC:
		err = me6_ioctl_ipsec(ifr);
		break;
        case ME6_IIF:
                err = me6_ioctl_iif(ifr);
                break;
	case ME6_PMTU:
		err = me6_ioctl_pmtu(ifr);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static const struct net_device_ops me6_netdev_ops = {
	.ndo_start_xmit = me6_rcv,
	.ndo_do_ioctl = me6_ioctl,
};

static const struct header_ops me6_header_ops ____cacheline_aligned = {
	.create = eth_header,
};

/**
 * me6_dev_setup - setup virtual device
 *   @dev: virtual device associated
 *
 * Description:
 *   Initialize function pointers and device parameters
 **/
static void me6_dev_setup(struct net_device *dev)
{
	struct sa46_tbl *t = netdev_priv(dev);

	t->dev = dev;

	dev->netdev_ops = &me6_netdev_ops;
	dev->header_ops = &me6_header_ops;
	dev->destructor = free_netdev;

	dev->type = ARPHRD_ETHER;
	dev->hard_header_len = LL_MAX_HEADER + sizeof(struct ipv6hdr);
	dev->mtu = ETH_DATA_LEN;
	dev->flags |= IFF_MULTICAST;
	dev->flags |= IFF_ALLMULTI;
	dev->flags |= IFF_BROADCAST;
	dev->addr_len = ETH_ALEN;
	dev->features |= NETIF_F_NETNS_LOCAL;
}

static void init_me6_arp(void)
{
	/* me6 hash table clear */
	memset(me6_arp_tbl, 0, sizeof(me6_arp_tbl));
	memset(&me6_arp_info, 0, sizeof(me6_arp_info));
}

static void init_me6_ndp(void)
{
	/* me6 hash table clear */
	memset(me6_ndp_tbl, 0, sizeof(me6_ndp_tbl));
	memset(&me6_ndp_info, 0, sizeof(me6_ndp_info));
}

static void init_me6_stub_ndp(void)
{
	/* me6 hash table clear */
	memset(me6_stub_ndp_tbl, 0, sizeof(me6_stub_ndp_tbl));
	memset(&me6_stub_ndp_info, 0, sizeof(me6_stub_ndp_info));
}

static void init_me6_dev(void)
{
	me6_dev_tbl = NULL;
	memset(&me6_dev_info, 0, sizeof(me6_dev_info));
}

static void init_me6_pr(void)
{
	/* me6 hash table clear */
	memset(me6_pr_tbl, 0, sizeof(me6_pr_tbl));
	memset(&me6_pr_info, 0, sizeof(me6_pr_info));
}

static void init_me6_ipsec(void)
{
	/* me6 ipsec flag clear */
	memset(&me6_ipsec_info, 0, sizeof(me6_ipsec_info));
	me6_ipsec_info.ipsec_flag = ME6_IPSEC_OFF;
}

static void init_me6_pmtu(void)
{

	memset(me6_pmtu_tbl, 0, sizeof(me6_pmtu_tbl));
	memset(&me6_pmtu_info, 0, sizeof(me6_pmtu_info));
	rwlock_init(&me6_pmtu_tbl_lock);
	me6_pmtu_info.timeout = ME6_PMTU_TIMEOUT_DEF;

	/* timer for PMTU */
	init_timer(&me6_pmtu_timer);
	me6_pmtu_timer.entry.prev = NULL;
	me6_pmtu_timer.entry.next = NULL;
	me6_pmtu_timer.expires    = jiffies + ME6_PMTU_CYCLE_TIME;
	me6_pmtu_timer.data       = 0;
	me6_pmtu_timer.function   = me6_pmtu_timer_func;
	add_timer(&me6_pmtu_timer);
}

static int __init me6_init(void)
{
	int err;

	DBGp("me6e init start.");

	me6_dev = alloc_netdev(sizeof(struct sa46_tbl), "me6e0",
				me6_dev_setup);

	if (!me6_dev)
		return -ENOMEM;

	dev_hold(me6_dev);

	err = register_netdev(me6_dev);
	if (err) {
		free_netdev(me6_dev);
		return err;
	}

	if (me6_dev->dev_addr)
		random_ether_addr(me6_dev->dev_addr);

	init_me6_arp();
	init_me6_ndp();
	init_me6_stub_ndp();
	init_me6_dev();
	init_me6_pr();
	init_me6_ipsec();

	init_me6_pmtu();

	DBGp("me6e init end.");
	return 0;
}

static void __exit me6_cleanup(void)
{
	me6_arp_entry_free_all();
	me6_ndp_entry_free_all();
	me6_stub_ndp_entry_free_all();
	me6_dev_entry_free_all();
	me6_pr_entry_free_all();
	me6_iif_entry_free_all();

	timerstop = 1;
	del_timer_sync(&me6_pmtu_timer);
	me6_pmtu_entry_free_all();

	dev_put(me6_dev);
	unregister_netdev(me6_dev);
	DBGp("me6e exit!");
}


module_init(me6_init);
module_exit(me6_cleanup);
