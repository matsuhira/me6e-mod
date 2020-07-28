/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * Authors:
 * Mitarai           <m.mitarai@jp.fujitsu.com>
 * tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * Changes:
 * 2013.12.10 tamagawa new
 */

#ifndef _ME6E_H
#define _ME6E_H

#if 0
#define ME6_DEBUG 1
#endif

#ifdef ME6_DEBUG
#define DBGp(fmt, args...) do { printk(KERN_DEBUG fmt, ##args); } while (0)
#else
#define DBGp(fmt, ...) do { ; } while (0)
#endif

#define ME6_IPPROTO_ETHERIP	0x61	/* any host internal protocol */
#define ME6_FRAGMENT_ERR 0

#define ME6_GETSTATISTICS	(SIOCDEVPRIVATE)
#define ME6_ARP			(SIOCDEVPRIVATE+1)
#define ME6_SETARPENTRY		1
#define ME6_FREEARPENTRY		2
#define ME6_GETARPENTRYINFO		3
#define ME6_GETARPENTRY		4
#define ME6_SEARCHARPENTRY		5
#define ME6_NDP			(SIOCDEVPRIVATE+2)
#define ME6_SETNDPENTRY		6
#define ME6_FREENDPENTRY		7
#define ME6_GETNDPENTRYINFO		8
#define ME6_GETNDPENTRY		9
#define ME6_SEARCHNDPENTRY		10
#define ME6_DEV			(SIOCDEVPRIVATE+3)
#define ME6_SETDEVENTRY		11
#define ME6_STUB_NDP		(SIOCDEVPRIVATE+4)
#define ME6_STUB_SETNDPENTRY		12
#define ME6_STUB_FREENDPENTRY		13
#define ME6_STUB_GETNDPENTRYINFO	14
#define ME6_STUB_GETNDPENTRY		15
#define ME6_STUB_SEARCHNDPENTRY	16
#define ME6_PR			(SIOCDEVPRIVATE+5)
#define ME6_SETPRENTRY		17
#define ME6_FREEPRENTRY		18
#define ME6_GETPRENTRYNUM	19
#define ME6_GETPRENTRY		20
#define ME6_SETDEFPREFIX	21
#define ME6_FREEDEFPREFIX	22
#define ME6_SEARCHPRENTRY	23
#define ME6_IPSEC		(SIOCDEVPRIVATE+6)
#define ME6_IPSEC_FLAG		24
#define ME6_GETIPSECENTRYINFO	25
#define ME6_IIF			(SIOCDEVPRIVATE+7)
#define ME6_SETIIFENTRY		26
#define ME6_FREEIIFENTRY	27
#define ME6_GETIIFENTRYINFO	28
#define ME6_GETIIFENTRY		29
#define ME6_SEARCHIIFENTRY	30
#define ME6_PMTU		(SIOCDEVPRIVATE+8)
#define ME6_GETPMTUENTRYNUM	31
#define ME6_GETPMTUENTRY	32
#define ME6_SETPMTUENTRY	33
#define ME6_FREEPMTUENTRY	34
#define ME6_SETPMTUTIME		35
#define ME6_SETPMTUINFO		36

#define ME6_PMTU_STATIC_ENTRY 1
#define ME6_PMTU_HASH_SIZE 128
#define ME6_PMTU_TIMEOUT_DEF (10 * 60 * HZ) /* 10 minutes */
#define ME6_PMTU_CYCLE_TIME  (1 * 60 * HZ)  /*  1 minutes */
#define FORCE_FRAGMENT_OFF 0
#define FORCE_FRAGMENT_ON 1
#define ME6_SYS_CLOCK 1000
#define ME6_PMTU_EXPIRE_MIN 300    /* 5 minutes */
#define ME6_PMTU_EXPIRE_MAX 86400  /* 24 hour */
struct me6_pmtu_entry {
	uint32_t type;
	struct me6_pmtu_entry *next;
	struct in6_addr v6_host_addr;
	uint32_t me6_mtu;
	uint32_t pmtu_flags;
	uint64_t expires;
};

struct me6_pmtu_info {
	uint32_t type;
	uint32_t entry_num;
	uint32_t timeout;
	uint32_t force_fragment;
	uint64_t now;
};

#define ME6_ARP_HASH_SIZE 128
#define ME6_PR_HASH_SIZE 128
#define ME6_IIF_HASH_SIZE 128

#define ME6_ENT_HIT    0
#define ME6_ENT_NOTHIT -1

#define ME6_TRANSPORT_HED_STUB_OFFSET 118

struct me6_arphdr {
	unsigned char ar_sha[ETH_ALEN]; /* sender hardware address */
	unsigned char ar_sip[4];        /* sender IP address       */
	unsigned char ar_tha[ETH_ALEN]; /* target hardware address */
	unsigned char ar_tip[4];        /* target IP address       */
};

struct me6_arp_entry {
	uint32_t type;
	uint32_t code;
	struct me6_arp_entry *next;
	uint32_t planeid;
	struct in_addr daddr;
	unsigned char hw_addr[ETH_ALEN];
	char dummy[2];
};

struct me6_arp_info {
	uint32_t type;
	uint32_t entry_num;
};

struct me6_ethip_hdr {
#if defined(__BIG_ENDIAN_BITFIELD)
        uint16_t version : 4;
        uint16_t reserved : 12;
#else
        uint16_t reserved : 12;
        uint16_t version : 4;
#endif
};

union me6_ethip_hdr_ac {
	struct me6_ethip_hdr hdr;
	uint16_t hdr_all;
};

struct me6_pr_entry {
	uint32_t type;
	uint32_t plane_id;
	uint32_t prefix_len;
	struct in6_addr me6_addr;
	struct me6_pr_entry *next;
	char pad1[3];
	unsigned char hw_addr[ETH_ALEN];
	char pad2[2];
};

struct me6_pr_info {
	uint32_t type;
	uint32_t entry_num;
	uint32_t def_valid_flg;
	struct in6_addr me6_def_pre;
};

#define ME6_ETHIP_VERSION 0x3

#define ME6_NDP_HASH_SIZE 128
#define ME6_NDISC_RT_ON 1
#define ME6_NDISC_SOL_ON 1
#define ME6_NDISC_OVW_ON 1
#define ME6_NDISC_OPT 1

struct me6_ndp_entry {
	uint32_t type;
	uint32_t code;
	uint32_t plane_id;
	struct me6_ndp_entry *next;
	struct in6_addr daddr;
	unsigned char hw_addr[ETH_ALEN];
	char dummy[2];
};

struct me6_ndp_info {
	uint32_t type;
	uint32_t entry_num;
};

struct me6_dev_entry {
	uint32_t type;
	uint32_t code;
	struct me6_dev_entry *next;
	struct net_device *me6_dev;
};

struct me6_dev_info {
	uint32_t type;
	uint32_t entry_num;
};

struct me6_ipsec_entry {
	uint32_t type;
};

struct me6_ipsec_info {
	uint32_t type;
	uint32_t ipsec_flag;
};

struct me6_iif_entry {
        uint32_t type;
        uint32_t iif;
	uint32_t plane_id;
	struct me6_iif_entry *next;
	char pad[3];
};

struct me6_iif_info {
        uint32_t type;
        uint32_t entry_num;
};

#define ME6_IPSEC_OFF 0
#define ME6_IPSEC_ON 1
#define ME6_IPV6_MTU_MIN 1280

#ifdef __KERNEL__
struct sa46_tbl {
	struct sa46_tbl *next;
	struct net_device *dev;
	uint64_t encap_cnt;
	uint64_t decap_cnt;
	uint64_t decap_next_hdr_errors;
	uint64_t encap_tx_errors;
	uint64_t decap_tx_errors;
#if 0
	uint64_t decap_payload_len_errors;
        uint64_t decap_icmpv6_proto_errors;
        uint64_t decap_pmtu_set_errors;
	uint64_t encap_send_icmp;
	uint64_t encap_send_icmp_no_route;
	uint64_t encap_no_mac_header;
	uint64_t decap_ttl_errors;
	uint64_t encap_icmp;
	uint64_t encap_tcp;
	uint64_t encap_udp;
	uint64_t encap_other;
	uint64_t encap_tcp_ftp;
	uint64_t encap_tcp_ssh;
	uint64_t encap_tcp_telnet;
	uint64_t encap_tcp_smtp;
	uint64_t encap_tcp_dns;
	uint64_t encap_tcp_bootps;
	uint64_t encap_tcp_bootpc;
	uint64_t encap_tcp_http;
	uint64_t encap_tcp_pop3;
	uint64_t encap_tcp_netbios;
	uint64_t encap_tcp_imap;
	uint64_t encap_tcp_snmp;
	uint64_t encap_tcp_https;
	uint64_t encap_tcp_asmp_ctl;
	uint64_t encap_tcp_asmp_data;
	uint64_t encap_tcp_other;
	uint64_t encap_udp_ftp;
	uint64_t encap_udp_ssh;
	uint64_t encap_udp_telnet;
	uint64_t encap_udp_smtp;
	uint64_t encap_udp_dns;
	uint64_t encap_udp_bootps;
	uint64_t encap_udp_bootpc;
	uint64_t encap_udp_http;
	uint64_t encap_udp_pop3;
	uint64_t encap_udp_netbios;
	uint64_t encap_udp_imap;
	uint64_t encap_udp_snmp;
	uint64_t encap_udp_https;
	uint64_t encap_udp_asmp_ctl;
	uint64_t encap_udp_asmp_data;
	uint64_t encap_udp_other;
	uint64_t decap_icmp;
	uint64_t decap_tcp;
	uint64_t decap_udp;
	uint64_t decap_other;
	uint64_t decap_tcp_ftp;
	uint64_t decap_tcp_ssh;
	uint64_t decap_tcp_telnet;
	uint64_t decap_tcp_smtp;
	uint64_t decap_tcp_dns;
	uint64_t decap_tcp_bootps;
	uint64_t decap_tcp_bootpc;
	uint64_t decap_tcp_http;
	uint64_t decap_tcp_pop3;
	uint64_t decap_tcp_netbios;
	uint64_t decap_tcp_imap;
	uint64_t decap_tcp_snmp;
	uint64_t decap_tcp_https;
	uint64_t decap_tcp_asmp_ctl;
	uint64_t decap_tcp_asmp_data;
	uint64_t decap_tcp_other;
	uint64_t decap_udp_ftp;
	uint64_t decap_udp_ssh;
	uint64_t decap_udp_telnet;
	uint64_t decap_udp_smtp;
	uint64_t decap_udp_dns;
	uint64_t decap_udp_bootps;
	uint64_t decap_udp_bootpc;
	uint64_t decap_udp_http;
	uint64_t decap_udp_pop3;
	uint64_t decap_udp_netbios;
	uint64_t decap_udp_imap;
	uint64_t decap_udp_snmp;
	uint64_t decap_udp_https;
	uint64_t decap_udp_asmp_ctl;
	uint64_t decap_udp_asmp_data;
	uint64_t decap_udp_other;
	uint64_t decap_payload_len_errors;
	uint64_t decap_icmpv6_proto_errors;
	uint64_t decap_pmtu_set_errors;
#endif
	uint64_t encap_fragment_tx_error;
	uint64_t encap_fragment_tx_packet;
	uint64_t fragment_reasm_packet;
	uint64_t decap_next_hdr_type_errors;
	uint64_t proxy_ndp_backbone_tx_errors;
	uint64_t proxy_ndp_backbone_tx_packet;
	uint64_t proxy_ndp_stub_tx_errors;
	uint64_t proxy_ndp_stub_tx_packet;
	uint64_t proxy_arp_tx_errors;
	uint64_t proxy_arp_tx_packet;
};

enum {
	PROTO_FTP1 = 20,
	PROTO_FTP2 = 21,
	PROTO_SSH = 22,
	PROTO_TELNET = 23,
	PROTO_SMTP = 25,
	PROTO_DNS = 53,
	PROTO_BOOTPS = 67,
	PROTO_BOOTPC = 68,
	PROTO_HTTP = 80,
	PROTO_POP3 = 110,
	PROTO_NETBIOS = 139,
	PROTO_IMAP = 143,
	PROTO_SNMP = 161,
	PROTO_HTTPS = 443,
	PROTO_ASMP_CTL = 60230,
	PROTO_ASMP_DATA = 60231,
};

static struct net_device *me6_dev;

#ifdef ME6_DEBUG
static inline void dump_data(char *str, void *p, int len)
{
	char data[40];
	int i, j;
	unsigned char *d;

	d = (unsigned char *)p;

	memset(data, 0, sizeof(data));

	if (strcmp(str, "no") != 0)
		printk(KERN_INFO "\"%s\" len = %d\n", str, len);

	for (; len > 0; len -= 16, d += 16) {
		if (len >= 16) {
			sprintf(data, "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
				*d, *(d+1), *(d+2), *(d+3), *(d+4), *(d+5), *(d+6), *(d+7),
				*(d+8), *(d+9), *(d+10), *(d+11), *(d+12), *(d+13), *(d+14),
				*(d+15));
			printk(KERN_INFO "%s\n", data);
			memset(data, 0, sizeof(data));
		} else {
			for (i = 1, j = 0; len > 0 ; d++, len--, i++) {
				sprintf(&data[j], "%02x", *d);
				if (!(i % 4)) {
					j += 2;
					sprintf(&data[j], " ");
					j++;
				} else {
					j += 2;
				}
			}
			printk(KERN_INFO "%s\n", data);
		}
	}
}
#else
static inline void dump_data(char *str, void *p, int len) {return; }
#endif

#endif /* __KERNEL__ */

#endif /* _ME6E_H */
