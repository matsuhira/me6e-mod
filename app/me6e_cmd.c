/*
 * Command for ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * Statistics of ME6E
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 * Tamagawa        <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2010-2013 FUJITSU LIMITED
 *
 * Chaneges:
 * 2011.01.12 mitarai Statistical information is changed to 64bit.
 * 2012.09.14 mitarai Fragment support.
 * 2013.12.10 tamagawa me6e support
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/me6e.h"
#include "me6e_cli.h"

struct me6_tbl {
	struct me6_tbl *next;
	struct net_device *dev;
	uint64_t encap_cnt;
	uint64_t decap_cnt;
	uint64_t decap_next_hdr_errors;
	uint64_t encap_tx_errors;
	uint64_t decap_tx_errors;
#if 0
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

const char *stats_str[] = {
	"Encapsulation packets",
	"Decapsulation packets",
	"Next header errors(Decap)",
	"Encapsulation tx errors",
	"Decapsulation tx errors",
#if 0
	"Send ICMP packets(Encap)",
	"No route ICMP packets(Encap)",
	"No mac header(Encap)",
	"Ttl errors(Decap)",
	"Encapsulation icmp packets",
	"Encapsulation tcp packets",
	"Encapsulation udp packets",
	"Encapsulation other packets",
	"Encapsulation tcp packets(FTP)",
	"Encapsulation tcp packets(SSH)",
	"Encapsulation tcp packets(TELNET)",
	"Encapsulation tcp packets(SMTP)",
	"Encapsulation tcp packets(DNS)",
	"Encapsulation tcp packets(BOOTPS)",
	"Encapsulation tcp packets(BOOTPC)",
	"Encapsulation tcp packets(HTTP)",
	"Encapsulation tcp packets(POP3)",
	"Encapsulation tcp packets(NETBIOS)",
	"Encapsulation tcp packets(IMAP)",
	"Encapsulation tcp packets(SNMP)",
	"Encapsulation tcp packets(HTTPS)",
	"Encapsulation tcp packets(Any Source Multicast ctrl)",
	"Encapsulation tcp packets(Any Source Multicast data)",
	"Encapsulation tcp packets(OTHER)",
	"Encapsulation udp packets(FTP)",
	"Encapsulation udp packets(SSH)",
	"Encapsulation udp packets(TELNET)",
	"Encapsulation udp packets(SMTP)",
	"Encapsulation udp packets(DNS)",
	"Encapsulation udp packets(BOOTPS)",
	"Encapsulation udp packets(BOOTPC)",
	"Encapsulation udp packets(HTTP)",
	"Encapsulation udp packets(POP3)",
	"Encapsulation udp packets(NETBIOS)",
	"Encapsulation udp packets(IMAP)",
	"Encapsulation udp packets(SNMP)",
	"Encapsulation udp packets(HTTPS)",
	"Encapsulation udp packets(Any Source Multicast ctrl)",
	"Encapsulation udp packets(Any Source Multicast data)",
	"Encapsulation udp packets(OTHER)",
	"Decapsulation icmp packets",
	"Decapsulation tcp packets",
	"Decapsulation udp packets",
	"Decapsulation other packets",
	"Decapsulation tcp packets(FTP)",
	"Decapsulation tcp packets(SSH)",
	"Decapsulation tcp packets(TELNET)",
	"Decapsulation tcp packets(SMTP)",
	"Decapsulation tcp packets(DNS)",
	"Decapsulation tcp packets(BOOTPS)",
	"Decapsulation tcp packets(BOOTPC)",
	"Decapsulation tcp packets(HTTP)",
	"Decapsulation tcp packets(POP3)",
	"Decapsulation tcp packets(NETBIOS)",
	"Decapsulation tcp packets(IMAP)",
	"Decapsulation tcp packets(SNMP)",
	"Decapsulation tcp packets(HTTPS)",
	"Decapsulation tcp packets(Any Source Multicast ctrl)",
	"Decapsulation tcp packets(Any Source Multicast data)",
	"Decapsulation tcp packets(OTHER)",
	"Decapsulation udp packets(FTP)",
	"Decapsulation udp packets(SSH)",
	"Decapsulation udp packets(TELNET)",
	"Decapsulation udp packets(SMTP)",
	"Decapsulation udp packets(DNS)",
	"Decapsulation udp packets(BOOTPS)",
	"Decapsulation udp packets(BOOTPC)",
	"Decapsulation udp packets(HTTP)",
	"Decapsulation udp packets(POP3)",
	"Decapsulation udp packets(NETBIOS)",
	"Decapsulation udp packets(IMAP)",
	"Decapsulation udp packets(SNMP)",
	"Decapsulation udp packets(HTTPS)",
	"Decapsulation udp packets(Any Source Multicast ctrl)",
	"Decapsulation udp packets(Any Source Multicast data)",
	"Decapsulation udp packets(OTHER)",
	"Encapsulation fragmentation tx error",
	"Encapsulation fragmentation tx packet",
#endif
	"Encapsulation fragmentation tx error",
	"Encapsulation fragmentation tx packet",
	"Fragmentation reassemble packet",
	"Decapsulation next header type error",
	"Proxy ndp backbone tx error",
	"Proxy ndp backbone tx packet",
	"Proxy ndp stub tx error",
	"Proxy ndp stub tx packet",
	"Proxy arp tx error",
	"Proxy arp tx packet",
	NULL,
};

int me6_statistics_usage(int argc, char **argv)
{
	printf("\nUsage:\n");
	printf("statistics <device name>\n");

	return 0;
}

int me6_statistics(int argc, char **argv)
{
	int sock;
	struct ifreq req;
	int ret, i;
	struct me6_tbl me6_tbl;
	uint64_t *p;

	if (argc != 2) {
		/* command error */
		me6_statistics_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	memset(&me6_tbl, 0, sizeof(struct me6_tbl));

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("create socket error.");
		setuid(getuid());
		return ME6E_EXEERR_DEFAULT;
	}

	if(strlen(argv[1]) > ME6E_DEVNAME_MAX) {
		perror("device name length over.");
		close(sock);
		return ME6E_EXEERR_DEFAULT;
	}

	strcpy(req.ifr_name, argv[1]);
	req.ifr_data = &me6_tbl;
	ret = ioctl(sock, ME6_GETSTATISTICS, &req);
	if (ret == -1) {
		perror("ioctl error.");
		close(sock);
		return ME6E_EXEERR_DEFAULT;
	}

	close(sock);

	printf("\n     ME6E statistics (%s)\n\n", argv[1]);

	p = &me6_tbl.encap_cnt;
	for (i = 0; stats_str[i]; i++, p++)
		printf(" %20llu | %s\n", (long long unsigned int)*p, stats_str[i]);

	printf("\n");

	return 0;
}
