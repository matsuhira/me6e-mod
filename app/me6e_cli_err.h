/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E setting command error message.
 *
 * me6e_cli_err.h
 *
 * Authors:
 * tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * Changes:
 * 2013.08.26 tamagawa New
 * 2013.12.10 tamagawa me6e support
 *
 */

#ifndef ME6E_CLI_ERR_H_
#define ME6E_CLI_ERR_H_

/* error message */
#define ME6_ARP_ERR_CMDVAL "unknown command value"
#define ME6_IIF_ERR_CMDVAL "unknown command value"

/* PMTU perror */
#define ME6_PMTU_CMD_ERR		"sa46_pmtu_cmd:"
#define ME6_PMTU_PERR_SET		"set"
#define ME6_PMTU_PERR_DEL		"delete"
#define ME6_PMTU_PERR_GET		"get"
#define ME6_PMTU_PERR_TIME		"time"
#define ME6_PMTU_PERR_MALLOC		"malloc"
#define ME6_PMTU_PERR_SOCK		"socket"
#define ME6_PMTU_PERR_IOCTL		"ioctl"
#define ME6_PMTU_PERR_FRAG		"force fragment"

/* PR perror */
#define ME6_PR_CMD_ERR                 "me6_pr_cmd:"
#define ME6_PR_PERR_ADD                "add"
#define ME6_PR_PERR_DEL                "delete"
#define ME6_PR_PERR_GET                "get"
#define ME6_PR_PERR_MALLOC             "malloc"
#define ME6_PR_PERR_SOCK               "socket"
#define ME6_PR_PERR_IOCTL              "ioctl"
#define ME6_PR_PERR_SOCK_CLOSE		"socket close"

/* ARP perror */
#define ME6_ARP_CMD_ERR		"me6_arp_cmd:"
#define ME6_ARP_PERR_SOCK		"socket"
#define ME6_ARP_PERR_IOCTL		"ioctl"
#define ME6_ARP_PERR_SET		"set"
#define ME6_ARP_PERR_DEL		"del"
#define ME6_ARP_PERR_GET		"get"
#define ME6_ARP_PERR_MALLOC		"malloc"
#define ME6_ARP_PERR_SOCK_CLOSE	"socket close"

/* NDP perror */
#define ME6_NDP_CMD_ERR		"me6_stub_ndp_cmd:"
#define ME6_NDP_PERR_SOCK		"socket"
#define ME6_NDP_PERR_IOCTL		"ioctl"
#define ME6_NDP_PERR_SET		"set"
#define ME6_NDP_PERR_DEL		"del"
#define ME6_NDP_PERR_GET		"get"
#define ME6_NDP_PERR_MALLOC		"malloc"
#define ME6_NDP_PERR_SOCK_CLOSE	"socket close"

/* NDP perror */
#define ME6_STUB_NDP_CMD_ERR		"me6_ndp_cmd:"
#define ME6_STUB_NDP_PERR_SOCK		"socket"
#define ME6_STUB_NDP_PERR_IOCTL	"ioctl"
#define ME6_STUB_NDP_PERR_SET		"set"
#define ME6_STUB_NDP_PERR_DEL		"del"
#define ME6_STUB_NDP_PERR_GET		"get"
#define ME6_STUB_NDP_PERR_MALLOC	"malloc"

/* DEV perror */
#define ME6_DEV_CMD_ERR		"me6_dev_cmd:"
#define ME6_DEV_PERR_SOCK		"socket"
#define ME6_DEV_PERR_IOCTL		"ioctl"
#define ME6_DEV_PERR_SET		"set"
#define ME6_DEV_PERR_SOCK_CLOSE	"socket close"

/* IPsec perror */
#define ME6_IPSEC_CMD_ERR                 "me6_ipsec_cmd:"
#define ME6_IPSEC_PERR_SET               "set"
#define ME6_IPSEC_PERR_GET		"get"
#define ME6_IPSEC_PERR_SOCK               "socket"
#define ME6_IPSEC_PERR_IOCTL              "ioctl"
#define ME6_IPSEC_PERR_SOCK_CLOSE		"socket close"

/* ARP perror */
#define ME6_IIF_CMD_ERR         "me6_iif_cmd:"
#define ME6_IIF_PERR_SOCK               "socket"
#define ME6_IIF_PERR_IOCTL              "ioctl"
#define ME6_IIF_PERR_SET                "set"
#define ME6_IIF_PERR_DEL                "del"
#define ME6_IIF_PERR_GET                "get"
#define ME6_IIF_PERR_MALLOC             "malloc"
#define ME6_IIF_PERR_SOCK_CLOSE "socket close"

/* debug on = 1, off = 0 */
#define ME6_DEBUG_FLAG 0

#endif /* ME6E_CLI_ERR_H_ */
