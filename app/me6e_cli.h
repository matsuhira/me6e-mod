/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E setting command.
 *
 * me6e_cli.h
 *
 * Authors:
 * tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * Changes:
 * 2013.02.18 tamagawa New
 * 2013.12.10 tamagawa me6e support
 *
 */

#ifndef ME6E_CLI_H_
#define ME6E_CLI_H_

#define PUT_PROMPT do {printf("me6e >"); fflush(stdout); } while (0)
#define PUT_BAR_T(str)	do {printf("\n***********************************************************************\n"); \
			printf("* %s\n", str); \
			printf("***********************************************************************\n"); \
			 } while (0)
#define ME6E_CLI_HISTORY_MAX 20
#define ME6E_CLI_BUFSIZE 512
#define ME6E_TOKEN_MAX 8
#define ME6E_TOKEN_LEN_MAX 64
#define ME6E_TAB_SIZE 8
#define ME6E_TAB_WIDTH 60
#define ME6E_CLI_HISTORY_MAX 20
#define ME6E_DEVNAME_MAX 20

/* chk func error */
#define ME6E_CHKERR_SYNTAX		-2
#define ME6E_CHKERR_IPV4ADDR		-3
#define ME6E_CHKERR_IPV4MASK_VALUE	-4
#define ME6E_CHKERR_IPV6ADDR		-5
#define ME6E_CHKERR_INVALID_VALUE	-6
#define ME6E_CHKERR_FILE_NOT_FOUND	-7
#define ME6E_CHKERR_NSNAME_LEN		-8
#define ME6E_CHKERR_NSNAME		-9
#define ME6E_CHKERR_IFNAME_LEN		-10
#define ME6E_CHKERR_IF_EXSIST		-11
#define ME6E_CHKERR_IP_CMD_ERROR	-12
#define ME6E_CHKERR_IF_NOT_EXSIST	-13
#define ME6E_CHKERR_SWITCH		-14
#define ME6E_CHKERR_MAC		-15

/* execution error */
#define ME6E_EXEERR_DEFAULT		-100
#define ME6E_EXEERR_USAGE		-101
#define ME6E_EXEERR_FILE_NOT_FOUND	-102
#define ME6E_EXEERR_ADDR_EXIST		-103
#define ME6E_EXEERR_ENTRY_NOT_EXSIST	-104
#define ME6E_EXEERR_MACADDR_EXIST	-105

/* cmmand success */
#define ME6E_COM_SUCCESS		0

#define max(a, b) ((a) > (b) ? (a) : (b))

struct me6_cli_cmd_tbl {
	char *cmd_str;
	char *cmd_exp;
	struct me6_cli_cmd_tbl *next;
	int (*chk_func)(char *, char *);
	int (*call_func)(int, char **);
	int max_len;
};

typedef struct hist_tbl {
	struct hist_tbl *next;
	struct hist_tbl *prev;
	char str[ME6E_CLI_BUFSIZE];
} hist_t;

/* system command */
typedef struct me6_sys_cmd_tbl {
	char *cmd_str;
} me6_sys_cmd_tbl_t;

struct me6_in6_ifreq {
	struct in6_addr ifr6_addr;
	u_int32_t ifr6_prefixlen;
	int ifr6_ifindex;
};

/* cli main */
int me6_call_cmd(char *);
void me6_blank_del(char *);

/* common call */
void me6_debug_print(char *, char *);
int me6_com_help(int, char **);
int me6_load_conf_usage(int, char **);
int me6_load_conf(int, char **);

/* PMTU */
int me6_pmtu_usage(int, char **);
int me6_pmtu_set(int, char **);
int me6_pmtu_del(int, char **);
int me6_pmtu_time(int, char **);
int me6_pmtu_show(int, char **);
int me6_pmtu_get_ent_num(struct me6_pmtu_info *);
int me6_pmtu_get_ent(struct me6_pmtu_entry *);
int me6_pmtu_set_force_fragment(int, char **);

/* PR */
int me6_pr_usage(int, char **);
int me6_pr_entry_add(int, char **);
int me6_pr_entry_del(int, char **);
int me6_pr_entry_show(int, char **);
int me6_pr_entry_file(int, char **);

/* ARP */
int me6_arp_usage(int, char **);
int me6_arp_set(int, char **);
int me6_arp_del(int, char **);
int me6_arp_show(int, char **);

/* NDP */
int me6_ndp_usage(int, char **);
int me6_backbone_ndp_usage(int, char **);
int me6_ndp_set(int, char **);
int me6_ndp_del(int, char **);
int me6_ndp_show(int, char **);

/* stub NDP */
int me6_stub_ndp_usage(int, char **);
int me6_stub_ndp_set(int, char **);
int me6_stub_ndp_del(int, char **);
int me6_stub_ndp_show(int, char **);

/* DEV */
int me6_dev_usage(int, char **);
int me6_dev_set(int, char **);

/* IPsec */
//int me6_ipsec_usage(int, char **);
int me6_ipsec_set(int, char **);
int me6_ipsec_show(int, char **);

/* IIF */
int me6_iif_usage(int, char **);
int me6_iif_set(int, char **);
int me6_iif_del(int, char **);
int me6_iif_show(int, char **);

/* statistics */
int me6_statistics_usage(int, char **);
int me6_statistics(int, char **);

/* check関数 */
int me6_chk_ipv4_msk(char *, char *);
int me6_chk_ipv4(char *, char *);
int me6_chk_ipv6(char *, char *);
int me6_chk_num(char *, char *);
int me6_chk_filepath(char *, char *);
int me6_chk_ifname(char *, char *);
int me6_dummy(char *, char *);
int me6_chk_mac(char *, char *);
int me6_chk_swich(char *, char *);

extern me6_sys_cmd_tbl_t cmd_sys[];
extern struct me6_cli_cmd_tbl cmd_root[];

#endif /* ME6E_CLI_H_ */
