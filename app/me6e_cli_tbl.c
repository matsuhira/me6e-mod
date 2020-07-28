/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * setting command common function.
 *
 * me6e_cli_tbl.c
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


#include <arpa/inet.h>
#include <linux/netdevice.h>
#include "../include/me6e.h"
#include "me6e_cli.h"

/* -----------------------------------------------------------------------------
   statistics cmmand
   -----------------------------------------------------------------------------*/
/* statistics root */
static struct me6_cli_cmd_tbl cmd_statistics[] = {
	{"<device name>", "set me6e device name", 0, me6_chk_ifname, me6_statistics},
	{0}
};

/* -----------------------------------------------------------------------------
   load conf
   -----------------------------------------------------------------------------*/
/* load conf */
static struct me6_cli_cmd_tbl load_conf[] = {
	{"<filepath>", "setting file filepath", 0, me6_chk_filepath, me6_load_conf},
	{0}
};

/* conf root */
static struct me6_cli_cmd_tbl cmd_conf[] = {
	{"load", "xxx", load_conf, 0, me6_load_conf_usage},
	{0}
};

/* -----------------------------------------------------------------------------
   dev cmmand
   -----------------------------------------------------------------------------*/

/*
 * set
 */
/* dev root */
static struct me6_cli_cmd_tbl cmd_dev[] = {
	{"-s", "set device", 0, 0, me6_dev_set},
	{0}
};

/* -----------------------------------------------------------------------------
   ndp cmmand (backbone, stub)
   -----------------------------------------------------------------------------*/

/*
 * delete backbone
 */
/* set mac addr */
static struct me6_cli_cmd_tbl del_ndp_mac[] = {
	{"<macaddr>", "mac address", 0, me6_chk_mac, me6_ndp_del},
	{0}
};

/*
 * set backbone
 */
/* set mac addr */
static struct me6_cli_cmd_tbl set_ndp_mac[] = {
	{"<macaddr>", "mac address", 0, me6_chk_mac, me6_ndp_set},
	{0}
};

/*
 * delete stub
 */
/* set mac addr */
static struct me6_cli_cmd_tbl del_stub_ndp_v6addr[] = {
	{"<ipv6addr>", "ip v6 address", 0, me6_chk_ipv6, me6_stub_ndp_del},
	{0}
};

/*
 * set stub
 */
/* set planeid */
static struct me6_cli_cmd_tbl set_stub_ndp_planeid[] = {
        {"<0-4294967295>", "setting planeid", 0, me6_chk_num, me6_stub_ndp_set},
        {0}
};

/* set mac addr */
static struct me6_cli_cmd_tbl set_stub_ndp_mac[] = {
	{"<macaddr>", "mac address", set_stub_ndp_planeid, me6_chk_mac, me6_stub_ndp_usage},
	{0}
};

/* set ipv6 addr */
static struct me6_cli_cmd_tbl set_stub_ndp_v6addr[] = {
	{"<ipv6addr>", "ip v6 address", set_stub_ndp_mac, me6_chk_ipv6, me6_stub_ndp_usage},
	{0}
};

/*
 * root
 */
/* ndp backbone root */
static struct me6_cli_cmd_tbl cmd_bb_ndp[] = {
	{"-s", "set ndp entry", set_ndp_mac, 0, me6_ndp_show},
	{"-d", "delete ndp entry", del_ndp_mac, 0, me6_ndp_show},
	{0}
};

/* ndp stub root */
static struct me6_cli_cmd_tbl cmd_stub_ndp[] = {
	{"-s", "set ndp entry", set_stub_ndp_v6addr, 0, me6_stub_ndp_show},
	{"-d", "delete ndp entry", del_stub_ndp_v6addr, 0, me6_stub_ndp_show},
	{0}
};

/* ndp root */
static struct me6_cli_cmd_tbl cmd_ndp[] = {
	{"backbone", "backbone", cmd_bb_ndp, 0, me6_ndp_usage},
	{"stub", "stub", cmd_stub_ndp, 0, me6_ndp_usage},
	{0}
};

/* -----------------------------------------------------------------------------
   arp cmmand
   -----------------------------------------------------------------------------*/

/*
 * delete
 */
/* set plane id */
static struct me6_cli_cmd_tbl del_arp_planeid[] = {
	{"<0-4294967295>", "setting planeid", 0, me6_chk_num, me6_arp_del},
	{0}
};

/* set ip v4 addr */
static struct me6_cli_cmd_tbl del_arp_v4addr[] = {
	{"<ipv4addr>", "ip v4 address", del_arp_planeid, me6_chk_ipv4, me6_arp_usage},
	{0}
};

/*
 * set
 */
/* set plane id */
static struct me6_cli_cmd_tbl set_arp_planeid[] = {
	{"<0-4294967295>", "setting planeid", 0, me6_chk_num, me6_arp_set},
	{0}
};

/* set mac addr */
static struct me6_cli_cmd_tbl set_arp_mac[] = {
	{"<macaddr>", "mac address", set_arp_planeid, me6_chk_mac, me6_arp_usage},
	{0}
};

/* set ip v4 addr */
static struct me6_cli_cmd_tbl set_arp_v4addr[] = {
	{"<ipv4addr>", "ip v4 address", set_arp_mac, me6_chk_ipv4, me6_arp_usage},
	{0}
};

/* arp root */
static struct me6_cli_cmd_tbl cmd_arp[] = {
	{"-s", "set arp entry", set_arp_v4addr, 0, me6_arp_show},
	{"-d", "delete arp entry", del_arp_v4addr, 0, me6_arp_show},
	{0}
};

/* -----------------------------------------------------------------------------
   pr cmmand
   -----------------------------------------------------------------------------*/

/*
 *  * file
 *   */
/* entry add from file */
static struct me6_cli_cmd_tbl pr_filepath[] = {
        {"<filepath>", "setting file filepath", 0, me6_chk_filepath, me6_pr_entry_file},
        {0}
};

/*
 * delete
 */
/* delete plane id */
static struct me6_cli_cmd_tbl del_pr_plane_id[] = {
	{"<0-4294967295>", "planeID", 0, me6_chk_num, me6_pr_entry_del},
	{0}
};

/* delete ip MAC addr */
static struct me6_cli_cmd_tbl del_pr_MACaddr[] = {
	{"<MAC address>", "MAC address", del_pr_plane_id, me6_chk_mac, me6_pr_usage},
	{0}
};

/* delete prefix */
static struct me6_cli_cmd_tbl del_prefix_field[] = {
	{"pr-prefix", "delete pr config", del_pr_MACaddr, 0, me6_pr_usage},
	{"default", "delete default prefix", 0, 0, me6_pr_entry_del},
	{0}
};

/*
 * set
 */
/* set default me6e prefix */
static struct me6_cli_cmd_tbl set_default_me6_prefix[] = {
        {"<me6e-prefix>", "default me6e-prefix and planeID", 0, me6_chk_ipv6, me6_pr_entry_add},
        {0}
};

/* set plane id */
static struct me6_cli_cmd_tbl set_pr_plane_id[] = {
        {"<0-4294967295>", "planeID", 0, me6_chk_num, me6_pr_entry_add},
        {0}
};

#if 0
/* set me6e prefix */
static struct me6_cli_cmd_tbl set_pr_me6_prefix[] = {
        {"<me6e-prefix>", "me6e-prefix", set_pr_plane_id, me6_chk_ipv6, me6_pr_usage},
        {0}
};
#else
/* set me6e prefix */
static struct me6_cli_cmd_tbl set_pr_me6_prefix[] = {
        {"<me6e-prefix and planeID>", "me6e-prefix and planeID", set_pr_plane_id, me6_chk_ipv6, me6_pr_usage},
        {0}
};
#endif

/* set Mac addr */
static struct me6_cli_cmd_tbl set_pr_MACaddr[] = {
        {"<MAC address>", "MAC address", set_pr_me6_prefix, me6_chk_mac, me6_pr_usage},
        {0}
};

/* set prefix */
static struct me6_cli_cmd_tbl set_prefix_field[] = {
        {"pr-prefix", "set me6e pr prefix", set_pr_MACaddr, 0, me6_pr_usage},
        {"default", "set default prefix", set_default_me6_prefix, 0, me6_pr_usage},
        {0}
};

/* pr root */
static struct me6_cli_cmd_tbl cmd_pr[] = {
	{"-s", "set pr entry", set_prefix_field, 0, me6_pr_entry_show},
	{"-d", "delete", del_prefix_field, 0, me6_pr_entry_show},
	{"-f", "setting for file", pr_filepath, 0, me6_pr_entry_show},
	{0}
};

#if 0
/* -----------------------------------------------------------------------------
   ipsec cmmand
   -----------------------------------------------------------------------------*/

/* ipsec root */
static struct me6_cli_cmd_tbl cmd_ipsec[] = {
	{"flag", "ipsec flag", 0, 0, me6_ipsec_set},
	{0}
};
#endif // PMTU

/* -----------------------------------------------------------------------------
 *    iif cmmand
 * -----------------------------------------------------------------------------*/

/*
 *  * delete
 *   */
/* set ifindex */
static struct me6_cli_cmd_tbl del_iif_ifindex[] = {
        {"<0-4294967295>", "setting ifindex", 0, me6_chk_num, me6_iif_del},
        {0}
};

/*
 *  * set
 *   */
/* set plane id */
static struct me6_cli_cmd_tbl set_iif_planeid[] = {
        {"<0-4294967295>", "setting planeid", 0, me6_chk_num, me6_iif_set},
        {0}
};

/* ifindex */
static struct me6_cli_cmd_tbl set_iif_ifindex[] = {
        {"<0-4294967295>", "setting ifindex", set_iif_planeid, me6_chk_num, me6_iif_usage},
        {0}
};

/* arp root */
static struct me6_cli_cmd_tbl cmd_iif[] = {
        {"-s", "set iif entry", set_iif_ifindex, 0, me6_iif_show},
        {"-d", "delete iif entry", del_iif_ifindex, 0, me6_iif_show},
        {0}
};

/* -----------------------------------------------------------------------------
   pmtu cmmand
   -----------------------------------------------------------------------------*/
#if 0
/*
 * set force fragment
 */
/* set force fragment flag */
static struct me6_cli_cmd_tbl set_pmtu_force_fragment[] = {
	{"<on-off>", "force fragment flag", 0, me6_chk_swich, me6_pmtu_set_force_fragment},
	{0}
};
#endif

/*
 * expire
 */
/* set timeout */
static struct me6_cli_cmd_tbl set_pmtu_expire[] = {
	{"<300-86400>", "expire time", 0, me6_chk_num, me6_pmtu_time},
	{0}
};

/*
 * delete
 */
/* delete ip v6 addr */
static struct me6_cli_cmd_tbl del_pmtu_v6addr[] = {
	{"<ipv6addr>", "ip v6 address", 0, me6_chk_ipv6, me6_pmtu_del},
	{0}
};

/*
 * set
 */
/* set time value */
static struct me6_cli_cmd_tbl set_pmtu_mtu[] = {
	{"<1280-1500>", "Maximum Transmission Unit", 0, me6_chk_num, me6_pmtu_set},
	{0}
};

/* set ip v6 addr */
static struct me6_cli_cmd_tbl set_pmtu_v6addr[] = {
	{"<ipv6addr>", "ip v6 address", set_pmtu_mtu, me6_chk_ipv6, me6_pmtu_usage},
	{0}
};

/* pmtu root */
static struct me6_cli_cmd_tbl cmd_pmtu[] = {
	{"-s", "set", set_pmtu_v6addr, 0, me6_pmtu_show},
	{"-d", "delete", del_pmtu_v6addr, 0, me6_pmtu_show},
	{"-t", "pmtu entry expire time", set_pmtu_expire, 0, me6_pmtu_show},
#if 0
	{"-f", "set force fragment", set_pmtu_force_fragment, 0, me6_pmtu_show},
#endif
	{0}
};

/*
 * root
 */
struct me6_cli_cmd_tbl cmd_root[] = {
	{"pr", "setting ME6E PR", cmd_pr, 0, 0},
	{"arp_proxy", "setting ME6E ARP proxy", cmd_arp, 0, 0},
	{"ndp_proxy", "setting ME6E NDP proxy", cmd_ndp, 0, 0},
	{"pmtu", "setting PMTU", cmd_pmtu, 0, me6_pmtu_show},
	{"dev", "setting ME6E device", cmd_dev, 0, 0},
	{"statistics", "output ME6E statistics", cmd_statistics, 0, 0},
	{"config", "save & load config", cmd_conf, 0, 0},
#if 0
	{"ipsec", "ipsec setup", cmd_ipsec, 0, me6_ipsec_show},
#endif // PMTU
	{"iif", "iif setup", cmd_iif, 0, 0},
	{"help", "command manual", 0, 0, me6_com_help},
	{"exit", "exit ME6E cli", 0, 0, 0},
	{0}
};

