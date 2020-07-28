/*
 * Command for SA46T path mtu discovery
 * Stateless Automatic IPv4 over IPv6 Tunneling
 *
 * SA46T PMTU setting commands.
 *
 * Authors:
 * Mitarai           <m.mitarai@jp.fujitsu.com>
 * Tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * Copyright (C)2012-2013 FUJITSU LIMITED
 *
 * 2016.06.01 tamagawa New.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/me6e.h"
#include "me6e_cli.h"
#include "me6e_cli_err.h"

static int me6_pmtu_ioctl(void *, int);
static int me6_pmtu_sort(const void *, const void *);

int me6_pmtu_usage(int argc, char **argv)
{

	printf("\nUsage:\n");
	printf("pmtu -s <ipv6_addr> <mtu_value>\n"
	       "pmtu -d <ipv6_addr>\n"
	       "pmtu -t <timeout_value>\n");
#if 0
	       "pmtu -f <on-off>\n");
#endif
	return 0;
}

static int me6_pmtu_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_SOCK);
		return -1;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_IOCTL);

	close(sock);
	return ret;
}

int me6_pmtu_set_force_fragment(int argc, char **argv)
{
	struct me6_pmtu_info spmi;
	int ret;

	if (argc != 3) {
		me6_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	memset(&spmi, 0, sizeof(struct me6_pmtu_info));

	if (strcmp(argv[2], "on") == 0)
		spmi.force_fragment = FORCE_FRAGMENT_ON;

	spmi.type = ME6_SETPMTUINFO;

	ret = me6_pmtu_ioctl(&spmi, ME6_PMTU);
	if (ret) {
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_FRAG);
		return ret;
	}

	return 0;
}

int me6_pmtu_set(int argc, char **argv)
{
	struct in6_addr v6addr;
	struct me6_pmtu_entry ent;
	uint32_t mtu;
	char *err = NULL;
	int ret;

	if (argc != 4) {
		me6_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	inet_pton(AF_INET6, argv[2], &v6addr);

	mtu = strtoul(argv[3], &err, 0);

	/* create entry */
	memset(&ent, 0, sizeof(struct me6_pmtu_entry));
	ent.v6_host_addr = v6addr;
	ent.me6_mtu = mtu;
	ent.pmtu_flags = ME6_PMTU_STATIC_ENTRY;
	ent.type = ME6_SETPMTUENTRY;

	ret = me6_pmtu_ioctl(&ent, ME6_PMTU);
	if (ret)
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_SET);

	return ret;
}

int me6_pmtu_del(int argc, char **argv)
{
	struct in6_addr v6addr;
	struct me6_pmtu_entry ent;
	int ret;

	if (argc != 3) {
		me6_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	inet_pton(AF_INET6, argv[2], &v6addr);

	/* create entry */
	memset(&ent, 0, sizeof(ent));
	ent.v6_host_addr = v6addr;
	ent.type = ME6_FREEPMTUENTRY;

	ret = me6_pmtu_ioctl(&ent, ME6_PMTU);
	if (ret) {
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_DEL);
		printf("specified entry does not exist.\n");
		return 0;	//ここでエラーメッセージを出すため、復帰値は0
	}

	return ret;
}

int me6_pmtu_time(int argc, char **argv)
{
	struct me6_pmtu_info inf;
	uint32_t time;
	int ret;
	char *err;

	if (argc != 3) {
		me6_pmtu_usage(argc, argv);
		return 0;	//Useageの表示のみでエラーにはしない。
	}

	memset(&inf, 0, sizeof(struct me6_pmtu_info));
	time = strtoul(argv[2], &err, 0);
	if (time < ME6_PMTU_EXPIRE_MIN || time > ME6_PMTU_EXPIRE_MAX) {
		printf("invalid timer value. %s\nrange is from %d to %d.\n", optarg,
		       ME6_PMTU_EXPIRE_MIN, ME6_PMTU_EXPIRE_MAX);
		return -1;
	}
	inf.timeout = time;
	inf.type = ME6_SETPMTUTIME;

	ret = me6_pmtu_ioctl(&inf, ME6_PMTU);
	if (ret)
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_TIME);

	return ret;
}

static int me6_pmtu_sort(const void *a, const void *b)
{

	struct me6_pmtu_entry p, q;
	char c[40], d[40];

	memset(c, 0, sizeof(c));
	memset(d, 0, sizeof(d));

	memcpy(&p, a, sizeof(struct me6_pmtu_entry));
	memcpy(&q, b, sizeof(struct me6_pmtu_entry));

	inet_ntop(AF_INET6, &p.v6_host_addr, c, sizeof(c));
	inet_ntop(AF_INET6, &q.v6_host_addr, d, sizeof(d));

	return strcmp(c, d);
}

int me6_pmtu_show(int argc, char **argv)
{
	struct me6_pmtu_info inf;
	struct me6_pmtu_entry *ent;
	int ret, i;
	long long int time;
	char v6_str[40];
	char *tmp;

	memset(&inf, 0, sizeof(struct me6_pmtu_info));

	ret = me6_pmtu_get_ent_num(&inf);
	if (ret) {
		/* command error */
		return -1;
	}

#if 0
	if (inf.force_fragment == FORCE_FRAGMENT_OFF) {
		printf("force fragment = OFF\n");
	} else {
		printf("force fragment = ON\n");
	}
#endif
	printf("Address                                  MTU   Life(sec) : initial value = %d\n", inf.timeout / ME6_SYS_CLOCK);
	printf("---------------------------------------  ----  --------\n");

	if (!inf.entry_num) {
		printf("me6e pmtu table is not set.\n");
		return 0;
	}

	tmp = malloc((sizeof(struct me6_pmtu_entry) * inf.entry_num));
	if (!tmp) {
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_MALLOC);
		return -1;
	}

	ent = (struct me6_pmtu_entry *)tmp;

	memset(ent, 0, sizeof(struct me6_pmtu_entry) * inf.entry_num);

	ret = me6_pmtu_get_ent(ent);
	if (ret) {
		free(tmp);
		return -1;
	}

	qsort((void *)ent, inf.entry_num, sizeof(struct me6_pmtu_entry), me6_pmtu_sort);

	for (i = 0; i < inf.entry_num; i++, ent++) {
		memset(v6_str, 0, sizeof(v6_str));
		inet_ntop(AF_INET6, &ent->v6_host_addr, v6_str, sizeof(v6_str));
		printf("%-39s  ", v6_str);
		printf("%-4d  ", ent->me6_mtu);
		if (ent->expires) {
			time = ent->expires - inf.now;
			if (time < 0) {
				printf("---\n");
			} else {
				time /= ME6_SYS_CLOCK;
				printf("%-lld\n", time);
			}
		} else {
			printf("static\n");
		}
	}
	printf("Total entries : %d\n", inf.entry_num);

	free(tmp);

	return 0;
}

int me6_pmtu_get_ent_num(struct me6_pmtu_info *spmi)
{
	int ret;

	spmi->type = ME6_GETPMTUENTRYNUM;

	ret = me6_pmtu_ioctl(spmi, ME6_PMTU);
	if (ret) {
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_GET);
		return ret;
	}

	return 0;

}

int me6_pmtu_get_ent(struct me6_pmtu_entry *spme)
{
	int ret;

	spme->type = ME6_GETPMTUENTRY;

	ret = me6_pmtu_ioctl(spme, ME6_PMTU);
	if (ret) {
		me6_debug_print(ME6_PMTU_CMD_ERR, ME6_PMTU_PERR_GET);
		return ret;
	}

	return 0;
}
