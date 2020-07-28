/*
 * Command for ME6E-NDP
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E-STUB-NDP setting commands.
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 * Tamagawa        <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * 2013.12.10 tamagawa New.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/me6e.h"
#include "me6e_cli.h"
#include "me6e_cli_err.h"

int me6_stub_ndp_usage(int argc, char **argv)
{

	/* me6_stub_ndp_usage */
	printf("\nUsage:\n");
	printf("ndp_proxy stub -s <ipv6addr> <macaddr> <planeid>\n");
	printf("ndp_proxy stub -d <ipv6addr> <planeid>\n");

	return 0;
}

static int me6_stub_ndp_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_STUB_NDP_CMD_ERR, ME6_STUB_NDP_PERR_SOCK);
		return -1;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_STUB_NDP_CMD_ERR, ME6_STUB_NDP_PERR_IOCTL);

	close(sock);
	return ret;
}

int me6_stub_ndp_set(int argc, char **argv)
{
	struct me6_ndp_entry sne;
	int ret, i;
	char tmp[128];
	char *p, *mac_p, *save_p, *err;

	if (argc != 6) {
		/* command error */
		me6_stub_ndp_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	/* NDP entry set */
	memset(&sne, 0, sizeof(sne));

	inet_pton(AF_INET6, argv[3], &sne.daddr);

	strcpy(tmp, argv[4]);
	for (i = 0, p = tmp; i < 6; i++, p = NULL) {
		mac_p = strtok_r(p, ":", &save_p);
		if (mac_p  == NULL)
			return ME6E_EXEERR_DEFAULT;

		sne.hw_addr[i] = strtol(mac_p, NULL, 16);
	}

	sne.plane_id = strtoul(argv[5], &err, 0);
	if (*err != '\0') {
		printf("%s : %s\n", ME6_ARP_ERR_CMDVAL, err);
		return ME6E_EXEERR_DEFAULT;
	}

#if 0
	/* search existing entry */
	sne.type = ME6_STUB_SEARCHNDPENTRY;
	ret = me6_stub_ndp_ioctl(&sne, ME6_STUB_NDP);
	if (ret != 0) {
		return ME6E_EXEERR_ADDR_EXIST;
	}
#endif

	/* set entry */
	sne.type = ME6_STUB_SETNDPENTRY;

	ret = me6_stub_ndp_ioctl(&sne, ME6_STUB_NDP);
	if (ret) {
		me6_debug_print(ME6_STUB_NDP_CMD_ERR, ME6_STUB_NDP_PERR_SET);
		return ME6E_EXEERR_DEFAULT;
	}

	return 0;
}

int me6_stub_ndp_del(int argc, char **argv)
{
	struct me6_ndp_entry sne;
	int ret;

	if (argc != 4) {
		/* command error */
		me6_stub_ndp_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	memset(&sne, 0, sizeof(sne));

	inet_pton(AF_INET6, argv[3], &sne.daddr);

	sne.type = ME6_STUB_FREENDPENTRY;

	ret = me6_stub_ndp_ioctl(&sne, ME6_STUB_NDP);
	if (ret) {
		me6_debug_print(ME6_STUB_NDP_CMD_ERR, ME6_STUB_NDP_PERR_DEL);
		return ME6E_EXEERR_ENTRY_NOT_EXSIST;
	}

	return ret;
}

static int me6_stub_ndp_get_ent_info(struct me6_ndp_info *sai)
{
	int ret;

	sai->type = ME6_STUB_GETNDPENTRYINFO;

	ret = me6_stub_ndp_ioctl(sai, ME6_STUB_NDP);
	if (ret) {
		me6_debug_print(ME6_STUB_NDP_CMD_ERR, ME6_STUB_NDP_PERR_GET);
		return ret;
	}

	return 0;

}

static int me6_stub_ndp_get_ent(struct me6_ndp_entry *sne)
{
	int ret;

	sne->type = ME6_STUB_GETNDPENTRY;

	ret = me6_stub_ndp_ioctl(sne, ME6_STUB_NDP);
	if (ret) {
		me6_debug_print(ME6_STUB_NDP_CMD_ERR, ME6_STUB_NDP_PERR_GET);
		return ret;
	}

	return 0;
}

int me6_stub_ndp_show(int argc, char **argv)
{
	struct me6_ndp_entry *sne;
	struct me6_ndp_info sni;
	int i, j, ret;
	char v6_str[40];
	char *tmp;

	memset(&sni, 0, sizeof(struct me6_ndp_info));

	ret = me6_stub_ndp_get_ent_info(&sni);
	if (ret) {
		/* command error */
		return ME6E_EXEERR_DEFAULT;
	}

	if (sni.entry_num == 0) {
		printf("ME6E-STUB-NDP Table is not set.\n");
		return 0;
	}

	tmp = malloc(sizeof(struct me6_ndp_entry) * sni.entry_num);
	if (tmp == NULL) {
		me6_debug_print(ME6_STUB_NDP_CMD_ERR, ME6_STUB_NDP_PERR_MALLOC);
		return ME6E_EXEERR_DEFAULT;
	}

	sne = (struct me6_ndp_entry *)tmp;

	memset(sne, 0, sizeof(struct me6_ndp_entry) * sni.entry_num);

	ret = me6_stub_ndp_get_ent(sne);
	if (ret) {
		free(tmp);
		return ME6E_EXEERR_DEFAULT;
	}

	printf("   PlaneID MACaddr           IPv6addr\n");
	printf("---------- ----------------- ---------------------------------------\n");

	for (i = 0; i < sni.entry_num; i++, sne++) {
		printf("%10u ", sne->plane_id);
		for (j = 0; j < ETH_ALEN; j++) {
			printf("%02x", sne->hw_addr[j]);
			if ((j + 1) < ETH_ALEN)
				printf(":");
		}
		printf(" ");
		inet_ntop(AF_INET6, &sne->daddr, v6_str, sizeof(v6_str));
		printf("%-39s", v6_str);
		printf("\n");
	}

	free(tmp);

	return 0;
}

