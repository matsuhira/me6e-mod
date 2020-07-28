/*
 * Command for ME6E-NDP
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E-NDP setting commands.
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

int me6_ndp_usage(int argc, char **argv)
{
	/* me6_ndp_usage */
	printf("\nUsage:\n");
	printf("ndp_proxy backbone -s <macaddr>\n");
	printf("ndp_proxy backbone -d <macaddr>\n");
	printf("ndp_proxy stub -s <ipv6addr> <macaddr> <planeid>\n");
	printf("ndp_proxy stub -d <ipv6addr> <planeid>\n");
	return 0;
}

int me6_backbone_ndp_usage(int argc, char **argv)
{
	/* me6_backbone_ndp_usage */
	printf("\nUsage:\n");
	printf("ndp_proxy backbone -s <macaddr>\n");
	printf("ndp_proxy backbone -d <macaddr>\n");
	return 0;
}

static int me6_ndp_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret, ret2;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_NDP_CMD_ERR, ME6_NDP_PERR_SOCK);
		return ME6E_EXEERR_DEFAULT;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_NDP_CMD_ERR, ME6_NDP_PERR_IOCTL);

        ret2 = close(sock);
        if (ret2)
                me6_debug_print(ME6_DEV_CMD_ERR, ME6_NDP_PERR_SOCK_CLOSE);

	return ret;
}

int me6_ndp_set(int argc, char **argv)
{
	struct me6_ndp_entry sne;
	int ret, i;
	char tmp[128];
	char *p, *mac_p, *save_p;

	if (argc != 4) {
		/* command error */
		me6_backbone_ndp_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	/* NDP entry set */
	memset(&sne, 0, sizeof(sne));

	strcpy(tmp, argv[3]);
	for (i = 0, p = tmp; i < 6; i++, p = NULL) {
		mac_p = strtok_r(p, ":", &save_p);
		if (mac_p  == NULL)
			return ME6E_EXEERR_DEFAULT;

		sne.hw_addr[i] = strtol(mac_p, NULL, 16);
	}

#if 0
	/* search existing entry */
	sne.type = ME6_SEARCHNDPENTRY;
	ret = me6_ndp_ioctl(&sne, ME6_NDP);
	if (ret != 0) {
		return ME6E_EXEERR_ADDR_EXIST;
	}
#endif

	/* set entry */
	sne.type = ME6_SETNDPENTRY;

	ret = me6_ndp_ioctl(&sne, ME6_NDP);
	if (ret) {
		me6_debug_print(ME6_NDP_CMD_ERR, ME6_NDP_PERR_SET);
		return ME6E_EXEERR_DEFAULT;
	}

	return 0;
}

int me6_ndp_del(int argc, char **argv)
{
	struct me6_ndp_entry sne;
	int ret, i;
	char tmp[128];
	char *p, *mac_p, *save_p;

	if (argc != 4) {
		/* command error */
		me6_backbone_ndp_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	memset(&sne, 0, sizeof(sne));
	strcpy(tmp, argv[3]);
	for (i = 0, p = tmp; i < 6; i++, p = NULL) {
		mac_p = strtok_r(p, ":", &save_p);
		if (mac_p == NULL)
			return ME6E_EXEERR_DEFAULT;

		sne.hw_addr[i] = strtol(mac_p, NULL, 16);
	}

	sne.type = ME6_FREENDPENTRY;

	ret = me6_ndp_ioctl(&sne, ME6_NDP);
	if (ret) {
		me6_debug_print(ME6_NDP_CMD_ERR, ME6_NDP_PERR_DEL);
		return ME6E_EXEERR_ENTRY_NOT_EXSIST;
	}

	return ret;
}

static int me6_ndp_get_ent_info(struct me6_ndp_info *sai)
{
	int ret;

	sai->type = ME6_GETNDPENTRYINFO;

	ret = me6_ndp_ioctl(sai, ME6_NDP);
	if (ret) {
		me6_debug_print(ME6_NDP_CMD_ERR, ME6_NDP_PERR_GET);
		return ret;
	}

	return 0;

}

static int me6_ndp_get_ent(struct me6_ndp_entry *sne)
{
	int ret;

	sne->type = ME6_GETNDPENTRY;

	ret = me6_ndp_ioctl(sne, ME6_NDP);
	if (ret) {
		me6_debug_print(ME6_NDP_CMD_ERR, ME6_NDP_PERR_GET);
		return ret;
	}

	return 0;
}

int me6_ndp_show(int argc, char **argv)
{
	struct me6_ndp_entry *sne;
	struct me6_ndp_info sni;
	int i, j, ret;
	char *tmp;

	memset(&sni, 0, sizeof(struct me6_ndp_info));

	ret = me6_ndp_get_ent_info(&sni);
	if (ret) {
		/* command error */
		return ME6E_EXEERR_DEFAULT;
	}

	if (sni.entry_num == 0) {
		printf("ME6E-NDP Table is not set.\n");
		return 0;
	}

	tmp = malloc(sizeof(struct me6_ndp_entry) * sni.entry_num);
	if (tmp == NULL) {
		me6_debug_print(ME6_NDP_CMD_ERR, ME6_NDP_PERR_MALLOC);
		return ME6E_EXEERR_DEFAULT;
	}

	sne = (struct me6_ndp_entry *)tmp;

	memset(sne, 0, sizeof(struct me6_ndp_entry) * sni.entry_num);

	ret = me6_ndp_get_ent(sne);
	if (ret) {
		free(tmp);
		return ME6E_EXEERR_DEFAULT;
	}

	printf("MACaddr\n");
	printf("-----------------\n");

	for (i = 0; i < sni.entry_num; i++, sne++) {
		for (j = 0; j < ETH_ALEN; j++) {
			printf("%02x", sne->hw_addr[j]);
			if ((j + 1) < ETH_ALEN)
				printf(":");
		}
		printf("\n");
	}

	free(tmp);

	return 0;
}
