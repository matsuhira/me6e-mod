/*
 * Command for ME6E-ARP
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E-ARP setting commands.
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

int me6_arp_usage(int argc, char **argv)
{

	/* me6_arp_usage */
	printf("\nUsage:\n");
	printf("arp_proxy -s <ipv4addr> <macaddr> <planeid>\n");
	printf("arp_proxy -d <ipv4addr> <planeid>\n");

	return 0;
}

static int me6_arp_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret, ret2;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_ARP_CMD_ERR, ME6_ARP_PERR_SOCK);
		return ME6E_EXEERR_DEFAULT;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_ARP_CMD_ERR, ME6_ARP_PERR_IOCTL);

        ret2 = close(sock);
        if (ret2)
                me6_debug_print(ME6_DEV_CMD_ERR, ME6_DEV_PERR_SOCK_CLOSE);

	return ret;
}

int me6_arp_set(int argc, char **argv)
{
	struct me6_arp_entry sae;
	int ret, i;
	char tmp[128];
	char *p, *mac_p, *save_p, *err;

	if (argc != 5) {
		/* command error */
		me6_arp_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	/* ARP entry set */
	memset(&sae, 0, sizeof(sae));

	inet_pton(AF_INET, argv[2], &sae.daddr);
	strcpy(tmp, argv[3]);
	for (i = 0, p = tmp; i < 6; i++, p = NULL) {
		mac_p = strtok_r(p, ":", &save_p);
		if (mac_p  == NULL)
			return ME6E_EXEERR_DEFAULT;

		sae.hw_addr[i] = strtol(mac_p, NULL, 16);
	}

	sae.planeid = strtoul(argv[4], &err, 0);
	if (*err != '\0') {
		printf("%s : %s\n", ME6_ARP_ERR_CMDVAL, err);
		return ME6E_EXEERR_DEFAULT;
	}

#if 0
	/* search existing entry */
	sae.type = ME6_SEARCHARPENTRY;
	ret = me6_arp_ioctl(&sae, ME6_ARP);
	if (ret != 0) {
		return ME6E_EXEERR_ADDR_EXIST;
	}
#endif

	/* set entry */
	sae.type = ME6_SETARPENTRY;

	ret = me6_arp_ioctl(&sae, ME6_ARP);
	if (ret) {
		me6_debug_print(ME6_ARP_CMD_ERR, ME6_ARP_PERR_SET);
		return ME6E_EXEERR_DEFAULT;
	}

	return 0;
}

int me6_arp_del(int argc, char **argv)
{
	struct me6_arp_entry sae;
	int ret;
	char *err;

	if (argc != 4) {
		/* command error */
		me6_arp_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	memset(&sae, 0, sizeof(sae));

	inet_pton(AF_INET, argv[2], &sae.daddr);
	sae.planeid = strtoul(argv[3], &err, 0);
	if (*err != '\0') {
		printf("%s : %s\n", ME6_ARP_ERR_CMDVAL, err);
		return ME6E_EXEERR_DEFAULT;
	}

	sae.type = ME6_FREEARPENTRY;

	ret = me6_arp_ioctl(&sae, ME6_ARP);
	if (ret) {
		me6_debug_print(ME6_ARP_CMD_ERR, ME6_ARP_PERR_DEL);
		return ME6E_EXEERR_ENTRY_NOT_EXSIST;
	}

	return ret;
}

static int me6_arp_get_ent_info(struct me6_arp_info *sai)
{
	int ret;

	sai->type = ME6_GETARPENTRYINFO;

	ret = me6_arp_ioctl(sai, ME6_ARP);
	if (ret) {
		me6_debug_print(ME6_ARP_CMD_ERR, ME6_ARP_PERR_GET);
		return ret;
	}

	return 0;

}

static int me6_arp_get_ent(struct me6_arp_entry *sae)
{
	int ret;

	sae->type = ME6_GETARPENTRY;

	ret = me6_arp_ioctl(sae, ME6_ARP);
	if (ret) {
		me6_debug_print(ME6_ARP_CMD_ERR, ME6_ARP_PERR_GET);
		return ret;
	}

	return 0;
}

int me6_arp_show(int argc, char **argv)
{
	struct me6_arp_entry *sae;
	struct me6_arp_info sai;
	int i, j, ret;
	char v4_str[16];
	char *tmp;

	memset(&sai, 0, sizeof(struct me6_arp_info));

	ret = me6_arp_get_ent_info(&sai);
	if (ret) {
		/* command error */
		return ME6E_EXEERR_DEFAULT;
	}

	if (sai.entry_num == 0) {
		printf("ME6E-ARP Table is not set.\n");
		return 0;
	}

	tmp = malloc(sizeof(struct me6_arp_entry) * sai.entry_num);
	if (tmp == NULL) {
		me6_debug_print(ME6_ARP_CMD_ERR, ME6_ARP_PERR_MALLOC);
		return ME6E_EXEERR_DEFAULT;
	}

	sae = (struct me6_arp_entry *)tmp;

	memset(sae, 0, sizeof(struct me6_arp_entry) * sai.entry_num);

	ret = me6_arp_get_ent(sae);
	if (ret) {
		free(tmp);
		return ME6E_EXEERR_DEFAULT;
	}

	printf("   PlaneID IPv4addr        MACaddr\n");
	printf("---------- --------------- -----------------\n");

	for (i = 0; i < sai.entry_num; i++, sae++) {
		memset(v4_str, 0, sizeof(v4_str));
		inet_ntop(AF_INET, &sae->daddr, v4_str, sizeof(v4_str));
		printf("%10u ", sae->planeid);
		printf("%-15s ", v4_str);
		for (j = 0; j < ETH_ALEN; j++) {
			printf("%02x", sae->hw_addr[j]);
			if ((j + 1) < ETH_ALEN)
				printf(":");
		}
		printf("\n");
	}

	free(tmp);

	return 0;
}
