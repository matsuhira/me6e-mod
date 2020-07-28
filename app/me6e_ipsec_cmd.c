/*
 * Command for ME6E-IPSEC
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E-IPSEC setting commands.
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

int me6_ipsec_usage(int argc, char **argv)
{

	/* me6_arp_usage */
	printf("\nUsage:\n");
	printf("ipsec flag\n");

	return 0;
}

static int me6_ipsec_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret, ret2;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_IPSEC_CMD_ERR, ME6_IPSEC_PERR_SOCK);
		return ME6E_EXEERR_DEFAULT;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_IPSEC_CMD_ERR, ME6_IPSEC_PERR_IOCTL);

        ret2 = close(sock);
        if (ret2)
                me6_debug_print(ME6_IPSEC_CMD_ERR, ME6_IPSEC_PERR_SOCK_CLOSE);

	return ret;
}

int me6_ipsec_set(int argc, char **argv)
{
	struct me6_ipsec_entry sipe;
	int ret;

	if (argc != 2) {
		/* command error */
		me6_ipsec_show(argc, argv);
		//me6_ipsec_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	/* ipsec flag set */
	memset(&sipe, 0, sizeof(sipe));

	/* set entry */
	sipe.type = ME6_IPSEC_FLAG;

	ret = me6_ipsec_ioctl(&sipe, ME6_IPSEC);
	if (ret) {
		me6_debug_print(ME6_IPSEC_CMD_ERR, ME6_IPSEC_PERR_SET);
		return ME6E_EXEERR_DEFAULT;
	}

	return 0;
}

static int me6_ipsec_get_ent_info(struct me6_ipsec_info *sii)
{
        int ret;

        sii->type = ME6_GETIPSECENTRYINFO;

        ret = me6_ipsec_ioctl(sii, ME6_IPSEC);
        if (ret) {
                me6_debug_print(ME6_IPSEC_CMD_ERR, ME6_IPSEC_PERR_GET);
                return ret;
        }

        return 0;

}

int me6_ipsec_show(int argc, char **argv)
{
	struct me6_ipsec_info sii;
	int ret;

	memset(&sii, 0, sizeof(struct me6_ipsec_info));

	ret = me6_ipsec_get_ent_info(&sii);
	if (ret) {
		/* command error */
		return ME6E_EXEERR_DEFAULT;
	}

	if (sii.ipsec_flag == 0) {
		printf("IPsec OFF\n");
	} else {
		printf("IPsec ON\n");
	}

	return 0;
}

