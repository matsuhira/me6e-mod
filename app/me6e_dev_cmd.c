/*
 * Command for ME6E-DEV
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E-DEV setting commands.
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

int me6_dev_usage(int argc, char **argv)
{

	/* me6_dev_usage */
	printf("\nUsage:\n");
	printf("ndp -s\n");

	return 0;
}

static int me6_dev_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret, ret2;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_DEV_CMD_ERR, ME6_DEV_PERR_SOCK);
		return ME6E_EXEERR_DEFAULT;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_DEV_CMD_ERR, ME6_DEV_PERR_IOCTL);

	ret2 = close(sock);
	if (ret2)
		me6_debug_print(ME6_DEV_CMD_ERR, ME6_DEV_PERR_SOCK_CLOSE);

	return ret;
}

int me6_dev_set(int argc, char **argv)
{
	struct me6_dev_entry sde;
	int ret;

	if (argc != 2) {
		/* command error */
		me6_dev_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	/* dev entry set */
	memset(&sde, 0, sizeof(sde));

	sde.type = ME6_SETDEVENTRY;

	ret = me6_dev_ioctl(&sde, ME6_DEV);
	if (ret) {
		me6_debug_print(ME6_DEV_CMD_ERR, ME6_DEV_PERR_SET);
		return ME6E_EXEERR_DEFAULT;
	}

	return 0;
}
