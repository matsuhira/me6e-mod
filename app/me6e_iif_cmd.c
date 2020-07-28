/*
 * Command for ME6E-IIF
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E-IIF setting commands.
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 * Tamagawa        <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * 2016.7.19 tamagawa New.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/me6e.h"
#include "me6e_cli.h"
#include "me6e_cli_err.h"

int me6_iif_usage(int argc, char **argv)
{

	/* me6_iif_usage */
	printf("\nUsage:\n");
	printf("iif -s <if_index> <planeid>\n");
	printf("iif -d <if_index>\n");

	return 0;
}

static int me6_iif_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret, ret2;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_IIF_CMD_ERR, ME6_IIF_PERR_SOCK);
		return ME6E_EXEERR_DEFAULT;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_IIF_CMD_ERR, ME6_IIF_PERR_IOCTL);

        ret2 = close(sock);
        if (ret2)
                me6_debug_print(ME6_DEV_CMD_ERR, ME6_DEV_PERR_SOCK_CLOSE);

	return ret;
}

int me6_iif_set(int argc, char **argv)
{
	struct me6_iif_entry sie;
	int ret;
	char *err;

	if (argc != 4) {
		/* command error */
		me6_iif_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	/* IIF entry set */
	memset(&sie, 0, sizeof(sie));

	sie.iif = strtoul(argv[2], &err, 0);	
        if (*err != '\0') {
                printf("%s : %s\n", ME6_IIF_ERR_CMDVAL, err);
                return ME6E_EXEERR_DEFAULT;
        }

	sie.plane_id = strtoul(argv[3], &err, 0);
	if (*err != '\0') {
		printf("%s : %s\n", ME6_IIF_ERR_CMDVAL, err);
		return ME6E_EXEERR_DEFAULT;
	}

	/* search existing entry */
	sie.type = ME6_SEARCHIIFENTRY;
	ret = me6_iif_ioctl(&sie, ME6_IIF);
	if (ret != 0) {
		return ME6E_EXEERR_ADDR_EXIST;
	}

	/* set entry */
	sie.type = ME6_SETIIFENTRY;

	ret = me6_iif_ioctl(&sie, ME6_IIF);
	if (ret) {
		me6_debug_print(ME6_IIF_CMD_ERR, ME6_IIF_PERR_SET);
		return ME6E_EXEERR_DEFAULT;
	}

	return 0;
}

int me6_iif_del(int argc, char **argv)
{
	struct me6_iif_entry sie;
	int ret;
	char *err;

	if (argc != 3) {
		/* command error */
		me6_iif_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

        /* IIF entry set */
        memset(&sie, 0, sizeof(sie));

        sie.iif = strtoul(argv[2], &err, 0);
        if (*err != '\0') {
                printf("%s : %s\n", ME6_IIF_ERR_CMDVAL, err);
                return ME6E_EXEERR_DEFAULT;
        }

        sie.plane_id = 0;

	sie.type = ME6_FREEIIFENTRY;

	ret = me6_iif_ioctl(&sie, ME6_IIF);
	if (ret) {
		me6_debug_print(ME6_IIF_CMD_ERR, ME6_IIF_PERR_DEL);
		return ME6E_EXEERR_ENTRY_NOT_EXSIST;
	}

	return ret;
}

static int me6_iif_get_ent_info(struct me6_iif_info *sii)
{
	int ret;

	sii->type = ME6_GETIIFENTRYINFO;

	ret = me6_iif_ioctl(sii, ME6_IIF);
	if (ret) {
		me6_debug_print(ME6_IIF_CMD_ERR, ME6_IIF_PERR_GET);
		return ret;
	}

	return 0;

}

static int me6_iif_get_ent(struct me6_iif_entry *sie)
{
	int ret;

	sie->type = ME6_GETIIFENTRY;

	ret = me6_iif_ioctl(sie, ME6_IIF);
	if (ret) {
		me6_debug_print(ME6_IIF_CMD_ERR, ME6_IIF_PERR_GET);
		return ret;
	}

	return 0;
}

int me6_iif_show(int argc, char **argv)
{
	struct me6_iif_entry *sie;
	struct me6_iif_info sii;
	int i, ret;
	char *tmp;
	FILE *fp;
        char buf[256];
        char *cmdline = "/sbin/ip link";
        char *index, *name;

	memset(&sii, 0, sizeof(struct me6_iif_info));

	ret = me6_iif_get_ent_info(&sii);
	if (ret) {
		/* command error */
		return ME6E_EXEERR_DEFAULT;
	}

	if (sii.entry_num == 0) {
		printf("ME6E-IIF Table is not set.\n\n");
		goto IF_INDEX_SHOW;
		return 0;
	}

	tmp = malloc(sizeof(struct me6_iif_entry) * sii.entry_num);
	if (tmp == NULL) {
		me6_debug_print(ME6_IIF_CMD_ERR, ME6_IIF_PERR_MALLOC);
		return ME6E_EXEERR_DEFAULT;
	}

	sie = (struct me6_iif_entry *)tmp;

	memset(sie, 0, sizeof(struct me6_iif_entry) * sii.entry_num);

	ret = me6_iif_get_ent(sie);
	if (ret) {
		free(tmp);
		return ME6E_EXEERR_DEFAULT;
	}

	printf("       IIF PlaneID\n");
	printf("---------- ----------\n");

	for (i = 0; i < sii.entry_num; i++, sie++) {
		printf("%10u ", sie->iif);
		printf("%10u ", sie->plane_id);
		printf("\n");
	}
	printf("\n");

	free(tmp);

IF_INDEX_SHOW:
        if ((fp=popen(cmdline,"r")) == NULL) {
                err(EXIT_FAILURE, "%s", cmdline);
                return -1;
        }

        printf("index    name \n");
        printf("-------- ---------------- \n");

        memset(buf, 0, sizeof(buf));

        while(fgets(buf, 256, fp) != NULL) {
                if (*buf != ' ') {
                        index = strtok(buf, ":");
                        if (index == NULL) {
                                printf("%s\n", ME6_IIF_CMD_ERR);
                                return -1;
                        }
                        name = strtok(NULL, ":");
                        if (name == NULL) {
                                printf("%s\n", ME6_IIF_CMD_ERR);
                                return -1;
                        }
                        printf("%-8s %-16s\n", index, &name[1]);

                }
        }

        (void) pclose(fp);

	return 0;
}
