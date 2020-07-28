/*
 * Command for ME6E-PR
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E-PR setting commands.
 *
 * Authors:
 * Mitarai         <m.mitarai@jp.fujitsu.com>
 * Tamagawa        <tamagawa.daiki@jp.fujitsu.com>
 *
 * Copyright (C)2012-2016 FUJITSU LIMITED
 *
 * 2016.05.31 tamagawa New.
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

/* read line max length */
#define ME6E_PR_FILESET_LENGTH_MAX 128

#define PR_SET_FILENAME 2
#define COM_OPT_MAX 6
#define COM_OPT_MIN 2
#define ENTRY_ADD 0		/* entry add */
#define FORMAT_CHK 1		/* format check */

/* option length */
#define CMD_OPTIONS_MAX 6	/* command size max */
#define MAC_LENGTH_MAX 17	/* MAC address size max */
#define PREFIX_LENGTH_MAX 16	/* prefix size max */
#define PLANEID_LENGTH_MAX 10	/* plane ID size max */

/* error value */
#define FORMATERROR -1		/* format error */
#define CMDERROR -2		/* command error */
#define SOCKERROR -3		/* socket error */

static void me6_pr_cmd_malloc(char **);
static void me6_pr_cmd_free(int, char **);
static int me6_pr_ioctl(void *, int);
static int me6_pr_sort(const void *, const void *);
int me6_pr_get_ent_num(struct me6_pr_info *);
int me6_pr_get_ent(struct me6_pr_entry *);

int me6_pr_usage(int argc, char **argv)
{

	/* me6_pr_usage */
	printf("\nUsage:\n");
	printf("pr -s pr-prefix <macaddr> <me6e-prefix and planeid> <planeid>\n");
	printf("pr -s default <me6e-prefix and planeid>\n");
	printf("pr -d pr-prefix <macaddr> <planeid>\n");
	printf("pr -d default\n");
	printf("pr -f <filepath>\n");
	printf("File format: macaddr,me6e-prefix and planeid,planeid\n");

	return 0;
}

static int me6_pr_ioctl(void *p, int kind)
{
	struct ifreq req;
	int sock, ret, ret2;

	memset(&req, 0, sizeof(req));
	req.ifr_data = p;
	strcpy(req.ifr_name, "me6e0");

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sock) {
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_SOCK);
		return -1;
	}

	ret = ioctl(sock, kind, &req);
	if (ret)
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_IOCTL);

        ret2 = close(sock);
        if (ret2)
                me6_debug_print(ME6_DEV_CMD_ERR, ME6_PR_PERR_SOCK_CLOSE);

	return ret;
}

int me6_pr_entry_add(int argc, char **argv)
{
	struct me6_pr_entry spe;
	struct me6_pr_info spi;
	int ret, i;
	char *p, *mac_p, *save_p, **err = NULL;
	char tmp[128];
#if 0
	uint32_t planeId_be32 = 0;
#endif // planeID not set

	if (strncmp(argv[2], "default", 7) == 0) {

		if (argc != 4) {
			/* command error */
			me6_pr_usage(argc, argv);
			return 0;	//Usage出すのみでエラーにはしない
		}

		/* default prefix set */
		memset(&spi, 0, sizeof(spi));
		inet_pton(AF_INET6, argv[3], &spi.me6_def_pre);
		spi.type = ME6_SETDEFPREFIX;
		ret = me6_pr_ioctl(&spi, ME6_PR);
		if (ret) {
			me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_ADD);
		}
	} else {

		if (argc != 6) {
			/* command error */
			me6_pr_usage(argc, argv);
			return 0;	//Usage出すのみでエラーにはしない
		}

		/* PR entry set */
		memset(&spe, 0, sizeof(spe));

		/* MAC Address */
		strcpy(tmp, argv[3]);
		for (i = 0, p = tmp; i < 6; i++, p = NULL) {
			mac_p = strtok_r(p, ":", &save_p);
			if (mac_p  == NULL)
				return ME6E_EXEERR_DEFAULT;

			spe.hw_addr[i] = strtol(mac_p, NULL, 16);
		}

		inet_pton(AF_INET6, argv[4], &spe.me6_addr);

#if 0
		planeId_be32 = htonl(strtoul(argv[5], err, 0));
		memcpy(&spe.me6_addr.s6_addr[6], &planeId_be32, 4);
#endif // planeID not set
		memcpy(&spe.me6_addr.s6_addr[10], spe.hw_addr, ETH_ALEN);
		spe.plane_id = strtoul(argv[5], err, 0);

#if 0
        	/* search existing entry */
        	spe.type = ME6_SEARCHPRENTRY;
        	ret = me6_pr_ioctl(&spe, ME6_PR);
        	if (ret != 0) {
                	return ME6E_EXEERR_MACADDR_EXIST;
        	}
#endif

		spe.type = ME6_SETPRENTRY;

		ret = me6_pr_ioctl(&spe, ME6_PR);
		if (ret) {
			me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_ADD);
		}
	}

	return ret;
}

/*
 * entry_flag
 * ENTRY_ADD 0		add table entry
 * FORMAT_CHK 1		format check
 */
int me6_pr_entry_add_file(char **argv, int entry_flag)
{

	struct me6_pr_entry spe;
	struct me6_pr_info spi;
	int ret, i;
	char *p, *mac_p, *save_p, **err = NULL, tmp[128];
	__be32 planeId_be32 = 0;

	if (strncmp(argv[3], "default", 7) == 0) {

		/* default prefix set */
		memset(&spi, 0, sizeof(spi));
		if (inet_pton(AF_INET6, argv[4], &spi.me6_def_pre) <= 0) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		}

		/* フォーマットチェック時はテーブルの追加をしない */
		if (entry_flag == FORMAT_CHK)
			return 0;

		spi.type = ME6_SETDEFPREFIX;

		ret = me6_pr_ioctl(&spi, ME6_PR);
		if (ret)
			me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_ADD);

	} else {

		/* PR entry set */
		memset(&spe, 0, sizeof(spe));

                /* MAC Address */
                strcpy(tmp, argv[3]);
                for (i = 0, p = tmp; i < 6; i++, p = NULL) {
                        mac_p = strtok_r(p, ":", &save_p);
                        if (mac_p  == NULL) {
                        	if (entry_flag == FORMAT_CHK) {
                                	return FORMATERROR;
                        	} else {
                                	return CMDERROR;
                        	}
			}

                        spe.hw_addr[i] = strtol(mac_p, NULL, 16);
                }

		if (inet_pton(AF_INET6, argv[4], &spe.me6_addr) <= 0) {
			if (entry_flag == FORMAT_CHK) {
				return FORMATERROR;
			} else {
				return CMDERROR;
			}
		}

		/* フォーマットチェック時はテーブルの追加をしない */
		if (entry_flag == FORMAT_CHK) {
			return 0;
		}

                planeId_be32 = htonl(strtoul(argv[5], err, 0));
                memcpy(&spe.me6_addr.s6_addr[6], &planeId_be32, 4);
                memcpy(&spe.me6_addr.s6_addr[10], spe.hw_addr, ETH_ALEN);
                spe.plane_id = strtoul(argv[5], err, 0);

		spe.type = ME6_SETPRENTRY;

		ret = me6_pr_ioctl(&spe, ME6_PR);
		if (ret)
			me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_ADD);
	}

	return ret;
}

int me6_pr_entry_del(int argc, char **argv)
{

	struct me6_pr_entry spe;
	struct me6_pr_info spi;
	int ret = 0, i = 0;
	char *p, *mac_p, *save_p, **err = NULL;
	char tmp[128];

	if (strncmp(argv[2], "default", 7) == 0) {
		if (argc != 3) {
			/* command error */
			me6_pr_usage(argc, argv);
			return 0;	//Usageを出すのみで、エラーにはしない
		}
		/* default prefix free */
		memset(&spi, 0, sizeof(spi));

		spi.type = ME6_FREEDEFPREFIX;

		ret = me6_pr_ioctl(&spi, ME6_PR);
		if (ret) {
			me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_DEL);
		}

	} else {
		if (argc != 5) {
			/* command error */
			me6_pr_usage(argc, argv);
			return 0;	//Usageを出すのみで、エラーにはしない
		}
		/* PR entry free */
		memset(&spe, 0, sizeof(spe));

		/* MAC Address */
		strcpy(tmp, argv[3]);
		for (i = 0, p = tmp; i < 6; i++, p = NULL) {
			mac_p = strtok_r(p, ":", &save_p);
			if (mac_p  == NULL)
				return ME6E_EXEERR_DEFAULT;

			spe.hw_addr[i] = strtol(mac_p, NULL, 16);
		}

		spe.plane_id = strtoul(argv[4], err, 0);

		spe.type = ME6_FREEPRENTRY;

		ret = me6_pr_ioctl(&spe, ME6_PR);
		if (ret) {
			me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_DEL);
			printf("specified entry does not exist.\n");
			return 0;	//ここでメッセージ表示するため、エラーは返さない。
		}
	}

	return ret;
}

static int me6_pr_sort(const void *a, const void *b)
{

	struct me6_pr_entry p, q;
	char c[16], d[16];

	memset(c, 0, sizeof(c));
	memset(d, 0, sizeof(d));

	memcpy(&p, a, sizeof(struct me6_pr_entry));
	memcpy(&q, b, sizeof(struct me6_pr_entry));

	if(p.plane_id < q.plane_id) {
		return -1;
	}

	return 1;
}

int me6_pr_entry_show(int argc, char **argv)
{

	struct me6_pr_info spi;
	struct me6_pr_entry *spe;
	int i, j, ret;
	char v6_str[40];
	char *tmp;
	struct in6_addr tmp_default_addr;

	memset(&spi, 0, sizeof(struct me6_pr_info));

	ret = me6_pr_get_ent_num(&spi);
	if (ret) {
		/* command error */
		return -1;
	}

	if (spi.entry_num == 0 && spi.def_valid_flg == 0) {
		printf("ME6E-PR Table is not set.\n");
		return 0;
	}

	if (spi.entry_num == 0) {

		printf("   PlaneID MACaddr           ME6E-PR Prefix\n");
		printf("---------- ----------------- ---------------------------------------\n");

		memset(v6_str, 0, sizeof(v6_str));

		/* Prefixで使用されるのは、48bit目までなので、それ以降のbitを0にして表示 */
		tmp_default_addr = spi.me6_def_pre;
		tmp_default_addr.s6_addr32[2] = 0;
		tmp_default_addr.s6_addr32[3] = 0;
		inet_ntop(AF_INET6, &tmp_default_addr, v6_str, sizeof(v6_str));

		printf("%10s ", " ");
		printf("%-15s ", "default");
		printf("%-39s\n", v6_str);

		return 0;
	}

	tmp = malloc(sizeof(struct me6_pr_entry) * spi.entry_num);
	if (tmp == NULL) {
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_MALLOC);
		return -1;
	}

	spe = (struct me6_pr_entry *)tmp;

	memset(spe, 0, sizeof(struct me6_pr_entry) * spi.entry_num);

	ret = me6_pr_get_ent(spe);
	if (ret) {
		free(tmp);
		return -1;
	}

	qsort((void *)spe, spi.entry_num, sizeof(struct me6_pr_entry), me6_pr_sort);

	printf("   PlaneID MACaddr           ME6E-PR Prefix\n");
	printf("---------- ----------------- ---------------------------------------\n");

	for (i = 0; i < spi.entry_num; i++, spe++) {
		memset(v6_str, 0, sizeof(v6_str));
		inet_ntop(AF_INET6, &spe->me6_addr, v6_str, sizeof(v6_str));
		printf("%10u ", spe->plane_id);
		for (j = 0; j < ETH_ALEN; j++) {
			printf("%02x", spe->hw_addr[j]);
			if ((j + 1) < ETH_ALEN)
				printf(":");
		}
		printf(" %-39s\n", v6_str);
	}

	if (spi.def_valid_flg != 0) {
		memset(v6_str, 0, sizeof(v6_str));

		/* Prefixで使用されるのは、48bit目までなので、それ以降のbitを0にして表示 */
		tmp_default_addr = spi.me6_def_pre;
		tmp_default_addr.s6_addr32[2] = 0;
		tmp_default_addr.s6_addr32[3] = 0;
		inet_ntop(AF_INET6, &tmp_default_addr, v6_str, sizeof(v6_str));

		printf("%10s ", " ");
		printf("%-17s ", "default");
		printf("%-39s\n", v6_str);
	}

	free(tmp);

	return 0;
}

int me6_pr_entry_file(int argc, char **argv)
{

	FILE *fp;
	char *info;				/* PR情報退避領域 */
	char *tmp;
	int line_cnt = 1;			/* 行数カウンタ */
	int err = 0;
	char *v[COM_OPT_MAX];			/* opt tmp */

	if (argc != 3) {
		/* command error */
		me6_pr_usage(argc, argv);
		return 0;	//Usageを出すのみで、エラーにはしない
	}

	if ((fp = fopen(argv[2], "r")) == NULL) {
		//printf("%s not exists\n", argv[2]);
		return -1;
	}

	memset(v, 0, COM_OPT_MAX);
	me6_pr_cmd_malloc(v);

	info = (char *) malloc(ME6E_PR_FILESET_LENGTH_MAX);
	if (info == NULL) {
		me6_pr_cmd_free(COM_OPT_MAX, v);
		fclose(fp);
		return -1;
	}

	memset(info, 0, ME6E_PR_FILESET_LENGTH_MAX);

	/* ファイルからエントリを読込みフォーマットをチェックする */
	while (fgets(info, ME6E_PR_FILESET_LENGTH_MAX, fp) != NULL) {

		/* 空行、コメント行は飛ばす */
		if (*info != '\r' && *info != '#' && *info != '\n') {

			tmp = strtok(info, ",");
			if (tmp == NULL || strlen(tmp) > MAC_LENGTH_MAX) {
				printf("line %d : format error.\n", line_cnt++);
				err = FORMATERROR;
				continue;
			}
			strcpy(v[3], tmp);

			tmp = strtok(NULL, ",");
			if (tmp == NULL || strlen(tmp) > PREFIX_LENGTH_MAX) {
				printf("line %d : format error.\n", line_cnt++);
				err = FORMATERROR;
				continue;
			}
			strcpy(v[4], tmp);

			tmp = strtok(NULL, "");
			if (tmp == NULL || strlen(tmp) > PLANEID_LENGTH_MAX) {
				printf("line %d : format error.\n", line_cnt++);
				err = FORMATERROR;
				continue;
			}
			strcpy(v[5], tmp);

			if (FORMATERROR == me6_pr_entry_add_file(v, FORMAT_CHK)) {
				printf("line %d : format error.\n", line_cnt);
				err = FORMATERROR;
			}
		}
		line_cnt++;
	}

	/* フォーマットエラーがあった場合エントリを追加せず終了する */
	if (err == FORMATERROR) {
		fclose(fp);
		free(info);
		me6_pr_cmd_free(COM_OPT_MAX, v);
		printf("file entry failed.\n");
		return 0;	//エラーメッセージ"file entry failed"をここで出すので、復帰値は0
	} else {
		/* 再度先頭から読み込む */
		rewind(fp);
	}

	/* ファイルから読込んだテーブルエントリの追加 */
	while (fgets(info, ME6E_PR_FILESET_LENGTH_MAX, fp) != NULL) {

		if (*info != '\r' && *info != '#' && *info != '\n') {

			strcpy(v[3], strtok(info, ","));
			strcpy(v[4], strtok(NULL, ","));
			strcpy(v[5], strtok(NULL, ""));
			if (me6_pr_entry_add_file(v,ENTRY_ADD)) {
				fclose(fp);
				free(info);
				me6_pr_cmd_free(COM_OPT_MAX, v);
				printf("file entry failed.\n");
				return 0;	//エラーメッセージ"file entry failed"をここで出すので、復帰値は0
			}
		}
	}

	fclose(fp);
	free(info);

	/* 退避領域の解放 */
	me6_pr_cmd_free(COM_OPT_MAX, v);

	return 0;
}

static void me6_pr_cmd_malloc(char **v)
{

	v[0] = NULL;
	v[1] = NULL;
	v[2] = NULL;

	/* 領域の確保 */
	v[3] = (char *) malloc(MAC_LENGTH_MAX);
	if(v[3] == NULL) {
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_MALLOC);
		exit(1);
	}
	memset(v[3], 0, MAC_LENGTH_MAX);

	v[4] = (char *) malloc(PREFIX_LENGTH_MAX);
	if(v[4] == NULL) {
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_MALLOC);
		free(v[3]);
		exit(1);
	}
	memset(v[4], 0, PREFIX_LENGTH_MAX);

	v[5] = (char *) malloc(PLANEID_LENGTH_MAX);
	if(v[5] == NULL) {
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_MALLOC);
		free(v[3]);
		free(v[4]);
		exit(1);
	}
	memset(v[5], 0, PLANEID_LENGTH_MAX);

	return;

}

static void me6_pr_cmd_free(int argc, char **v)
{

	int i;


	for (i =3; i < argc; i++) {
		free(v[i]);
	}

	return;
}

int me6_pr_get_ent_num(struct me6_pr_info *spi)
{
	int ret;

	spi->type = ME6_GETPRENTRYNUM;

	ret = me6_pr_ioctl(spi, ME6_PR);
	if (ret) {
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_GET);
		return ret;
	}

	return 0;

}

int me6_pr_get_ent(struct me6_pr_entry *spe)
{
	int ret;

	spe->type = ME6_GETPRENTRY;

	ret = me6_pr_ioctl(spe, ME6_PR);
	if (ret) {
		me6_debug_print(ME6_PR_CMD_ERR, ME6_PR_PERR_GET);
		return ret;
	}

	return 0;
}

