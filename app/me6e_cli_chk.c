/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * setting command check function.
 *
 * me6e_cli_chk.c
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
 * 2013.03.26 tamagawa me6_chk_num is changed to unsigned.
 * 2013.12.10 tamagawa me6e support
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <ctype.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "../include/me6e.h"
#include "me6e_cli.h"

/* v4アドレスチェック(IPアドレス、マスク) */
int me6_chk_ipv4_msk(char *str, char *chk_str)
{
	uint32_t mask;
	char *p, *q;
	char tmp[ME6E_CLI_BUFSIZE];
	int chk_ret = 0;

	memcpy(tmp, str, (sizeof(tmp) - 1));

	/* v4アドレスの分解 */
	p = strtok(tmp, "/");
	if (p == NULL)
		return ME6E_CHKERR_SYNTAX;

	chk_ret = me6_chk_ipv4(p, NULL);
	if (chk_ret < 0)
		return chk_ret;

	/* マスクの分解 */
	q = strtok(NULL, "/");
	if (q == NULL)
		return ME6E_CHKERR_SYNTAX;
	else
		mask = atoi(q);

	if (mask < 1 || mask > 32)
		return ME6E_CHKERR_IPV4MASK_VALUE;

	return 0;
}

/* v4アドレスチェック(IPアドレスのみ) */
int me6_chk_ipv4(char *str, char *chk_str)
{
	int digit, i, pos;
	char addr_tmp[ME6E_TOKEN_LEN_MAX];
	char *ip_addr_p, *save_p, *p;

	memset(addr_tmp, 0, sizeof(addr_tmp));

	if (strlen(str) > 255)
		return ME6E_CHKERR_IPV4ADDR;

	strcpy(addr_tmp, str);

	/* 入力形式チェック */
	for (digit = i = pos = 0; addr_tmp[i]; i++) {
		if (isdigit(addr_tmp[i]) != 0) {
			digit++;
		} else {
			if ((addr_tmp[i] == '.') && (digit > 0)
				&& (digit < 4) && (pos < 4)) {
				digit = 0;
				pos++;
			} else {
				return ME6E_CHKERR_IPV4ADDR;
			}
		}
	}

	if (pos != 3)
		return ME6E_CHKERR_IPV4ADDR;

	/* 1～4オクテット目 */
	for (i = 0, p = &addr_tmp[0]; i < 4; i++, p = NULL) {
		ip_addr_p = (char *)strtok_r(p, ".", &save_p);
		if (ip_addr_p == NULL)
			return ME6E_CHKERR_IPV4ADDR;

		/* 範囲チェック */
		if ((0 > atoi(ip_addr_p)) || (atoi(ip_addr_p) > 255))
			return ME6E_CHKERR_IPV4ADDR;
	}

	return 0;
}

int me6_chk_ipv6(char *str, char *chk_str)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET6, str, &addr) <= 0)
		return ME6E_CHKERR_IPV6ADDR;

	return 0;
}

/*
 * 入力された数値が範囲内か
 */
int me6_chk_num(char *str, char *chk_str)
{
	double min, max, num;
	int i;
	char buf[ME6E_CLI_BUFSIZE];
	char *tmp, **err = NULL;

	memset(buf, 0, sizeof(buf));

	if (strlen(chk_str) > 255)
		return ME6E_CHKERR_INVALID_VALUE;

	strcpy(buf, chk_str);
	min = 0;

	/* チェック範囲設定 */
	for (i = 0; buf[i]; i++) {
		if (isdigit(buf[i]) == 0)
			continue;

		tmp = strchr(&buf[i], '-');
		if (tmp)
			*tmp = '\0';

		/* 最小値設定 */
		min = strtoul(&buf[i], err, 0);

		/* 区切り文字(-)まで移動 */
		for (; buf[i] != '\0'; i++)
			;
		i++;
		break;
	}

	max = strtoul(&buf[i], err, 0);

	/* 数値かどうかチェック */
	for (i = 0; str[i]; i++) {
		if (isdigit(str[i]) == 0)
			return ME6E_CHKERR_INVALID_VALUE;
	}

	errno = 0;
	num = strtoul(str, err, 0);
	if (errno == ERANGE)
		return ME6E_CHKERR_INVALID_VALUE;
	if (num < min || num > max)
		return ME6E_CHKERR_INVALID_VALUE;

	return 0;

}

int me6_chk_filepath(char *str, char *chk_str)
{

	FILE *fp;

	fp = fopen(str, "r");
	if (fp == NULL)
		return ME6E_CHKERR_FILE_NOT_FOUND;

	fclose(fp);

	return 0;
}

int me6_chk_ifname(char *str, char *chk_str)
{
	FILE	*fp;
	char	buf[ME6E_CLI_BUFSIZE];
	char	*cmdline = "/sbin/ip link";
	char	*i, *n;


	if (strlen(str) >= IFNAMSIZ)
		return ME6E_CHKERR_IF_NOT_EXSIST;

	fp = popen(cmdline, "r");
	if (fp == NULL) {
		err(EXIT_FAILURE, "%s", cmdline);
		return ME6E_CHKERR_IP_CMD_ERROR;
	}

	memset(buf, 0, sizeof(buf));

	/* index name search */
	while (fgets(buf, ME6E_CLI_BUFSIZE, fp) != NULL) {
		if (*buf != ' ') {
			i = strtok(buf, ":");
			if (i == NULL) {
				pclose(fp);
				return ME6E_CHKERR_IP_CMD_ERROR;
			}
			n = strtok(NULL, ":");
			if (n == NULL) {
				pclose(fp);
				return ME6E_CHKERR_IP_CMD_ERROR;
			}
			if (strcmp(&n[1], str) == 0) {
				pclose(fp);
				return 0;
			}
		}
	}

	pclose(fp);
	/* not exist net device */
	return ME6E_CHKERR_IF_NOT_EXSIST;
}

int me6_dummy(char *str, char *chk_str)
{
	int ret;

	ret = strcmp(str, chk_str);
	if (ret == 0)
		return -1;

	return 0;
}

int me6_chk_mac(char *str, char *chk_str)
{
	int digit, pos, i;

	digit = pos = i = 0;

	for (; str[i]; i++) {
		if (isxdigit(str[i]) != 0) {
			digit++;
		} else {
			/* 区切り文字のチェック */
			if (str[i] == ':') {
				/* 各オクテットの桁数チェック */
				if ((digit > 0) && (digit < 3))
					digit = 0;
				else
					return ME6E_CHKERR_MAC;

				/* 区切り文字数チェック */
				if (pos < 6)
					pos++;
				else
					return ME6E_CHKERR_MAC;
			} else {
				return ME6E_CHKERR_MAC;
			}
		}
	}

	if ((pos != 5) || (digit < 1) || (digit > 2))
		return ME6E_CHKERR_MAC;

	return 0;
}

int me6_chk_swich(char *str, char *chk_str)
{

	if (strcmp(str, "on") == 0 || strcmp(str, "off") == 0) {
		return 0;
	}

	return ME6E_CHKERR_SWITCH;
}

