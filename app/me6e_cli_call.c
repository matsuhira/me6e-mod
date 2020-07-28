/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * setting command common function.
 *
 * me6e_cli_call.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include "../include/me6e.h"
#include "me6e_cli.h"
#include "me6e_cli_err.h"

#define GET_CONFIG_INFO_AND_ENTRY_NUM	0	/* get info and entry num*/
#define GET_CONFIG_ENTRY		1	/* get entry */

void me6_debug_print(char *str1, char *str2)
{
	char buf[32];

	if (ME6_DEBUG_FLAG) {
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "%s %s", str1, str2);
		perror(buf);
	}

	return;
}

int me6_com_help(int argc, char **argv)
{
	FILE	*fp;
	char	buf[ME6E_CLI_BUFSIZE];
	char	*cmdline = "cat ./ME6E_command_manual.txt";
	int	j = 0, ret;
	char	ch;
	struct	winsize	winsz;

	/* 端末のwindow幅を取得する */
	ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsz);
	if (ret) {
                err(EXIT_FAILURE, "ioctl error.");
                return ME6E_EXEERR_DEFAULT;
	}

	fp = popen(cmdline, "r");
	if (fp == NULL) {
		err(EXIT_FAILURE, "%s", cmdline);
		return ME6E_EXEERR_DEFAULT;
	}

	while (fgets(buf, ME6E_CLI_BUFSIZE, fp) != NULL) {
		j++;
		/* window幅分先行して出力する */
		if (j < winsz.ws_row) {
			fputs(buf, stdout);
			continue;
		}
		for (;;) {
			ch = (char)fgetc(stdin);
			if ((ch == '\n') || (ch == '\r')) {
				fputs(buf, stdout);
				break;
			} else if (ch == 0x20) {
				j = 0;
				fputs(buf, stdout);
				break;
			} else if (ch == 'q') {
				goto CLOSE;
			}
		}
	}

CLOSE:
	pclose(fp);

	return 0;

}

int me6_load_conf_usage(int argc, char **argv)
{

	printf("\nUsage:\n");
	printf("config load <filepath>\n");

	return 0;
}

int me6_load_conf(int argc, char **argv)
{
	FILE *fp;
	char ch[ME6E_CLI_BUFSIZE];
	int ret;
	int cnt = 1;

	if (argc != 3) {
		me6_load_conf_usage(argc, argv);
		return ME6E_EXEERR_USAGE;
	}

	memset(ch, 0, ME6E_CLI_BUFSIZE);
	fp = fopen(argv[2], "r");
	if (fp == NULL) {
		return ME6E_EXEERR_FILE_NOT_FOUND;
	}

	while (fgets(ch, ME6E_CLI_BUFSIZE, fp) != NULL) {
		me6_blank_del(ch);
		ret = me6_call_cmd(ch);
		if (ret != 0) {
			printf("error at line %d. : %s", cnt, ch);
		}
		cnt++;
	}

	fclose(fp);
	return 0;
}

