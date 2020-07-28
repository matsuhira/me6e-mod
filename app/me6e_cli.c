/*
 * ME6E
 * Multiple Ethernet - IPv6 adress mapping encapsulation
 *
 * ME6E setting command.
 *
 * me6e_cli.c
 *
 * Authors:
 * Mitarai           <m.mitarai@jp.fujitsu.com>
 * tamagawa          <tamagawa.daiki@jp.fujitsu.com>
 *
 * https://sites.google.com/site/sa46tnet/
 *
 * Copyright (C)2013 FUJITSU LIMITED
 *
 * Changes:
 * 2013.02.18 mitarai tamagawa New
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <termios.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netdevice.h>
#include "../include/me6e.h"
#include "me6e_cli.h"

static int me6_chk_cmdstr_max(struct me6_cli_cmd_tbl *);
static int me6_print_all_cand(struct me6_cli_cmd_tbl *);
static void me6_chk_tab(char *, int *, int *);
static void me6_print_buf(int, char **, char *, int *, int *);
static void me6_cli_clr_line(char *, int *, int *);
static void me6_set_term(struct termios *);
static void me6_restore_term(struct termios *);
static void me6_print_sup(int, char **, int, char *,
				struct me6_cli_cmd_tbl *, int *, int *);
static void me6_print_cand(int, char **, int, char *,
				struct me6_cli_cmd_tbl *, int, int *, int *);
static void init_hist(hist_t *);

int main(int argc, char **argv)
{

	struct termios save_term;
	hist_t hist[ME6E_CLI_HISTORY_MAX];
	char buf[ME6E_CLI_BUFSIZE], save_buf[ME6E_CLI_BUFSIZE], ch;
	hist_t *cur, *save_cur;
	int hist_flg;
	int end_pos = 0;	/* 文字列末尾位置('\0'の位置) */
	int cursor_pos = 0;	/* カーソル位置 */

	/* 外部入力 */
	if (argc == 3) {
		if (strcmp(argv[1], "-f") != 0) {
			printf("command error.\n");
			return -1;
		}

		if (me6_load_conf(argc, argv) != 0) {
			/* printf("command error.\n"); */
			return -1;
		}
		return 0;
	}

	/* 非カノニカルモードへ */
	me6_set_term(&save_term);

	memset(hist, 0, sizeof(hist));
	init_hist(hist);
	cur = hist;

	for (;;) {
		memset(buf, 0, sizeof(buf));
		memset(save_buf, 0, sizeof(save_buf));
		save_cur = cur;
		hist_flg = 0;
		end_pos = 0;
		cursor_pos = 0;

		PUT_PROMPT;

		for (;;) {
			ch = (char)fgetc(stdin);

			if (isprint(ch)) {
				if (end_pos >= (ME6E_CLI_BUFSIZE - 1)) {
					;
				} else {
					memmove(&buf[cursor_pos + 1],
						&buf[cursor_pos],
						(end_pos - cursor_pos + 1));
					buf[cursor_pos] = ch;
					buf[end_pos + 1] = '\0';
					/* カーソル位置から末尾までクリア */
					printf("\x1b[0J");
					printf("%s", &buf[cursor_pos]);
					if (cursor_pos < end_pos) {
						printf("\x1b[%dD",
							(end_pos - cursor_pos));
					}
					end_pos++;
					cursor_pos++;
				}
			} else if ((ch == '\n') || (ch == '\r')) {
				printf("%c", ch);
				break;
			} else if (ch == '\t') {
				/* TAB */
				me6_chk_tab(buf, &end_pos, &cursor_pos);
			} else if (ch == '\b' || ch == 0x7f) {
				/* BackSpace */
				if (cursor_pos <= 0) {
					;
				} else {
					memmove(&buf[cursor_pos - 1],
						&buf[cursor_pos],
						(end_pos - cursor_pos + 1));
					buf[end_pos - 1] = '\0';
					printf("\b");
					printf("\x1b[0J");
					printf("%s", &buf[cursor_pos - 1]);
					if (cursor_pos < end_pos) {
						printf("\x1b[%dD",
							(end_pos - cursor_pos));
					}
					end_pos--;
					cursor_pos--;
				}
			} else if (ch == 0x1b) {
				/* エスケープシーケンス */
				ch = fgetc(stdin);
				if (ch == '[') {
					ch = fgetc(stdin);
					if (ch == 'A') {
						/* 上キー */
						if (strlen(cur->prev->str) != 0) {
							if (hist_flg == 0) {
								hist_flg = 1;
								/* 現在の入力を保存 */
								strcpy(save_buf, buf);
							}
							if (cur->prev != save_cur) {
								me6_cli_clr_line(buf, &end_pos, &cursor_pos);
								strcpy(buf, cur->prev->str);
								printf("%s", buf);
								end_pos = strlen(buf);
								cursor_pos = strlen(buf);
								cur = cur->prev;
							}
						}
					} else if (ch == 'B') {
						/* 下キー */
						if (hist_flg == 1) {
							me6_cli_clr_line(buf, &end_pos, &cursor_pos);
							if (cur->next == save_cur) {
								strcpy(buf, save_buf);
								hist_flg = 0;
							} else {
								strcpy(buf, cur->next->str);
							}
							printf("%s", buf);
							end_pos = strlen(buf);
							cursor_pos = strlen(buf);
							cur = cur->next;
						}
					} else if (ch == 'C') {
						/* 右キー */
						if (cursor_pos < end_pos) {
							/* カーソルを右移動 */
							printf("\x1b[C");
							cursor_pos++;
						}

					} else if (ch == 'D') {
						/* 左キー */
						if (cursor_pos > 0) {
							/* カーソルを左移動 */
							printf("\x1b[D");
							cursor_pos--;
						}

					} else {
						/* その他矢印キー */
						;
					}
				}
			} else if (ch == 0x3) {
				/* CTRL+C */
				raise(SIGINT);  /* デバッグ用 */
			} else {
				/* その他 */
				;
			}
		}

		if (strlen(buf)) {

			me6_blank_del(buf);
			if (strlen(buf) == 0)
				continue;

			/* history保存 */
			memcpy(save_cur->str, buf, ME6E_CLI_BUFSIZE-1);
			cur = save_cur->next;

			if (strcmp(buf, "exit") == 0) {
				me6_restore_term(&save_term);
				exit(0);
			} else {
				me6_call_cmd(buf);
			}

		}

	}

	return 0;
}

int me6_call_cmd(char *buf)
{

	struct me6_cli_cmd_tbl *cmdp;
	int argc, i, ret = 0, chk_ret = 0;
	int command_found = 0;
	char *argv[ME6E_TOKEN_MAX], *p, *save_p;
	char token[ME6E_TOKEN_MAX][ME6E_TOKEN_LEN_MAX];
	char *cmd_str_p = NULL;
	char *cmd_exp_p = NULL;

	memset(argv, 0, sizeof(argv));
	memset(token, 0, sizeof(token));
	ret = 0;
	save_p = NULL;

	for (argc = 0, p = buf; (p = strtok_r(p, " ", &save_p)) != NULL;
		p = NULL, argc++) {
		if (argc > (ME6E_TOKEN_MAX - 1)) {
			printf("command error. too much tokens.\n");
			return -1;
		} else {
			if (strlen(p) > (ME6E_TOKEN_LEN_MAX - 1)) {
				printf("command error. too much tokens.\n");
				return -1;
			}

			strcpy(token[argc], p);
			argv[argc] = token[argc];
		}
	}

	if (!argc)
		return 0;

	cmdp = cmd_root;

	for (i = 0; cmdp->cmd_str != NULL; ) {
		if (cmdp->chk_func != NULL) {
			chk_ret = cmdp->chk_func(argv[i], cmdp->cmd_str);
			cmd_str_p = cmdp->cmd_str;
			cmd_exp_p = cmdp->cmd_exp;
			if (chk_ret == 0) {
				goto CALL_NEXT;
			} else {
				cmdp++;
				if (cmdp == NULL) {
					break;
				} else {
					continue;
				}
			}
		} else {
			if (strcmp(argv[i], cmdp->cmd_str) == 0) {
CALL_NEXT:
				command_found = 1;
				if (cmdp->next == NULL) {
					if (i == (argc - 1)) {
						break;
					} else {
						cmdp++;
						i++;
					}
				} else {
					/* 次のツリー */
					cmdp = cmdp->next;
					i++;
					if (i == argc)
						break;
				}
			} else {
				cmdp++;
			}
		}

	}

	if (cmdp->call_func != NULL) {
		ret = cmdp->call_func(argc, argv);
		if (ret == ME6E_EXEERR_FILE_NOT_FOUND) {
			printf("file not found.\n");
		} else if (ret == ME6E_EXEERR_ADDR_EXIST) {
			printf("specified address already exists.\n");
		} else if (ret == ME6E_EXEERR_ENTRY_NOT_EXSIST) {
			printf("specified entry does not exist.\n");
		} else if (ret == ME6E_EXEERR_MACADDR_EXIST) {
			printf("specified MAC address already exists.\n");
		} else if (ret == ME6E_EXEERR_USAGE) {
			/* このエラーは各関数内でメッセージを表示 */
		} else if (ret == ME6E_COM_SUCCESS) {
			/* cmmand success. nothing todo. */
		} else {
			/* その他エラーはすべてME6E_EXEERR_DEFAULT */
			printf("command execution error.\n");
		}

	} else {
		/* 該当するコマンド自体が見つからなかった場合 */
		if (command_found != 1) {
			for (i = 0; i < argc; i++)
				printf("%s ", argv[i]);

			printf(": command not found.\n");
		} else if (chk_ret == ME6E_CHKERR_IPV4ADDR) {
			printf("%s : invalid ipv4 address.\n", cmd_str_p);
		} else if (chk_ret == ME6E_CHKERR_IPV4MASK_VALUE) {
			printf("%s : invalid mask value.\n", cmd_str_p);
		} else if (chk_ret == ME6E_CHKERR_IPV6ADDR) {
			printf("%s : invalid ipv6 address.\n", cmd_str_p);
		} else if (chk_ret == ME6E_CHKERR_INVALID_VALUE) {
			printf("%s : invalid value. expected %s.\n", cmd_exp_p, cmd_str_p);
		} else if (chk_ret == ME6E_CHKERR_FILE_NOT_FOUND) {
			printf("file not found.\n");
		} else if (chk_ret == ME6E_CHKERR_NSNAME_LEN) {
			printf("NameSpace name length must be 65 characters or less.\n");
		} else if (chk_ret == ME6E_CHKERR_NSNAME) {
			printf("invalid NameSpace name.\n");
		} else if (chk_ret == ME6E_CHKERR_IFNAME_LEN) {
			printf("device name length must be 16 characters or less.\n");
		} else if (chk_ret == ME6E_CHKERR_IF_EXSIST) {
			printf("specified device name already exists.\n");
		} else if (chk_ret == ME6E_CHKERR_IP_CMD_ERROR) {
			printf("ip command error.\n");
		} else if (chk_ret == ME6E_CHKERR_IF_NOT_EXSIST) {
			printf("specified device does not exist.\n");
		} else if (chk_ret == ME6E_CHKERR_SWITCH) {
			printf("invalid flag : expected <on-off>\n");
		} else if (chk_ret == ME6E_CHKERR_MAC) {
			printf("%s : invalid MAC address.\n", cmd_str_p);
		} else {
			/* その他エラーはすべてME6E_CHKERR_SYNTAX */
			for (i = 0; i < argc; i++)
				printf("%s ", argv[i]);

			printf(": command syntax error.\n");
		}
		return -1;
	}

	return ret;

}


static void me6_chk_tab(char *buf, int *end_pos_p, int *cursor_pos_p)
{
	struct me6_cli_cmd_tbl *cmdp, *cur_cmdp;
	int argc, cand, cnt, i, j;
	char tab_str[ME6E_CLI_BUFSIZE], token[ME6E_TOKEN_MAX][ME6E_TOKEN_LEN_MAX];
	char t_buf[ME6E_CLI_BUFSIZE];
	char *argv[ME6E_TOKEN_MAX], *save_p, *tab_str_p, *p;

	memset(tab_str, 0, sizeof(tab_str));
	memset(t_buf, 0, sizeof(t_buf));
	memset(token, 0, sizeof(token));
	memset(argv, 0, sizeof(argv));
	cmdp = cur_cmdp = cmd_root;

	/* トークン取り出し（スペース区切りで文字列を分解） */
	memcpy(t_buf, buf, sizeof(t_buf));
	for (argc = 0, tab_str_p = t_buf; (p = strtok_r(tab_str_p, " ", &save_p)) != NULL; tab_str_p = NULL, argc++) {
		if (argc >= ME6E_TOKEN_LEN_MAX) {
			return;
		} else {
			/* 長すぎる文字列入力 */
			if (strlen(p) > (ME6E_TOKEN_LEN_MAX - 1)) {
				printf("\n");
				PUT_PROMPT;
				return;
			}
			strcpy(token[argc], p);
			argv[argc] = token[argc];
		}
	}

	/* コマンド入力無しの場合 */
	if (argc == 0) {
		/* root全表示 */
		if (me6_print_all_cand(cmdp) == 1) {
			/* 候補が１つだったら補完 */
			me6_cli_clr_line(buf, end_pos_p, cursor_pos_p);
			strcat(buf, cmdp->cmd_str);
			printf("%s", buf);
			*end_pos_p = strlen(buf);
			*cursor_pos_p = strlen(buf);
		} else {
			printf("\n");
			PUT_PROMPT;
		}
		return;
	}

	/* コマンド入力とコマンド（ツリー構造）の比較 */
	for (cnt = i = 0; cmdp->cmd_str != NULL;) {

		if (cmdp->chk_func != NULL) {

			/* チェック関数がある（=次のトークンが任意文字列）の場合 */
			if (cmdp->chk_func(argv[i], cmdp->cmd_str) == 0) {
				goto NEXT;	/* チェック結果OKなら、完全一致とみなす */
			} else {
				cmdp++;
				if (cmdp == NULL) {
					cnt = 0;
					break;
				} else {
					continue;
				}
			}

		} else {

			/* チェック関数が無い（=次のトークンがコマンド、オプション）の場合 */
			if (strcmp(argv[i], cmdp->cmd_str) == 0) {
NEXT:
				/* 完全一致 */
				if (cmdp->next == NULL) {
					/* 次のツリーがなかったら終了 */
					cnt = 0;
					if (i != (argc - 1))
						break;

					me6_print_buf(argc, argv, buf, end_pos_p, cursor_pos_p);
					break;
				} else {
					/* 次のツリーへ */
					cmdp = cur_cmdp = cmdp->next;
					cnt = 0;
					i++;
					if (i == argc) {
						if (buf[strlen(buf)-1] == ' ') {
							cand = me6_print_all_cand(cmdp);
							if (cand == 1) {
								/* 候補が１つだったら補完 */
								/* チェック関数がある場合は補完しない */
								if (cmdp->chk_func) {
									/* 候補は表示する */
									printf("\n%s\n", cmdp->cmd_str);
									PUT_PROMPT;
									printf("%s", buf);
									*end_pos_p = strlen(buf);
									*cursor_pos_p = strlen(buf);
									break;
								}
								/* 補完 */
								strcpy(token[argc], cmdp->cmd_str);
								argv[argc] = token[argc];
								argc++;
								me6_print_buf(argc, argv, buf, end_pos_p, cursor_pos_p);
							} else if (cand > 1) {
								/* 補完できるところまで補完する */
								char buf_char;
								int k;
								for (k = 0; k < strlen(cmdp->cmd_str); k++, cmdp = cur_cmdp) {
									buf_char = cmdp->cmd_str[k];
									for (j = 0; cmdp->cmd_str != NULL; cmdp++, j++) {
										if (buf_char != cmdp->cmd_str[0])
											break;

									}
									if (j == cand) {
										/* 全候補一致 */
										strncat(buf, &buf_char, 1);
									} else {
										PUT_PROMPT;
										printf("%s", buf);
										*end_pos_p = strlen(buf);
										*cursor_pos_p = strlen(buf);
										break;
									}
								}
							}
						} else {
							strcat(buf, " ");
							printf("%s", " ");
							(*end_pos_p)++;
							(*cursor_pos_p)++;
						}
						break;
					}
				}
			} else if (strncmp(argv[i], cmdp->cmd_str, strlen(argv[i])) == 0) {
				/* 一部一致 */
				cnt++;
				cmdp++;
			} else {
				cmdp++;
			}
		}
	}

	if (cnt == 1) {
		/* 補完処理 */
		me6_print_sup(argc, argv, i, buf, cur_cmdp, end_pos_p, cursor_pos_p);
	} else if (cnt > 1) {
		/* 候補表示 */
		me6_print_cand(argc, argv, i, buf, cur_cmdp, cnt, end_pos_p, cursor_pos_p);
	} else {
		/* ヒットなし */
		;
	}

	return;

}

static int me6_chk_cmdstr_max(struct me6_cli_cmd_tbl *cmdp)
{
	int max_len;

	for (max_len = 0; cmdp->cmd_str != NULL; cmdp++) {
		if (max_len < strlen(cmdp->cmd_str))
			max_len = strlen(cmdp->cmd_str);
	}

	return max_len;
}

static int me6_print_all_cand(struct me6_cli_cmd_tbl *cmdp)
{
	int max_len, cnt;
	char tab_str[ME6E_CLI_BUFSIZE];
	char tab_fmt[ME6E_TAB_SIZE];
	char *p;

	memset(tab_str, 0, sizeof(tab_str));
	memset(tab_fmt, 0, sizeof(tab_fmt));

	/* 出力フォーマット作成(最大文字+3) */
	max_len = (me6_chk_cmdstr_max(cmdp) + 3);

	sprintf(tab_fmt, "%%-%ds", max_len);

	cnt = 0;
	for (p = tab_str; cmdp->cmd_str != NULL; cmdp++, cnt++) {
		sprintf(p, tab_fmt, cmdp->cmd_str);
		if (strlen(tab_str) > (ME6E_TAB_WIDTH - 1)) {
			printf("\n%s", tab_str);
			memset(tab_str, 0, sizeof(tab_str));
			p = tab_str;
		} else {
			p += max_len;
		}
	}

	if (cnt != 1) {
		if (strlen(tab_str) != 0)
			printf("\n%s\n", tab_str);
	}
	return cnt;
}

/*
 * 入力バッファの再表示
 */
static void me6_print_buf(int argc, char **argv, char *buf, int *end_pos_p, int *cursor_pos_p)
{
	int i;

	/* 表示、入力バッファをクリア */
	me6_cli_clr_line(buf, end_pos_p, cursor_pos_p);

	/* トークン（argv[i]）に記載された内容をスペース区切りでバッファにコピー */
	for (i = 0; i < argc; i++) {
		strcat(buf, argv[i]);
		strcat(buf, " ");
	}
	/* 再表示 */
	printf("%s", buf);
	*end_pos_p = strlen(buf);
	*cursor_pos_p = strlen(buf);
}

/*
 * 現在入力されたコマンドラインのクリア
 */
static void me6_cli_clr_line(char *buf, int *end_pos_p, int *cursor_pos_p)
{
	/* 表示、入力バッファをクリア */
	if (*cursor_pos_p < *end_pos_p)
		printf("\x1b[%dC", (*end_pos_p - *cursor_pos_p));

	for (; strlen(buf);) {
		buf[strlen(buf)-1] = '\0';
		printf("\b");
		printf("\x1b[0J");
	}
	*end_pos_p = 0;
	*cursor_pos_p = 0;
}

/*
 * 先頭と終わりの空白を削除する
 */
void me6_blank_del(char *buf)
{
	int i, j, len, b_flag;
	char t_buf[ME6E_CLI_BUFSIZE];

	memset(t_buf, 0, sizeof(t_buf));

	for (b_flag = i = j = 0, len = strlen(buf); i < len; i++) {
		if (isspace(buf[i])) {
			if (b_flag == 0) {
				continue;
			} else {
				b_flag = 1;
				if (buf[i+1] == '\0')
					break;
				if (isspace(buf[i+1])) {
					continue;
				} else {
					t_buf[j] = buf[i];
					j++;
				}
			}
		} else {
			b_flag = 1;
			t_buf[j] = buf[i];
			j++;
		}
	}
	memcpy(buf, t_buf, sizeof(t_buf));
}

static void me6_set_term(struct termios *save_term)
{
	struct termios new_term;

	/* 現在の設定を保存 */
	tcgetattr(0, save_term);

	new_term = *save_term;
	new_term.c_lflag &= (~ICANON);
	new_term.c_lflag &= ECHOE;
	new_term.c_cc[VTIME] = 0;
	new_term.c_cc[VMIN]  = 1;

	tcsetattr(0, TCSANOW, &new_term);
}

static void me6_restore_term(struct termios *save_term)
{

	tcsetattr(0, TCSANOW, save_term);
}

/*
 * 補完処理
 */
static void me6_print_sup(int argc, char **argv, int pos, char *buf, struct me6_cli_cmd_tbl *cmdp, int *end_pos_p, int *cursor_pos_p)
{
	/* 部分一致したのが最後のトークンでない場合、何もしない */
	if (pos != argc - 1)
		return;

	/* 再検索 */
	for (; cmdp->cmd_str != NULL; cmdp++) {
		if (strncmp(argv[pos], cmdp->cmd_str, strlen(argv[pos])) == 0)
			break;
	}

	/* 最後のトークンの後に空白があると、補完した文字の前に空白が入ってしまう */
	/* そのための対応として、表示とバッファをクリアする */
	/* ただし、前に別のトークンがある場合は、そこまでをバッファに入れて再表示する */
	if (argc > 1)
		me6_print_buf((argc - 1), argv, buf, end_pos_p, cursor_pos_p);
	else
		me6_cli_clr_line(buf, end_pos_p, cursor_pos_p);


	/* 最後のトークンを補完 */
	if (cmdp->cmd_str != NULL) {
		strcat(buf, cmdp->cmd_str);
		strcat(buf, " ");
	}

	/* 補完した部分だけ追加表示 */
	printf("%s", &buf[*end_pos_p]);

	*end_pos_p = strlen(buf);
	*cursor_pos_p = strlen(buf);

	return;
}

/*
 * 一部の候補を表示
 */
static void me6_print_cand(int argc, char **argv, int pos, char *buf, struct me6_cli_cmd_tbl *cmdp, int cnt, int *end_pos_p, int *cursor_pos_p)
{
	int max_len, i;
	char tab_str[ME6E_CLI_BUFSIZE], tab_fmt[ME6E_TAB_SIZE];
	char *p;
	char tmp_str[cnt][ME6E_CLI_BUFSIZE];

	memset(tab_str, 0, sizeof(tab_str));
	memset(tab_fmt, 0, sizeof(tab_fmt));
	memset(tmp_str, 0, sizeof(tmp_str));

	/* 部分一致したのが最後のトークンでない場合、何もしない */
	if (pos != argc - 1)
		return;

	/* 出力フォーマット作成(最大文字+3) */
	max_len = (me6_chk_cmdstr_max(cmdp) + 3);
	sprintf(tab_fmt, "%%-%ds", max_len);

	printf("\n");

	/* 再検索 */
	for (i = 0, p = tab_str; cmdp->cmd_str != NULL; cmdp++) {
		if (strncmp(argv[pos], cmdp->cmd_str, strlen(argv[pos])) == 0) {
			sprintf(p, tab_fmt, cmdp->cmd_str);

			if (strlen(cmdp->cmd_str) > (ME6E_CLI_BUFSIZE - 1))
				return;

			strcpy(tmp_str[i], cmdp->cmd_str);
			i++;
			if (strlen(tab_str) > ME6E_TAB_WIDTH) {
				printf("%s\n", tab_str);
				memset(tab_str, 0, sizeof(tab_str));
				p = tab_str;
			} else {
				p += max_len;
			}
		}
	}

	/* 候補表示 */
	printf("%s\n", tab_str);

	/* 途中まで補完 */
	for (i = strlen(argv[pos]); i < strlen(tmp_str[0]); i++) {
		/* 全候補の中で一致するか？ 1文字単位で比較 */
		int j;
		for (j = 1; j < cnt; j++) {
			if (tmp_str[0][i] != tmp_str[j][i])
				break;
		}
		if (j == cnt) {
			/* 全候補が一致したので1文字だけ追加 */
			strncat(buf, &tmp_str[0][i], 1);
		} else {
			break;
		}
	}

	/* 入力バッファの再出力 */
	PUT_PROMPT;
	me6_blank_del(buf);
	printf("%s", buf);
	*end_pos_p = strlen(buf);
	*cursor_pos_p = strlen(buf);

	return;
}

/*
 * history領域の初期化(リスト作成)
 */
static void init_hist(hist_t *hist)
{
	int i;

	for (i = 0; i < ME6E_CLI_HISTORY_MAX; i++) {
		hist[i].next = &hist[i+1];
		hist[i].prev = &hist[i-1];
	}

	hist[ME6E_CLI_HISTORY_MAX-1].next = &hist[0];
	hist[0].prev = &hist[ME6E_CLI_HISTORY_MAX-1];

	return;
}

