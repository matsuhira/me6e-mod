# me6ecli Makefile
CC     = gcc
CFLAGS = -Wall -O2 -g
TARGET = me6ecli
OBJS   = me6e_cli.o me6e_cli_call.o me6e_cli_chk.o me6e_cmd.o me6e_cli_tbl.o me6e_arp_cmd.o me6e_ndp_cmd.o me6e_dev_cmd.o me6e_stub_ndp_cmd.o me6e_pr_cmd.o me6e_ipsec_cmd.o me6e_iif_cmd.o me6e_pmtu_cmd.o

.SUFFIXES: .c .o

.PHONY: all
all: depend $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $^

.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TARGET) depend.inc *~

.PHONY: depend
depend: $(OBJS:.o=.c)
	-@ $(RM) depend.inc
	-@ for i in $^; do cpp -MM $$i | sed "s/\ [_a-zA-Z0-9][_a-zA-Z0-9]*\.c//g" >> depend.inc; done

-include depend.inc
