OPENSSL_DIR?=$(realpath ../../openssl_patch/openssl-3.6.0-beta1-install)
OPENSSL_INCLUDE=$(OPENSSL_DIR)/include

# Dynamically determine if we should use lib or lib64
OPENSSL_LIB=$(shell if [ -d "$(OPENSSL_DIR)/lib64" ]; then echo "$(OPENSSL_DIR)/lib64"; else echo "$(OPENSSL_DIR)/lib"; fi)

CC=gcc

CFLAGS=-g -Wall -Wextra -Werror -Wpedantic -I$(OPENSSL_INCLUDE)
LDFLAGS=-L$(OPENSSL_LIB) -lssl -lcrypto -Wl,-rpath,$(OPENSSL_LIB),--disable-new-dtags -ldl -lpthread

all: s_server.o s_timer.o s_timer_quic.o s_timer_ct.o s_timer_ct_quic.o

s_timer.o: s_timer.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

s_timer_ct.o: s_timer_ct.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

s_server.o: s_server.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

s_timer_quic.o: s_timer_quic.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@
	
s_timer_ct_quic.o: s_timer_ct_quic.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f *.o
	pkill s_server.o || true
	pkill s_timer.o || true