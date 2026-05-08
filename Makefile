# Builds ntg-audio-hook.so for LD_PRELOAD injection into the tg-bridge process.
# Requires: gcc, glibc-devel
# Target: x86_64 Linux, NTgCalls 2.1.0 (ntgcalls.cpython-311-x86_64-linux-gnu.so)

CC      = gcc
CFLAGS  = -O2 -Wall -fPIC -shared
LDFLAGS = -ldl

all: ntg-audio-hook.so

ntg-audio-hook.so: ntg-audio-hook.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: ntg-audio-hook.so
	cp ntg-audio-hook.so /usr/local/lib/ntg-audio-hook.so
	@echo "Installed to /usr/local/lib/ntg-audio-hook.so"
	@echo "Add LD_PRELOAD=/usr/local/lib/ntg-audio-hook.so to your service environment."

clean:
	rm -f ntg-audio-hook.so

.PHONY: all install clean
