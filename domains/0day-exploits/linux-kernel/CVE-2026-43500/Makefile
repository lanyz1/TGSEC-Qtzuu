# DIRTYFAIL — Makefile
#
# Builds a single statically-linked binary `dirtyfail` from src/*.c.
#
# Targets:
#   make           build optimized binary
#   make debug     build with -O0 -g for gdb
#   make static    build a fully static binary (musl recommended for portability)
#   make clean     remove build artifacts
#   make scan      build and run --scan against localhost
#
# Build prerequisites: gcc or clang, make, libc headers including
# <linux/xfrm.h>. On Debian/Ubuntu: `apt install build-essential linux-libc-dev`.
# On RHEL/Fedora: `dnf install gcc make kernel-headers`.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -Wno-pointer-arith \
           -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS ?=

SRC_DIR := src
BUILD   := build
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD)/%.o,$(SOURCES))
BIN     := dirtyfail

.PHONY: all debug static clean scan install test test-fcrypt test-aes-ecb

all: $(BIN)

# === Tests ===========================================================
#
#   make test          build + run all primitive selftests
#   make test-fcrypt   just fcrypt (cipher, brute force) — runs anywhere
#   make test-aes-ecb  AF_ALG ecb(aes) round-trip — Linux only
#
# Tests live in tests/, build standalone executables that link the
# minimum from src/. They don't pull in netlink / xfrm / rxrpc — those
# require root or AA bypass to exercise meaningfully and are tested
# end-to-end via `--exploit-* --no-shell` on a target host instead.

TEST_DIR  := tests
TEST_BUILD:= $(BUILD)/tests

# fcrypt selftest needs only fcrypt + common (for log_*) — no Linux deps
$(TEST_BUILD)/test_fcrypt: $(TEST_DIR)/test_fcrypt.c $(SRC_DIR)/fcrypt.c $(SRC_DIR)/common.c | $(TEST_BUILD)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $^

# AES-ECB AF_ALG round-trip — Linux only, no DIRTYFAIL src deps
$(TEST_BUILD)/test_aes_ecb: $(TEST_DIR)/test_aes_ecb.c | $(TEST_BUILD)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_BUILD): | $(BUILD)
	@mkdir -p $(TEST_BUILD)

test-fcrypt: $(TEST_BUILD)/test_fcrypt
	@echo "=== test_fcrypt ==="
	$<
	@echo ""

test-aes-ecb: $(TEST_BUILD)/test_aes_ecb
	@echo "=== test_aes_ecb ==="
	$<
	@echo ""

test: test-fcrypt test-aes-ecb
	@echo "=== all primitive selftests passed ==="

$(BIN): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/common.h | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

$(BUILD):
	@mkdir -p $(BUILD)

debug: CFLAGS := -O0 -g3 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
debug: clean $(BIN)

# `make static` works best with musl-gcc; glibc static linking pulls in
# NSS at runtime which breaks getpwnam.
static: LDFLAGS += -static
static: clean $(BIN)

clean:
	rm -rf $(BUILD) $(BIN)

scan: $(BIN)
	./$(BIN) --scan

install: $(BIN)
	install -m 0755 $(BIN) /usr/local/bin/dirtyfail
