API ?= 35
PROJECT ?= rodin
OUTDIR ?= build/$(PROJECT)/bin
EMBEDDIR ?= build/embed

TARGET_DIR := src/targets/$(PROJECT)
TARGET_HEADER := $(TARGET_DIR)/target.h

NEEDS_TARGET_HEADER := $(if $(MAKECMDGOALS),$(filter-out generate-target detect-profile list-projects clean,$(MAKECMDGOALS)),1)
ifneq ($(NEEDS_TARGET_HEADER),)
ifeq ($(wildcard $(TARGET_HEADER)),)
$(error unknown PROJECT=$(PROJECT), missing $(TARGET_HEADER))
endif
endif

define pick_src
$(if $(wildcard $(TARGET_DIR)/$(1)),$(TARGET_DIR)/$(1),src/$(1))
endef

PRELOAD := $(OUTDIR)/preload.so
EMBED_KSUD := $(EMBEDDIR)/ksud

CORE_SRCS := \
  $(call pick_src,main.c) \
  $(call pick_src,util.c) \
  $(call pick_src,slide.c) \
  $(call pick_src,fops.c) \
  $(call pick_src,pipe.c) \
  src/root.c
PRELOAD_SRCS := $(CORE_SRCS) src/preload.c src/ksud_blob.S

.DEFAULT_GOAL := preload

DEFAULT_NDK_ROOT := $(HOME)/android-ndk-r29
NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(wildcard $(DEFAULT_NDK_ROOT)))
NDK_TOOLCHAIN ?= $(if $(NDK_ROOT),$(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64)
NDK_CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
HOST_CLANG ?= clang
SYSROOT ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/sysroot)
RESOURCE_DIR ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/lib/clang/21)\

HOST_TARGET_FLAGS := \
  --target=aarch64-linux-android$(API) \
  --sysroot=$(SYSROOT) \
  -resource-dir $(RESOURCE_DIR) \
  --rtlib=compiler-rt \
  --unwindlib=none
HOST_COMMON_LDFLAGS := \
  -fuse-ld=lld \
  -Wl,-rpath-link,$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android
HOST_PIE_LDFLAGS := \
  $(HOST_COMMON_LDFLAGS) \
  -Wl,-dynamic-linker,/system/bin/linker64

ifneq ($(origin CC),default)
  TARGET_CC := $(CC)
  TARGET_FLAGS :=
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else ifneq ($(wildcard $(NDK_CC)),)
  NDK_CC_WORKS := $(shell $(NDK_CC) --version >/dev/null 2>&1 && echo yes)
  ifeq ($(NDK_CC_WORKS),yes)
    TARGET_CC := $(NDK_CC)
    TARGET_FLAGS :=
    TARGET_COMMON_LDFLAGS :=
    TARGET_PIE_LDFLAGS :=
  else
    TARGET_CC := $(HOST_CLANG)
    TARGET_FLAGS := $(HOST_TARGET_FLAGS)
    TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
    TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
  endif
else
  TARGET_CC := $(HOST_CLANG)
  TARGET_FLAGS := $(HOST_TARGET_FLAGS)
  TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
  TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
endif

COMMON_CFLAGS := -O2 -g0 -Wall -Wextra -Isrc
PIE_CFLAGS := -fPIE -pie $(COMMON_CFLAGS)
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
TARGET_CFLAGS := -DTARGET_CONFIG_H=\"targets/$(PROJECT)/target.h\"

BOOT ?=
PROFILE ?=
PROFILE_OUT ?= profile.json
TARGET_GEN ?= tools/generate_target.py

.PHONY: all preload clean info list-projects generate-target detect-profile

all: preload

preload: $(PRELOAD)

$(OUTDIR):
	mkdir -p $@

$(EMBEDDIR):
	mkdir -p $@

$(PRELOAD): $(PRELOAD_SRCS) $(TARGET_HEADER) $(EMBED_KSUD) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) \
	  $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) \
	  -shared -o $@ -pthread
	sha256sum $@

info:
	@echo "PROJECT=$(PROJECT)"
	@echo "TARGET_DIR=$(TARGET_DIR)"
	@echo "NDK_ROOT=$(NDK_ROOT)"
	@echo "NDK_HOST_TAG=$(NDK_HOST_TAG)"
	@echo "NDK_TOOLCHAIN=$(NDK_TOOLCHAIN)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "TARGET_FLAGS=$(TARGET_FLAGS)"
	@echo "TARGET_COMMON_LDFLAGS=$(TARGET_COMMON_LDFLAGS)"
	@echo "TARGET_PIE_LDFLAGS=$(TARGET_PIE_LDFLAGS)"
	@echo "SYSROOT=$(SYSROOT)"
	@echo "RESOURCE_DIR=$(RESOURCE_DIR)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "CORE_SRCS=$(CORE_SRCS)"

list-projects:
	@find src/targets -mindepth 2 -maxdepth 2 -name target.h -printf '%h\n' | sed 's#src/targets/##' | sort

clean:
	@test ! -d build || find build -mindepth 1 -maxdepth 1 ! -name embed -exec rm -rf {} +
generate-target:
	@test -n "$(BOOT)" || { echo "BOOT=/path/to/boot.img is required" >&2; exit 2; }
	@test -n "$(PROFILE)" || { echo "PROFILE=/path/to/profile.json is required (or use tools/generate_target.py --detect-adb-and-generate)" >&2; exit 2; }
	$(TARGET_GEN) --project "$(PROJECT)" --boot "$(BOOT)" --profile "$(PROFILE)"

detect-profile:
	$(TARGET_GEN) --detect-adb-profile -o "$(PROFILE_OUT)"

