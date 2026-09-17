MODULE  := github.com/Percivalll/Dirty-Frag-Kubernetes-PoC
IMAGE   ?= dirtyfrag-poc
TAG     ?= eks

CC      ?= x86_64-linux-gnu-gcc
BUILDDIR := build

.PHONY: all payload-eks payload-header build-eks docker-build-eks clean

all: build-eks

# ── Step 1: compile nolibc payload → static ELF ──────────────────────
payload-eks: $(BUILDDIR)/payload

$(BUILDDIR)/payload: payload/payload-eks.c
	@mkdir -p $(BUILDDIR)
	$(CC) -static -nostdlib -include payload/nolibc/nolibc.h \
		-o $(BUILDDIR)/payload payload/payload-eks.c

# ── Step 2: generate C header with embedded payload bytes ────────────
payload-header: $(BUILDDIR)/payload_bin.h

$(BUILDDIR)/payload_bin.h: $(BUILDDIR)/payload
	xxd -i $(BUILDDIR)/payload > $(BUILDDIR)/payload_bin.h

# ── Step 3: compile exploit (links embedded payload) ─────────────────
build-eks: $(BUILDDIR)/dirtyfrag

$(BUILDDIR)/dirtyfrag: $(BUILDDIR)/payload_bin.h exploit/dirtyfrag.c
	$(CC) -O0 -Wall -static -I$(BUILDDIR) \
		-o $(BUILDDIR)/dirtyfrag exploit/dirtyfrag.c

# ── Step 4: build container image ────────────────────────────────────
docker-build-eks: $(BUILDDIR)/dirtyfrag
	docker build -f Dockerfile.eks -t $(IMAGE):$(TAG) .

# ── Convenience: build with nerdctl on EKS node ─────────────────────
nerdctl-build-eks: $(BUILDDIR)/dirtyfrag
	nerdctl --namespace k8s.io build -f Dockerfile.eks -t $(IMAGE):$(TAG) .

clean:
	rm -rf $(BUILDDIR)
