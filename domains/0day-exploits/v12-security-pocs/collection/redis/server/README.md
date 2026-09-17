# Redis Remote RCE

This vulnerability was discovered with [V12](https://v12.sh) by Rick de
Jager of the [V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at
> [v12.sh](https://v12.sh).

The bug is a still-reachable sibling-eviction variant of CVE-2026-23479. The
upstream fix protects the blocked client whose command is currently executing,
but not a different blocked client freed from the list being iterated.

The bug was fixed in
[#15594](https://github.com/redis/redis/pull/15594) and shipped in Redis 8.8.2.
This lab uses a container pinned to the vulnerable Redis 8.8.0 version.

## Abstract

This PoC turns a heap use-after-free in Redis
`handleClientsBlockedOnKey()` into arbitrary command execution as the
`redis-server` process. It uses only the normal TCP command interface and works
with full RELRO: no writable GOT, module loading, file write, debugger, or
server restart is required.

The exploit targets the official Redis 8.8.0 amd64 image, pinned by digest in
`start.sh`. A remote user needs permission to run the commands used by the
chain, including `CONFIG SET`; the disposable lab uses Redis's default user
without authentication.

## Exploitation

Start the target in one terminal:

```bash
./start.sh
```

After Redis reports that it is ready, run the exploit in another terminal:

```bash
python3 exploit.py
```

The default payload runs `id`; its output appears in the target terminal. Use
`--cmd` to run a different command:

```bash
python3 exploit.py --cmd 'uname -a'
```

The exploit uses only the Python standard library. In case the exploit is not
successful on first run, restart the docker container and try again.

## How It Works

1. `handleClientsBlockedOnKey()` walks `db->blocking_keys[key]` with a raw list
   iterator. Re-executing one blocked client's command enters
   `evictClients()`, which can free a sibling blocked client and the iterator's
   next node. The next iteration dereferences reclaimed data as a `client`.
2. Heap grooming reclaims the sibling's 1280-byte jemalloc slot with a fake
   `client`. Controlled `last_memory_type` and `last_memory_usage` fields make
   `updateClientMemoryUsage()` subtract an attacker-chosen value at a
   `server`-relative index.
3. `EVAL "return tostring(redis.call)"` discloses the address of Redis's Lua
   `redis.call` CClosure. Redirecting the normally NULL
   `bind_source_addr` field and reading it through `CONFIG GET` turns the
   subtraction primitive into an arbitrary pointer read.
4. The first read obtains the CClosure function pointer and derives the Redis
   PIE base. The second reads `umask@GOT`, deriving the image's glibc base and
   `system` address.
5. A third subtraction replaces
   `commandTableDictType.hashFunction` (`dictSdsCaseHash`) with `system`.
   Sending the payload as a command name executes `system(payload)` during
   command-table lookup.

## Credit

Found with V12 by Rick de Jager of the V12 security team:
[v12.sh](https://v12.sh): dangerously powerful agentic security.
