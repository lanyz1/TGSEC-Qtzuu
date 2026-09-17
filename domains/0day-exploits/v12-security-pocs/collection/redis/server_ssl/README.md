# Redis TLS Pending-List Remote RCE

This vulnerability was discovered with [V12](https://v12.sh) by hexamine.

> Want to find issues like this in your own code? Try V12 at
> [v12.sh](https://v12.sh).

## Abstract

This PoC turns a heap use-after-free in Redis's TLS pending-data list into
arbitrary command execution as the `redis-server` process. It reaches the bug
through the normal TLS command interface; no module loading, file write,
debugger, or prior access to the target filesystem is required.

The exploit targets the official amd64 Redis 8.8.0 image pinned by digest in
`start.sh`. It depends on that build's PIE offsets, jemalloc behavior, embedded
Lua 5.1 implementation, and TLS support.

The packaged Redis 8.8.0 target is affected. Redis fixed the flaw in
[commit `6d088c3`](https://github.com/redis/redis/commit/6d088c335d5c3ec49a6c28486140b498e70b7834),
which shipped in Redis 8.8.2.

## Exploitation

Install the Python dependencies:

```bash
python3 -m pip install pwntools z3-solver
```

Start the target in one terminal:

```bash
./start.sh
```

The launcher keeps Redis in the foreground so its logs and payload output stay
visible. After Redis reports that it is ready, run the exploit in another
terminal:

```bash
python3 exploit.py
```

The default payload runs `id`. Its output appears in the target terminal before
the container exits:

```text
uid=999(redis) gid=999(redis) groups=999(redis)
```

Use `--cmd` to select another command:

```bash
python3 exploit.py --cmd 'uname -a'
```

The optional positional arguments select the Redis TLS host and port; they
default to `127.0.0.1` and `6380`. The exploit reports
`payload command dispatched` after triggering the patched restart path; the
foreground target terminal shows the command's actual output.

The exploit is timing- and heap-layout-sensitive and makes up to eight attempts.
Stop and restart the target before retrying after a failed run.

## How It Works

The vulnerable object is a node in Redis's TLS pending-data list. Connections
with decrypted OpenSSL bytes still waiting to be consumed are linked through
`el->privdata[1]`, and `tlsProcessPendingData()` walks that list:

```c
listRewind(pending_list, &li);
while ((ln = listNext(&li))) {
    tls_connection *conn = listNodeValue(ln);
    tlsHandleEvent(conn, AE_READABLE);
}
```

The `adlist` iterator is not resilient to removal of its cached successor.
`listNext()` saves `current->next` in the iterator before returning `current`.
Command processing for the current connection can re-enter the event loop, so
the saved node can be unlinked and freed before the outer loop asks for it.

The exploit turns that stale-node dereference into RCE in seven stages:

1. **Leak Lua anchors and prepare fake objects.** Lua object stringification
   reveals the addresses of `_G`, the `redis` API table, the `pairs` CClosure,
   and several candidate fake TLS strings. A temporary closure with 60 upvalues
   is allocated in the same size class as the fake TLS `TString`; its leaked
   address predicts the payload base at `closure + 0x18`.

   Several candidate bases are kept because allocator placement determines
   which HSET value later reclaims the stale list node. The reclaim spray cycles
   through all candidates. The first candidate also becomes writable storage
   for `/bin/sh`, `-c`, the command string, and the final argv vector.

2. **Arrange the unsafe iterator ordering.** The trigger uses three connection
   roles. Client A sends the slow `EVAL`; RESP3 Pub/Sub clients B accumulate
   enough output to become close candidates; a blocker client runs `LPOS`
   against a large list to shape event-loop timing.

   A and B are primed with partial RESP `ECHO` requests. A's final request bytes
   are sent together with the Lua trigger, while each B client receives a tail
   fragment after subscribing. The required condition is specific: B must
   follow A in the outer pending list, and the outer iterator must cache B's
   `listNode *` before nested processing closes B. Merely closing B is not
   sufficient.

3. **Free and reclaim B's cached node.** A's Lua script performs a large
   `PUBLISH`, burns CPU long enough to cross Redis's Lua timeout path, and then
   overwrites groomed HSET values:

   ```lua
   redis.call('PUBLISH', KEYS[1], string.rep('A', 35651584))
   local a = 0 for i = 1, 1500000000 do a = a + 1 end
   redis.call('HSET', KEYS[2], unpack(h))
   ```

   Lua timeout handling pumps the event loop while the script remains active.
   Pub/Sub output pressure closes B in that nested event loop.
   `tlsPendingRemove()` unlinks and frees B's 24-byte `listNode`, but the outer
   iterator still stores its address.

   The final HSET replaces pre-groomed 80-byte values with 22-byte SDS values.
   These allocations fit the freed node's allocator class and shape the fields
   consumed when the outer loop resumes:

   ```text
   stale listNode + 0x08 -> controlled/zero next pointer
   stale listNode + 0x10 -> fake tls_connection pointer
   ```

   The replacement need not form a complete list node. The iterator already
   holds the stale node address; only the fields read after resumption must be
   safe and useful.

4. **Convert the stale pointer into a one-bit write.** The resumed outer walk
   reads the reclaimed node's `value` as a `tls_connection *`. The fake
   connection sets `state` to connected, `fd` to zero, supplies no read or
   write handlers, and points `el` at a fake `aeEventLoop` embedded in the same
   Lua string.

   The fake event loop aliases `events[0].mask` to `_G + 8`, the Lua table's
   type-tag byte. Its epoll state uses `epfd = -1`; the backend ignores the
   failed `epoll_ctl()` deletion, after which `aeDeleteFileEvent()` still
   executes the mask update:

   ```c
   aeApiDelEvent(eventLoop, fd, mask);
   fe->mask = fe->mask & (~mask);
   ```

   With no handlers on the fake connection, `updateSSLEvent()` removes
   `AE_READABLE`. This clears bit zero at `_G + 8`, changing the object type
   from `LUA_TTABLE` (`5`, `0b0101`) to `LUA_TSTRING` (`4`, `0b0100`).

5. **Reclaim the `redis` table and build a read/write primitive.** Once `_G` no
   longer has a table type, Lua's garbage collector does not traverse its table
   entries normally. A full collection can therefore release the `redis` API
   table while the running script retains a stale reference to its allocation.

   A Lua `Table` is 72 bytes in this build. A `TString` with a 24-byte header,
   47 controlled bytes, and a trailing NUL is also 72 bytes, so sprayed
   47-byte strings can occupy the freed table slot. Z3 solves the unconstrained
   bytes so each string has Lua hash zero while fixed positions encode a fake
   table's array and hash fields.

   Integer index `r[1]` accesses the fake array slot, while integer key `r[0]`
   reaches a fake hash node overlapping the array pointer. Pointing that array
   at a real helper table makes assignments to `r[1]` retarget `p[1]`; reads and
   writes through `p[1]` then access an attacker-selected qword.

   This is target-aware rather than a clean byte-granular primitive. Values pass
   through Lua number `TValue`s, and a write also places a number type tag at
   `target + 8`. The exploit chooses final targets where that collateral is
   acceptable.

6. **Derive PIE and patch restart state.** The exploit reads the raw
   `luaB_pairs` function pointer from the leaked `pairs` CClosure and subtracts
   its known image offset to obtain the Redis PIE base. It then writes the
   command strings and argv into the first fake TLS buffer and patches:

   - `server.executable` to point to `/bin/sh`;
   - `server.exec_argv` to point to `[NULL, "-c", command, NULL]`;
   - `server.enable_debug_cmd` to enable protected DEBUG actions; and
   - `redisCommandTable[DEBUG].flags` to include `CMD_NO_AUTH`.

   Redis replaces `exec_argv[0]` with `server.executable` immediately before
   `execve()`, producing `["/bin/sh", "-c", command, NULL]`.

7. **Enter the restart path.** With the protected-action gate and command flags
   patched, the exploit sends `DEBUG CRASH-AND-RECOVER`. Redis closes the
   connection during restart and executes `/bin/sh -c <command>` as the
   `redis-server` user.

The packaged launcher configures TLS without client certificates and grants the
default user only:

```conf
+ping +echo +eval +eval_ro +publish +hello +subscribe +lpos +rpush +del +hset
```

Different Redis builds require new offsets and may require different heap
grooming. Disabling scripting or denying any command used by the trigger breaks
this exploit chain as written.

## Credit

Found with V12 by hexamine:
[v12.sh](https://v12.sh): dangerously powerful agentic security.
