# HARDENING.md — non-destructive operation of A_exploit_stock.py

What the exploit guarantees, what it leaves behind, and why.

## Guarantees (validated: 3 consecutive fresh-container runs + soak)

1. **The server never crashes during exploitation.** All crash-prone
   primitives were eliminated:
   - The XPENDING fake-consumer echo is used exactly once, with
     `klist=[3,4]`, so the sds prefix is the robj's own header (bounded
     ≤255-byte reply, no runaway read).
   - All leaks (PIE, libc, `server.db`) go through the bounded GETRANGE
     channel (≤128-byte reads).
   - The `db[0].dict` leak is *verified deterministically before any
     write* (`verify_dict_type`: `D[0]=0xa0` → type-5 sds, len 20,
     content must equal `pie+0x205ba0`); a mismatch aborts the run
     cleanly instead of writing to a wrong address.
2. **RCE fires exactly once** (the trigger command runs via
   `system(key)` in the poisoned db's `dictFind`).
3. **The target is fully functional afterwards** — `db->dict->type` is
   written back in place (the dict/table was never freed or
   restructured), configs (`save`, `slowlog-log-slower-than`) are
   restored, and ~1300 grooming keys are deleted. Verified by a command
   battery (PING/SET/GET/INFO/DBSIZE) and a 45s+ soak per run.

## How non-destructiveness is achieved (design notes)

- **Endgame**: in-place poison of an *empty* db's dict `type` pointer
  (found by scanning `D + k*96` for `dbDictType`). Two subtleties:
  - `dictFind` short-circuits on `used==0` *before* hashing, so a
    `dummykey` is SET (and DELeted, via the same deterministic
    exit-code hash) around the trigger GET. Net dict change: zero.
  - db0 is never poisoned, so the fake-entry write channel stays alive
    to write the original `type` back.
- **Write safety**: `dictType` pointers are 8-aligned, so `D[0]` is
  always a valid type-5 sds header (alloc ≥ 7); only `D[1..7]` is ever
  written (one 7-byte SETRANGE per direction). The fake dictType is
  placed at a BUF offset whose low byte equals `orig_type & 0xFF`.
- **Persistence guard**: `CONFIG SET save ""` during the run so no
  BGSAVE can serialize the mid-exploit corrupt state; restored after.

## Residue (deliberate, inert, stable)

- **`k001` (the fake dictEntry key)**, **the 22-char binary-name key**,
  and **`BUF`** remain in db0. Deleting them would free *interior*
  pointers (the fake key/robj live inside BUF's sds; the binary key's
  sds is the double-freed chunk) and corrupt the heap.
- **`streamkey*` (the g2 fake-consumer stream), `fck`, and the
  `g*G2MARK42*` marker keys** remain. The stream still holds a dangling
  NACK pointing at the reclaimed chunk (now a marker key's sds);
  deleting either owner double-frees it (this caused a delayed cron
  `dictRehash` crash in earlier revisions — fixed by leaving them).
- **Phantom-used boots (~40%)**: the fake entry's `next=NULL` orphans
  any entries chained behind it at plant time — they remain counted in
  `used` but unreachable. The exploit measures this
  (`dbsize − scan`) and, only on phantom boots, leaves ~210 filler keys
  so the dict never enters the shrink-rehash path (whose unbounded
  empty-bucket scan would otherwise run off the table — the `0x12`
  `dictRehash` crash). On clean boots, `dbsize` ends at ~21 keys.

## Reliability

- Per-boot success ≈ 85–100% locally (dominant failure: dict-pointer
  low byte < 4 → clean abort, no target impact). Wrap in a retry loop
  (see `A_loop_target.sh` / `remote_loop.sh`) for full automation; a
  failed attempt never corrupts the target (all writes are verified
  before firing, and the read channel is bounded).
