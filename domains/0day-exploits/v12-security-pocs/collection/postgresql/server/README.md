# PostgreSQL `to_char('TZ'/'TZtz')` Heap-Overflow RCE

This vulnerability was independently discovered with [V12](https://v12.sh) by
Rick de Jager of the [V12 security team](https://x.com/v12sec).

## Description

`datetime_to_char_body()` sizes its working buffer from the format string, but
the `TZ` and `TZtz` paths copy the session's POSIX timezone abbreviation into
that buffer without checking its length. An authenticated user can set an
oversized abbreviation and trigger a heap overflow through `to_char()`,
potentially executing code with the privileges of the PostgreSQL server.

## Build

The PoC targets the pinned official **PostgreSQL 19beta1 x64 Debian image**
with digest
`sha256:a6bdd01b51b115f446a03135f9395575b3eb6ba90a92bfb692da82088f8820f8`.
Its offsets are build-specific; other builds will normally fail or crash a
backend instead of executing the payload.

Requirements are Docker with Compose, Python 3, and the packages in
`requirements.txt`:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

No local PostgreSQL build is required. Compose starts the pinned target on
`127.0.0.1:55432`.

## Run

Start the disposable target lab and follow its logs:

```bash
docker compose up -d
docker compose logs -f postgres
```

From a separate shell, run `poc.py`. It only opens PostgreSQL connections and
never invokes Docker or inspects the target filesystem:

```bash
. .venv/bin/activate
python poc.py
```

Expected client output:

```text
[+] PIE base (ELF) = 0x...
[*] Heap pointer leaked: 0x...
[+] Exploit payload sent; check the target logs
```

The Docker log terminal shows the default payload output:

```text
pg-tzlab  | PWNED
pg-tzlab  | uid=999(postgres) gid=999(postgres) ...
```

> This is a remote code-execution PoC. Run it only in a disposable environment
> that you control.

## How It Works

1. `datetime_to_char_body()` sizes its output workspace from the format-string
   length: `palloc(fmt_len * DCH_MAX_ITEM_SIZ + 1)`. The `DCH_TZ` and `DCH_tz`
   paths then copy the session's user-controlled POSIX timezone abbreviation
   into that workspace without checking its length.
2. Two adjacent `to_char(now(), 'TZ')` calls reuse the same freed workspace
   hole. The second overflow rewrites the first result's varlena length, causing
   binary COPY output to disclose about 16 KiB of adjacent heap. Function
   pointers in that data reveal the PostgreSQL PIE base.
3. A 50-byte timezone abbreviation reaches the invalid-pointer free path. Its
   error message includes the rejected address, disclosing a live heap pointer.
4. A priming `to_char('TZtz')` corrupts allocator metadata so a subsequent
   execution-time `decode(..., 'hex')` allocation overflows into printtup's
   per-row memory context. The payload repairs required context fields, installs
   a fake `MemoryContextCallback`, and points it at `system()` and the command.
5. At the end of the row, `MemoryContextReset()` invokes the forged callback and
   executes the configured command in the backend process.

The final allocator state depends on heap residue fixed when the postmaster is
forked. An unsuitable instance exits during heap grooming before the final
decode. The PoC reports that condition without a traceback. Restart the lab
with `docker compose restart`, then rerun `poc.py`.

## Fixed upstream

[PostgreSQL commit `3d724bf4`](https://github.com/postgres/postgres/commit/3d724bf4fde67a2931733a5143b7d6c12b23990c)
adds length checks to the `DCH_TZ` and `DCH_tz` paths and identifies the issue as
[CVE-2026-14669](https://www.cve.org/CVERecord?id=CVE-2026-14669).