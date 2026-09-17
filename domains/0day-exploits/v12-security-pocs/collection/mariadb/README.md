# MariaDB Low-Privilege RCE

These vulnerabilities were discovered with [V12](https://v12.sh) by Rick de
Jager of the [V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at
> [v12.sh](https://v12.sh).

We are releasing the PoC early because both bugs are now public. We duped on
the `ST_Area` ASLR bypass, which now has a
[public patch](https://jira.mariadb.org/browse/MDEV-40328). We reported the
cursor-array use-after-free first, but another researcher subsequently
[published it on GitHub](https://github.com/dinosn/mariadb-13-rce-lab/tree/main)
as a 0-day.

## Abstract

This PoC chains two MariaDB memory-safety bugs to execute an arbitrary command
as the `mariadbd` process from a low-privilege database account:

- an `ST_Area` out-of-bounds read leaks heap and PIE addresses;
- a `SYS_REFCURSOR` cursor-array use-after-free provides control flow.

The exploit targets the pinned `mariadb:13.0.1-rc` Docker image. It uses only
the normal TCP query interface and does not require `FILE`, `SUPER`, or an
administrative account.

## Exploitation

Install the Python dependency:

```bash
python3 -m pip install pymysql
```

Start the target in one terminal:

```bash
./start.sh
```

After MariaDB reports that it is ready, run the exploit in another terminal:

```bash
python3 exploit.py
```

The default payload runs `id`; its output appears in the target terminal. Use
`--cmd` or `EXP_CMD` to run a different command:

```bash
python3 exploit.py --cmd 'uname -a'
```

## How It Works

1. A crafted `MULTIPOLYGON` makes `ST_Area` read beyond its geometry buffer,
   disclosing a heap pointer.
2. Cursor-array reallocation frees storage still referenced by open cursors. A
   controlled split leaves a vtable pointer that the same `ST_Area` primitive
   discloses, revealing the PIE base.
3. A session variable reclaims the freed cursor storage with a fake vtable and
   COOP chain.
4. `FETCH` follows the stale cursor pointer and dispatches through the reclaimed
   object, invoking `execlp("/bin/sh", "sh", "-c", command)`.

The command replaces the container's PID 1, so the database connection closes
and the disposable container exits after successful exploitation.

## Credit

Found with V12 by Rick de Jager of the V12 security team:
[v12.sh](https://v12.sh): dangerously powerful agentic security.
