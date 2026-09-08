# PostgreSQL RI Owner-Switched Implicit Cast PoC

This entry documents server-side command execution through PostgreSQL referential-integrity checking when a foreign-key column uses an attacker-owned implicit cast into the referenced primary-key operator class type.

The PoC drives a normal PostgreSQL server through `psql`. It creates the owner and attacker roles, grants column-level `REFERENCES` on the primary-key column, creates the attacker-owned type, SQL function, implicit cast, and foreign-key table, then inserts a row that forces the RI lookup to invoke the cast function while the effective database role is the referenced table owner.

## Target

| Field | Value |
| --- | --- |
| Product | PostgreSQL |
| Tested commit | `e0ff7fd9aa2e6f77c38825e71200ced742220d55` |
| Tested binary | `PostgreSQL 20devel on x86_64-pc-linux-gnu` |
| Platform | Linux x86-64 |
| Interface | `psql` against a stock server |
| Required owner capability for the payload | membership in `pg_execute_server_program` |
| Required attacker grant on the referenced table | `REFERENCES (id)` |

## Impact

An attacker who can create a data type, SQL function, implicit cast, and referencing table can place attacker-owned SQL in the FK type-to-PK type cast path. When a row is inserted into the referencing table, PostgreSQL's RI check switches to the referenced table owner before it probes the referenced table. The implicit cast is then invoked as a normal `SECURITY INVOKER` SQL function under that owner-switched effective role.

If the referenced table owner has `pg_execute_server_program`, the attacker-owned SQL function can reach `COPY ... TO PROGRAM`. The PoC writes a marker containing `current_user`, `session_user`, and `is_superuser`; a successful run produces:

```text
ri_owner_probe:ri_attacker_probe:off
```

## Source Trace

| File | Relevant path |
| --- | --- |
| `src/backend/commands/functioncmds.c` | `CreateCast()` allows cast creation when the caller owns the source or target type and records `AS IMPLICIT` casts in `pg_cast`. |
| `src/backend/commands/tablecmds.c` | FK creation accepts an implicit cast from the FK type to the primary-key operator-class input type through `can_coerce_type(..., COERCION_IMPLICIT)`. |
| `src/backend/commands/tablecmds.c` | Referenced-table permission checks accept table-level or column-level `REFERENCES`. |
| `src/backend/utils/adt/ri_triggers.c` | `ri_PlanCheck()` and `ri_PerformCheck()` switch to the owner of the table being queried for RI enforcement. |
| `src/backend/utils/adt/ri_triggers.c` | `ri_FastPathCheck()` and `ri_FastPathBatchFlush()` switch to the referenced table owner before building scan keys and probing the PK index. |
| `src/backend/utils/adt/ri_triggers.c` | `build_index_scankeys()` calls the cached cast function for FK values that must be coerced to the operator input type. |
| `src/backend/utils/adt/ri_triggers.c` | `ri_CompareWithCast()` and `ri_HashCompareOp()` resolve and call implicit cast functions during RI comparisons. |
| `src/backend/executor/functions.c` | SQL functions reject client-side `COPY`, while file and program `COPY` utility statements continue into normal execution. |
| `src/backend/executor/spi.c` | SPI rejects client-side `COPY` and permits filename/program `COPY` utility statements to proceed. |
| `src/backend/commands/copy.c` | `COPY TO/FROM PROGRAM` checks `pg_execute_server_program` against `GetUserId()`. |
| `src/backend/commands/copyto.c` | A permitted `COPY TO PROGRAM` reaches `OpenPipeStream()`. |

The relevant owner switch in `ri_PerformCheck()` sets the active user ID to the owner of the relation being queried. The foreign-key insert path queries the referenced table, so the active user ID becomes the referenced table owner before the implicit cast executes.

## Reproduction Flow

1. Connect as a bootstrap database role that can create roles, create a database, and grant `pg_execute_server_program`.
2. Create `ri_owner_probe` and grant it `pg_execute_server_program`.
3. Create `ri_attacker_probe`.
4. Create `ri_owner_probe.pk(id integer primary key)` and insert `7`.
5. Grant `REFERENCES (id)` on `ri_owner_probe.pk` to `ri_attacker_probe`.
6. As `ri_attacker_probe`, create a composite type, a SQL cast function, an implicit cast from that type to `integer`, and a referencing table.
7. Confirm a direct call to the cast function is blocked by the `COPY TO PROGRAM` privilege check.
8. Insert `ROW(7)::ri_attacker_probe.fkkey` into the FK table.
9. Confirm that the marker file was created with `current_user` equal to the referenced table owner and `session_user` equal to the attacker role.

## Usage

Start a stock PostgreSQL server and run the PoC with a bootstrap role:

```bash
python3 poc.py \
  --psql /path/to/psql \
  --host 127.0.0.1 \
  --port 5432 \
  --admin-user postgres \
  --admin-db postgres \
  --marker /tmp/postgres_ri_cast_marker.txt
```

If the bootstrap role requires a password, pass it through the environment:

```bash
PGPASSWORD='bootstrap-password' python3 poc.py --admin-user postgres
```

The marker path is interpreted by the PostgreSQL server host because it is used inside `COPY ... TO PROGRAM`.

Expected output shape:

```json
{
  "database": "ri_cast_probe",
  "owner_role": "ri_owner_probe",
  "attacker_role": "ri_attacker_probe",
  "direct_function_call_blocked": true,
  "insert_returncode": 0,
  "marker": "ri_owner_probe:ri_attacker_probe:off",
  "expected_marker": "ri_owner_probe:ri_attacker_probe:off",
  "reproduced": true
}
```

## Local Verification

The committed PoC was replayed from this folder against a fresh stock PostgreSQL build:

```text
PostgreSQL 20devel on x86_64-pc-linux-gnu
commit e0ff7fd9aa2e6f77c38825e71200ced742220d55
```

Representative output is saved in [`evidence/local-verification.txt`](evidence/local-verification.txt).

## Files

| Path | Purpose |
| --- | --- |
| [`poc.py`](poc.py) | End-to-end PostgreSQL RI implicit-cast proof. |
| [`evidence/local-verification.txt`](evidence/local-verification.txt) | Output from a successful local replay against a stock PostgreSQL server. |

## Notes

The script drops and recreates the probe database and two probe roles named in the command-line options. Run it against a disposable database instance or use role/database names reserved for this validation.

Only run this against systems you own or have explicit permission to test.
