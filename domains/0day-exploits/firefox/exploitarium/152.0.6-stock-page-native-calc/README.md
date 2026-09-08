# Firefox 152.0.6 Stock Page Native Calculator PoC

This folder contains a standalone browser-page proof for signed Windows x64 Firefox `152.0.6`. A normal HTTP navigation reaches native execution in the Firefox content process, crosses the parent broker path, and opens Windows Calculator. The page performs its own allocation calibration and derives the native addresses it uses during the run.

The final effect is deliberately limited to launching Calculator. The marker body and broker body modified during the proof are restored and compared before the page emits its final success signal.

## Tested Target

| Property | Value |
| --- | --- |
| Platform | Windows x64 |
| Firefox | `152.0.6` |
| Build ID | `20260713164047` |
| JIT configuration | Stock defaults |
| `firefox.exe` SHA-256 | `02F15ADE493DF6E9CAFEA1303E443B02AC658A0DC4FA56480D1C6C9441637667` |
| `xul.dll` SHA-256 | `15CC192CE21F2957B18833621D13D31FCBBBA7DF7999E15BD8027486E05DA46F` |

The native layout and broker payload are tied to this exact Firefox build. Confirm both executable hashes before reproduction.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Entry page that transfers the navigation to the stock bootstrap. |
| `wasm_gc_rw_stock.html` | Allocation calibration, stale iterator-index trigger, raw value primitive, native read setup, and continuation loader. |
| `full_chain_calc_tail.js` | Native read and write continuation, registered Wasm body handling, broker stage installation, dispatch, verification, and restoration. |
| `firefox-152.0.6-rce-marker.wasm` | Small registered Wasm function and linear memory used for the native marker and absolute-copy bridge. |
| `broker-stage.wasm` | Registered sacrificial function body and linear memory used for the broker stage. |
| `broker_calculator_stage.bin` | `547`-byte Windows x64 parent-broker Calculator payload. |
| `README.md` | Reproduction, analysis, validation record, and artifact identities. |

## Reproduction

Close existing Calculator windows so the new process and top-level window are unambiguous. From this folder, start a local static server:

```powershell
python -m http.server 8941 --bind 127.0.0.1
```

Open the following URL in the tested Firefox build:

```text
http://127.0.0.1:8941/
```

The entry page redirects to `wasm_gc_rw_stock.html?full=1`. The bootstrap loads the continuation and the three binary assets from the same origin. Successful completion opens a new visible Calculator window.

The page also sends optional diagnostic requests to `/report.gif`. A plain static server responds with `404`, while its request log still records the ordered checkpoints and their values.

## Expected Checkpoints

The diagnostic sequence is:

1. `ready`
2. `native_read_success`
3. `native_marker_success`
4. `broker_dispatch_success`
5. `calc_success`

The final checkpoint is sent only after the native marker returns the expected value, both broker calls return successfully, the broker body matches its backup, and both modified marker words match their originals.

## Technical Analysis

### Stale Iterator Index

The page trains a `for-in` access shape in which Ion can reuse an `MIteratorMore` result after a dominating `MIteratorEnd`. Iterator shutdown resets the native cursor to zero. The optimized slot access still consumes `indices[cursor - 1]`, so the word immediately before the indices array is interpreted as an unchecked dynamic-slot index.

The trigger supports both a property load and a property store. The page warms object-valued and integer-valued stores before optimization so later raw-value operations retain the required optimized graph.

### Allocator Adjacency

The bootstrap prepares tenured objects with property-slot allocations across power-of-two size buckets. Each source allocation is followed immediately by a size-matched mutable Wasm-GC `i64` array allocation. Calibration identifies the property name whose stale slot index aliases an element of the adjacent Wasm carrier.

That alias exposes the raw `JS::Value` representation. The page verifies the primitive with an object round trip and the controlled integer value `0x13371337` before consuming any native address.

### Native Read

A `BigUint64Array` supplies stable inline storage for a two-digit `JS::BigInt` layout. The forged header redirects `heapDigits_` to a chosen native address. JS-to-Wasm `i64` conversion captures the selected native qword in a Wasm global. The forged value is then dropped, the raw carrier is returned to a safe integer representation, and the captured qword is materialized as a genuine JavaScript `BigInt`.

Every object address disclosure re-enters the optimized trigger before and after the store. The fake BigInt storage address is refreshed after the final allocation and promotion phase, keeping the interior pointer synchronized with the live tenured object.

### Native Write

The continuation creates a genuine `OBJECT4` plain object with the required shape, elements pointer, fixed slots, and dynamic-slot geometry. It clones that layout into page-owned typed-array inline storage and retargets dynamic slot `75`, corresponding to property `p79`. Finite `JS::Value` words can then be written to selected native qwords through an ordinary property assignment.

The page first writes and restores a controlled qword in page-owned storage. It then derives the registered Wasm function-body pointers and verifies that the words selected for modification preserve the finite-number constraint used by the write path.

### Registered Wasm Control Flow

The marker module provides a genuine Wasm export trampoline and a small registered body. Two qwords in that body are backed up, replaced with a compact native marker, invoked through the export, and restored. The marker writes `0x52434521` to page-owned linear memory and returns `1`.

The same two finite qwords then hold a `16`-byte absolute-copy bridge. That bridge copies the bundled broker payload from page-owned memory into the registered broker function body. A second copy verifies the installed bytes before dispatch.

### Parent Broker Dispatch

The installed stage sends two ordered `PContent` messages carrying the `calculator:` URI. The first call installs the Calculator handler used by the exact build, and the second immediately invokes it through the same parent channel. Both calls return `1` with status `0x444e4553`.

After dispatch, the absolute-copy bridge restores the complete broker body from its backup and copies it back into page memory for byte comparison. The original marker qwords are restored and checked as well. Calculator launch is reported only after all restoration checks pass.

## Verified Stock Replay

The runtime assets were exercised twice on July 15, 2026 against the signed target listed above. The first captured run used an isolated Firefox profile, ordinary HTTP navigation, and stock JIT settings. The second run repeated the chain with a visible browser session.

| Milestone | Captured result |
| --- | --- |
| Page ready | `127 ms` after navigation |
| Native read proof | `106 ms` after page start |
| Final page checkpoint | `1839 ms` after page start |
| Visible Calculator window | `6063.513 ms` after Firefox launch |
| Native marker return | `1` |
| Native marker value | `0x52434521` |
| Broker payload | `547` bytes, native copy verified |
| Broker returns | `1`, `1` |
| Broker statuses | `0x444e4553`, `0x444e4553` |
| Broker body restored | `true` |
| Marker body restored | `true` |
| Target executable hashes after replay | unchanged |

The baseline contained zero Calculator processes. The captured result included a new `CalculatorApp.exe` process and a visible top-level window titled `Calculator`. Scoped cleanup closed the new window, stopped the created process tree, removed the isolated profile, and left zero Firefox or Calculator processes from the replay.

## Runtime Artifact Hashes

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `index.html` | `233` | `A76BDFE994043F247A42D84BF3B45BC2A22D8B5060D6BA3FA7A1F8E8D2A7A028` |
| `wasm_gc_rw_stock.html` | `13858` | `0D4F4A8FA818A63610E1557BFD4F3A977831C9A559A215F17F4242A4665A29ED` |
| `full_chain_calc_tail.js` | `17323` | `F0AD470F84CA508057BB97C6D91E72DC987E8D5292366B937A26254005DADCE3` |
| `firefox-152.0.6-rce-marker.wasm` | `83` | `C07F61992D8499D2153D5FD4FA366C4D70016CD23196716C1E7DD1ECFB363646` |
| `broker-stage.wasm` | `3426` | `4E5E9095FF9ED8DD3EE01273F0EABB20A271FBEB5E03CA3D1A59BC047D8CD08F` |
| `broker_calculator_stage.bin` | `547` | `AFBF3F9CB8E98C85D24BAD7F73E7311ED989F19B48FF8F85F44506914BBDA5A5` |

## Fix Direction

Iterator-index optimization should accept only an `MIteratorMore` whose uses remain valid across iterator shutdown. A use dominated by `MIteratorEnd` must retain the normal property access path. Native iterator access should also assert that the iterator is active and that its cursor is nonzero before reading `indices[cursor - 1]`.

Regression coverage should exercise property loads and stores after the iterator-closing control-flow shape, including optimized graphs with object and integer stores and cursor-zero state.

## Responsible Use

Use this material only for authorized reproduction, browser hardening, and regression testing.
