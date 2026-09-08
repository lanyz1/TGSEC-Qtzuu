# panda-rev — reverse engineering skill pack (fused)

Incremental reverse skills fused by attack surface:

| Skill | Domain path | Use |
|-------|-------------|-----|
| rev-symbol | `reverse-engineering/panda-rev/rev-symbol` | Restore symbols from decompile/export |
| rev-struct | `reverse-engineering/panda-rev/rev-struct` | Reconstruct structs from access patterns |
| rev-idapython | `reverse-engineering/panda-rev/rev-idapython` | IDAPython / IDALib reference |
| rev-unicorn-debug | `reverse-engineering/panda-rev/rev-unicorn-debug` | Unicorn snippet emulation |
| rev-frida | `mobile-security/panda-rev/rev-frida` | Modern Frida hook script gen |
| rev-dex-dumper | `mobile-security/panda-rev/rev-dex-dumper` | Android in-memory DEX dump (+ binary) |
| rev-u3d-dump | `mobile-security/panda-rev/rev-u3d-dump` | Unity IL2CPP symbol dump |
| rev-ios-dump | `mobile-security/panda-rev/rev-ios-dump` | iOS FairPlay dump via frida-ios-dump |

Also mirrored under local reverse-skill package `skills/rev-*` for route discovery.

**Note:** Designed around IDA-NO-MCP export layout (`decompile/*.c`, strings/imports/exports).
Works with IDA Pro MCP when connected.



@TGSEC社区 · @TGSEC-Qtzuu 整理
