Fortinet Hunter 2026 CTF — evidence pack
Captured live from docker exec against the re-keyed inner ELF.

Sandbox
  container  gatex-cage-bypass-smoke-bp
  image      gatex-cage:noble
  platform   linux/amd64
  network    none
  caps       ALL dropped
  user       65532:65532
  timestamp  2026-08-26 18:23:26Z

How the gate was opened
  The Nuitka inner ELF (7350FH.bin) was not brute-forced.
  XOR-scrambled Argon2id + AES-GCM banner blobs were re-keyed so
  FH_PASS=gatex satisfies both checks. Plugins were already compiled in.

Files
  00-bypass-log.png / .txt     GateX --bypass
  01-version.png / .txt        --version  →  fortinet-hunter 2026.08
  02-help.png / .txt           --help     →  full CLI
  03-list-banner.png           list (banner + detectors + exploits)
  03-list-full.png / .txt      complete plugin + CVE dump
  04-score-ml.png / .txt       score --ml
  05-before-after.png / .txt   original ELF denies gatex; patched ELF opens

The .txt files are the raw docker-exec captures (source of the PNGs).
