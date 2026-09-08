# KB Fusion Report — 2026-09-08

Generated: 2026-09-08 22:00 UTC

## Stats

- copied/updated files: **1276**
- identical skipped: 708
- exists skipped: 0
- dirs created: 266
- by source: `{"TORCH": 551, "reverse-skills": 20, "AboutSecurity": 346, "hack-skills": 1, "SQL-Wordlist": 3, "exploitarium": 354, "generated": 1}`

## Log

# START fusion
## TORCH fusion
-   wiki/techniques/web -> web-injection/torch-wiki/techniques-web (85 files)
-   wiki/techniques/active-directory -> ad-attack/torch-wiki/active-directory (104 files)
-   wiki/techniques/cloud -> cloud-security/torch-wiki/cloud (54 files)
-   wiki/techniques/network -> recon/torch-wiki/network (20 files)
-   wiki/techniques/linux -> linux-post/torch-wiki/linux (11 files)
-   wiki/techniques/macos -> windows-post/torch-wiki/macos (20 files)
-   wiki/techniques/mobile-iot -> mobile-security/torch-wiki/mobile-iot (6 files)
-   wiki/techniques/exploit-dev -> binary-pwn/torch-wiki/exploit-dev (20 files)
-   wiki/techniques/osint -> recon/torch-wiki/osint (9 files)
-   wiki/techniques/cracking -> post-exp-tools/torch-wiki/cracking (7 files)
-   wiki/techniques/red-team -> redteam-framework/torch-wiki/red-team (16 files)
-   wiki/techniques/forensics -> malware-dfir/torch-wiki/forensics (3 files)
-   wiki/techniques/blockchain -> crypto-attacks/torch-wiki/blockchain (3 files)
-   wiki/techniques/methodology -> redteam-framework/torch-wiki/methodology (13 files)
-   wiki/tools -> recon/torch-wiki/tools (70)
-   wiki/cheatsheets -> recon/torch-wiki/cheatsheets (30)
-   hunt/hunt-sqli -> web-injection/torch-hunt/hunt-sqli
-   hunt/hunt-xss -> web-injection/torch-hunt/hunt-xss
-   hunt/hunt-ssrf -> web-injection/torch-hunt/hunt-ssrf
-   hunt/hunt-injection -> web-injection/torch-hunt/hunt-injection
-   hunt/hunt-rce -> web-injection/torch-hunt/hunt-rce
-   hunt/hunt-deserialization -> web-injection/torch-hunt/hunt-deserialization
-   hunt/hunt-upload -> file-vulns/torch-hunt/hunt-upload
-   hunt/hunt-idor -> auth-security/torch-hunt/hunt-idor
-   hunt/hunt-auth -> auth-security/torch-hunt/hunt-auth
-   hunt/hunt-federation -> auth-security/torch-hunt/hunt-federation
-   hunt/hunt-api -> api-security/torch-hunt/hunt-api
-   hunt/hunt-smuggling -> web-attack/torch-hunt/hunt-smuggling
-   hunt/hunt-cache -> web-attack/torch-hunt/hunt-cache
-   hunt/hunt-bizlogic -> business-logic/torch-hunt/hunt-bizlogic
-   hunt/hunt-secrets -> recon/torch-hunt/hunt-secrets
-   hunt/hunt-cloud -> cloud-security/torch-hunt/hunt-cloud
-   hunt/hunt-ad -> ad-attack/torch-hunt/hunt-ad
-   hunt/hunt-windows -> windows-post/torch-hunt/hunt-windows
-   hunt/hunt-macos -> linux-post/torch-hunt/hunt-macos
-   hunt/hunt-llm -> llm-ai-security/torch-hunt/hunt-llm
-   hunt/hunt-mcp -> llm-ai-security/torch-hunt/hunt-mcp
-   hunt/hunt-cicd -> cloud-security/torch-hunt/hunt-cicd
-   hunt/hunt-m365 -> cloud-security/torch-hunt/hunt-m365
-   hunt/hunt-vpn -> recon/torch-hunt/hunt-vpn
-   hunt/hunt-ics -> other/torch-hunt/hunt-ics
-   hunt/hunt-core -> redteam-framework/torch-hunt/hunt-core
-   workflow/pt-workflow -> redteam-framework/torch-workflow/pt-workflow
-   workflow/bb-workflow -> redteam-framework/torch-workflow/bb-workflow
-   workflow/ctf-workflow -> ctf/torch-workflow/ctf-workflow
-   workflow/ctf-box -> ctf/torch-workflow/ctf-box
-   workflow/ctf-category -> ctf/torch-workflow/ctf-category
-   workflow/coverage -> redteam-framework/torch-workflow/coverage
-   workflow/next-move -> redteam-framework/torch-workflow/next-move
-   workflow/triage -> redteam-framework/torch-workflow/triage
-   workflow/evidence -> redteam-framework/torch-workflow/evidence
-   workflow/wiki-recon -> recon/torch-workflow/wiki-recon
-   workflow/wiki-arsenal -> recon/torch-workflow/wiki-arsenal
-   workflow/arsenal -> recon/torch-workflow/arsenal
-   workflow/learn -> redteam-framework/torch-workflow/learn
-   workflow/redteamlead -> redteam-framework/torch-workflow/redteamlead
-   workflow/delegate -> redteam-framework/torch-workflow/delegate
-   workflow/nday -> 0day-exploits/torch-workflow/nday
-   workflow/fuzz -> binary-pwn/torch-workflow/fuzz
-   workflow/research-ingest -> recon/torch-workflow/research-ingest
-   workflow/ingest -> recon/torch-workflow/ingest
-   workflow/walkthrough -> ctf/torch-workflow/walkthrough
-   workflow/campaign-health -> redteam-framework/torch-workflow/campaign-health
-   workflow/metasploit -> post-exp-tools/torch-workflow/metasploit
-   scripts/wordlists (5)
-   TORCH delta note written
## P4nda0s reverse-skills fusion
-   rev-symbol -> reverse-engineering/panda-rev/rev-symbol (1)
-   rev-struct -> reverse-engineering/panda-rev/rev-struct (1)
-   rev-idapython -> reverse-engineering/panda-rev/rev-idapython (1)
-   rev-unicorn-debug -> reverse-engineering/panda-rev/rev-unicorn-debug (1)
-   rev-frida -> mobile-security/panda-rev/rev-frida (1)
-   rev-dex-dumper -> mobile-security/panda-rev/rev-dex-dumper (2)
-   rev-u3d-dump -> mobile-security/panda-rev/rev-u3d-dump (1)
-   rev-ios-dump -> mobile-security/panda-rev/rev-ios-dump (1)
-   package mirror skills/rev-symbol (1)
-   package mirror skills/rev-struct (1)
-   package mirror skills/rev-idapython (1)
-   package mirror skills/rev-unicorn-debug (1)
-   package mirror skills/rev-frida (1)
-   package mirror skills/rev-dex-dumper (2)
-   package mirror skills/rev-u3d-dump (1)
-   package mirror skills/rev-ios-dump (1)
## AboutSecurity / hack-skills
-   AboutSecurity present=True size-ish ok
-   hack-skills present=True SKILL count check next
-   Dic mirror recon/AboutSecurity-Dic (298 new)
-   Vuln/cloud delta 5
-   Vuln/network delta 20
-   Vuln/ai delta 23
-   hack-skills local deep skills: 102
-   skills.json index mirrored
## SQL-Wordlist fusion
-   sql.txt -> /root/security-suite/domains/web-injection/Payload/sqli/sql-wordlist-orwa.txt (1080 lines)
-   unique vs existing payloads: 835 / 1080
-   installed /root/SQL-Wordlist canonical
## exploitarium → 0day-exploits
-   7zip-rar5-motw-chain-poc -> 7zip/exploitarium/rar5-motw-chain (3)
-   anydesk-printer-com-impersonation-poc -> anydesk/exploitarium/printer-com-impersonation-9.7.6 (4)
-   c-ares-tcp-uaf-calc-poc -> c-ares/exploitarium/tcp-getaddrinfo-uaf (7)
-   curl-smtp-expn-recipient-crlf-injection -> curl/exploitarium/smtp-expn-rcpt-crlf (3)
-   discord-activity-stock-client-rce-poc -> discord/exploitarium/activity-stock-client-rce-1.0.9245 (8)
-   discourse-scoped-api-key-preauth-bypass -> discourse/exploitarium/scoped-api-key-preauth-bypass (3)
-   docker-cp-copyout-destination-escape -> docker/exploitarium/cp-copyout-destination-escape-29.6.0 (5)
-   ffmpeg-rasc-dlta-calc-poc -> ffmpeg/exploitarium/rasc-dlta-oob-write (9)
-   firefox-152.0.5-backup-nss-rce-poc -> firefox/exploitarium/152.0.5-backup-nss-rce (12)
-   firefox-152.0.6-stock-page-native-calc-poc -> firefox/exploitarium/152.0.6-stock-page-native-calc (7)
-   firefox-smartwindow-private-url-exfil-poc -> firefox/exploitarium/smartwindow-private-url-exfil (3)
-   floci-apigateway-vtl-rce-poc -> aws-apigateway/exploitarium/floci-vtl-rce (3)
-   flowise-mcp-env-case-bypass-poc -> flowise/exploitarium/mcp-env-case-bypass (3)
-   ghidra-12.1.2-rce-ace-calc-poc -> ghidra/exploitarium/12.1.2-rce-ace (9)
-   gitea-act-runner-container-options-poc -> gitea/exploitarium/act-runner-container-options (4)
-   gogs-admin-csrf-git-hook-rce-poc -> gogs/exploitarium/admin-csrf-git-hook-rce (3)
-   imagemagick-gs-delegate-hijack-poc -> imagemagick/exploitarium/gs-delegate-hijack (5)
-   ladybird-wasm-esm-host-function-rce-poc -> ladybird/exploitarium/wasm-esm-host-function-rce (2)
-   libarchive-zip-debuginfod-size-boundary -> libarchive/exploitarium/zip-debuginfod-size-boundary (6)
-   libssh2-cve-2026-55200-poc -> libssh2/exploitarium/CVE-2026-55200 (7)
-   libssh2-publickey-list-calc-poc -> libssh2/exploitarium/publickey-list-calc (8)
-   lunar-modrinth-chain-poc -> lunar-modrinth/exploitarium/chain-poc (6)
-   mybb-limited-acp-to-admin -> mybb/exploitarium/limited-acp-to-admin (5)
-   nextcloud-federated-share-bearer-token-poc -> nextcloud/exploitarium/federated-share-bearer-token (3)
-   nextjs-unstable-cache-object-argument-collision -> nextjs/exploitarium/unstable-cache-object-argument-collision (3)
-   nghttp2-nghttpx-upgrade-queue-poison-poc -> nghttp2/exploitarium/nghttpx-upgrade-queue-poison (3)
-   nmap-ipv6-extlen-wrap-poc -> nmap/exploitarium/ipv6-extlen-wrap (4)
-   nodebb-activitypub-attributedto-local-uid-spoof-poc -> nodebb/exploitarium/activitypub-attributedto-uid-spoof (3)
-   objdump-dlx-calc-poc -> binutils-objdump/exploitarium/dlx-oob-write (154)
-   openssh-agent-lock-provider-bypass -> openssh/exploitarium/agent-lock-provider-bypass (4)
-   openvpn-connect-echo-script-ace-poc -> openvpn-connect/exploitarium/echo-script-ace (8)
-   php857-streambucket-soap-rce-rpoc -> php/exploitarium/8.5.7-streambucket-soap-rce (6)
-   pillow-imagecms-output-mode-oob-poc -> pillow/exploitarium/imagecms-output-mode-oob (3)
-   postgres-ri-owner-switched-cast-poc -> postgresql/exploitarium/ri-owner-switched-cast (3)
-   qemu-cxl-type3-mailbox-escape-poc -> qemu/exploitarium/cxl-type3-mailbox-escape (7)
-   redis-vset-duplicate-hnsw-id-rce-poc -> redis/exploitarium/vset-duplicate-hnsw-id-rce (3)
-   rustdesk-session-permission-pocs -> rustdesk/exploitarium/session-permission (17)
-   systeminformer-phsvc-trusted-host-lpe-poc -> systeminformer/exploitarium/phsvc-trusted-host-lpe (3)
-   vlc-vp9-reschange-crash-poc -> vlc/exploitarium/vp9-reschange-crash (3)
-   0day README updated
## index / router updates
-   README patch web-injection: TORCH + SQL wordlist (2026-09-08)
-   README patch reverse-engineering: panda-rev (2026-09-08)
-   README patch mobile-security: panda-rev mobile (2026-09-08)
-   README patch 0day-exploits: exploitarium (2026-09-08)
-   README patch redteam-framework: TORCH campaign layer (2026-09-08)
-   README patch recon: TORCH wiki tools/cheatsheets (2026-09-08)
-   MASTER.md appended batch note
-   ROUTING.md keywords added
## Hermes router skill updates
-   0day-exploit-library SKILL updated
-   reverse-skill SKILL updated
-   security-kb-ingest archive table updated
-   pentest-execution SKILL pointer added


@TGSEC社区 · @TGSEC-Qtzuu 整理
