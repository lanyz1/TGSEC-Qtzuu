# aimy-skill fusion index

Source absorbed by attack-surface (not stacked as domains/aimy/).
Bundled `ai-mian/hack-skills` skipped — 0 unique skill names vs suite.

## Layout

- `domains/<face>/aimy-tools/` — Python checkers/weaponizers
- `domains/web-injection/aimy-payloads/` — YAML payload seeds
- `domains/*/aimy-docs/` — SRC/report/playbook docs
- `domains/redteam-framework/aimy-engine|aimy-cli/` — shared engine/CLI

## Tool → domain map (generated)

### api-security
- `api-security/aimy-tools/param_classifier.py`
- `api-security/aimy-tools/param_miner.py`

### auth-security
- `auth-security/aimy-tools/_session.py`
- `auth-security/aimy-tools/auth_bypass.py`
- `auth-security/aimy-tools/auth_engine.py`
- `auth-security/aimy-tools/auth_state_machine.py`
- `auth-security/aimy-tools/dual_session.py`
- `auth-security/aimy-tools/idor_scanner.py`
- `auth-security/aimy-tools/jwt_attacker.py`
- `auth-security/aimy-tools/jwt_detector.py`
- `auth-security/aimy-tools/jwt_exploiter.py`
- `auth-security/aimy-tools/opsec_session.py`
- `auth-security/aimy-tools/playwright_auth.py`
- `auth-security/aimy-tools/saml_sso.py`
- `auth-security/aimy-tools/session.py`
- `auth-security/aimy-tools/session_matrix.py`
- `auth-security/aimy-tools/unauth_scan.py`

### binary-pwn
- `binary-pwn/aimy-tools/binary_analyzer.py`
- `binary-pwn/aimy-tools/binary_search.py`

### business-logic
- `business-logic/aimy-tools/biz_logic_scanner.py`
- `business-logic/aimy-tools/biz_logic_v2.py`
- `business-logic/aimy-tools/workflow.py`

### cloud-security
- `cloud-security/aimy-tools/cloud_pwn.py`

### file-vulns
- `file-vulns/aimy-tools/code_audit.py`
- `file-vulns/aimy-tools/file_upload.py`
- `file-vulns/aimy-tools/response_profiler.py`

### linux-post
- `linux-post/aimy-tools/db_lateral.py`
- `linux-post/aimy-tools/interactive_shell.py`
- `linux-post/aimy-tools/lateral_move.py`
- `linux-post/aimy-tools/post_exploit.py`
- `linux-post/aimy-tools/smb_lateral.py`

### llm-ai-security
- `llm-ai-security/aimy-tools/ai_vuln_hunter.py`

### mobile-security
- `mobile-security/aimy-tools/mobile_scanner.py`

### post-exp-tools
- `post-exp-tools/aimy-tools/c2_beacon.py`
- `post-exp-tools/aimy-tools/reverse_shell.py`
- `post-exp-tools/aimy-tools/tunnel_agent.py`

### recon
- `recon/aimy-tools/active_prober.py`
- `recon/aimy-tools/attack_surface.py`
- `recon/aimy-tools/batch_recon.py`
- `recon/aimy-tools/cms_fingerprint.py`
- `recon/aimy-tools/crawler.py`
- `recon/aimy-tools/domain_attacks.py`
- `recon/aimy-tools/domain_hunt.py`
- `recon/aimy-tools/internal_scan.py`
- `recon/aimy-tools/leak_scanner.py`
- `recon/aimy-tools/recon/dir_fuzzer.py`
- `recon/aimy-tools/recon/git_leak.py`
- `recon/aimy-tools/recon/port_scanner.py`
- `recon/aimy-tools/recon/subdomain.py`
- `recon/aimy-tools/recon/tech_fingerprint.py`
- `recon/aimy-tools/spa_crawler.py`
- `recon/aimy-tools/version_fingerprint.py`

### redteam-framework
- `redteam-framework/aimy-cli/__init__.py`
- `redteam-framework/aimy-cli/arg_parsers.py`
- `redteam-framework/aimy-cli/check_commands.py`
- `redteam-framework/aimy-engine/__init__.py`
- `redteam-framework/aimy-engine/config.py`
- `redteam-framework/aimy-engine/cvss.py`
- `redteam-framework/aimy-engine/diff.py`
- `redteam-framework/aimy-engine/layering.py`
- `redteam-framework/aimy-engine/oob.py`
- `redteam-framework/aimy-engine/reproducibility.py`
- `redteam-framework/aimy-tools/_context.py`
- `redteam-framework/aimy-tools/_enrich.py`
- `redteam-framework/aimy-tools/_finding.py`
- `redteam-framework/aimy-tools/adaptive_fuzzer.py`
- `redteam-framework/aimy-tools/adaptive_payload.py`
- `redteam-framework/aimy-tools/attack_graph.py`
- `redteam-framework/aimy-tools/attack_tree.py`
- `redteam-framework/aimy-tools/auto_pwn.py`
- `redteam-framework/aimy-tools/chain_engine.py`
- `redteam-framework/aimy-tools/challenge.py`
- `redteam-framework/aimy-tools/constraint_graph.py`
- `redteam-framework/aimy-tools/context_memory.py`
- `redteam-framework/aimy-tools/cross_validator.py`
- `redteam-framework/aimy-tools/deviation_oracle.py`
- `redteam-framework/aimy-tools/evasion_engine.py`
- `redteam-framework/aimy-tools/exceptions.py`
- `redteam-framework/aimy-tools/false_positive_filter.py`
- `redteam-framework/aimy-tools/fuzz_engine.py`
- `redteam-framework/aimy-tools/html_context_parser.py`
- `redteam-framework/aimy-tools/http_client.py`
- `redteam-framework/aimy-tools/kali_capture.py`
- `redteam-framework/aimy-tools/kali_executor.py`
- `redteam-framework/aimy-tools/kali_toolset.py`
- `redteam-framework/aimy-tools/knowledge_graph.py`
- `redteam-framework/aimy-tools/log_utils.py`
- `redteam-framework/aimy-tools/mitm_proxy.py`
- `redteam-framework/aimy-tools/mode.py`
- `redteam-framework/aimy-tools/oob_server.py`
- `redteam-framework/aimy-tools/orchestrator.py`
- `redteam-framework/aimy-tools/orchestrator_engine/detect/detect_engine.py`
- `redteam-framework/aimy-tools/orchestrator_engine/helpers.py`
- `redteam-framework/aimy-tools/orchestrator_engine/recon/recon_engine.py`
- `redteam-framework/aimy-tools/output.py`
- `redteam-framework/aimy-tools/packet_capture.py`
- `redteam-framework/aimy-tools/payload_engine.py`
- `redteam-framework/aimy-tools/payload_mutator.py`
- `redteam-framework/aimy-tools/pipeline.py`
- `redteam-framework/aimy-tools/playwright_engine.py`
- `redteam-framework/aimy-tools/proto_pollution.py`
- `redteam-framework/aimy-tools/protocol_fuzzer.py`
- `redteam-framework/aimy-tools/proxy_pool.py`
- `redteam-framework/aimy-tools/reasoning_engine.py`
- `redteam-framework/aimy-tools/reporter.py`
- `redteam-framework/aimy-tools/responder_kit.py`
- `redteam-framework/aimy-tools/response_analyzer.py`
- `redteam-framework/aimy-tools/retry.py`
- `redteam-framework/aimy-tools/robust_verifier.py`
- `redteam-framework/aimy-tools/second_order_verifier.py`
- `redteam-framework/aimy-tools/semantic_analyzer.py`
- `redteam-framework/aimy-tools/semantic_diff.py`
- `redteam-framework/aimy-tools/service_mapping.py`
- `redteam-framework/aimy-tools/settings.py`
- `redteam-framework/aimy-tools/smart_fuzzer.py`
- `redteam-framework/aimy-tools/src_report.py`
- `redteam-framework/aimy-tools/storage.py`
- `redteam-framework/aimy-tools/tls_adapter.py`
- `redteam-framework/aimy-tools/tool_registry.py`
- `redteam-framework/aimy-tools/verification_oracle.py`
- `redteam-framework/aimy-tools/vuln_context.py`
- `redteam-framework/aimy-tools/weakpass.py`
- `redteam-framework/aimy-tools/weaponize_engine.py`

### web-attack
- `web-attack/aimy-tools/clickjacking.py`
- `web-attack/aimy-tools/cors_scanner.py`
- `web-attack/aimy-tools/csrf_scanner.py`
- `web-attack/aimy-tools/open_redirect.py`
- `web-attack/aimy-tools/race_condition.py`
- `web-attack/aimy-tools/race_profiler.py`
- `web-attack/aimy-tools/smuggler.py`
- `web-attack/aimy-tools/waf_bypass.py`
- `web-attack/aimy-tools/web_cache.py`
- `web-attack/aimy-tools/workflow_tracer.py`

### web-injection
- `web-injection/aimy-tools/cmdi_detector.py`
- `web-injection/aimy-tools/crlf_injection.py`
- `web-injection/aimy-tools/deser_weaponizer.py`
- `web-injection/aimy-tools/deserialization_detector.py`
- `web-injection/aimy-tools/dom_xss.py`
- `web-injection/aimy-tools/graphql_abuser.py`
- `web-injection/aimy-tools/graphql_scanner.py`
- `web-injection/aimy-tools/hpp.py`
- `web-injection/aimy-tools/lfi_scanner.py`
- `web-injection/aimy-tools/nosqli_detector.py`
- `web-injection/aimy-tools/second_order_sqli.py`
- `web-injection/aimy-tools/sql_injection.py`
- `web-injection/aimy-tools/sqli_blind.py`
- `web-injection/aimy-tools/sqli_oob.py`
- `web-injection/aimy-tools/sqli_weaponizer.py`
- `web-injection/aimy-tools/ssrf_chain.py`
- `web-injection/aimy-tools/ssrf_detector.py`
- `web-injection/aimy-tools/ssrf_pwn.py`
- `web-injection/aimy-tools/ssti_detector.py`
- `web-injection/aimy-tools/type_confusion.py`
- `web-injection/aimy-tools/xss_browser_verify.py`
- `web-injection/aimy-tools/xss_detector.py`
- `web-injection/aimy-tools/xss_validator.py`
- `web-injection/aimy-tools/xxe_detector.py`

