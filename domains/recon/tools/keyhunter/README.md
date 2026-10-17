# 🔑 KeyHunter

[![Crates.io](https://img.shields.io/crates/v/github-keyhunter?style=flat-square)](https://crates.io/crates/github-keyhunter)
[![Downloads](https://img.shields.io/crates/d/github-keyhunter?style=flat-square)](https://crates.io/crates/github-keyhunter)
[![GitHub stars](https://img.shields.io/github/stars/fadidevv/keyhunter?style=flat-square)](https://github.com/fadidevv/keyhunter/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/fadidevv/keyhunter?style=flat-square)](https://github.com/fadidevv/keyhunter/network)
[![GitHub issues](https://img.shields.io/github/issues/fadidevv/keyhunter?style=flat-square)](https://github.com/fadidevv/keyhunter/issues)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

Fast GitHub API key leak scanner written in Rust. Find exposed API keys and help developers secure their secrets.

<p align="center">
  <img src="assets/screenshot.png" alt="KeyHunter scanning for API keys" width="800">
</p>

<p align="center">
  <strong>Find leaked API keys across all public GitHub repositories</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#docker-setup">Docker</a> •
  <a href="#keyhunter-verify">Verify</a> •
  <a href="#supported-providers-45">Providers</a> •
  <a href="#configuration">Config</a> •
  <a href="#development">Development</a>
</p>

---

## Features

- 🚀 **Blazing Fast**: Parallel scanning with token rotation
- 🎯 **45+ Providers**: AI/LLM, Cloud, Payment, Database, and more
- 🔄 **Rate Limit Bypass**: Use multiple GitHub tokens for unlimited scanning
- 🔍 **Smart Search**: Finds keys in ANY file, not just .env
- ✅ **Key Verification**: Test if found keys are still active (20+ providers)
- 🎯 **Verified-Only Mode**: Use `-V` to scan+verify and output only active keys
- 📊 **Clean Output**: Table, JSON, or CSV formats
- 💾 **Auto-save**: Results saved with timestamps
- ⏹️ **Graceful Stop**: Press Ctrl+C anytime to stop and save collected results
- 📝 **Verbose Mode**: See detailed logs of every file and URL being processed
- 🐳 **Docker Ready**: No Rust installation required - just use Docker

---

## Why KeyHunter?

### Smart Search Strategy

Most tools search for patterns like `sk-proj-` which appear in tutorials, docs, and examples. KeyHunter uses **unique pattern segments** that only exist in real keys:

| Provider | Others Search | KeyHunter Searches |
|----------|---------------|-------------------|
| OpenAI | `sk-proj-` | `T3BlbkFJ` (unique Base64 in all keys) |
| Anthropic | `sk-ant-` | `sk-XXXXant-api03-` (real key prefix) |
| Stripe | `sk_live_` | `sk_live_` + length validation |

### Multi-Query Approach

For each provider, KeyHunter runs multiple searches:
1. **Pattern search** - Unique identifier (`T3BlbkFJ`)
2. **Filename filter** - Pattern + `filename:.env`
3. **Env var search** - `OPENAI_API_KEY`

This catches keys that single-pattern tools miss.

### False Positive Filtering

KeyHunter automatically skips placeholder keys:
```
sk-proj-EXAMPLE     ← skipped (placeholder)
sk-proj-EXAMPLE    ← skipped (example)
sk-proj-EXAMPLE      ← skipped (test key)
sk-proj-EXAMPLE...    ← ✓ real key
```

### Modern Provider Coverage

KeyHunter includes AI providers that most tools don't have yet:

| Category | Providers |
|----------|-----------|
| **AI / LLM** | Anthropic, OpenAI, Google AI, Grok, DeepSeek, Groq, Perplexity, Replicate, HuggingFace, Fireworks, Cohere, Mistral, Together |
| **New** | Grok (xAI), DeepSeek, Groq, Perplexity |

### Offensive vs Defensive

| Tool Type | Purpose | Examples |
|-----------|---------|----------|
| **Hunters** (KeyHunter) | Find leaked keys across ALL public repos | Active scanning |
| **Defenders** | Scan YOUR repos to prevent leaks | TruffleHog, Gitleaks, git-secrets |

KeyHunter is built for **security researchers** who need to find exposed keys at scale.

## Quick Start

### 1. Get a GitHub Token

Go to: https://github.com/settings/tokens/new

- **Note**: `keyhunter`
- **Expiration**: 30 days
- **Scopes**: ✅ `public_repo` only

Click **Generate token** and copy it.

### 2. Configure

```bash
cp config.toml.example config.toml
```

Edit `config.toml`:

```toml
[github]
tokens = [
    "ghp_YOUR_ACTUAL_TOKEN_HERE",
]
```

### 3. Choose Your Installation

#### Option A: Install from crates.io (Recommended)

```bash
cargo install github-keyhunter

# Run
keyhunter scan -p openai
```

#### Option B: Build from Source

```bash
# Build (first time takes ~2 min)
cargo build --release

# Run
./target/release/keyhunter scan -p openai
```

#### Option C: With Docker (No Rust Required)

```bash
# Build image (~3-5 min first time)
docker build -t keyhunter .

# Run
docker run -v $(pwd)/config.toml:/app/config.toml \
           -v $(pwd)/results:/app/results \
           keyhunter scan -p openai
```

### 4. Typical Workflow

**Option A: Two-step (recommended for large scans)**
```bash
# Step 1: Scan for keys
./target/release/keyhunter scan -p openai
# Output: results/findings_20260119_143022.json

# Step 2: Verify which keys are active
./target/release/keyhunter verify -i results/findings_20260119_143022.json
# Output: results/verified_20260119_143100.json
#         results/verified_20260119_143100_active.json (only active keys)
```

**Option B: One-step with `-V` (for smaller scans)**
```bash
# Scan + verify in one command (verifies first 50 keys)
./target/release/keyhunter scan -p openai -V
# Output: results/verified_active_20260119_143022.json (only active keys)

# Or verify ALL found keys (caution: may hit rate limits)
./target/release/keyhunter scan -p openai -V --verify-all
```

---

## Docker Setup

Full Docker documentation for those without Rust installed.

### Build & Run

```bash
# 1. Setup config
cp config.toml.example config.toml
# Edit config.toml with your GitHub token

# 2. Build image (~3-5 min first time)
docker build -t keyhunter .

# 3. Run scan
docker run -v $(pwd)/config.toml:/app/config.toml \
           -v $(pwd)/results:/app/results \
           keyhunter scan -p openai

# With verbose mode
docker run -v $(pwd)/config.toml:/app/config.toml \
           -v $(pwd)/results:/app/results \
           keyhunter scan -p openai -v

# Show help
docker run keyhunter --help

# Show patterns
docker run keyhunter patterns
```

### Docker Compose

Simpler syntax using docker-compose:

```bash
# Run with docker-compose
docker-compose run keyhunter scan -p openai

# With verbose
docker-compose run keyhunter scan -p openai -v

# Scan all providers
docker-compose run keyhunter scan

# Show patterns
docker-compose run keyhunter patterns
```

### Docker Commands Reference

| Command | Description |
|---------|-------------|
| `docker build -t keyhunter .` | Build image |
| `docker run keyhunter --help` | Show help |
| `docker run keyhunter patterns` | List providers |
| `docker run -v ... keyhunter scan` | Run scan |
| `docker run -v ... keyhunter scan -V` | Scan + verify (active only) |
| `docker run -v ... keyhunter verify -i ...` | Verify keys |
| `docker-compose run keyhunter scan` | Run with compose |

### Volume Mounts

| Mount | Purpose |
|-------|---------|
| `./config.toml:/app/config.toml` | Your config file |
| `./results:/app/results` | Save results locally |

Results are saved to your local `./results` folder.

### Docker Tips

```bash
# Create alias for easier usage
alias keyhunter='docker run -v $(pwd)/config.toml:/app/config.toml -v $(pwd)/results:/app/results keyhunter'

# Then just run:
keyhunter scan -p openai
keyhunter scan -v
keyhunter patterns
```

---

## CLI Reference

```
keyhunter <COMMAND>

COMMANDS:
    scan        Scan GitHub for leaked API keys
    verify      Verify if found keys are active
    patterns    Show all supported providers and patterns
    help        Show help for a command
```

---

### `keyhunter scan`

Scan GitHub for leaked API keys.

**Usage:**

```bash
# Scan all providers
./target/release/keyhunter scan

# Scan specific provider
./target/release/keyhunter scan -p openai
./target/release/keyhunter scan -p anthropic
./target/release/keyhunter scan -p stripe_live
./target/release/keyhunter scan -p aws

# Verbose mode - see detailed logs
./target/release/keyhunter scan -v
./target/release/keyhunter scan -p openai -v
./target/release/keyhunter scan --verbose

# Custom search query (any GitHub code search)
./target/release/keyhunter scan -q "T3BlbkFJ"
./target/release/keyhunter scan -q "sk-XXXXant-api03"
./target/release/keyhunter scan -q "OPENAI_API_KEY filename:.env"
./target/release/keyhunter scan -q "mongodb+srv:// filename:config.js"

# Different output formats
./target/release/keyhunter scan -o table    # default, pretty
./target/release/keyhunter scan -o json     # machine readable
./target/release/keyhunter scan -o csv      # spreadsheet

# Use different config file
./target/release/keyhunter scan -c myconfig.toml

# Combine options
./target/release/keyhunter scan -p openai -o json -v
./target/release/keyhunter scan -p anthropic --verbose -c prod.toml

# Verified-only mode - only output active keys
./target/release/keyhunter scan -p openai -V
./target/release/keyhunter scan -p openai -V --verify-all
./target/release/keyhunter scan -p openai -V -o json

# Combine verbose + verified-only
./target/release/keyhunter scan -p openai -v -V
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --config <FILE>` | Config file path | `config.toml` |
| `-p, --provider <n>` | Provider to scan | `all` |
| `-q, --query <QUERY>` | Custom GitHub search query | - |
| `-o, --output <FORMAT>` | Output: table, json, csv | `table` |
| `-v, --verbose` | Show detailed logs (files, URLs, etc.) | `false` |
| `-V, --verified-only` | Only save active (verified) keys | `false` |
| `--verify-all` | With -V: verify all keys (not just 50) | `false` |
| `-h, --help` | Show help | - |

**Verified-Only Mode (`-V`):**

Scan and verify in one command - only outputs keys that are confirmed active:

```bash
# Scan + verify first 50 keys, output only active
./target/release/keyhunter scan -p openai -V

# Scan + verify ALL keys (caution: may hit rate limits)
./target/release/keyhunter scan -p openai -V --verify-all
```

> **Note:** Without `-V`, scan outputs all found keys (unverified). Use `verify` command later to check which are active.

---

### `keyhunter patterns`

Show all supported providers and their regex patterns.

**Usage:**

```bash
./target/release/keyhunter patterns
```

**Output:**

```
╭─────────────┬─────────────────────────┬─────────────────────╮
│ Provider    │ Pattern                 │ Example             │
├─────────────┼─────────────────────────┼─────────────────────┤
│ Anthropic   │ sk-XXXXant-api03-[...]{93}  │ sk-ant-XXXXapi03-xxxxx  │
│ OpenAI      │ sk-proj-[...]{48,180}   │ sk-XXXXproj-xxxxx       │
│ Google AI   │ AIza[...]{35}           │ AIzaSyDxxxxx        │
│ AWS         │ AKIA[0-9A-Z]{16}        │ AKIAXXXXIOSFODNN7       │
│ Stripe      │ sk_live_[...]{24,99}    │ sk_live_xxxxx       │
│ ...         │ ...                     │ ...                 │
╰─────────────┴─────────────────────────┴─────────────────────╯
```

---

### `keyhunter verify`

Verify if found keys are still active by testing against provider APIs.

> **Tip:** For quick scans, use `scan -V` to scan+verify in one step. Use this separate `verify` command when you want more control over batch verification of large result files.

**Usage:**

```bash
# Verify first 50 keys (default, safe)
./target/release/keyhunter verify -i results/findings.json

# Verify only OpenAI keys
./target/release/keyhunter verify -i results/findings.json -p openai

# Verify first 100 keys
./target/release/keyhunter verify -i results/findings.json -l 100

# Verify ALL keys (careful - may hit rate limits)
./target/release/keyhunter verify -i results/findings.json -a

# More concurrent requests (faster but riskier)
./target/release/keyhunter verify -i results/findings.json -c 10

# Save to specific file
./target/release/keyhunter verify -i results/findings.json -o verified.json
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --input <FILE>` | Results JSON file (required) | - |
| `-l, --limit <N>` | Verify first N keys | `50` |
| `-p, --provider <NAME>` | Verify only this provider | all |
| `-a, --all` | Verify all keys (ignore limit) | `false` |
| `-c, --concurrent <N>` | Parallel requests | `5` |
| `-o, --output <FILE>` | Save verified results | auto |
| `-h, --help` | Show help | - |

**Output:**

```
📂 Loaded 567 keys from results/findings.json
🔍 Verifying 50 keys with 5 concurrent requests

    OpenAI 35 keys
    Anthropic 10 keys
    Stripe 5 keys

  ✓ ACTIVE sk-proj-...xxxx (OpenAI)
  ✓ ACTIVE sk-ant-a...yyyy (Anthropic)

════════════════════════════════════════════════════════════
✓ Verification Complete

    🔴 12 keys are ACTIVE (leaked & working!)
    🟢 35 keys are revoked/invalid
    🟡 3 keys had errors (rate limited/timeout)

💾 Results saved to: results/verified_20260119.json
🔴 Active keys saved to: results/verified_20260119_active.json
```

**Supported Verification:**

| Provider | Method | Status |
|----------|--------|--------|
| OpenAI | GET /v1/models | ✅ |
| Anthropic | POST /v1/messages | ✅ |
| Google AI | GET /v1/models | ✅ |
| Groq | GET /v1/models | ✅ |
| Perplexity | POST /chat/completions | ✅ |
| HuggingFace | GET /api/whoami-v2 | ✅ |
| Replicate | GET /v1/account | ✅ |
| Fireworks | GET /v1/models | ✅ |
| Cohere | GET /v1/models | ✅ |
| Mistral | GET /v1/models | ✅ |
| Together | GET /v1/models | ✅ |
| DeepSeek | GET /v1/models | ✅ |
| GitHub | GET /user | ✅ |
| GitLab | GET /api/v4/user | ✅ |
| Stripe | GET /v1/balance | ✅ |
| SendGrid | GET /v3/scopes | ✅ |
| Mailgun | GET /v3/domains | ✅ |
| Slack | GET /api/auth.test | ✅ |
| Discord | GET /users/@me | ✅ |
| Telegram | GET /getMe | ✅ |
| Mapbox | GET /tokens/v2 | ✅ |
| New Relic | GET /v2/users.json | ✅ |
| Datadog | GET /api/v1/validate | ✅ |
| AWS | ⚠️ Requires secret key pair | ❌ |
| Twilio | ⚠️ Requires Account SID | ❌ |
| Firebase | ⚠️ Requires project ID | ❌ |

---

## Provider Names

Use these names with `-p` flag:

**AI / LLM:**
```
anthropic, openai, google, grok, deepseek, huggingface, 
replicate, perplexity, groq, fireworks
```

**Cloud:**
```
aws
```

**Payment:**
```
stripe_live, stripe_restricted, paypal, square
```

**Communication:**
```
twilio, sendgrid, mailgun, mailchimp
```

**Developer Platforms:**
```
github_token, gitlab, npm, pypi
```

**Social / Messaging:**
```
slack_bot, slack_user, slack_webhook, discord, 
discord_webhook, telegram
```

**Database:**
```
mongodb, postgres, mysql, redis
```

**Other:**
```
firebase, mapbox, sentry, newrelic, planetscale, 
doppler, private_key
```

---

## Supported Providers (45+)

### AI / LLM

| Provider | Pattern | Search Term |
|----------|---------|-------------|
| Anthropic | `sk-XXXXant-api03-...` | `sk-XXXXant-api03-` |
| OpenAI | `sk-proj-...` | `T3BlbkFJ` |
| Google AI | `AIza...` | `AIzaSy` |
| xAI Grok | `xai-...` | `xai-` |
| DeepSeek | `sk-[hex]` | `DEEPSEEK_API_KEY` |
| HuggingFace | `hf_...` | `hf_` |
| Replicate | `r8_...` | `r8_` |
| Perplexity | `pplx-...` | `pplx-` |
| Groq | `gsk_...` | `gsk_` |
| Fireworks | `fw_...` | `fw_` |

### Cloud & Infrastructure

| Provider | Pattern |
|----------|---------|
| AWS | `AKIA...` |
| Azure | `...(86 chars)==` |

### Payment

| Provider | Pattern |
|----------|---------|
| Stripe | `sk_live_...` |
| Square | `sq0csp-...` |
| PayPal | `access_token$...` |

### Communication

| Provider | Pattern |
|----------|---------|
| Twilio | `SK[hex]{32}` |
| SendGrid | `SG....` |
| Mailgun | `key-...` |
| Mailchimp | `...-us14` |

### Developer Platforms

| Provider | Pattern |
|----------|---------|
| GitHub | `ghp_...`, `github_pat_...` |
| GitLab | `glpat-...` |
| NPM | `npm_...` |
| PyPI | `pypi-...` |

### Social / Messaging

| Provider | Pattern |
|----------|---------|
| Slack Bot | `xoxb-...` |
| Slack User | `xoxp-...` |
| Slack Webhook | `hooks.slack.com/...` |
| Discord | Bot tokens |
| Discord Webhook | `discord.com/api/webhooks/...` |
| Telegram | `123456789:ABC...` |

### Database

| Provider | Pattern |
|----------|---------|
| MongoDB | `mongodb+srv://...` |
| PostgreSQL | `postgres://...` |
| MySQL | `mysql://...` |
| Redis | `redis://...` |

### Other Services

| Provider | Pattern |
|----------|---------|
| Firebase | `AAAA...:...` |
| Mapbox | `pk.eyJ...` |
| Sentry | `https://...@sentry.io` |
| New Relic | `NRAK-...` |
| PlanetScale | `pscale_tkn_...` |
| Doppler | `dp.pt....` |
| Private Key | `-----BEGIN PRIVATE KEY-----` |

---

## Output Examples

### Normal Mode (default)

```
🔍 Scanning 1 provider(s), 6 queries total
ℹ Press Ctrl+C to stop and save results

→ Provider: OpenAI (OpenAI API Key)
    ⟩ Query 1/6: T3BlbkFJ
      ⠙ [█████████▓░░░░░░░░░░░░░░░] 3/10 pages | 28 keys
      ↳ 282 keys found
    ⟩ Query 2/6: T3BlbkFJ filename:.env
      ↳ 285 keys found
    ✓ Running total: 567 unique keys

════════════════════════════════════════════════════════════════════════════════
🔑 Found 567 potential leaked keys
```

### Verified-Only Mode (`-V`)

```
🔍 Scanning 1 provider(s), 6 queries total
ℹ Press Ctrl+C to stop and save results

→ Provider: OpenAI (OpenAI API Key)
    ⟩ Query 1/6: T3BlbkFJ
      ↳ 282 keys found
    ✓ Running total: 248 unique keys

🔍 Verifying keys...

🔍 Verifying 50 keys (--verified-only mode)
  ✓ ACTIVE sk-proj-SL...apsA (OpenAI)
  ✓ ACTIVE sk-proj-KK..._uIA (OpenAI)

════════════════════════════════════════════════════════════
🔑 Found 4 ACTIVE keys

💾 Active keys saved to: results/verified_active_20260119_143022.json
```

### Verbose Mode (`-v`)

```
🔍 Scanning 1 provider(s), 6 queries total
ℹ Press Ctrl+C to stop and save results
📝 Verbose mode enabled - showing detailed logs

→ Provider: OpenAI (OpenAI API Key)
    ⟩ Query 1/6: T3BlbkFJ
      · Page 1/10 - 30 files to process
        ✓ user/chatbot/.env → 2 key(s)
          https://github.com/user/chatbot/blob/main/.env
        ✓ dev/project/config.js → 1 key(s)
          https://github.com/dev/project/blob/main/config.js
        · corp/docs/README.md → no keys
        ✓ startup/api/.env.local → 3 key(s)
          https://github.com/startup/api/blob/main/.env.local
      ↳ Page 1 complete: 28 keys found
      · Page 2/10 - 30 files to process
        ✓ another/repo/.env → 1 key(s)
          https://github.com/another/repo/blob/main/.env
        ...
      ↳ 282 keys found
    ⟩ Query 2/6: T3BlbkFJ filename:.env
      · Page 1/10 - 30 files to process
        ...
    ✓ Running total: 567 unique keys

════════════════════════════════════════════════════════════════════════════════
🔑 Found 567 potential leaked keys
```

---

## Graceful Stop (Ctrl+C)

Press `Ctrl+C` anytime during scanning to stop and save all collected results.

```
🔍 Scanning 1 provider(s), 6 queries total
ℹ Press Ctrl+C to stop and save results

→ Provider: OpenAI (OpenAI API Key)
    ⟩ Query 1/6: T3BlbkFJ
      ↳ 282 keys found
    ⟩ Query 2/6: T3BlbkFJ filename:.env
^C
⚠ Interrupted! Saving collected results...
💾 Saved 450 keys to: results/findings_20260119_143022_interrupted.json
```

Results are saved to `*_interrupted.json` so you don't lose your progress.

---

## Configuration

### Config File: `config.toml`

```toml
[github]
tokens = [
    "ghp_YOUR_TOKEN_HERE",
]
concurrency = 5      # parallel requests
delay_ms = 500       # delay between requests

[scan]
max_results = 1000   # max results per query

[output]
format = "table"     # table, json, csv (CLI -o overrides)
save_to_file = true
output_path = "results"

[providers]
openai = true
anthropic = true
aws = true
# ... see config.toml.example for all options
```

### Results Volume

Control how many results to fetch with `max_results`:

| max_results | Pages | Speed | Keys (approx) |
|-------------|-------|-------|---------------|
| 30 | ~1 | Fast test | ~50 |
| 100 | ~3 | Quick scan | ~150 |
| 300 | ~10 | Medium | ~500 |
| 500 | ~17 | Good coverage | ~1000 |
| 1000 | ~33 | Maximum | ~2000+ |

```toml
[scan]
max_results = 300    # adjust as needed
```

### Speed Settings

| Setup | concurrency | delay_ms | Speed |
|-------|-------------|----------|-------|
| Safe (1 token) | 3 | 1000 | ~30/min |
| Normal (1 token) | 5 | 500 | ~60/min |
| Fast (3+ tokens) | 10 | 300 | ~150/min |
| Blazing (5+ tokens) | 20 | 100 | ~300/min |

### Multiple Tokens (Different Accounts)

For maximum speed, use tokens from different GitHub accounts:

```toml
[github]
tokens = [
    "ghp_from_account_1",
    "ghp_from_account_2",
    "ghp_from_account_3",
    "ghp_from_account_4",
    "ghp_from_account_5",
]
concurrency = 20
delay_ms = 100
```

| Setup | Speed | Keys Found |
|-------|-------|------------|
| 1 token, 1 account | 30/min | ~500/scan |
| 5 tokens, 5 accounts | 150/min | ~5000/scan |
| 10 tokens, 10 accounts | 300/min | ~10000/scan |

---

## Project Structure

```
keyhunter/
├── Cargo.toml
├── config.toml.example
├── config.toml          # Your config (git-ignored)
├── Dockerfile           # Docker build
├── docker-compose.yml   # Docker compose
├── .dockerignore
├── README.md
├── .gitignore
├── LICENSE
├── assets/
│   └── screenshot.png   # Screenshot for README
├── results/             # Scan results saved here
├── src/
│   ├── main.rs          # CLI entry point
│   ├── config.rs        # Config parser
│   ├── patterns.rs      # 45+ provider patterns
│   ├── github.rs        # GitHub API client
│   ├── scanner.rs       # Core scanner
│   └── verifier.rs      # Key verification (20+ providers)
└── tests/
    ├── config_test.rs   # Configuration tests
    ├── filters_test.rs  # False positive filter tests
    └── patterns_test.rs # Regex pattern tests
```

---

## Development

### Prerequisites

**Option A: Native (Rust)**
- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

**Option B: Docker**
- Docker 20.10+

### Building

**Native:**
```bash
# Clone repository
git clone https://github.com/fadidevv/keyhunter.git
cd keyhunter

# Build debug (faster compile)
cargo build

# Build release (optimized)
cargo build --release
```

**Docker:**
```bash
# Clone repository
git clone https://github.com/fadidevv/keyhunter.git
cd keyhunter

# Build image
docker build -t keyhunter .
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test patterns_test
cargo test --test filters_test
cargo test --test config_test

# Run with output
cargo test -- --nocapture
```

**Test Coverage:**
- `patterns_test.rs` - 34 tests for regex pattern matching
- `filters_test.rs` - 13 tests for false positive filtering
- `config_test.rs` - 12 tests for configuration parsing

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Check without building
cargo check
```

### Running in Development

**Native:**
```bash
# Setup config
cp config.toml.example config.toml
# Edit config.toml with your GitHub token

# Run debug build
cargo run -- scan -p openai

# Run release build
cargo run --release -- scan -p openai
```

**Docker:**
```bash
# Setup config
cp config.toml.example config.toml
# Edit config.toml with your GitHub token

# Run with Docker
docker run -v $(pwd)/config.toml:/app/config.toml \
           -v $(pwd)/results:/app/results \
           keyhunter scan -p openai
```

### Adding New Providers

1. Add pattern to `src/patterns.rs`:
```rust
KeyPattern {
    name: "new_provider",
    display_name: "New Provider",
    regex: r"prefix_[a-zA-Z0-9]{32}",
    confidence: "high",
    search_terms: vec!["prefix_", "NEW_PROVIDER_KEY"],
    example: "prefix_abc123...",
}
```

2. Add config toggle to `src/config.rs`:
```rust
pub new_provider: bool,
```

3. Add to `enabled_providers()` in `src/config.rs`

4. (Optional) Add verification in `src/verifier.rs`

5. Run tests: `cargo test`

---

## ⚠️ Disclaimer

This tool is for **security research and educational purposes only**.

- Only scan repositories you own or have permission to scan
- Report leaked keys responsibly to developers
- Never use found keys for unauthorized access
- Misuse may violate laws and GitHub Terms of Service

**The authors are not responsible for misuse of this tool.**

---

## Ethical Use

This tool is for:
- ✅ Security researchers finding and reporting leaked keys
- ✅ Developers scanning their own repositories
- ✅ Organizations auditing their code
- ✅ Helping developers secure their secrets

**NOT** for:
- ❌ Stealing or misusing credentials
- ❌ Unauthorized access to systems
- ❌ Any malicious purposes

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-provider`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run linter (`cargo clippy`)
6. Format code (`cargo fmt`)
7. Commit changes (`git commit -m 'Add new provider'`)
8. Push to branch (`git push origin feature/new-provider`)
9. Open a Pull Request

**Ideas for contributions:**
- Add new API key providers
- Improve regex patterns
- Add verification for more providers
- Documentation improvements
- Bug fixes

---

## License

MIT License - see [LICENSE](LICENSE) for details.