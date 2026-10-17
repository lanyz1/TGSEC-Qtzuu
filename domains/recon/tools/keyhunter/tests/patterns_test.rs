//! Tests for API key pattern matching.
//!
//! Verifies that regex patterns correctly match valid keys and reject invalid ones.

use regex::Regex;

// ============================================================================
// AI / LLM Providers
// ============================================================================

#[test]
fn test_openai_pattern() {
    let pattern = Regex::new(r"sk-proj-[A-Za-z0-9_-]{20,}").unwrap();

    // Valid keys
    assert!(pattern.is_match("sk-proj-EXAMPLE"));
    assert!(pattern.is_match("sk-proj-EXAMPLE"));

    // Invalid - too short
    assert!(!pattern.is_match("sk-XXXXproj-short"));
    assert!(!pattern.is_match("sk-XXXXproj-abc"));
}

#[test]
fn test_openai_marker() {
    let pattern = Regex::new(r"T3BlbkFJ").unwrap();

    assert!(pattern.is_match("sk-proj-EXAMPLE"));
    assert!(!pattern.is_match("sk-proj-EXAMPLE"));
}

#[test]
fn test_anthropic_pattern() {
    let pattern = Regex::new(r"sk-XXXXant-api03-[A-Za-z0-9_-]{93}").unwrap();

    // Valid - exactly 93 chars after prefix
    let valid_key = format!("sk-XXXXant-api03-{}", "a".repeat(93));
    assert!(pattern.is_match(&valid_key));

    // Invalid - too short
    assert!(!pattern.is_match("sk-ant-XXXXapi03-tooshort"));
    assert!(!pattern.is_match("sk-ant-XXXXapi03-abc"));
}

#[test]
fn test_google_ai_pattern() {
    let pattern = Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap();

    // Valid - exactly 35 chars after AIza
    let valid_key = format!("AIza{}", "a".repeat(35));
    assert!(pattern.is_match(&valid_key));

    // Invalid - wrong prefix
    assert!(!pattern.is_match(&format!("AIzb{}", "a".repeat(35))));

    // Invalid - too short
    assert!(!pattern.is_match("AIzaSyDshort"));
}

#[test]
fn test_groq_pattern() {
    let pattern = Regex::new(r"gsk_[a-zA-Z0-9]{52}").unwrap();

    let valid_key = format!("gsk_{}", "a".repeat(52));
    assert!(pattern.is_match(&valid_key));

    assert!(!pattern.is_match("gsk_tooshort"));
}

#[test]
fn test_huggingface_pattern() {
    let pattern = Regex::new(r"hf_[a-zA-Z0-9]{34}").unwrap();

    let valid_key = format!("hf_{}", "a".repeat(34));
    assert!(pattern.is_match(&valid_key));

    assert!(!pattern.is_match("hf_short"));
}

#[test]
fn test_replicate_pattern() {
    let pattern = Regex::new(r"r8_[a-zA-Z0-9]{37}").unwrap();

    let valid_key = format!("r8_{}", "a".repeat(37));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_perplexity_pattern() {
    let pattern = Regex::new(r"pplx-[a-f0-9]{48}").unwrap();

    let valid_key = format!("pplx-{}", "a".repeat(48));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_fireworks_pattern() {
    let pattern = Regex::new(r"fw_[a-zA-Z0-9]{32}").unwrap();

    let valid_key = format!("fw_{}", "a".repeat(32));
    assert!(pattern.is_match(&valid_key));
}

// ============================================================================
// Cloud Providers
// ============================================================================

#[test]
fn test_aws_access_key_pattern() {
    let pattern = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();

    // Valid
    assert!(pattern.is_match("AKIAIOSFODNN7EXAMPLE"));

    // Invalid - wrong prefix
    assert!(!pattern.is_match("ASIAIOSFODNN7EXAMPLE"));

    // Invalid - lowercase
    assert!(!pattern.is_match("akiaiosfodnn7example"));

    // Invalid - too short
    assert!(!pattern.is_match("AKIA123"));
}

// ============================================================================
// Payment Providers
// ============================================================================

#[test]
fn test_stripe_live_pattern() {
    let pattern = Regex::new(r"sk_live_[a-zA-Z0-9]{24,}").unwrap();

    // Valid
    assert!(pattern.is_match("sk_live_REDACTED"));

    // Invalid - test key should not match live pattern
    assert!(!pattern.is_match("sk_test_REDACTED"));
}

#[test]
fn test_stripe_restricted_pattern() {
    let pattern = Regex::new(r"rk_live_[a-zA-Z0-9]{24,}").unwrap();

    assert!(pattern.is_match("rk_live_REDACTED"));
}

// ============================================================================
// Developer Platforms
// ============================================================================

#[test]
fn test_github_pat_ghp_pattern() {
    let pattern = Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap();

    let valid_key = format!("ghp_{}", "a".repeat(36));
    assert!(pattern.is_match(&valid_key));

    assert!(!pattern.is_match("ghp_tooshort"));
}

#[test]
fn test_github_pat_gho_pattern() {
    let pattern = Regex::new(r"gho_[a-zA-Z0-9]{36}").unwrap();

    let valid_key = format!("gho_{}", "a".repeat(36));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_gitlab_pattern() {
    let pattern = Regex::new(r"glpat-[a-zA-Z0-9_-]{20}").unwrap();

    assert!(pattern.is_match("glpat-abcdefghij1234567890"));
}

#[test]
fn test_npm_pattern() {
    let pattern = Regex::new(r"npm_[a-zA-Z0-9]{36}").unwrap();

    let valid_key = format!("npm_{}", "a".repeat(36));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_pypi_pattern() {
    let pattern = Regex::new(r"pypi-[A-Za-z0-9_-]{50,}").unwrap();

    let valid_key = format!("pypi-{}", "a".repeat(50));
    assert!(pattern.is_match(&valid_key));
}

// ============================================================================
// Social / Messaging
// ============================================================================

#[test]
fn test_slack_bot_pattern() {
    let pattern = Regex::new(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}").unwrap();

    assert!(pattern.is_match("xoxb-EXAMPLE"));
}

#[test]
fn test_slack_user_pattern() {
    let pattern = Regex::new(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}").unwrap();

    assert!(pattern.is_match("xoxb-EXAMPLE"));
}

#[test]
fn test_discord_bot_pattern() {
    let pattern = Regex::new(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}").unwrap();

    assert!(pattern.is_match("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAx.abcdef.abcdefghijklmnopqrstuvwxyz1"));
}

#[test]
fn test_telegram_pattern() {
    let pattern = Regex::new(r"\d{9,10}:[A-Za-z0-9_-]{35}").unwrap();

    let valid_key = format!("1234567890:{}", "a".repeat(35));
    assert!(pattern.is_match(&valid_key));

    // Invalid - ID too short
    assert!(!pattern.is_match(&format!("123:{}", "a".repeat(35))));
}

// ============================================================================
// Communication
// ============================================================================

#[test]
fn test_sendgrid_pattern() {
    let pattern = Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").unwrap();

    let valid_key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_twilio_pattern() {
    let pattern = Regex::new(r"SK[a-f0-9]{32}").unwrap();

    let valid_key = format!("SK{}", "a".repeat(32));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_mailgun_pattern() {
    let pattern = Regex::new(r"key-[a-zA-Z0-9]{32}").unwrap();

    let valid_key = format!("key-{}", "a".repeat(32));
    assert!(pattern.is_match(&valid_key));
}

// ============================================================================
// Database
// ============================================================================

#[test]
fn test_mongodb_pattern() {
    let pattern = Regex::new(r"mongodb\+srv://[^\s]+").unwrap();

    assert!(pattern.is_match("mongodb+srv://user:password@cluster0.abc123.mongodb.net/mydb"));
}

#[test]
fn test_postgres_pattern() {
    let pattern = Regex::new(r"postgres://[^\s]+").unwrap();

    assert!(pattern.is_match("postgres://user:password@localhost:5432/mydb"));
}

#[test]
fn test_mysql_pattern() {
    let pattern = Regex::new(r"mysql://[^\s]+").unwrap();

    assert!(pattern.is_match("mysql://root:password@localhost:3306/app"));
}

#[test]
fn test_redis_pattern() {
    let pattern = Regex::new(r"redis://[^\s]+").unwrap();

    assert!(pattern.is_match("redis://user:password@localhost:6379/0"));
}

// ============================================================================
// Other Services
// ============================================================================

#[test]
fn test_mapbox_public_pattern() {
    let pattern = Regex::new(r"pk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap();

    assert!(pattern.is_match("pk.eyJ1IjoibXl1c2VyIiwiYSI6ImNsYWJjZGVmZyJ9.abcdefghij"));
}

#[test]
fn test_mapbox_secret_pattern() {
    let pattern = Regex::new(r"sk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap();

    assert!(pattern.is_match("sk.eyJ1IjoibXl1c2VyIiwiYSI6ImNsYWJjZGVmZyJ9.abcdefghij"));
}

#[test]
fn test_newrelic_pattern() {
    let pattern = Regex::new(r"NRAK-[A-Z0-9]{27}").unwrap();

    assert!(pattern.is_match(concat!("NRAK-", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1")));
}

#[test]
fn test_planetscale_pattern() {
    let pattern = Regex::new(r"pscale_tkn_[a-zA-Z0-9_]{32,}").unwrap();

    let valid_key = format!("pscale_tkn_{}", "a".repeat(32));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_doppler_pattern() {
    let pattern = Regex::new(r"dp\.pt\.[a-zA-Z0-9]{40,}").unwrap();

    let valid_key = format!("dp.pt.{}", "a".repeat(40));
    assert!(pattern.is_match(&valid_key));
}

#[test]
fn test_private_key_pattern() {
    let pattern = Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap();

    assert!(pattern.is_match("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(pattern.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(pattern.is_match("-----BEGIN PRIVATE KEY-----"));
    assert!(pattern.is_match("-----BEGIN EC PRIVATE KEY-----"));
}
