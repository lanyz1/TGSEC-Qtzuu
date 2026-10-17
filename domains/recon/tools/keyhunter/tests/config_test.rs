//! Tests for configuration parsing and defaults.

use std::fs;
use std::path::Path;

/// Test that config.toml.example exists and is valid TOML
#[test]
fn test_example_config_exists() {
    let path = Path::new("config.toml.example");
    assert!(path.exists(), "config.toml.example should exist");
}

/// Test that config.toml.example can be parsed
#[test]
fn test_example_config_valid_toml() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: Result<toml::Value, _> = toml::from_str(&content);
    assert!(parsed.is_ok(), "config.toml.example should be valid TOML");
}

/// Test that config.toml.example has all required sections
#[test]
fn test_example_config_has_sections() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    // Check required sections exist
    assert!(parsed.get("github").is_some(), "Should have [github] section");
    assert!(parsed.get("scan").is_some(), "Should have [scan] section");
    assert!(parsed.get("output").is_some(), "Should have [output] section");
    assert!(parsed.get("providers").is_some(), "Should have [providers] section");
}

/// Test that github section has required fields
#[test]
fn test_github_section_fields() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let github = parsed.get("github").expect("Should have github section");

    assert!(github.get("tokens").is_some(), "Should have tokens field");
    assert!(github.get("concurrency").is_some(), "Should have concurrency field");
    assert!(github.get("delay_ms").is_some(), "Should have delay_ms field");
}

/// Test that output section has required fields
#[test]
fn test_output_section_fields() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let output = parsed.get("output").expect("Should have output section");

    assert!(output.get("format").is_some(), "Should have format field");
    assert!(output.get("save_to_file").is_some(), "Should have save_to_file field");
    assert!(output.get("output_path").is_some(), "Should have output_path field");
}

/// Test that format value is valid
#[test]
fn test_output_format_valid_value() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let format = parsed["output"]["format"].as_str()
        .expect("format should be a string");

    let valid_formats = ["table", "json", "csv"];
    assert!(
        valid_formats.contains(&format),
        "format '{}' should be one of: {:?}",
        format,
        valid_formats
    );
}

/// Test that scan section has max_results
#[test]
fn test_scan_section_fields() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let scan = parsed.get("scan").expect("Should have scan section");

    assert!(scan.get("max_results").is_some(), "Should have max_results field");
}

/// Test that providers section has AI providers
#[test]
fn test_providers_has_ai_providers() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let providers = parsed.get("providers").expect("Should have providers section");

    // Check key AI providers exist
    assert!(providers.get("openai").is_some(), "Should have openai provider");
    assert!(providers.get("anthropic").is_some(), "Should have anthropic provider");
    assert!(providers.get("google").is_some(), "Should have google provider");
    assert!(providers.get("groq").is_some(), "Should have groq provider");
}

/// Test that providers section has cloud providers
#[test]
fn test_providers_has_cloud_providers() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let providers = parsed.get("providers").expect("Should have providers section");

    assert!(providers.get("aws").is_some(), "Should have aws provider");
}

/// Test that providers section has payment providers
#[test]
fn test_providers_has_payment_providers() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let providers = parsed.get("providers").expect("Should have providers section");

    assert!(providers.get("stripe_live").is_some(), "Should have stripe_live provider");
}

/// Test that example config has placeholder token
#[test]
fn test_example_config_has_placeholder_token() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    // Should contain placeholder token, not a real one
    assert!(
        content.contains("ghp_xxxx") || content.contains("YOUR_TOKEN"),
        "Example config should have placeholder token"
    );
}

/// Count total providers in config
#[test]
fn test_provider_count() {
    let content = fs::read_to_string("config.toml.example")
        .expect("Should be able to read config.toml.example");

    let parsed: toml::Value = toml::from_str(&content)
        .expect("Should parse as TOML");

    let providers = parsed.get("providers")
        .and_then(|p| p.as_table())
        .expect("Should have providers table");

    // Should have at least 40 providers
    assert!(
        providers.len() >= 40,
        "Should have at least 40 providers, found {}",
        providers.len()
    );
}
