//! Tests for false positive filtering logic.
//!
//! Verifies that placeholder and example keys are correctly filtered out.

/// Check if a key looks like a placeholder/example that should be filtered.
fn is_false_positive(key: &str) -> bool {
    let key_lower = key.to_lowercase();

    // Check for placeholder patterns
    if key_lower.contains("xxxx")
        || key_lower.contains("your_")
        || key_lower.contains("_here")
        || key_lower.contains("example")
        || key_lower.contains("dummy")
        || key_lower.contains("test_")
        || key_lower.contains("fake")
        || key_lower.contains("sample")
        || key_lower.contains("placeholder")
    {
        return true;
    }

    // Check for repeated characters (like aaaaa or 00000)
    let chars: Vec<char> = key.chars().collect();
    if chars.len() > 10 {
        let last_10: String = chars[chars.len() - 10..].iter().collect();
        let first_char = last_10.chars().next().unwrap();
        if last_10.chars().all(|c| c == first_char) {
            return true;
        }
    }

    false
}

#[test]
fn test_filter_xxxx_placeholder() {
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("sk-proj-EXAMPLE"));
}

#[test]
fn test_filter_your_key_placeholder() {
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("AKIAXXXXYOUR_ACCESS_KEY_ID"));
}

#[test]
fn test_filter_here_suffix() {
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("INSERT_TOKEN_HERE"));
}

#[test]
fn test_filter_example_text() {
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("EXAMPLE_API_KEY_12345"));
}

#[test]
fn test_filter_dummy_text() {
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("dummy_token_for_testing"));
}

#[test]
fn test_filter_test_prefix() {
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("test_api_key_12345678901234"));
}

#[test]
fn test_filter_fake_text() {
    assert!(is_false_positive("fake_api_key_1234567890123"));
    assert!(is_false_positive("sk-proj-EXAMPLE"));
}

#[test]
fn test_filter_sample_text() {
    assert!(is_false_positive("sample_key_1234567890123456"));
    assert!(is_false_positive("SAMPLE_API_TOKEN_123456789"));
}

#[test]
fn test_filter_placeholder_text() {
    assert!(is_false_positive("placeholder_token_12345678"));
    assert!(is_false_positive("API_PLACEHOLDER_KEY_12345"));
}

#[test]
fn test_filter_repeated_chars() {
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("AKIAXXXXEXAMPLEKEY1"));
}

#[test]
fn test_real_key_not_filtered() {
    // Real-looking keys should NOT be filtered
    assert!(!is_false_positive("sk-proj-EXAMPLE"));
    assert!(!is_false_positive("AKIAXXXXEXAMPLEKEY1")); // Note: AWS docs use "EXAMPLE" which IS filtered
    assert!(!is_false_positive("ghp_EXAMPLE"));
    assert!(!is_false_positive("sk-ant-EXAMPLE"));
}

#[test]
fn test_aws_example_key_is_filtered() {
    // AWS documentation uses "EXAMPLE" which should be filtered
    assert!(is_false_positive("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn test_mixed_case_filtering() {
    // Should filter regardless of case
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("sk-proj-EXAMPLE"));
    assert!(is_false_positive("sk-proj-EXAMPLE"));
}
