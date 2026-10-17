//! Configuration management for KeyHunter.
//!
//! Handles loading and parsing of TOML configuration files,
//! including GitHub tokens, scan settings, and provider toggles.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Main configuration structure.
///
/// Loaded from a TOML file (default: `config.toml`).
/// Contains all settings for GitHub API access, scanning behavior,
/// output preferences, and provider toggles.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// GitHub API configuration
    pub github: GitHubConfig,
    /// Scan behavior settings
    pub scan: ScanConfig,
    /// Output and file saving settings
    pub output: OutputConfig,
    /// Per-provider enable/disable toggles
    #[serde(default)]
    pub providers: ProvidersConfig,
}

/// GitHub API configuration.
///
/// Contains authentication tokens and rate limiting settings.
#[derive(Debug, Deserialize, Clone)]
pub struct GitHubConfig {
    /// List of GitHub Personal Access Tokens for API authentication.
    /// Multiple tokens enable round-robin rotation to bypass rate limits.
    pub tokens: Vec<String>,
    /// Number of concurrent API requests (default: 5)
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Delay between API requests in milliseconds (default: 500)
    #[serde(default = "default_delay")]
    pub delay_ms: u64,
}

/// Scan behavior configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ScanConfig {
    /// Maximum results to fetch per search query (default: 1000).
    /// GitHub API limits to ~1000 results per query.
    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

/// Output and file saving configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct OutputConfig {
    /// Output format: "table", "json", or "csv" (default: "table")
    #[serde(default = "default_format")]
    pub format: String,
    /// Whether to automatically save results to JSON files
    #[serde(default)]
    pub save_to_file: bool,
    /// Directory path for saving result files (default: "results")
    #[serde(default = "default_output_path")]
    pub output_path: String,
}

/// Provider enable/disable toggles.
///
/// Each field controls whether that provider's patterns are scanned.
/// Providers with high false-positive rates are disabled by default.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProvidersConfig {
    // ═══════════════════════════════════════════════════════════
    // AI / LLM Providers
    // ═══════════════════════════════════════════════════════════
    /// Anthropic Claude API keys (sk-ant-api03-...)
    #[serde(default = "default_true")]
    pub anthropic: bool,
    /// OpenAI GPT API keys (sk-proj-..., T3BlbkFJ)
    #[serde(default = "default_true")]
    pub openai: bool,
    /// Google AI / Gemini keys (AIza...)
    #[serde(default = "default_true")]
    pub google: bool,
    /// xAI Grok API keys (xai-...)
    #[serde(default = "default_true")]
    pub grok: bool,
    /// DeepSeek API keys
    #[serde(default = "default_true")]
    pub deepseek: bool,
    /// HuggingFace tokens (hf_...)
    #[serde(default = "default_true")]
    pub huggingface: bool,
    /// Replicate API tokens (r8_...)
    #[serde(default = "default_true")]
    pub replicate: bool,
    /// Cohere API keys (low confidence pattern)
    #[serde(default = "default_true")]
    pub cohere: bool,
    /// Mistral AI API keys (low confidence pattern)
    #[serde(default = "default_true")]
    pub mistral: bool,
    /// Together AI API keys (low confidence pattern)
    #[serde(default = "default_true")]
    pub together: bool,
    /// Perplexity API keys (pplx-...)
    #[serde(default = "default_true")]
    pub perplexity: bool,
    /// Groq API keys (gsk_...)
    #[serde(default = "default_true")]
    pub groq: bool,
    /// Fireworks AI API keys (fw_...)
    #[serde(default = "default_true")]
    pub fireworks: bool,

    // ═══════════════════════════════════════════════════════════
    // Cloud Providers
    // ═══════════════════════════════════════════════════════════
    /// AWS Access Key IDs (AKIA...)
    #[serde(default = "default_true")]
    pub aws: bool,
    /// AWS Secret Access Keys (high false positive rate)
    #[serde(default = "default_true")]
    pub aws_secret: bool,
    /// Azure API keys
    #[serde(default = "default_true")]
    pub azure: bool,

    // ═══════════════════════════════════════════════════════════
    // Payment Providers
    // ═══════════════════════════════════════════════════════════
    /// Stripe live secret keys (sk_live_...)
    #[serde(default = "default_true")]
    pub stripe_live: bool,
    /// Stripe restricted keys (rk_live_...)
    #[serde(default = "default_true")]
    pub stripe_restricted: bool,
    /// PayPal access tokens
    #[serde(default = "default_true")]
    pub paypal: bool,
    /// Square API tokens (sq0...)
    #[serde(default = "default_true")]
    pub square: bool,

    // ═══════════════════════════════════════════════════════════
    // Communication Services
    // ═══════════════════════════════════════════════════════════
    /// Twilio API keys (SK...)
    #[serde(default = "default_true")]
    pub twilio: bool,
    /// SendGrid API keys (SG....)
    #[serde(default = "default_true")]
    pub sendgrid: bool,
    /// Mailgun API keys (key-...)
    #[serde(default = "default_true")]
    pub mailgun: bool,
    /// Mailchimp API keys (...-us14)
    #[serde(default = "default_true")]
    pub mailchimp: bool,

    // ═══════════════════════════════════════════════════════════
    // Developer Platforms
    // ═══════════════════════════════════════════════════════════
    /// GitHub Personal Access Tokens (ghp_..., github_pat_...)
    #[serde(default = "default_true")]
    pub github_token: bool,
    /// GitLab Personal Access Tokens (glpat-...)
    #[serde(default = "default_true")]
    pub gitlab: bool,
    /// NPM access tokens (npm_...)
    #[serde(default = "default_true")]
    pub npm: bool,
    /// PyPI API tokens (pypi-...)
    #[serde(default = "default_true")]
    pub pypi: bool,

    // ═══════════════════════════════════════════════════════════
    // Social / Messaging
    // ═══════════════════════════════════════════════════════════
    /// Slack bot tokens (xoxb-...)
    #[serde(default = "default_true")]
    pub slack_bot: bool,
    /// Slack user tokens (xoxp-...)
    #[serde(default = "default_true")]
    pub slack_user: bool,
    /// Slack webhook URLs
    #[serde(default = "default_true")]
    pub slack_webhook: bool,
    /// Discord bot tokens
    #[serde(default = "default_true")]
    pub discord: bool,
    /// Discord webhook URLs
    #[serde(default = "default_true")]
    pub discord_webhook: bool,
    /// Telegram bot tokens
    #[serde(default = "default_true")]
    pub telegram: bool,

    // ═══════════════════════════════════════════════════════════
    // Database Connection Strings
    // ═══════════════════════════════════════════════════════════
    /// MongoDB connection strings (mongodb+srv://...)
    #[serde(default = "default_true")]
    pub mongodb: bool,
    /// PostgreSQL connection strings (postgres://...)
    #[serde(default = "default_true")]
    pub postgres: bool,
    /// MySQL connection strings (mysql://...)
    #[serde(default = "default_true")]
    pub mysql: bool,
    /// Redis connection strings (redis://...)
    #[serde(default = "default_true")]
    pub redis: bool,

    // ═══════════════════════════════════════════════════════════
    // Other Services
    // ═══════════════════════════════════════════════════════════
    /// Firebase / FCM keys
    #[serde(default = "default_true")]
    pub firebase: bool,
    /// Supabase API keys (JWT pattern)
    #[serde(default = "default_true")]
    pub supabase: bool,
    /// Vercel API tokens
    #[serde(default = "default_true")]
    pub vercel: bool,
    /// Netlify auth tokens
    #[serde(default = "default_true")]
    pub netlify: bool,
    /// Heroku API keys
    #[serde(default = "default_true")]
    pub heroku: bool,
    /// Algolia API keys
    #[serde(default = "default_true")]
    pub algolia: bool,
    /// Mapbox access tokens (pk.eyJ..., sk.eyJ...)
    #[serde(default = "default_true")]
    pub mapbox: bool,
    /// Sentry DSN URLs
    #[serde(default = "default_true")]
    pub sentry: bool,
    /// Datadog API keys
    #[serde(default = "default_true")]
    pub datadog: bool,
    /// New Relic API keys (NRAK-...)
    #[serde(default = "default_true")]
    pub newrelic: bool,
    /// PlanetScale tokens (pscale_tkn_...)
    #[serde(default = "default_true")]
    pub planetscale: bool,
    /// Doppler tokens (dp.pt....)
    #[serde(default = "default_true")]
    pub doppler: bool,
    /// Private keys (RSA, SSH, etc.)
    #[serde(default = "default_true")]
    pub private_key: bool,
}

// ═══════════════════════════════════════════════════════════════════
// Default Value Functions
// ═══════════════════════════════════════════════════════════════════

/// Default concurrent requests (5)
fn default_concurrency() -> usize {
    5
}

/// Default delay between requests (500ms)
fn default_delay() -> u64 {
    500
}

/// Default max results per query (1000)
fn default_max_results() -> usize {
    1000
}

/// Default output directory ("results")
fn default_output_path() -> String {
    "results".to_string()
}

/// Default output format ("table")
fn default_format() -> String {
    "table".to_string()
}

/// Default boolean value (true) for provider toggles
fn default_true() -> bool {
    true
}

// ═══════════════════════════════════════════════════════════════════
// Config Implementation
// ═══════════════════════════════════════════════════════════════════

impl Config {
    /// Loads configuration from a TOML file.
    ///
    /// # Arguments
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Returns
    /// * `Result<Config>` - Parsed configuration or error
    ///
    /// # Errors
    /// * File not found or unreadable
    /// * Invalid TOML syntax
    /// * No GitHub tokens provided
    /// * Placeholder tokens detected
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            fs::read_to_string(path).context(format!("Cannot read config file: {:?}", path))?;

        let config: Config = toml::from_str(&content).context("Failed to parse config file")?;

        // Validate: at least one token required
        if config.github.tokens.is_empty() {
            anyhow::bail!("At least one GitHub token is required in config");
        }

        // Validate: check for placeholder tokens
        for token in &config.github.tokens {
            if token.contains("YOUR_TOKEN")
                || token.contains("YOUR_NEW")
                || token.contains("xxxx")
                || token.len() < 20
            {
                anyhow::bail!(
                    "Please replace placeholder token with real GitHub token in config.toml"
                );
            }
        }

        Ok(config)
    }

    /// Returns a list of enabled provider names.
    ///
    /// Iterates through all provider toggles and returns the names
    /// of providers that are enabled in the configuration.
    ///
    /// # Returns
    /// * `Vec<&'static str>` - List of enabled provider identifiers
    pub fn enabled_providers(&self) -> Vec<&'static str> {
        let mut providers = Vec::new();
        let p = &self.providers;

        // AI/LLM Providers
        if p.anthropic {
            providers.push("anthropic");
        }
        if p.openai {
            providers.push("openai");
        }
        if p.google {
            providers.push("google");
        }
        if p.grok {
            providers.push("grok");
        }
        if p.deepseek {
            providers.push("deepseek");
        }
        if p.huggingface {
            providers.push("huggingface");
        }
        if p.replicate {
            providers.push("replicate");
        }
        if p.cohere {
            providers.push("cohere");
        }
        if p.mistral {
            providers.push("mistral");
        }
        if p.together {
            providers.push("together");
        }
        if p.perplexity {
            providers.push("perplexity");
        }
        if p.groq {
            providers.push("groq");
        }
        if p.fireworks {
            providers.push("fireworks");
        }

        // Cloud Providers
        if p.aws {
            providers.push("aws");
        }
        if p.aws_secret {
            providers.push("aws_secret");
        }
        if p.azure {
            providers.push("azure");
        }

        // Payment Providers
        if p.stripe_live {
            providers.push("stripe_live");
        }
        if p.stripe_restricted {
            providers.push("stripe_restricted");
        }
        if p.paypal {
            providers.push("paypal");
        }
        if p.square {
            providers.push("square");
        }

        // Communication Services
        if p.twilio {
            providers.push("twilio");
        }
        if p.sendgrid {
            providers.push("sendgrid");
        }
        if p.mailgun {
            providers.push("mailgun");
        }
        if p.mailchimp {
            providers.push("mailchimp");
        }

        // Developer Platforms
        if p.github_token {
            providers.push("github_token");
        }
        if p.gitlab {
            providers.push("gitlab");
        }
        if p.npm {
            providers.push("npm");
        }
        if p.pypi {
            providers.push("pypi");
        }

        // Social / Messaging
        if p.slack_bot {
            providers.push("slack_bot");
        }
        if p.slack_user {
            providers.push("slack_user");
        }
        if p.slack_webhook {
            providers.push("slack_webhook");
        }
        if p.discord {
            providers.push("discord");
        }
        if p.discord_webhook {
            providers.push("discord_webhook");
        }
        if p.telegram {
            providers.push("telegram");
        }

        // Database
        if p.mongodb {
            providers.push("mongodb");
        }
        if p.postgres {
            providers.push("postgres");
        }
        if p.mysql {
            providers.push("mysql");
        }
        if p.redis {
            providers.push("redis");
        }

        // Other Services
        if p.firebase {
            providers.push("firebase");
        }
        if p.supabase {
            providers.push("supabase");
        }
        if p.vercel {
            providers.push("vercel");
        }
        if p.netlify {
            providers.push("netlify");
        }
        if p.heroku {
            providers.push("heroku");
        }
        if p.algolia {
            providers.push("algolia");
        }
        if p.mapbox {
            providers.push("mapbox");
        }
        if p.sentry {
            providers.push("sentry");
        }
        if p.datadog {
            providers.push("datadog");
        }
        if p.newrelic {
            providers.push("newrelic");
        }
        if p.planetscale {
            providers.push("planetscale");
        }
        if p.doppler {
            providers.push("doppler");
        }
        if p.private_key {
            providers.push("private_key");
        }

        providers
    }
}
