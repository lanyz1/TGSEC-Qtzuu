//! API key pattern definitions for KeyHunter.
//!
//! This module defines regex patterns for detecting API keys from 45+ providers.
//! Each pattern includes:
//! - A unique regex for matching the key format
//! - Search terms for GitHub code search
//! - Confidence level (high, medium, low)
//!
//! ## Supported Provider Categories
//!
//! - **AI/LLM**: OpenAI, Anthropic, Google AI, Groq, HuggingFace, etc.
//! - **Cloud**: AWS, Azure
//! - **Payment**: Stripe, PayPal, Square
//! - **Communication**: Twilio, SendGrid, Slack, Discord
//! - **Developer**: GitHub, GitLab, NPM, PyPI
//! - **Database**: MongoDB, PostgreSQL, MySQL, Redis
//! - **Other**: Firebase, Mapbox, Sentry, and more

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

/// Represents a pattern for detecting a specific type of API key.
///
/// Each pattern contains the regex for matching, search terms for
/// finding potential keys on GitHub, and metadata about the provider.
#[derive(Debug, Clone)]
pub struct KeyPattern {
    /// Human-readable provider name (e.g., "OpenAI", "Stripe")
    pub name: &'static str,
    /// Compiled regex for matching the key format
    pub regex: Regex,
    /// Search terms to use in GitHub code search
    pub search_terms: Vec<&'static str>,
    /// Description of what this key type is
    pub description: &'static str,
    /// Confidence level: "high", "medium", or "low"
    /// - high: Unique prefix/format, very few false positives
    /// - medium: Somewhat unique, may have some false positives
    /// - low: Generic pattern, requires additional context
    pub confidence: &'static str,
}

lazy_static! {
    /// Global map of all API key patterns, keyed by provider identifier.
    pub static ref PATTERNS: HashMap<&'static str, KeyPattern> = {
        let mut m = HashMap::new();

        // ═══════════════════════════════════════════════════════════════════
        // AI/LLM PROVIDERS
        // ═══════════════════════════════════════════════════════════════════

        // Anthropic Claude - Very unique prefix
        m.insert(
            "anthropic",
            KeyPattern {
                name: "Anthropic",
                regex: Regex::new(r"sk-ant-api03-[A-Za-z0-9_-]{93}").unwrap(),
                search_terms: vec![
                    "sk-ant-api03-",
                    "ANTHROPIC_API_KEY",
                    "CLAUDE_API_KEY",
                    "anthropic_api_key",
                ],
                description: "Anthropic Claude API Key",
                confidence: "high",
            },
        );

        // OpenAI - Multiple formats including unique T3BlbkFJ base64 segment
        m.insert(
            "openai",
            KeyPattern {
                name: "OpenAI",
                regex: Regex::new(
                    r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-proj-[A-Za-z0-9_-]{48,180}|sk-[a-zA-Z0-9]{48}"
                ).unwrap(),
                search_terms: vec![
                    "T3BlbkFJ",           // Base64 encoded part - very unique!
                    "sk-proj-",
                    "OPENAI_API_KEY",
                    "OPENAI_KEY",
                    "openai.api_key",
                    "openai_api_key",
                ],
                description: "OpenAI API Key",
                confidence: "high",
            },
        );

        // Google AI / Gemini / Vertex - AIza prefix
        m.insert(
            "google",
            KeyPattern {
                name: "Google AI",
                regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
                search_terms: vec![
                    "AIzaSy",
                    "GOOGLE_API_KEY",
                    "GEMINI_API_KEY",
                    "GOOGLE_AI_KEY",
                    "GCP_API_KEY",
                ],
                description: "Google AI / Gemini API Key",
                confidence: "high",
            },
        );

        // xAI Grok - xai- prefix
        m.insert(
            "grok",
            KeyPattern {
                name: "xAI Grok",
                regex: Regex::new(r"xai-[A-Za-z0-9]{48,}").unwrap(),
                search_terms: vec![
                    "xai-",
                    "XAI_API_KEY",
                    "GROK_API_KEY",
                ],
                description: "xAI Grok API Key",
                confidence: "high",
            },
        );

        // DeepSeek - sk- prefix with hex characters
        m.insert(
            "deepseek",
            KeyPattern {
                name: "DeepSeek",
                regex: Regex::new(r"sk-[a-f0-9]{32}").unwrap(),
                search_terms: vec![
                    "DEEPSEEK_API_KEY",
                    "DEEPSEEK_KEY",
                    "deepseek_api",
                ],
                description: "DeepSeek API Key",
                confidence: "medium",
            },
        );

        // Hugging Face - hf_ prefix
        m.insert(
            "huggingface",
            KeyPattern {
                name: "HuggingFace",
                regex: Regex::new(r"hf_[A-Za-z0-9]{34,}").unwrap(),
                search_terms: vec![
                    "hf_",
                    "HUGGINGFACE_TOKEN",
                    "HUGGINGFACE_API_KEY",
                    "HF_TOKEN",
                    "HF_API_KEY",
                ],
                description: "Hugging Face Token",
                confidence: "high",
            },
        );

        // Replicate - r8_ prefix
        m.insert(
            "replicate",
            KeyPattern {
                name: "Replicate",
                regex: Regex::new(r"r8_[A-Za-z0-9]{38,}").unwrap(),
                search_terms: vec![
                    "r8_",
                    "REPLICATE_API_TOKEN",
                    "REPLICATE_API_KEY",
                ],
                description: "Replicate API Token",
                confidence: "high",
            },
        );

        // Cohere - Generic pattern, needs context
        m.insert(
            "cohere",
            KeyPattern {
                name: "Cohere",
                regex: Regex::new(r"[a-zA-Z0-9]{40}").unwrap(),
                search_terms: vec![
                    "COHERE_API_KEY",
                    "CO_API_KEY",
                    "cohere_api_key",
                ],
                description: "Cohere API Key",
                confidence: "low",
            },
        );

        // Mistral AI - Generic pattern
        m.insert(
            "mistral",
            KeyPattern {
                name: "Mistral AI",
                regex: Regex::new(r"[A-Za-z0-9]{32}").unwrap(),
                search_terms: vec![
                    "MISTRAL_API_KEY",
                    "MISTRAL_KEY",
                ],
                description: "Mistral AI API Key",
                confidence: "low",
            },
        );

        // Together AI - 64 hex chars
        m.insert(
            "together",
            KeyPattern {
                name: "Together AI",
                regex: Regex::new(r"[a-f0-9]{64}").unwrap(),
                search_terms: vec![
                    "TOGETHER_API_KEY",
                    "TOGETHER_AI_KEY",
                ],
                description: "Together AI API Key",
                confidence: "low",
            },
        );

        // Perplexity - pplx- prefix
        m.insert(
            "perplexity",
            KeyPattern {
                name: "Perplexity",
                regex: Regex::new(r"pplx-[A-Za-z0-9]{48,}").unwrap(),
                search_terms: vec![
                    "pplx-",
                    "PERPLEXITY_API_KEY",
                    "PPLX_API_KEY",
                ],
                description: "Perplexity API Key",
                confidence: "high",
            },
        );

        // Groq - gsk_ prefix
        m.insert(
            "groq",
            KeyPattern {
                name: "Groq",
                regex: Regex::new(r"gsk_[A-Za-z0-9]{52,}").unwrap(),
                search_terms: vec![
                    "gsk_",
                    "GROQ_API_KEY",
                    "GROQ_KEY",
                ],
                description: "Groq API Key",
                confidence: "high",
            },
        );

        // Fireworks AI - fw_ prefix
        m.insert(
            "fireworks",
            KeyPattern {
                name: "Fireworks AI",
                regex: Regex::new(r"fw_[A-Za-z0-9]{32,}").unwrap(),
                search_terms: vec![
                    "fw_",
                    "FIREWORKS_API_KEY",
                ],
                description: "Fireworks AI API Key",
                confidence: "high",
            },
        );

        // ═══════════════════════════════════════════════════════════════════
        // CLOUD PROVIDERS
        // ═══════════════════════════════════════════════════════════════════

        // AWS Access Key - AKIA prefix
        m.insert(
            "aws",
            KeyPattern {
                name: "AWS Access Key",
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                search_terms: vec![
                    "AKIA",
                    "AWS_ACCESS_KEY",
                    "AWS_ACCESS_KEY_ID",
                    "aws_access_key_id",
                ],
                description: "AWS Access Key ID",
                confidence: "high",
            },
        );

        // AWS Secret Key - 40 chars, base64-like
        m.insert(
            "aws_secret",
            KeyPattern {
                name: "AWS Secret Key",
                regex: Regex::new(r"[A-Za-z0-9/+=]{40}").unwrap(),
                search_terms: vec![
                    "AWS_SECRET_ACCESS_KEY",
                    "aws_secret_access_key",
                    "AWS_SECRET_KEY",
                ],
                description: "AWS Secret Access Key",
                confidence: "medium",
            },
        );

        // Azure - 86 chars + ==
        m.insert(
            "azure",
            KeyPattern {
                name: "Azure",
                regex: Regex::new(r"[a-zA-Z0-9+/]{86}==").unwrap(),
                search_terms: vec![
                    "AZURE_API_KEY",
                    "AZURE_STORAGE_KEY",
                    "AZURE_SUBSCRIPTION_KEY",
                    "AZURE_OPENAI_KEY",
                ],
                description: "Azure API Key",
                confidence: "medium",
            },
        );

        // ═══════════════════════════════════════════════════════════════════
        // PAYMENT PROVIDERS
        // ═══════════════════════════════════════════════════════════════════

        // Stripe Live - sk_live_ prefix
        m.insert(
            "stripe_live",
            KeyPattern {
                name: "Stripe Live",
                regex: Regex::new(r"sk_live_[0-9a-zA-Z]{24,99}").unwrap(),
                search_terms: vec![
                    "sk_live_",
                    "STRIPE_SECRET_KEY",
                    "STRIPE_LIVE_KEY",
                ],
                description: "Stripe Live Secret Key",
                confidence: "high",
            },
        );

        // Stripe Restricted - rk_live_ prefix
        m.insert(
            "stripe_restricted",
            KeyPattern {
                name: "Stripe Restricted",
                regex: Regex::new(r"rk_live_[0-9a-zA-Z]{24,99}").unwrap(),
                search_terms: vec![
                    "rk_live_",
                ],
                description: "Stripe Restricted Key",
                confidence: "high",
            },
        );

        // PayPal access token
        m.insert(
            "paypal",
            KeyPattern {
                name: "PayPal",
                regex: Regex::new(r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}").unwrap(),
                search_terms: vec![
                    "PAYPAL_CLIENT_SECRET",
                    "PAYPAL_ACCESS_TOKEN",
                ],
                description: "PayPal Access Token",
                confidence: "high",
            },
        );

        // Square - sq0 prefix
        m.insert(
            "square",
            KeyPattern {
                name: "Square",
                regex: Regex::new(r"sq0[a-z]{3}-[0-9A-Za-z_-]{22,50}").unwrap(),
                search_terms: vec![
                    "sq0csp-",
                    "sq0atp-",
                    "SQUARE_ACCESS_TOKEN",
                ],
                description: "Square API Token",
                confidence: "high",
            },
        );

        // ═══════════════════════════════════════════════════════════════════
        // COMMUNICATION SERVICES
        // ═══════════════════════════════════════════════════════════════════

        // Twilio - SK prefix
        m.insert(
            "twilio",
            KeyPattern {
                name: "Twilio",
                regex: Regex::new(r"SK[a-f0-9]{32}").unwrap(),
                search_terms: vec![
                    "TWILIO_API_KEY",
                    "TWILIO_API_SECRET",
                    "TWILIO_AUTH_TOKEN",
                    "twilio_auth_token",
                ],
                description: "Twilio API Key",
                confidence: "high",
            },
        );

        // SendGrid - SG. prefix
        m.insert(
            "sendgrid",
            KeyPattern {
                name: "SendGrid",
                regex: Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap(),
                search_terms: vec![
                    "SG.",
                    "SENDGRID_API_KEY",
                    "SENDGRID_KEY",
                ],
                description: "SendGrid API Key",
                confidence: "high",
            },
        );

        // Mailgun - key- prefix
        m.insert(
            "mailgun",
            KeyPattern {
                name: "Mailgun",
                regex: Regex::new(r"key-[a-f0-9]{32}").unwrap(),
                search_terms: vec![
                    "key-",
                    "MAILGUN_API_KEY",
                    "MAILGUN_KEY",
                ],
                description: "Mailgun API Key",
                confidence: "high",
            },
        );

        // Mailchimp - ...-usXX suffix
        m.insert(
            "mailchimp",
            KeyPattern {
                name: "Mailchimp",
                regex: Regex::new(r"[a-f0-9]{32}-us[0-9]{1,2}").unwrap(),
                search_terms: vec![
                    "MAILCHIMP_API_KEY",
                    "-us1",
                    "-us2",
                    "-us3",
                ],
                description: "Mailchimp API Key",
                confidence: "high",
            },
        );

        // ═══════════════════════════════════════════════════════════════════
        // DEVELOPER PLATFORMS
        // ═══════════════════════════════════════════════════════════════════

        // GitHub Token - ghp_, gho_, ghu_, ghs_, ghr_, github_pat_ prefixes
        m.insert(
            "github_token",
            KeyPattern {
                name: "GitHub",
                regex: Regex::new(
                    r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}"
                ).unwrap(),
                search_terms: vec![
                    "ghp_",
                    "gho_",
                    "github_pat_",
                    "GITHUB_TOKEN",
                    "GITHUB_API_KEY",
                    "GH_TOKEN",
                ],
                description: "GitHub Personal Access Token",
                confidence: "high",
            },
        );

        // GitLab - glpat- prefix
        m.insert(
            "gitlab",
            KeyPattern {
                name: "GitLab",
                regex: Regex::new(r"glpat-[A-Za-z0-9_-]{20,}").unwrap(),
                search_terms: vec![
                    "glpat-",
                    "GITLAB_TOKEN",
                    "GITLAB_API_KEY",
                ],
                description: "GitLab Personal Access Token",
                confidence: "high",
            },
        );

        // NPM - npm_ prefix
        m.insert(
            "npm",
            KeyPattern {
                name: "NPM",
                regex: Regex::new(r"npm_[A-Za-z0-9]{36}").unwrap(),
                search_terms: vec![
                    "npm_",
                    "NPM_TOKEN",
                    "NPM_AUTH_TOKEN",
                ],
                description: "NPM Access Token",
                confidence: "high",
            },
        );

        // PyPI - pypi- prefix
        m.insert(
            "pypi",
            KeyPattern {
                name: "PyPI",
                regex: Regex::new(r"pypi-[A-Za-z0-9_-]{50,}").unwrap(),
                search_terms: vec![
                    "pypi-",
                    "PYPI_TOKEN",
                    "PYPI_API_TOKEN",
                ],
                description: "PyPI API Token",
                confidence: "high",
            },
        );

        // ═══════════════════════════════════════════════════════════════════
        // SOCIAL / MESSAGING
        // ═══════════════════════════════════════════════════════════════════

        // Slack Bot Token - xoxb- prefix
        m.insert(
            "slack_bot",
            KeyPattern {
                name: "Slack Bot",
                regex: Regex::new(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}").unwrap(),
                search_terms: vec![
                    "xoxb-",
                    "SLACK_BOT_TOKEN",
                    "SLACK_TOKEN",
                ],
                description: "Slack Bot Token",
                confidence: "high",
            },
        );

        // Slack User Token - xoxp- prefix
        m.insert(
            "slack_user",
            KeyPattern {
                name: "Slack User",
                regex: Regex::new(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}").unwrap(),
                search_terms: vec![
                    "xoxp-",
                    "SLACK_USER_TOKEN",
                ],
                description: "Slack User Token",
                confidence: "high",
            },
        );

        // Slack Webhook URL
        m.insert(
            "slack_webhook",
            KeyPattern {
                name: "Slack Webhook",
                regex: Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}").unwrap(),
                search_terms: vec![
                    "hooks.slack.com/services",
                    "SLACK_WEBHOOK",
                ],
                description: "Slack Webhook URL",
                confidence: "high",
            },
        );

        // Discord Bot Token
        m.insert(
            "discord",
            KeyPattern {
                name: "Discord",
                regex: Regex::new(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}").unwrap(),
                search_terms: vec![
                    "DISCORD_TOKEN",
                    "DISCORD_BOT_TOKEN",
                    "BOT_TOKEN",
                ],
                description: "Discord Bot Token",
                confidence: "high",
            },
        );

        // Discord Webhook URL
        m.insert(
            "discord_webhook",
            KeyPattern {
                name: "Discord Webhook",
                regex: Regex::new(r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68}").unwrap(),
                search_terms: vec![
                    "discord.com/api/webhooks",
                    "discordapp.com/api/webhooks",
                    "DISCORD_WEBHOOK",
                ],
                description: "Discord Webhook URL",
                confidence: "high",
            },
        );

        // Telegram Bot Token
        m.insert(
            "telegram",
            KeyPattern {
                name: "Telegram",
                regex: Regex::new(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}").unwrap(),
                search_terms: vec![
                    "TELEGRAM_BOT_TOKEN",
                    "TELEGRAM_TOKEN",
                    "TG_BOT_TOKEN",
                ],
                description: "Telegram Bot Token",
                confidence: "high",
            },
        );

        // ═══════════════════════════════════════════════════════════════════
        // DATABASE CONNECTION STRINGS
        // ═══════════════════════════════════════════════════════════════════

        // MongoDB connection string
        m.insert(
            "mongodb",
            KeyPattern {
                name: "MongoDB",
                regex: Regex::new(r"mongodb\+srv://[^:]+:[^@]+@[^\s]+").unwrap(),
                search_terms: vec![
                    "mongodb+srv://",
                    "MONGODB_URI",
                    "MONGO_URL",
                    "DATABASE_URL",
                ],
                description: "MongoDB Connection String",
                confidence: "high",
            },
        );

        // PostgreSQL connection string
        m.insert(
            "postgres",
            KeyPattern {
                name: "PostgreSQL",
                regex: Regex::new(r"postgres://[^:]+:[^@]+@[^\s]+").unwrap(),
                search_terms: vec![
                    "postgres://",
                    "POSTGRES_URL",
                    "DATABASE_URL",
                    "PG_CONNECTION",
                ],
                description: "PostgreSQL Connection String",
                confidence: "high",
            },
        );

        // MySQL connection string
        m.insert(
            "mysql",
            KeyPattern {
                name: "MySQL",
                regex: Regex::new(r"mysql://[^:]+:[^@]+@[^\s]+").unwrap(),
                search_terms: vec![
                    "mysql://",
                    "MYSQL_URL",
                    "DATABASE_URL",
                ],
                description: "MySQL Connection String",
                confidence: "high",
            },
        );

        // Redis connection string
        m.insert(
            "redis",
            KeyPattern {
                name: "Redis",
                regex: Regex::new(r"redis://[^:]*:[^@]+@[^\s]+").unwrap(),
                search_terms: vec![
                    "redis://",
                    "REDIS_URL",
                    "REDIS_PASSWORD",
                ],
                description: "Redis Connection String",
                confidence: "high",
            },
        );

        // ═══════════════════════════════════════════════════════════════════
        // OTHER SERVICES
        // ═══════════════════════════════════════════════════════════════════

        // Firebase Cloud Messaging
        m.insert(
            "firebase",
            KeyPattern {
                name: "Firebase",
                regex: Regex::new(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}").unwrap(),
                search_terms: vec![
                    "FIREBASE_API_KEY",
                    "FIREBASE_KEY",
                    "FCM_API_KEY",
                ],
                description: "Firebase Cloud Messaging Key",
                confidence: "high",
            },
        );

        // Supabase (JWT format)
        m.insert(
            "supabase",
            KeyPattern {
                name: "Supabase",
                regex: Regex::new(r"eyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{50,}").unwrap(),
                search_terms: vec![
                    "SUPABASE_KEY",
                    "SUPABASE_ANON_KEY",
                    "SUPABASE_SERVICE_KEY",
                ],
                description: "Supabase API Key (JWT)",
                confidence: "medium",
            },
        );

        // Vercel - Generic pattern
        m.insert(
            "vercel",
            KeyPattern {
                name: "Vercel",
                regex: Regex::new(r"[A-Za-z0-9]{24}").unwrap(),
                search_terms: vec![
                    "VERCEL_TOKEN",
                    "VERCEL_API_TOKEN",
                ],
                description: "Vercel API Token",
                confidence: "low",
            },
        );

        // Netlify - Generic pattern
        m.insert(
            "netlify",
            KeyPattern {
                name: "Netlify",
                regex: Regex::new(r"[A-Za-z0-9_-]{40,}").unwrap(),
                search_terms: vec![
                    "NETLIFY_AUTH_TOKEN",
                    "NETLIFY_API_KEY",
                ],
                description: "Netlify Auth Token",
                confidence: "low",
            },
        );

        // Heroku - UUID format
        m.insert(
            "heroku",
            KeyPattern {
                name: "Heroku",
                regex: Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
                search_terms: vec![
                    "HEROKU_API_KEY",
                    "HEROKU_TOKEN",
                ],
                description: "Heroku API Key",
                confidence: "medium",
            },
        );

        // Algolia - 32 hex chars
        m.insert(
            "algolia",
            KeyPattern {
                name: "Algolia",
                regex: Regex::new(r"[a-f0-9]{32}").unwrap(),
                search_terms: vec![
                    "ALGOLIA_API_KEY",
                    "ALGOLIA_ADMIN_KEY",
                    "ALGOLIA_SEARCH_KEY",
                ],
                description: "Algolia API Key",
                confidence: "low",
            },
        );

        // Mapbox - pk.eyJ or sk.eyJ prefix
        m.insert(
            "mapbox",
            KeyPattern {
                name: "Mapbox",
                regex: Regex::new(r"pk\.[a-zA-Z0-9]{60,}|sk\.[a-zA-Z0-9]{60,}").unwrap(),
                search_terms: vec![
                    "pk.eyJ",
                    "sk.eyJ",
                    "MAPBOX_TOKEN",
                    "MAPBOX_ACCESS_TOKEN",
                ],
                description: "Mapbox Access Token",
                confidence: "high",
            },
        );

        // Sentry DSN URL
        m.insert(
            "sentry",
            KeyPattern {
                name: "Sentry",
                regex: Regex::new(r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+").unwrap(),
                search_terms: vec![
                    "ingest.sentry.io",
                    "SENTRY_DSN",
                ],
                description: "Sentry DSN",
                confidence: "high",
            },
        );

        // Datadog - 32 hex chars
        m.insert(
            "datadog",
            KeyPattern {
                name: "Datadog",
                regex: Regex::new(r"[a-f0-9]{32}").unwrap(),
                search_terms: vec![
                    "DD_API_KEY",
                    "DATADOG_API_KEY",
                    "DD_APP_KEY",
                ],
                description: "Datadog API Key",
                confidence: "low",
            },
        );

        // New Relic - NRAK- prefix
        m.insert(
            "newrelic",
            KeyPattern {
                name: "New Relic",
                regex: Regex::new(r"NRAK-[A-Z0-9]{27}").unwrap(),
                search_terms: vec![
                    "NRAK-",
                    "NEW_RELIC_LICENSE_KEY",
                    "NEWRELIC_API_KEY",
                ],
                description: "New Relic API Key",
                confidence: "high",
            },
        );

        // PlanetScale - pscale_tkn_ prefix
        m.insert(
            "planetscale",
            KeyPattern {
                name: "PlanetScale",
                regex: Regex::new(r"pscale_tkn_[A-Za-z0-9_]{32,}").unwrap(),
                search_terms: vec![
                    "pscale_tkn_",
                    "PLANETSCALE_TOKEN",
                ],
                description: "PlanetScale Token",
                confidence: "high",
            },
        );

        // Doppler - dp.pt. prefix
        m.insert(
            "doppler",
            KeyPattern {
                name: "Doppler",
                regex: Regex::new(r"dp\.pt\.[A-Za-z0-9]{40,}").unwrap(),
                search_terms: vec![
                    "dp.pt.",
                    "DOPPLER_TOKEN",
                ],
                description: "Doppler Token",
                confidence: "high",
            },
        );

        // Private Keys (RSA, EC, OpenSSH, DSA)
        m.insert(
            "private_key",
            KeyPattern {
                name: "Private Key",
                regex: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
                search_terms: vec![
                    "BEGIN RSA PRIVATE KEY",
                    "BEGIN PRIVATE KEY",
                    "BEGIN OPENSSH PRIVATE KEY",
                ],
                description: "Private Key File",
                confidence: "high",
            },
        );

        m
    };
}

/// Gets a pattern by provider name.
///
/// # Arguments
/// * `name` - Provider identifier (e.g., "openai", "stripe_live")
///
/// # Returns
/// * `Option<&KeyPattern>` - The pattern if found
#[allow(dead_code)]
pub fn get_pattern(name: &str) -> Option<&KeyPattern> {
    PATTERNS.get(name)
}

/// Returns a list of all patterns for display purposes.
///
/// Returns tuples of (provider_name, pattern_format, example).
/// Used by the `patterns` CLI command.
pub fn get_all_patterns() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        // AI/LLM
        ("Anthropic", r"sk-ant-api03-...", "sk-ant-api03-xxxxx..."),
        ("OpenAI", r"sk-proj-... / T3BlbkFJ", "sk-proj-xxxxx..."),
        ("Google AI", r"AIza...", "AIzaSyDxxxxx..."),
        ("xAI Grok", r"xai-...", "xai-xxxxx..."),
        ("DeepSeek", r"sk-[hex]{32}", "sk-abc123..."),
        ("HuggingFace", r"hf_...", "hf_xxxxx..."),
        ("Replicate", r"r8_...", "r8_xxxxx..."),
        ("Perplexity", r"pplx-...", "pplx-xxxxx..."),
        ("Groq", r"gsk_...", "gsk_xxxxx..."),
        ("Fireworks", r"fw_...", "fw_xxxxx..."),
        // Cloud
        ("AWS", r"AKIA...", "AKIAIOSFODNN7..."),
        ("Azure", r"...(86 chars)==", "abc...=="),
        // Payment
        ("Stripe Live", r"sk_live_...", "sk_live_xxxxx..."),
        ("Square", r"sq0...", "sq0csp-xxxxx..."),
        ("PayPal", r"access_token$production$...", "access_token$..."),
        // Communication
        ("Twilio", r"SK[hex]{32}", "SKxxxxx..."),
        ("SendGrid", r"SG.....", "SG.xxxxx..."),
        ("Mailgun", r"key-...", "key-xxxxx..."),
        ("Mailchimp", r"...-us[N]", "abc...-us14"),
        // Developer
        ("GitHub", r"ghp_... / github_pat_...", "ghp_xxxxx..."),
        ("GitLab", r"glpat-...", "glpat-xxxxx..."),
        ("NPM", r"npm_...", "npm_xxxxx..."),
        ("PyPI", r"pypi-...", "pypi-xxxxx..."),
        // Social
        ("Slack Bot", r"xoxb-...", "xoxb-xxxxx..."),
        ("Discord", r"[MN].....", "MTIxxxxx..."),
        ("Telegram", r"[0-9]{10}:...", "123456:ABC..."),
        // Database
        ("MongoDB", r"mongodb+srv://...", "mongodb+srv://..."),
        ("PostgreSQL", r"postgres://...", "postgres://..."),
        ("Redis", r"redis://...", "redis://..."),
        // Other
        ("Firebase", r"AAAA...:...", "AAAA...:..."),
        ("Mapbox", r"pk.eyJ... / sk.eyJ...", "pk.eyJxxxxx..."),
        (
            "Sentry DSN",
            r"https://...@sentry.io/...",
            "https://xxx@...",
        ),
        (
            "Private Key",
            r"-----BEGIN PRIVATE KEY-----",
            "-----BEGIN...",
        ),
    ]
}

/// Extracts API keys from content using regex patterns.
///
/// # Arguments
/// * `content` - Text content to search for keys
/// * `provider` - Optional provider filter (None = search all)
///
/// # Returns
/// * `Vec<(provider_name, full_key, masked_key)>` - Found keys
///
/// Automatically filters out placeholder keys and duplicates.
pub fn extract_keys(content: &str, provider: Option<&str>) -> Vec<(String, String, String)> {
    let mut results = Vec::new();

    // Get patterns to check (single provider or all)
    let patterns_to_check: Vec<(&str, &KeyPattern)> = match provider {
        Some(p) => PATTERNS
            .get(p)
            .map(|pat| vec![(p, pat)])
            .unwrap_or_default(),
        None => PATTERNS.iter().map(|(k, v)| (*k, v)).collect(),
    };

    for (_provider_name, pattern) in patterns_to_check {
        for cap in pattern.regex.find_iter(content) {
            let key = cap.as_str().to_string();

            // Skip placeholders and examples
            if is_placeholder(&key) {
                continue;
            }

            // Skip short keys for low-confidence patterns
            if key.len() < 16 && pattern.confidence == "low" {
                continue;
            }

            let masked = mask_key(&key);
            results.push((pattern.name.to_string(), key, masked));
        }
    }

    // Deduplicate by key value
    results.sort_by(|a, b| a.1.cmp(&b.1));
    results.dedup_by(|a, b| a.1 == b.1);

    results
}

/// Checks if a key appears to be a placeholder or example.
///
/// Detects common placeholder patterns like "xxxx", "your_key_here", etc.
fn is_placeholder(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("xxxx")
        || lower.contains("yyyy")
        || lower.contains("zzzz")
        || lower.contains("your_")
        || lower.contains("your-")
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("insert")
        || lower.contains("_here")
        || lower.contains("<your")
        || lower.contains("test_")
        || lower.contains("dummy")
        || lower.contains("sample")
        || lower.contains("fake")
        || lower == "sk-EXAMPLE"
        || key
            .chars()
            .all(|c| c == 'x' || c == 'X' || c == '-' || c == '_')
}

/// Masks a key for safe display.
///
/// Shows first 10 and last 4 characters with "..." in between.
/// For short keys (<=16 chars), shows first 8 chars + "...".
fn mask_key(key: &str) -> String {
    let len = key.len();
    if len <= 16 {
        return format!("{}...", &key[..key.len().min(8)]);
    }
    let start = &key[..10];
    let end = &key[len - 4..];
    format!("{}...{}", start, end)
}
