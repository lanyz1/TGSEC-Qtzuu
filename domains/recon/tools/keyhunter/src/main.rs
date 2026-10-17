//! # KeyHunter
//!
//! A fast GitHub API key leak scanner written in Rust.
//!
//! KeyHunter searches GitHub for exposed API keys from 45+ providers including
//! OpenAI, Anthropic, AWS, Stripe, and more. It can verify if found keys are
//! still active.
//!
//! ## Usage
//!
//! ```bash
//! # Scan for all providers
//! keyhunter scan
//!
//! # Scan specific provider
//! keyhunter scan -p openai
//!
//! # Verify found keys
//! keyhunter verify -i results/findings.json
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use std::path::PathBuf;

mod config;
mod github;
mod patterns;
mod scanner;
mod verifier;

use config::Config;
use scanner::Scanner;
use verifier::Verifier;

/// Command-line interface structure for KeyHunter.
///
/// Parses command-line arguments and dispatches to appropriate subcommands.
#[derive(Parser)]
#[command(name = "keyhunter")]
#[command(about = "Fast GitHub API key leak scanner", long_about = None)]
#[command(version)]
struct Cli {
    /// The subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available CLI subcommands.
///
/// - `Scan`: Search GitHub for leaked API keys
/// - `Verify`: Test if found keys are still active
/// - `Patterns`: Display all supported provider patterns
#[derive(Subcommand)]
enum Commands {
    /// Scan GitHub for leaked API keys
    Scan {
        /// Config file path
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,

        /// Provider to scan (or "all")
        #[arg(short, long, default_value = "all")]
        provider: String,

        /// Custom search query
        #[arg(short, long)]
        query: Option<String>,

        /// Output format: table, json, csv (overrides config.toml)
        #[arg(short, long)]
        output: Option<String>,

        /// Verbose mode - show detailed logs (files, URLs, etc.)
        #[arg(short, long)]
        verbose: bool,

        /// Only save verified (active) keys - verifies first 50 by default
        #[arg(short = 'V', long)]
        verified_only: bool,

        /// When using --verified-only, verify all keys (caution: may hit rate limits)
        #[arg(long)]
        verify_all: bool,
    },

    /// Verify if found keys are still active
    Verify {
        /// Input file with keys to verify (JSON from scan)
        #[arg(short, long)]
        input: PathBuf,

        /// Only verify keys from this provider
        #[arg(short, long)]
        provider: Option<String>,

        /// Limit number of keys to verify
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Verify all keys (ignore limit)
        #[arg(short, long)]
        all: bool,

        /// Concurrent verification requests
        #[arg(short, long, default_value = "5")]
        concurrent: usize,

        /// Output file for results
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show supported providers and patterns
    Patterns,
}

/// Application entry point.
///
/// Parses CLI arguments and executes the appropriate command:
/// - Scan: Searches GitHub for leaked keys
/// - Verify: Tests if keys are active
/// - Patterns: Shows supported providers
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Commands::Scan {
            config,
            provider,
            query,
            output,
            verbose,
            verified_only,
            verify_all,
        } => {
            // Load configuration from TOML file
            let cfg = Config::load(&config).context("Failed to load config file")?;

            // Use CLI output format if specified, otherwise use config format
            let output_format = output.unwrap_or_else(|| cfg.output.format.clone());

            // Initialize scanner with config and verbose mode
            let scanner = Scanner::new(cfg, verbose).await?;

            // Skip normal output if verified_only (we'll output only active keys later)
            let skip_output = verified_only;

            // Execute scan - either custom query or provider-based
            let findings = if let Some(q) = query {
                scanner.search_custom(&q, &output_format, skip_output).await?
            } else {
                scanner.scan_all(&provider, &output_format, skip_output).await?
            };

            // If --verified-only flag, verify and filter to active keys only
            if verified_only {
                println!("\n{} Verifying keys...\n", "🔍".bright_cyan());

                let verifier = Verifier::new(5)?;
                let limit = if verify_all { None } else { Some(50) };

                verifier.verify_and_filter(findings, limit, &output_format).await?;
            }
        }
        Commands::Verify {
            input,
            provider,
            limit,
            all,
            concurrent,
            output,
        } => {
            // Initialize verifier with concurrency setting
            let verifier = Verifier::new(concurrent)?;

            // Apply limit unless --all flag is set
            let limit_opt = if all { None } else { Some(limit) };
            let output_path = output.as_ref().map(|p| p.to_string_lossy().to_string());

            // Run verification on input file
            verifier
                .verify_file(
                    &input.to_string_lossy(),
                    provider.as_deref(),
                    limit_opt,
                    output_path.as_deref(),
                )
                .await?;
        }
        Commands::Patterns => {
            show_patterns();
        }
    }

    Ok(())
}

/// Prints the ASCII art banner and application title.
fn print_banner() {
    println!(
        "{}",
        r#"
    ╦╔═╔═╗╦ ╦╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
    ╠╩╗║╣ ╚╦╝╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ╩ ╩╚═╝ ╩ ╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═
    "#
        .bright_cyan()
    );
    println!("    {}", "Fast GitHub API Key Scanner".bright_white());
    println!("    {}\n", "────────────────────────────".bright_black());
}

/// Displays a table of all supported providers and their regex patterns.
///
/// Shows provider name, pattern format, and example key format.
fn show_patterns() {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Provider").fg(Color::Cyan),
            Cell::new("Pattern").fg(Color::Cyan),
            Cell::new("Example").fg(Color::Cyan),
        ]);

    for (name, pattern, example) in patterns::get_all_patterns() {
        table.add_row(vec![
            Cell::new(name).fg(Color::Green),
            Cell::new(pattern).fg(Color::Yellow),
            Cell::new(example).fg(Color::White),
        ]);
    }

    println!("{table}");
}
