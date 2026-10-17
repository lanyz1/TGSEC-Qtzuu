//! Scanner module for KeyHunter.
//!
//! This module provides the core scanning functionality that searches GitHub
//! for leaked API keys using the configured patterns and search terms. It
//! handles pagination, progress display, deduplication, and graceful
//! interruption via Ctrl+C.

use anyhow::Result;
use chrono::Utc;
use colored::*;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::github::{GitHubClient, SearchItem};
use crate::patterns::{self, PATTERNS};

/// Global flag for tracking Ctrl+C interruption.
///
/// When set to `true`, scanning loops will exit gracefully and save
/// any collected results before terminating.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Represents a discovered API key with full context.
///
/// Contains all metadata about where the key was found, including
/// repository information, file location, and optional verification status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFinding {
    /// Provider name (e.g., "openai", "anthropic", "stripe_live")
    pub provider: String,
    /// The full API key value
    pub key: String,
    /// Masked version of the key for safe display (e.g., "sk-...abc123")
    pub key_masked: String,
    /// Path to the file within the repository
    pub file_path: String,
    /// Direct URL to view the file on GitHub
    pub file_url: String,
    /// Full repository name (owner/repo)
    pub repo_name: String,
    /// URL to the repository on GitHub
    pub repo_url: String,
    /// Username or organization that owns the repository
    pub owner: String,
    /// URL to the owner's GitHub profile
    pub owner_url: String,
    /// Type of owner ("User" or "Organization")
    pub owner_type: String,
    /// ISO 8601 timestamp when the key was discovered
    pub found_at: String,
    /// Verification status: `Some(true)` = active, `Some(false)` = invalid, `None` = not verified
    pub verified: Option<bool>,
}

/// Main scanner that searches GitHub for leaked API keys.
///
/// The scanner uses the GitHub Code Search API to find potential key leaks,
/// extracts keys using regex patterns, and deduplicates results. It supports
/// graceful interruption via Ctrl+C, saving partial results.
pub struct Scanner {
    /// Application configuration
    config: Config,
    /// GitHub API client for making requests
    client: GitHubClient,
    /// Thread-safe collection of discovered keys
    findings: Arc<Mutex<Vec<KeyFinding>>>,
    /// Set of seen keys for deduplication
    seen_keys: Arc<Mutex<HashSet<String>>>,
    /// Whether to show verbose output
    verbose: bool,
}

impl Scanner {
    /// Creates a new Scanner instance.
    ///
    /// # Arguments
    /// * `config` - Application configuration including tokens and scan settings
    /// * `verbose` - Whether to show detailed progress output
    ///
    /// # Returns
    /// * `Result<Self>` - Configured scanner or error
    pub async fn new(config: Config, verbose: bool) -> Result<Self> {
        let client = GitHubClient::new(
            config.github.tokens.clone(),
            config.github.concurrency,
            config.github.delay_ms,
        )?;

        Ok(Self {
            config,
            client,
            findings: Arc::new(Mutex::new(Vec::new())),
            seen_keys: Arc::new(Mutex::new(HashSet::new())),
            verbose,
        })
    }

    /// Sets up a Ctrl+C handler for graceful interruption.
    ///
    /// When triggered, saves all collected findings to a JSON file
    /// with "_interrupted" suffix before exiting.
    fn setup_ctrlc_handler(&self) {
        let findings = Arc::clone(&self.findings);
        let output_path = self.config.output.output_path.clone();

        ctrlc::set_handler(move || {
            INTERRUPTED.store(true, Ordering::SeqCst);

            println!(
                "\n\n{} Interrupted! Saving collected results...",
                "⚠".yellow()
            );

            let findings_guard = findings.blocking_lock();
            if !findings_guard.is_empty() {
                let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
                let _ = fs::create_dir_all(&output_path);
                let json_path = format!("{}/findings_{}_interrupted.json", output_path, timestamp);

                if let Ok(mut file) = File::create(&json_path) {
                    if let Ok(json) = serde_json::to_string_pretty(&*findings_guard) {
                        let _ = file.write_all(json.as_bytes());
                        println!(
                            "{} Saved {} keys to: {}",
                            "💾".bright_green(),
                            findings_guard.len().to_string().bright_yellow(),
                            json_path.bright_blue()
                        );
                    }
                }
            } else {
                println!("{} No keys collected yet.", "ℹ".bright_blue());
            }

            std::process::exit(0);
        })
        .expect("Error setting Ctrl+C handler");
    }

    /// Checks if Ctrl+C was pressed.
    ///
    /// # Returns
    /// * `bool` - `true` if interrupted, `false` otherwise
    fn is_interrupted(&self) -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }

    /// Logs a message only if verbose mode is enabled.
    ///
    /// # Arguments
    /// * `msg` - Message to display
    fn log_verbose(&self, msg: &str) {
        if self.verbose {
            println!("{}", msg);
        }
    }

    /// Scans all configured providers for leaked keys.
    ///
    /// Iterates through each enabled provider's search terms, queries GitHub,
    /// and extracts matching API keys. Results are deduplicated and can be
    /// output in multiple formats.
    ///
    /// # Arguments
    /// * `provider_filter` - Provider to scan, or "all" for all enabled providers
    /// * `output_format` - Output format: "table", "json", or "csv"
    /// * `skip_output` - If true, suppresses output (for use with verification)
    ///
    /// # Returns
    /// * `Result<Vec<KeyFinding>>` - All discovered keys
    pub async fn scan_all(
        &self,
        provider_filter: &str,
        output_format: &str,
        skip_output: bool,
    ) -> Result<Vec<KeyFinding>> {
        self.setup_ctrlc_handler();

        let providers = if provider_filter == "all" {
            self.config.enabled_providers()
        } else {
            vec![provider_filter]
        };

        let mut total_queries = 0;
        for provider in &providers {
            if let Some(pattern) = PATTERNS.get(*provider) {
                total_queries += pattern.search_terms.len() * 2;
            }
        }

        println!(
            "{} Scanning {} provider(s), {} queries total",
            "🔍".bright_cyan(),
            providers.len().to_string().bright_yellow(),
            total_queries.to_string().bright_yellow()
        );
        println!(
            "{} Press Ctrl+C to stop and save results",
            "ℹ".bright_black()
        );

        if self.verbose {
            println!(
                "{} Verbose mode enabled - showing detailed logs\n",
                "📝".bright_magenta()
            );
        } else {
            println!();
        }

        let mut query_num = 0usize;

        'outer: for provider in &providers {
            if self.is_interrupted() {
                break;
            }

            if let Some(pattern) = PATTERNS.get(*provider) {
                println!(
                    "{} Provider: {} ({})",
                    "→".bright_blue(),
                    pattern.name.bright_green(),
                    pattern.description.bright_black()
                );

                for search_term in &pattern.search_terms {
                    if self.is_interrupted() {
                        break 'outer;
                    }

                    match self
                        .search_provider(provider, search_term, &mut query_num, total_queries)
                        .await
                    {
                        Ok(new_findings) => {
                            let mut findings = self.findings.lock().await;
                            let mut seen = self.seen_keys.lock().await;

                            for finding in new_findings {
                                if !seen.contains(&finding.key) {
                                    seen.insert(finding.key.clone());
                                    findings.push(finding);
                                }
                            }
                        }
                        Err(e) => {
                            println!(
                                "    {} Search failed: {}",
                                "⚠".yellow(),
                                e.to_string().bright_black()
                            );
                        }
                    }
                }

                let findings = self.findings.lock().await;
                println!(
                    "    {} Running total: {} unique keys\n",
                    "✓".green(),
                    findings.len().to_string().bright_yellow()
                );
            }
        }

        let findings = self.findings.lock().await;
        if !skip_output {
            self.output_results(&findings, output_format)?;
        }

        Ok(findings.clone())
    }

    /// Searches GitHub with a custom query string.
    ///
    /// Allows arbitrary GitHub code search queries instead of using
    /// predefined provider patterns. Useful for targeted searches.
    ///
    /// # Arguments
    /// * `query` - GitHub code search query string
    /// * `output_format` - Output format: "table", "json", or "csv"
    /// * `skip_output` - If true, suppresses output (for use with verification)
    ///
    /// # Returns
    /// * `Result<Vec<KeyFinding>>` - All discovered keys
    pub async fn search_custom(
        &self,
        query: &str,
        output_format: &str,
        skip_output: bool,
    ) -> Result<Vec<KeyFinding>> {
        self.setup_ctrlc_handler();

        println!(
            "{} Custom search: {}",
            "🔍".bright_cyan(),
            query.bright_yellow()
        );
        println!(
            "{} Press Ctrl+C to stop and save results",
            "ℹ".bright_black()
        );

        if self.verbose {
            println!(
                "{} Verbose mode enabled - showing detailed logs\n",
                "📝".bright_magenta()
            );
        } else {
            println!();
        }

        let new_findings = self.search_and_extract(query, None, true).await?;

        {
            let mut findings = self.findings.lock().await;
            let mut seen = self.seen_keys.lock().await;

            for finding in new_findings {
                if !seen.contains(&finding.key) {
                    seen.insert(finding.key.clone());
                    findings.push(finding);
                }
            }
        }

        let findings = self.findings.lock().await;
        if !skip_output {
            self.output_results(&findings, output_format)?;
        }

        Ok(findings.clone())
    }

    /// Searches for a specific provider's keys using its search terms.
    ///
    /// Executes two queries per search term: one plain search and one
    /// filtered to .env files specifically.
    ///
    /// # Arguments
    /// * `provider` - Provider identifier (e.g., "openai")
    /// * `search_term` - Search term from the provider's pattern
    /// * `query_num` - Current query number (for progress display)
    /// * `total_queries` - Total number of queries (for progress display)
    ///
    /// # Returns
    /// * `Result<Vec<KeyFinding>>` - Keys found for this search term
    async fn search_provider(
        &self,
        provider: &str,
        search_term: &str,
        query_num: &mut usize,
        total_queries: usize,
    ) -> Result<Vec<KeyFinding>> {
        let queries = vec![
            format!("{}", search_term),
            format!("{} filename:.env", search_term),
        ];

        let mut findings = Vec::new();

        for query in queries {
            if self.is_interrupted() {
                break;
            }

            *query_num += 1;
            println!(
                "    {} Query {}/{}: {}",
                "⟩".bright_black(),
                query_num.to_string().bright_cyan(),
                total_queries.to_string().bright_cyan(),
                query.bright_black()
            );
            println!("      {} Searching...", "⠋".bright_cyan());

            match self.search_and_extract(&query, Some(provider), true).await {
                Ok(results) => findings.extend(results),
                Err(e) => {
                    if !e.to_string().contains("Rate limited") {
                        self.log_verbose(&format!(
                            "        {} Error: {}",
                            "✗".red(),
                            e.to_string().bright_black()
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Executes a GitHub search and extracts keys from results.
    ///
    /// Handles pagination up to the configured max_results, processes each
    /// file to extract API keys, and optionally saves results in real-time
    /// for Ctrl+C safety.
    ///
    /// # Arguments
    /// * `query` - GitHub code search query
    /// * `provider` - Optional provider filter for key extraction
    /// * `save_realtime` - If true, saves findings immediately for Ctrl+C safety
    ///
    /// # Returns
    /// * `Result<Vec<KeyFinding>>` - Extracted keys from all pages
    async fn search_and_extract(
        &self,
        query: &str,
        provider: Option<&str>,
        save_realtime: bool,
    ) -> Result<Vec<KeyFinding>> {
        let mut findings = Vec::new();
        let mut page = 1u32;
        let per_page = 30u32;
        let max_pages = (self.config.scan.max_results as u32 / per_page).clamp(1, 10);

        let pb = if !self.verbose {
            let pb = ProgressBar::new(max_pages as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "      {spinner:.green} [{bar:25.cyan/blue}] {pos}/{len} pages | {msg}",
                    )
                    .unwrap()
                    .progress_chars("█▓░"),
            );
            Some(pb)
        } else {
            None
        };

        loop {
            if self.is_interrupted() || page > max_pages {
                if let Some(ref pb) = pb {
                    pb.set_message(if self.is_interrupted() {
                        "stopped"
                    } else {
                        "done"
                    });
                }
                break;
            }

            match self.client.search_code(query, page, per_page).await {
                Ok(response) => {
                    if response.items.is_empty() {
                        if let Some(ref pb) = pb {
                            pb.set_message("no more results");
                        }
                        self.log_verbose(&format!(
                            "      {} Page {} - no more results",
                            "·".bright_black(),
                            page
                        ));
                        break;
                    }

                    let item_count = response.items.len();

                    if self.verbose {
                        println!(
                            "      {} Page {}/{} - {} files to process",
                            "·".bright_black(),
                            page,
                            max_pages,
                            item_count.to_string().bright_cyan()
                        );
                    }

                    // Process items
                    let mut page_keys = 0;
                    for item in response.items {
                        if self.is_interrupted() {
                            break;
                        }

                        let item_path = item.path.clone();
                        let item_repo = item.repository.full_name.clone();
                        let item_url = item.html_url.clone();

                        match Self::process_item_verbose(&self.client, item, provider, self.verbose)
                            .await
                        {
                            Ok(item_findings) => {
                                let keys_found = item_findings.len();
                                if keys_found > 0 {
                                    page_keys += keys_found;

                                    if self.verbose {
                                        println!(
                                            "        {} {}/{} → {} key(s)",
                                            "✓".green(),
                                            item_repo.bright_blue(),
                                            item_path.bright_white(),
                                            keys_found.to_string().bright_yellow()
                                        );
                                        println!("          {}", item_url.bright_black());
                                    }

                                    // Save to shared state in real-time for Ctrl+C safety
                                    if save_realtime {
                                        let mut shared_findings = self.findings.lock().await;
                                        let mut shared_seen = self.seen_keys.lock().await;
                                        for finding in &item_findings {
                                            if !shared_seen.contains(&finding.key) {
                                                shared_seen.insert(finding.key.clone());
                                                shared_findings.push(finding.clone());
                                            }
                                        }
                                    }

                                    findings.extend(item_findings);
                                } else if self.verbose {
                                    println!(
                                        "        {} {}/{} → no keys",
                                        "·".bright_black(),
                                        item_repo.bright_black(),
                                        item_path.bright_black()
                                    );
                                }
                            }
                            Err(e) => {
                                if self.verbose {
                                    println!(
                                        "        {} {}/{} → error: {}",
                                        "✗".red(),
                                        item_repo.bright_black(),
                                        item_path.bright_black(),
                                        e.to_string().bright_red()
                                    );
                                }
                            }
                        }
                    }

                    if let Some(ref pb) = pb {
                        pb.set_message(format!("{} keys", page_keys));
                        pb.inc(1);
                    }

                    if self.verbose && page_keys > 0 {
                        println!(
                            "      {} Page {} complete: {} keys found",
                            "↳".bright_black(),
                            page,
                            page_keys.to_string().bright_green()
                        );
                    }

                    page += 1;
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    if err_msg.contains("Rate limited") {
                        let msg = format!("      {} Rate limited! Waiting 60s...", "⚠".yellow());
                        if let Some(ref pb) = pb {
                            pb.println(&msg);
                        } else {
                            println!("{}", msg);
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                        continue;
                    }
                    if let Some(ref pb) = pb {
                        pb.set_message("error");
                    }
                    self.log_verbose(&format!(
                        "      {} Error: {}",
                        "✗".red(),
                        err_msg.bright_red()
                    ));
                    break;
                }
            }
        }

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }

        if !findings.is_empty() {
            println!(
                "      {} {} keys found",
                "↳".bright_black(),
                findings.len().to_string().bright_green()
            );
        }

        Ok(findings)
    }

    /// Processes a single search result item to extract keys.
    ///
    /// Fetches the raw file content from GitHub and applies regex patterns
    /// to extract any API keys present.
    ///
    /// # Arguments
    /// * `client` - GitHub client for fetching file content
    /// * `item` - Search result item containing file metadata
    /// * `provider` - Optional provider to filter extraction patterns
    /// * `_verbose` - Verbose flag (currently unused)
    ///
    /// # Returns
    /// * `Result<Vec<KeyFinding>>` - Keys extracted from the file
    async fn process_item_verbose(
        client: &GitHubClient,
        item: SearchItem,
        provider: Option<&str>,
        _verbose: bool,
    ) -> Result<Vec<KeyFinding>> {
        let mut findings = Vec::new();

        let content = match client.get_raw_content(&item.html_url).await {
            Ok(c) => c,
            Err(_) => item
                .text_matches
                .iter()
                .map(|m| m.fragment.clone())
                .collect::<Vec<_>>()
                .join("\n"),
        };

        let extracted = patterns::extract_keys(&content, provider);

        for (prov, key, masked) in extracted {
            findings.push(KeyFinding {
                provider: prov,
                key: key.clone(),
                key_masked: masked,
                file_path: item.path.clone(),
                file_url: item.html_url.clone(),
                repo_name: item.repository.full_name.clone(),
                repo_url: item.repository.html_url.clone(),
                owner: item.repository.owner.login.clone(),
                owner_url: item.repository.owner.html_url.clone(),
                owner_type: item.repository.owner.owner_type.clone(),
                found_at: Utc::now().to_rfc3339(),
                verified: None,
            });
        }

        Ok(findings)
    }

    /// Outputs scan results in the specified format.
    ///
    /// Displays a summary and the findings in the requested format,
    /// optionally saving to a file if configured.
    ///
    /// # Arguments
    /// * `findings` - Collection of discovered keys
    /// * `format` - Output format: "table", "json", or "csv"
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn output_results(&self, findings: &[KeyFinding], format: &str) -> Result<()> {
        println!("\n{}", "═".repeat(80).bright_black());
        println!(
            "{} Found {} potential leaked keys\n",
            "🔑".bright_green(),
            findings.len().to_string().bright_yellow().bold()
        );

        if findings.is_empty() {
            println!("{}", "No keys found.".bright_black());
            return Ok(());
        }

        match format {
            "json" => self.output_json(findings)?,
            "csv" => self.output_csv(findings)?,
            _ => self.output_table(findings)?,
        }

        if self.config.output.save_to_file {
            self.save_results(findings)?;
        }

        Ok(())
    }

    /// Displays findings as a formatted ASCII table.
    ///
    /// Shows up to 50 results in the table view, with a detailed list
    /// of the first 20 findings below. Uses color coding for verified status.
    ///
    /// # Arguments
    /// * `findings` - Collection of discovered keys
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn output_table(&self, findings: &[KeyFinding]) -> Result<()> {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec![
                Cell::new("#").fg(Color::DarkGrey),
                Cell::new("Provider").fg(Color::Cyan),
                Cell::new("Key").fg(Color::Cyan),
                Cell::new("Repository").fg(Color::Cyan),
                Cell::new("Owner").fg(Color::Cyan),
                Cell::new("File").fg(Color::Cyan),
            ]);

        for (i, finding) in findings.iter().enumerate().take(50) {
            let status_color = match finding.verified {
                Some(true) => Color::Red,
                Some(false) => Color::Green,
                None => Color::Yellow,
            };

            table.add_row(vec![
                Cell::new(i + 1).fg(Color::DarkGrey),
                Cell::new(&finding.provider).fg(Color::Magenta),
                Cell::new(&finding.key_masked).fg(status_color),
                Cell::new(truncate(&finding.repo_name, 25)).fg(Color::Blue),
                Cell::new(&finding.owner).fg(Color::Green),
                Cell::new(truncate(&finding.file_path, 20)).fg(Color::White),
            ]);
        }

        println!("{table}");

        if findings.len() > 50 {
            println!(
                "\n{} Showing first 50 of {} results. Check saved file for all.",
                "ℹ".bright_blue(),
                findings.len()
            );
        }

        println!("\n{}", "Detailed Findings:".bright_white().underline());
        for (i, finding) in findings.iter().enumerate().take(20) {
            println!(
                "\n{}. {} {}",
                (i + 1).to_string().bright_black(),
                finding.provider.bright_magenta(),
                finding.key_masked.bright_yellow()
            );
            println!(
                "   {} {}",
                "URL:".bright_black(),
                finding.file_url.bright_blue()
            );
            println!(
                "   {} {} ({})",
                "Owner:".bright_black(),
                finding.owner.bright_green(),
                finding.owner_type
            );
        }

        Ok(())
    }

    /// Outputs findings as pretty-printed JSON.
    ///
    /// # Arguments
    /// * `findings` - Collection of discovered keys
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn output_json(&self, findings: &[KeyFinding]) -> Result<()> {
        let json = serde_json::to_string_pretty(findings)?;
        println!("{}", json);
        Ok(())
    }

    /// Outputs findings as CSV format.
    ///
    /// Includes header row with columns: provider, key_masked, key_full,
    /// repo, owner, file_path, file_url.
    ///
    /// # Arguments
    /// * `findings` - Collection of discovered keys
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn output_csv(&self, findings: &[KeyFinding]) -> Result<()> {
        println!("provider,key_masked,key_full,repo,owner,file_path,file_url");
        for f in findings {
            println!(
                "{},{},{},{},{},{},{}",
                f.provider, f.key_masked, f.key, f.repo_name, f.owner, f.file_path, f.file_url
            );
        }
        Ok(())
    }

    /// Saves findings to a JSON file with timestamp.
    ///
    /// Creates the output directory if it doesn't exist and writes
    /// all findings as pretty-printed JSON.
    ///
    /// # Arguments
    /// * `findings` - Collection of discovered keys
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    fn save_results(&self, findings: &[KeyFinding]) -> Result<()> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let dir = &self.config.output.output_path;
        fs::create_dir_all(dir)?;

        let json_path = format!("{}/findings_{}.json", dir, timestamp);
        let mut file = File::create(&json_path)?;
        file.write_all(serde_json::to_string_pretty(findings)?.as_bytes())?;

        println!(
            "\n{} Results saved to: {}",
            "💾".bright_green(),
            json_path.bright_blue()
        );

        Ok(())
    }
}

/// Truncates a string to the specified maximum length.
///
/// If the string exceeds `max` characters, it is truncated from the
/// beginning with "..." prefix to show the end of the string.
///
/// # Arguments
/// * `s` - String to truncate
/// * `max` - Maximum length including "..." prefix
///
/// # Returns
/// * `String` - Original string if short enough, or truncated version
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - max + 3..])
    }
}
