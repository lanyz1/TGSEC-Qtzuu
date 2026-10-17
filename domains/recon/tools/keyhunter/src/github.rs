//! GitHub API client for KeyHunter.
//!
//! Provides authenticated access to GitHub's code search API with
//! support for token rotation, rate limiting, and concurrent requests.

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::{header, Client};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

/// GitHub API client with multi-token support.
///
/// Manages multiple HTTP clients (one per token) and rotates between them
/// to maximize API throughput and avoid rate limits.
#[derive(Clone)]
pub struct GitHubClient {
    /// HTTP clients, one per GitHub token
    clients: Vec<Client>,
    /// Counter for round-robin token selection
    current_token: Arc<AtomicUsize>,
    /// Semaphore for limiting concurrent requests
    semaphore: Arc<Semaphore>,
    /// Delay between requests in milliseconds
    delay_ms: u64,
}

/// Response from GitHub code search API.
#[derive(Debug, Deserialize)]
pub struct SearchResponse {
    /// Total number of matching results (may exceed returned items)
    #[allow(dead_code)]
    pub total_count: u64,
    /// Whether results are incomplete due to timeout
    #[allow(dead_code)]
    pub incomplete_results: bool,
    /// List of matching code items
    pub items: Vec<SearchItem>,
}

/// Individual search result item.
///
/// Represents a file that matched the search query.
#[derive(Debug, Deserialize, Clone)]
pub struct SearchItem {
    /// Filename without path
    #[allow(dead_code)]
    pub name: String,
    /// Full path within repository
    pub path: String,
    /// Git SHA of the file
    #[allow(dead_code)]
    pub sha: String,
    /// API URL for file contents
    #[allow(dead_code)]
    pub url: String,
    /// Web URL to view file on GitHub
    pub html_url: String,
    /// Repository containing the file
    pub repository: Repository,
    /// Search relevance score
    #[allow(dead_code)]
    pub score: f64,
    /// Text fragments showing match context
    #[serde(default)]
    pub text_matches: Vec<TextMatch>,
}

/// Repository information from search results.
#[derive(Debug, Deserialize, Clone)]
pub struct Repository {
    /// Unique repository ID
    #[allow(dead_code)]
    pub id: u64,
    /// Repository name (without owner)
    #[allow(dead_code)]
    pub name: String,
    /// Full name (owner/repo)
    pub full_name: String,
    /// Web URL to repository
    pub html_url: String,
    /// Repository owner information
    pub owner: Owner,
}

/// Repository owner information.
#[derive(Debug, Deserialize, Clone)]
pub struct Owner {
    /// Username or organization name
    pub login: String,
    /// Unique user/org ID
    #[allow(dead_code)]
    pub id: u64,
    /// Profile URL
    pub html_url: String,
    /// "User" or "Organization"
    #[serde(rename = "type")]
    pub owner_type: String,
}

/// Text match fragment from search results.
///
/// Contains the actual matched text with surrounding context.
#[derive(Debug, Deserialize, Clone)]
pub struct TextMatch {
    /// API URL for the matched object
    #[allow(dead_code)]
    pub object_url: String,
    /// Type of matched object
    #[allow(dead_code)]
    pub object_type: String,
    /// Property that matched (usually "content")
    #[allow(dead_code)]
    pub property: String,
    /// Text fragment containing the match
    pub fragment: String,
    /// Specific match locations within fragment
    #[allow(dead_code)]
    pub matches: Vec<Match>,
}

/// Individual match location within a text fragment.
#[derive(Debug, Deserialize, Clone)]
pub struct Match {
    /// The matched text
    #[allow(dead_code)]
    pub text: String,
    /// Start and end indices within fragment
    #[allow(dead_code)]
    pub indices: Vec<u64>,
}

/// File content response from GitHub API.
#[derive(Debug, Deserialize)]
pub struct FileContent {
    /// File content (may be base64 encoded)
    pub content: String,
    /// Encoding type ("base64" or "utf-8")
    pub encoding: String,
}

impl GitHubClient {
    /// Creates a new GitHub client with the specified tokens.
    ///
    /// # Arguments
    /// * `tokens` - List of GitHub Personal Access Tokens
    /// * `concurrency` - Maximum concurrent requests
    /// * `delay_ms` - Delay between requests in milliseconds
    ///
    /// # Returns
    /// * `Result<GitHubClient>` - Configured client or error
    pub fn new(tokens: Vec<String>, concurrency: usize, delay_ms: u64) -> Result<Self> {
        let mut clients = Vec::new();

        // Create one HTTP client per token
        for token in &tokens {
            let mut headers = header::HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!("Bearer {}", token))?,
            );
            // Request text-match data for search context
            headers.insert(
                header::ACCEPT,
                header::HeaderValue::from_static("application/vnd.github.text-match+json"),
            );
            headers.insert(
                header::USER_AGENT,
                header::HeaderValue::from_static("keyhunter/0.1"),
            );

            let client = Client::builder()
                .default_headers(headers)
                .timeout(Duration::from_secs(30))
                .build()?;

            clients.push(client);
        }

        Ok(Self {
            clients,
            current_token: Arc::new(AtomicUsize::new(0)),
            semaphore: Arc::new(Semaphore::new(concurrency)),
            delay_ms,
        })
    }

    /// Gets the next client in round-robin rotation.
    ///
    /// Atomically increments the counter and returns the corresponding client.
    fn get_client(&self) -> &Client {
        let idx = self.current_token.fetch_add(1, Ordering::SeqCst) % self.clients.len();
        &self.clients[idx]
    }

    /// Searches GitHub code with the given query.
    ///
    /// # Arguments
    /// * `query` - GitHub code search query string
    /// * `page` - Page number (1-indexed)
    /// * `per_page` - Results per page (max 100)
    ///
    /// # Returns
    /// * `Result<SearchResponse>` - Search results or error
    ///
    /// # Errors
    /// * Rate limited (HTTP 403)
    /// * Invalid query (HTTP 422)
    /// * Network or API errors
    pub async fn search_code(
        &self,
        query: &str,
        page: u32,
        per_page: u32,
    ) -> Result<SearchResponse> {
        // Acquire semaphore permit for concurrency control
        let _permit = self.semaphore.acquire().await?;

        let client = self.get_client();
        let url = format!(
            "https://api.github.com/search/code?q={}&page={}&per_page={}",
            urlencoding::encode(query),
            page,
            per_page
        );

        // Delay to respect rate limits
        sleep(Duration::from_millis(self.delay_ms)).await;

        let response = client
            .get(&url)
            .send()
            .await
            .context("Failed to send search request")?;

        let status = response.status();

        // Handle rate limiting (403)
        if status == 403 {
            let headers = response.headers().clone();
            let wait_time = headers
                .get("X-RateLimit-Reset")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|reset| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if reset > now {
                        reset - now
                    } else {
                        60
                    }
                })
                .unwrap_or(60);

            return Err(anyhow::anyhow!(
                "Rate limited. Retry after {} seconds",
                wait_time
            ));
        }

        // Handle invalid query (422)
        if status == 422 {
            return Err(anyhow::anyhow!("Query validation failed"));
        }

        // Handle other errors
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("GitHub API error {}: {}", status, text));
        }

        let text = response.text().await?;

        // Parse response with fallback for malformed text_matches
        let result: SearchResponse = match serde_json::from_str(&text) {
            Ok(r) => r,
            Err(_) => {
                // Fallback: parse manually without text_matches
                let v: serde_json::Value = serde_json::from_str(&text)
                    .context("Failed to parse GitHub response as JSON")?;

                SearchResponse {
                    total_count: v["total_count"].as_u64().unwrap_or(0),
                    incomplete_results: v["incomplete_results"].as_bool().unwrap_or(false),
                    items: v["items"]
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| {
                                    Some(SearchItem {
                                        name: item["name"].as_str()?.to_string(),
                                        path: item["path"].as_str()?.to_string(),
                                        sha: item["sha"].as_str()?.to_string(),
                                        url: item["url"].as_str()?.to_string(),
                                        html_url: item["html_url"].as_str()?.to_string(),
                                        repository: Repository {
                                            id: item["repository"]["id"].as_u64()?,
                                            name: item["repository"]["name"].as_str()?.to_string(),
                                            full_name: item["repository"]["full_name"]
                                                .as_str()?
                                                .to_string(),
                                            html_url: item["repository"]["html_url"]
                                                .as_str()?
                                                .to_string(),
                                            owner: Owner {
                                                login: item["repository"]["owner"]["login"]
                                                    .as_str()?
                                                    .to_string(),
                                                id: item["repository"]["owner"]["id"].as_u64()?,
                                                html_url: item["repository"]["owner"]["html_url"]
                                                    .as_str()?
                                                    .to_string(),
                                                owner_type: item["repository"]["owner"]["type"]
                                                    .as_str()?
                                                    .to_string(),
                                            },
                                        },
                                        score: item["score"].as_f64().unwrap_or(0.0),
                                        text_matches: vec![], // Skip on fallback
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            }
        };

        Ok(result)
    }

    /// Fetches raw file content from GitHub.
    ///
    /// Converts the HTML URL to raw.githubusercontent.com format.
    ///
    /// # Arguments
    /// * `html_url` - GitHub web URL to the file
    ///
    /// # Returns
    /// * `Result<String>` - Raw file content or error
    pub async fn get_raw_content(&self, html_url: &str) -> Result<String> {
        let _permit = self.semaphore.acquire().await?;

        // Convert github.com URL to raw.githubusercontent.com
        let raw_url = html_url
            .replace("github.com", "raw.githubusercontent.com")
            .replace("/blob/", "/");

        let client = self.get_client();
        sleep(Duration::from_millis(self.delay_ms)).await;

        let response = client
            .get(&raw_url)
            .send()
            .await
            .context("Failed to fetch raw content")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch raw file: {}",
                response.status()
            ));
        }

        Ok(response.text().await?)
    }

    /// Fetches file content via GitHub API (with base64 decoding).
    ///
    /// # Arguments
    /// * `url` - GitHub API URL for file contents
    ///
    /// # Returns
    /// * `Result<String>` - Decoded file content or error
    #[allow(dead_code)]
    pub async fn get_file_content(&self, url: &str) -> Result<String> {
        let _permit = self.semaphore.acquire().await?;

        let client = self.get_client();
        sleep(Duration::from_millis(self.delay_ms)).await;

        let response = client
            .get(url)
            .send()
            .await
            .context("Failed to fetch file content")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch file: {}",
                response.status()
            ));
        }

        let file: FileContent = response.json().await?;

        // Decode base64 content if needed
        if file.encoding == "base64" {
            let decoded =
                base64::engine::general_purpose::STANDARD.decode(file.content.replace('\n', ""))?;
            Ok(String::from_utf8_lossy(&decoded).to_string())
        } else {
            Ok(file.content)
        }
    }
}
