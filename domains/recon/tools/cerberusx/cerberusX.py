import requests
import concurrent.futures
import argparse
import webbrowser
from urllib.parse import urlparse, urljoin, parse_qs, quote
from datetime import datetime
import os
import hashlib
import json
import socket
import time
import threading
from pyfiglet import Figlet
from rich.console import Console
from colorama import Fore, init
import urllib3
import random
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
from collections import deque
from urllib.robotparser import RobotFileParser

# Disabling SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)
console = Console()

# Banner_One
PURPLE = '\033[0;35m'
END = "\033[0m"

banner = f"""
  {PURPLE}
███╗   ██╗ █████╗ ███████╗██╗██╗  ██╗███████╗███████╗                    
████╗  ██║██╔══██╗╚══███╔╝██║╚██╗██╔╝██╔════╝██╔════╝                    
██╔██╗ ██║███████║  ███╔╝ ██║ ╚███╔╝ ███████╗███████╗                    
██║╚██╗██║██╔══██║ ███╔╝  ██║ ██╔██╗ ╚════██║╚════██║                    
██║ ╚████║██║  ██║███████╗██║██╔╝ ██╗███████║███████║                    
╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝                    
                                                                         
 ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗██╗  ██╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝╚██╗██╔╝
██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗ ╚███╔╝ 
██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║ ██╔██╗ 
╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║██╔╝ ██╗
 ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
{Fore.YELLOW}
╔═══════════════════════════════════════════════════════════╗
║      Professional CerberusX Tool - Secure & Ethical       ║
║  Warning: Use --strict-ssl for secure mode (default: off) ║
╚═══════════════════════════════════════════════════════════╝
{Fore.RESET}"""

print(banner)

# Random User-Agent List (Improved)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36"
]

# List of common parameters for XSS testing
COMMON_PARAMS = ['q', 'search', 'id', 'name', 'user', 'query', 'keyword']

# Advanced (improved) payloads
DEFAULT_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<svg onload=alert(1)>',
    'javascript:alert`1`',
    '{{7*7}}',
    "'-alert(1)-'",
    '<img src=x oneonerror=alert(1)>',
]

# Initialize JSON logging (overridable via --output)
LOG_FILE = 'xss_scan_results.json'
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
LOG_HASH_FILE = 'xss_scan_results.sha256'

# Session setup to increase speed
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
session.mount('http://', HTTPAdapter(max_retries=retries))
session.mount('https://', HTTPAdapter(max_retries=retries))

# Cache for external scripts (thread-safe)
SCRIPT_CACHE = {}
cache_lock = threading.Lock()

# FIX: log writes happen from many worker threads concurrently; without a
# lock, the read-modify-write in SecureWriteLog can lose entries or corrupt
# the JSON file. One lock around the whole read+write cycle fixes this.
log_lock = threading.Lock()


def SecureWriteLog(message):
    """Save results as JSON with improved error length (thread-safe)"""
    with log_lock:
        try:
            existing_data = []
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
                with open(LOG_FILE, 'r') as f:
                    try:
                        existing_data = json.load(f)
                    except json.JSONDecodeError:
                        existing_data = []

            new_entry = {
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "message": message,
                "type": "XSS" if "XSS found" in message else "LOG"
            }
            existing_data.append(new_entry)

            if len(json.dumps(existing_data)) > MAX_LOG_SIZE:
                RotateLogFile()
                existing_data = [new_entry]

            with open(LOG_FILE, 'w') as f:
                json.dump(existing_data, f, indent=4)

            UpdateLogHash()
        except Exception as e:
            print(Fore.RED + f"Logging error: {str(e)[:200]}")


def RotateLogFile():
    """JSON file rotation"""
    try:
        if os.path.exists(LOG_FILE):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            os.rename(LOG_FILE, f"xss_scan_results_{timestamp}.json")
    except Exception:
        pass


def UpdateLogHash():
    """Calculating a hash for a JSON file"""
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            with open(LOG_HASH_FILE, 'w') as f:
                f.write(file_hash)
    except Exception:
        pass


def IsResolvable(hostname, timeout=3):
    """NEW: quick DNS check so we don't waste time scanning subdomains that don't exist."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(None)


def GetSubdomains(domain):
    """Get subdomains with fallback to alternative sources"""
    subdomains = set()

    try:
        if '://' in domain:
            domain = domain.split('://')[1]
        domain = domain.split('/')[0]
        parts = domain.split('.')
        main_domain = '.'.join(parts[-2:]) if len(parts) > 1 else domain

        try:
            response = session.get(
                f"https://crt.sh/?q=%.{main_domain}&output=json",
                timeout=10,
                headers={'User-Agent': random.choice(USER_AGENTS)}
            )
            data = response.json()
            subdomains.update(
                item['name_value'].lower().strip()
                for item in data
                if '*' not in item['name_value'] and not item['name_value'].startswith('*.')
            )
        except Exception as e:
            SecureWriteLog(f"crt.sh failed: {str(e)[:200]}")

        if not subdomains:
            try:
                response = session.get(
                    f"http://web.archive.org/cdx/search/cdx?url=*.{main_domain}/*&output=json&fl=original&collapse=urlkey",
                    timeout=10,
                    headers={'User-Agent': random.choice(USER_AGENTS)}
                )
                if response.status_code == 200:
                    urls = response.json()
                    for url in urls[1:]:
                        parsed = urlparse(url[0])
                        if parsed.netloc.endswith(main_domain):
                            subdomains.add(parsed.netloc.split('.')[0])
            except Exception as e:
                SecureWriteLog(f"Wayback Machine failed: {str(e)[:200]}")

        return sorted(subdomains) if subdomains else ['www', 'mail', 'admin', 'api']

    except Exception as e:
        SecureWriteLog(f"Subdomain discovery failed: {str(e)[:200]}")
        return ['www', 'mail', 'admin', 'api']


def DiscoverParameters(target_url):
    """Auto-discover URL parameters and HTML forms with better recognition capabilities"""
    params = set(COMMON_PARAMS)

    try:
        parsed = urlparse(target_url)
        if parsed.query:
            # FIX: the old `q.split('=')[0]` approach mishandled params with
            # no value or multiple '=' signs. parse_qs handles this correctly.
            params.update(parse_qs(parsed.query).keys())

        response = session.get(
            target_url,
            timeout=10,
            verify=args.strict_ssl,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        )
        soup = BeautifulSoup(response.text, 'html.parser')

        # Discover form parameters
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                if input_tag.get('name'):
                    params.add(input_tag['name'])

        # JavaScript parameter discovery (improved)
        for script in soup.find_all('script'):
            script_text = (script.string or '').lower()
            # Detect AJAX parameters
            params.update(re.findall(r'\.(?:get|post|put|delete|fetch)\(["\']([^"\']+)', script_text))
            # Detecting URL hash parameters
            if 'location.hash' in script_text:
                params.update(re.findall(r'location\.hash\.split\(["\']([^"\']+)', script_text))
            # Detection of new parameters
            if 'window.location.search' in script_text:
                params.update(re.findall(r'window\.location\.search\.split\(["\']([^"\']+)', script_text))

    except Exception as e:
        SecureWriteLog(f"Parameter discovery failed: {str(e)[:200]}")

    return list(params)[:100]  # Limit to prevent overload


def DetectXssType(response, payload, target_url):
    """Detecting XSS type (Reflected or Stored)"""
    soup = BeautifulSoup(response.text, 'html.parser')

    # Checking whether the payload is saved in subsequent responses
    try:
        follow_up = session.get(
            target_url,
            timeout=10,
            verify=args.strict_ssl,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        )
        if payload in follow_up.text:
            return "Stored (Persistent)"
    except Exception:
        pass

    # Regular review
    for tag in soup.find_all():
        if payload in str(tag):
            return "Stored (Potential)"

    return "Reflected"


def AssessConfidence(response_text, payload):
    """
    NEW: rough confidence scoring for a reflected payload to cut down on
    false positives. A raw string match alone doesn't tell you whether the
    payload actually landed somewhere executable.
    """
    if payload not in response_text:
        return None

    idx = response_text.find(payload)
    window = response_text[max(0, idx - 60):idx + len(payload) + 60]

    # If an HTML-encoded version shows up right around the same spot, the
    # payload is very likely neutralized rather than exploitable.
    encoded = payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    if encoded in window and payload not in window.replace(encoded, ''):
        return "Low"

    if '<script' in window.lower() or re.search(r'on\w+\s*=\s*["\']?[^"\'>]*' + re.escape(payload[:10]), window, re.IGNORECASE):
        return "High"

    return "Medium"


def CheckDomXss(target_url, payload):
    """Advanced DOM-Based XSS inspection with dangerous pattern detection"""
    try:
        response = session.get(
            target_url,
            timeout=15,  # Increased time for heavy pages
            verify=args.strict_ssl,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        )

        # Dangerous Patterns in JavaScript (Improved)
        dangerous_patterns = [
            r'eval\(.*\)',
            r'document\.write\(.*\)',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'setTimeout\(.*\)',
            r'setInterval\(.*\)',
            r'location\.hash',
            r'window\.name',
            r'document\.cookie',
            r'new Function\(.*\)',
            r'\.replaceWith\(.*\)',
            r'\.append\(.*\)',
            r'\.insertAdjacentHTML\(',
            r'\.replaceState\(',
            r'\.parseFromString\(',
            r'\.execScript\('
        ]

        # Checking inline scripts
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup.find_all('script'):
            script_text = script.string or ''
            for pattern in dangerous_patterns:
                if re.search(pattern, script_text, re.IGNORECASE):
                    return True

        # Check for HTML events
        for tag in soup.find_all():
            for attr in tag.attrs:
                if attr.lower().startswith('on') and tag[attr]:
                    return True

        # Checking external scripts using cache (thread-safe)
        external_scripts = [script['src'] for script in soup.find_all('script', src=True)]
        for script_url in external_scripts:
            try:
                full_url = urljoin(target_url, script_url)
                with cache_lock:
                    cached = SCRIPT_CACHE.get(full_url)
                if cached is None:
                    script_response = session.get(full_url, timeout=10, verify=args.strict_ssl)
                    cached = script_response.text
                    with cache_lock:
                        SCRIPT_CACHE[full_url] = cached
                for pattern in dangerous_patterns:
                    if re.search(pattern, cached, re.IGNORECASE):
                        return True
            except Exception:
                continue

        return False

    except Exception as e:
        SecureWriteLog(f"DOM check failed: {str(e)[:200]}")
        return False


def CheckXss(target_url):
    """Check for XSS with all improvements"""
    vulnerable_urls = []

    if not target_url.startswith(('http://', 'https://')):
        target_url = f"http://{target_url}"

    params = DiscoverParameters(target_url)
    if not params:
        params = ['xss_test']

    for payload in XSS_PAYLOADS:
        try:
            # GET test
            for param in params:
                # FIX: payloads were concatenated into the URL unescaped,
                # which can break the request line or get silently mangled.
                # Encode for transport; detection still matches the raw
                # payload string against the (server-decoded) response body.
                encoded_payload = quote(payload, safe='')
                test_url = f"{target_url}?{param}={encoded_payload}"
                response = session.get(
                    test_url,
                    timeout=10,
                    verify=args.strict_ssl,
                    headers={'User-Agent': random.choice(USER_AGENTS)}
                )

                if args.delay:
                    time.sleep(args.delay)

                if payload in response.text:
                    confidence = AssessConfidence(response.text, payload)
                    if confidence == "Low":
                        # Looks neutralized/encoded nearby - skip to cut false positives
                        continue
                    xss_type = DetectXssType(response, payload, target_url)
                    SecureWriteLog(f"{xss_type} XSS found (GET, confidence={confidence}): {test_url}")
                    vulnerable_urls.append(f"[{xss_type}|{confidence}] GET {test_url}")
                    break

                # FIX: this used to auto-return True for any URL containing
                # '?' or '#', flagging nearly every scanned URL as DOM XSS
                # regardless of content. CheckDomXss now always does the
                # real pattern-based inspection.
                if CheckDomXss(test_url, payload):
                    SecureWriteLog(f"DOM-Based XSS found (GET): {test_url}")
                    vulnerable_urls.append(f"[DOM-Based] GET {test_url}")
                    break

            # POST/PUT/DELETE test (if advanced mode is enabled)
            if args.advanced:
                methods = ['POST', 'PUT', 'DELETE']
                response = session.get(target_url, timeout=10, verify=args.strict_ssl)
                soup = BeautifulSoup(response.text, 'html.parser')

                for form in soup.find_all('form'):
                    form_data = {}
                    for input_tag in form.find_all('input'):
                        if input_tag.get('name'):
                            form_data[input_tag['name']] = payload

                    if form_data:
                        for method in methods:
                            try:
                                if method == 'POST':
                                    response = session.post(
                                        target_url,
                                        data=form_data,
                                        timeout=10,
                                        verify=args.strict_ssl,
                                        headers={'User-Agent': random.choice(USER_AGENTS)}
                                    )
                                elif method == 'PUT':
                                    response = session.put(
                                        target_url,
                                        data=form_data,
                                        timeout=10,
                                        verify=args.strict_ssl,
                                        headers={'User-Agent': random.choice(USER_AGENTS)}
                                    )
                                elif method == 'DELETE':
                                    response = session.delete(
                                        target_url,
                                        data=form_data,
                                        timeout=10,
                                        verify=args.strict_ssl,
                                        headers={'User-Agent': random.choice(USER_AGENTS)}
                                    )

                                if args.delay:
                                    time.sleep(args.delay)

                                if payload in response.text:
                                    confidence = AssessConfidence(response.text, payload)
                                    if confidence == "Low":
                                        continue
                                    xss_type = DetectXssType(response, payload, target_url)
                                    SecureWriteLog(f"{xss_type} XSS found ({method}, confidence={confidence}): {target_url}")
                                    vulnerable_urls.append(f"[{xss_type}|{confidence}] {method} {target_url}")
                                    break

                                if CheckDomXss(target_url, payload):
                                    SecureWriteLog(f"DOM-Based XSS found ({method}): {target_url}")
                                    vulnerable_urls.append(f"[DOM-Based] {method} {target_url}")
                                    break
                            except Exception:
                                continue

        except Exception as e:
            SecureWriteLog(f"XSS check failed: {str(e)[:200]}")
            continue

    return vulnerable_urls


def CrawlWebsite(base_url, max_pages=50):
    """Crawl the website and extract all unique URLs"""
    visited = set()
    queue = deque()
    queue.append(base_url)
    visited.add(base_url)
    crawled_urls = []

    # Check robots.txt
    rp = RobotFileParser()
    try:
        rp.set_url(urljoin(base_url, "/robots.txt"))
        rp.read()
    except Exception:
        pass

    while queue and len(visited) < max_pages:
        current_url = queue.popleft()
        try:
            response = session.get(
                current_url,
                timeout=10,
                verify=args.strict_ssl,
                headers={'User-Agent': random.choice(USER_AGENTS)}
            )

            if args.delay:
                time.sleep(args.delay)

            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(current_url, href)
                parsed = urlparse(absolute_url)

                # Filtering irrelevant URLs
                if parsed.netloc != urlparse(base_url).netloc:
                    continue
                if parsed.scheme not in ('http', 'https'):
                    continue

                # Remove query strings to avoid duplicate pages
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                if clean_url not in visited and rp.can_fetch("*", clean_url):
                    visited.add(clean_url)
                    queue.append(clean_url)
                    crawled_urls.append(clean_url)
                    if not args.quiet:
                        print(Fore.BLUE + f"[Crawling] Found: {clean_url}")

        except Exception as e:
            SecureWriteLog(f"Crawling error on {current_url}: {str(e)[:200]}")

    return crawled_urls


def ScanTarget(target):
    """Scan target with all improvements"""
    start_time = time.time()
    SecureWriteLog(f"Starting scan for: {target}")
    print(f"\n🔍 Scanning {target}...")

    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"

    parsed = urlparse(target)
    domain = parsed.netloc

    # Step 1: Crawling all paths
    print(Fore.CYAN + "\n🕷️ Crawling website to discover all paths...")
    crawled_urls = CrawlWebsite(target, max_pages=args.max_pages)

    # Step 2: Scan subdomains (NEW: filter out ones that don't even resolve)
    print(Fore.CYAN + "\n🌐 Discovering and checking subdomains...")
    subdomains = GetSubdomains(domain)
    live_subdomain_urls = []
    for sub in subdomains:
        host = f"{sub}.{domain}"
        if IsResolvable(host):
            live_subdomain_urls.append(f"{parsed.scheme}://{host}")
    if not args.quiet:
        print(Fore.GREEN + f"✅ {len(live_subdomain_urls)}/{len(subdomains)} subdomains resolved")

    # Combination of discovered URLs
    urls_to_scan = [target] + crawled_urls + live_subdomain_urls
    urls_to_scan = list(set(urls_to_scan))  # Remove duplicates

    print(Fore.GREEN + f"\n✅ Found {len(urls_to_scan)} URLs to scan (Main + Subdomains + Crawled paths)")

    # Step 3: Scan all URLs
    all_vulnerabilities = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(CheckXss, url): url for url in urls_to_scan}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                all_vulnerabilities.extend(future.result())
            except Exception as e:
                SecureWriteLog(f"Scan failed for {url}: {str(e)[:200]}")

    elapsed = time.time() - start_time

    # De-duplicate findings (same URL+type can be found more than once across payloads)
    all_vulnerabilities = sorted(set(all_vulnerabilities))

    if all_vulnerabilities:
        SecureWriteLog(f"Found {len(all_vulnerabilities)} vulnerabilities")
        print("\n🔥 Vulnerable URLs found:")
        for i, url in enumerate(all_vulnerabilities, 1):
            print(f"{i}. {url}")

        print(Fore.CYAN + f"\n⏱️ Scan finished in {elapsed:.1f}s — {len(urls_to_scan)} URLs tested, {len(all_vulnerabilities)} findings.")

        choice = input("\nEnter number to test in browser (0 to exit): ")
        if choice.isdigit() and 0 < int(choice) <= len(all_vulnerabilities):
            webbrowser.open(all_vulnerabilities[int(choice) - 1].split(' ')[-1])
    else:
        SecureWriteLog("No vulnerabilities found")
        print("\n✅ No XSS vulnerabilities found")
        print(Fore.CYAN + f"\n⏱️ Scan finished in {elapsed:.1f}s — {len(urls_to_scan)} URLs tested.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CerberusX - Advanced XSS Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target URL or domain')
    parser.add_argument('--delay', type=float, default=0.2, help='Delay between requests (seconds)')
    parser.add_argument('--strict-ssl', action='store_true', help='Enable strict SSL verification')
    parser.add_argument('--advanced', action='store_true', help='Enable advanced methods (PUT, DELETE)')
    parser.add_argument('--proxy', help='Proxy server (e.g., http://proxy.example.com:8080)')
    parser.add_argument('--max-pages', type=int, default=50, help='Maximum pages to crawl (default: 50)')
    # NEW flags
    parser.add_argument('--threads', type=int, default=15, help='Concurrent scan workers (default: 15)')
    parser.add_argument('--output', help='Custom path for the JSON results log (default: xss_scan_results.json)')
    parser.add_argument('--payloads', help='Path to a custom payload file (default: xss_payloads.txt if present)')
    parser.add_argument('--quiet', action='store_true', help='Suppress verbose crawl/subdomain output')
    args = parser.parse_args()

    if args.output:
        LOG_FILE = args.output
        LOG_HASH_FILE = args.output + '.sha256'

    payload_file = args.payloads or 'xss_payloads.txt'
    try:
        with open(payload_file, 'r') as f:
            # FIX: the old check (`line.strip().startswith('#')`) treated ANY
            # line starting with '#' as a comment, silently dropping real
            # payloads like '#{alert(1)}' (Ruby/ERB template injection).
            # Section headers in this file always look like "# === Name ===",
            # so only skip lines that actually match that header shape.
            header_pattern = re.compile(r'^#\s*=+')
            XSS_PAYLOADS = [
                line.strip() for line in f
                if line.strip() and not header_pattern.match(line.strip())
            ]
        if not XSS_PAYLOADS:
            raise ValueError("Payload file was empty")
    except (FileNotFoundError, ValueError):
        XSS_PAYLOADS = DEFAULT_PAYLOADS
        print(Fore.YELLOW + f"⚠️ {payload_file} not found or empty, using default payloads")

    # Proxy settings if any
    if args.proxy:
        session.proxies = {'http': args.proxy, 'https': args.proxy}

    SecureWriteLog("=== CerberusX Scan Started ===")
    try:
        ScanTarget(args.target.lower().strip())
    except KeyboardInterrupt:
        SecureWriteLog("Scan stopped by user")
        print("\n🛑 Scan stopped by user")
    finally:
        SecureWriteLog("=== CerberusX Scan Finished ===")
