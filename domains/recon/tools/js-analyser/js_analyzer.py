#!/usr/bin/env python3
"""
JavaScript Security Analyzer
Analyzes JavaScript files from URLs for sensitive data, XSS vulnerabilities, and API endpoints.
"""

import re
import sys
import json
import argparse
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, asdict
from datetime import datetime
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)


@dataclass
class AnalysisResult:
    """Structure for analysis results"""
    url: str
    api_keys: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    interesting_comments: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    errors: List[str]
    file_size: int
    analysis_timestamp: str


class JavaScriptAnalyzer:
    """Main analyzer class for JavaScript security analysis"""
    
    def __init__(self):
        self.api_key_patterns = [
            # Generic API keys
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Generic API Key'),
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*([a-zA-Z0-9_\-]{20,})', 'Generic API Key (no quotes)'),
            
            # AWS
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
            (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key'),
            
            # Google API
            (r'AIza[0-9A-Za-z\-]{35}', 'Google API Key'),
            (r'(?i)google[_-]?api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Google API Key'),
            
            # GitHub
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
            (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained Token'),
            
            # Stripe
            (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Secret Key'),
            (r'sk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Secret Key'),
            (r'pk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Publishable Key'),
            (r'pk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Publishable Key'),
            
            # PayPal
            (r'access_token\$production\$[a-zA-Z0-9]{22}\$[a-zA-Z0-9]{86}', 'PayPal Access Token'),
            
            # Slack
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,48}', 'Slack Token'),
            
            # Firebase
            (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Cloud Messaging Token'),
            
            # JWT
            (r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'JWT Token'),
            
            # Generic tokens
            (r'(?i)(token|secret|auth[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Generic Token'),
        ]
        
        self.credential_patterns = [
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Password'),
            (r'(?i)(username|user[_-]?name|login)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Username'),
            (r'(?i)(email)\s*[:=]\s*["\']([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']', 'Email'),
            (r'(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Database Password'),
        ]
        
        self.comment_patterns = [
            (r'//\s*(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING)', 'Interesting Comment'),
            (r'/\*[\s\S]*?(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING)[\s\S]*?\*/', 'Interesting Comment (Multi-line)'),
            (r'//\s*(password|secret|key|token|admin|backdoor|debug|test)', 'Suspicious Comment'),
        ]
        
        self.xss_patterns = [
            # innerHTML usage
            (r'\.innerHTML\s*=\s*([^;]+)', 'innerHTML Assignment', 'high'),
            (r'\.outerHTML\s*=\s*([^;]+)', 'outerHTML Assignment', 'high'),
            
            # document.write
            (r'document\.write\s*\(([^)]+)\)', 'document.write()', 'high'),
            (r'document\.writeln\s*\(([^)]+)\)', 'document.writeln()', 'high'),
            
            # eval with user input
            (r'eval\s*\([^)]*(\$|location|window\.|document\.|user|input|param)', 'eval() with User Input', 'critical'),
            
            # dangerouslySetInnerHTML (React)
            (r'dangerouslySetInnerHTML\s*=\s*\{[^}]*\}', 'React dangerouslySetInnerHTML', 'high'),
            
            # jQuery HTML injection
            (r'\$\([^)]+\)\.html\s*\(([^)]+)\)', 'jQuery .html()', 'medium'),
            (r'\$\([^)]+\)\.append\s*\(([^)]+)\)', 'jQuery .append()', 'medium'),
            
            # URL manipulation without encoding
            (r'location\.(href|hash|search)\s*=\s*([^;]+)', 'Location Manipulation', 'medium'),
            
            # innerHTML with concatenation
            (r'innerHTML\s*[+\=]\s*["\']', 'innerHTML Concatenation', 'high'),
        ]
        
        self.api_patterns = [
            # fetch API
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch()'),
            (r'fetch\s*\(\s*`([^`]+)`', 'fetch() (template)'),
            
            # XMLHttpRequest
            (r'\.open\s*\(\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']', 'XMLHttpRequest'),
            
            # axios
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'axios (config)'),
            
            # jQuery AJAX
            (r'\$\.(ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jQuery AJAX'),
            (r'\$\.(ajax|get|post)\s*\(\s*["\']([^"\']+)["\']', 'jQuery AJAX (short)'),
            
            # $.getJSON
            (r'\$\.getJSON\s*\(\s*["\']([^"\']+)["\']', 'jQuery getJSON'),
            
            # API endpoint patterns
            (r'["\'](/api/[^"\']+)["\']', 'API Path'),
            (r'["\'](/v\d+/[^"\']+)["\']', 'API Versioned Path'),
            (r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', 'Base URL'),
            (r'api[_-]?url\s*[:=]\s*["\']([^"\']+)["\']', 'API URL Variable'),
        ]
    
    def fetch_js_file(self, url: str) -> Optional[str]:
        """Fetch JavaScript file from URL"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30, verify=False)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            return None
    
    def find_patterns(self, content: str, patterns: List[tuple], context_lines: int = 2) -> List[Dict[str, Any]]:
        """Find patterns in content with context"""
        findings = []
        lines = content.split('\n')
        
        for pattern, label, *extra in patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                # Get context
                start_line = max(0, line_num - context_lines - 1)
                end_line = min(len(lines), line_num + context_lines)
                context = '\n'.join(lines[start_line:end_line])
                
                finding = {
                    'type': label,
                    'match': match.group(0)[:100],  # Truncate long matches
                    'line': line_num,
                    'context': context,
                }
                
                if extra:
                    finding['severity'] = extra[0]
                
                findings.append(finding)
        
        return findings
    
    def extract_api_endpoints(self, content: str) -> List[Dict[str, Any]]:
        """Extract API endpoints and paths"""
        endpoints = []
        lines = content.split('\n')
        
        for pattern, method in self.api_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                # Extract URL/path from match
                url_path = match.group(1) if match.lastindex >= 1 else match.group(0)
                if len(match.groups()) > 1:
                    url_path = match.group(2) if match.lastindex >= 2 else match.group(1)
                
                endpoint = {
                    'method': method,
                    'path': url_path[:200],  # Truncate long paths
                    'line': line_num,
                    'full_match': match.group(0)[:150],
                }
                
                endpoints.append(endpoint)
        
        # Remove duplicates
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            key = (ep['path'], ep['line'])
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        return unique_endpoints
    
    def analyze(self, url: str) -> AnalysisResult:
        """Analyze a JavaScript file from URL"""
        errors = []
        
        # Fetch file
        content = self.fetch_js_file(url)
        if content is None:
            errors.append(f"Failed to fetch {url}")
            return AnalysisResult(
                url=url,
                api_keys=[],
                credentials=[],
                interesting_comments=[],
                xss_vulnerabilities=[],
                api_endpoints=[],
                errors=errors,
                file_size=0,
                analysis_timestamp=datetime.now().isoformat()
            )
        
        file_size = len(content)
        
        # Run analysis
        api_keys = self.find_patterns(content, self.api_key_patterns)
        credentials = self.find_patterns(content, self.credential_patterns)
        comments = self.find_patterns(content, self.comment_patterns)
        xss_vulns = self.find_patterns(content, self.xss_patterns)
        api_endpoints = self.extract_api_endpoints(content)
        
        return AnalysisResult(
            url=url,
            api_keys=api_keys,
            credentials=credentials,
            interesting_comments=comments,
            xss_vulnerabilities=xss_vulns,
            api_endpoints=api_endpoints,
            errors=errors,
            file_size=file_size,
            analysis_timestamp=datetime.now().isoformat()
        )


class OutputFormatter:
    """Format analysis results for display"""
    
    @staticmethod
    def format_json(results: List[AnalysisResult]) -> str:
        """Format results as JSON"""
        return json.dumps([asdict(r) for r in results], indent=2)
    
    @staticmethod
    def format_text(results: List[AnalysisResult]) -> str:
        """Format results as readable text"""
        output = []
        
        for result in results:
            output.append(f"\n{'='*80}")
            output.append(f"{Fore.CYAN}URL: {result.url}{Style.RESET_ALL}")
            output.append(f"File Size: {result.file_size:,} bytes")
            output.append(f"Analysis Time: {result.analysis_timestamp}")
            output.append(f"{'='*80}\n")
            
            if result.errors:
                output.append(f"{Fore.RED}Errors:{Style.RESET_ALL}")
                for error in result.errors:
                    output.append(f"  ❌ {error}")
                output.append("")
            
            # API Keys
            if result.api_keys:
                output.append(f"{Fore.YELLOW}🔑 API Keys Found: {len(result.api_keys)}{Style.RESET_ALL}")
                for key in result.api_keys[:10]:  # Limit to 10
                    output.append(f"  • {key['type']} (Line {key['line']})")
                    output.append(f"    Match: {key['match'][:60]}...")
                if len(result.api_keys) > 10:
                    output.append(f"  ... and {len(result.api_keys) - 10} more")
                output.append("")
            
            # Credentials
            if result.credentials:
                output.append(f"{Fore.RED}🔐 Credentials Found: {len(result.credentials)}{Style.RESET_ALL}")
                for cred in result.credentials[:10]:
                    output.append(f"  • {cred['type']} (Line {cred['line']})")
                    output.append(f"    Match: {cred['match'][:60]}...")
                if len(result.credentials) > 10:
                    output.append(f"  ... and {len(result.credentials) - 10} more")
                output.append("")
            
            # Comments
            if result.interesting_comments:
                output.append(f"{Fore.MAGENTA}💬 Interesting Comments: {len(result.interesting_comments)}{Style.RESET_ALL}")
                for comment in result.interesting_comments[:10]:
                    output.append(f"  • {comment['type']} (Line {comment['line']})")
                    output.append(f"    {comment['match'][:80]}")
                if len(result.interesting_comments) > 10:
                    output.append(f"  ... and {len(result.interesting_comments) - 10} more")
                output.append("")
            
            # XSS Vulnerabilities
            if result.xss_vulnerabilities:
                output.append(f"{Fore.RED}⚠️  XSS Vulnerabilities: {len(result.xss_vulnerabilities)}{Style.RESET_ALL}")
                for xss in result.xss_vulnerabilities:
                    severity = xss.get('severity', 'unknown')
                    severity_color = Fore.RED if severity == 'critical' else Fore.YELLOW if severity == 'high' else Fore.CYAN
                    output.append(f"  • {severity_color}[{severity.upper()}]{Style.RESET_ALL} {xss['type']} (Line {xss['line']})")
                    output.append(f"    {xss['match'][:80]}")
                output.append("")
            
            # API Endpoints
            if result.api_endpoints:
                output.append(f"{Fore.GREEN}🌐 API Endpoints: {len(result.api_endpoints)}{Style.RESET_ALL}")
                for endpoint in result.api_endpoints[:20]:
                    output.append(f"  • [{endpoint['method']}] {endpoint['path']} (Line {endpoint['line']})")
                if len(result.api_endpoints) > 20:
                    output.append(f"  ... and {len(result.api_endpoints) - 20} more")
                output.append("")
            
            # Summary
            total_findings = (len(result.api_keys) + len(result.credentials) + 
                            len(result.xss_vulnerabilities))
            if total_findings == 0 and not result.api_endpoints:
                output.append(f"{Fore.GREEN}✓ No security issues detected{Style.RESET_ALL}\n")
            else:
                output.append(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
                output.append(f"  • API Keys: {len(result.api_keys)}")
                output.append(f"  • Credentials: {len(result.credentials)}")
                output.append(f"  • XSS Vulnerabilities: {len(result.xss_vulnerabilities)}")
                output.append(f"  • API Endpoints: {len(result.api_endpoints)}")
                output.append("")
        
        return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description='JavaScript Security Analyzer - Analyze JS files for sensitive data and vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com/app.js
  %(prog)s https://example.com/app.js https://example.com/lib.js
  %(prog)s -f urls.txt
  %(prog)s https://example.com/app.js -o results.json
        """
    )
    
    parser.add_argument('urls', nargs='*', help='URL(s) of JavaScript file(s) to analyze')
    parser.add_argument('-f', '--file', help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file path (JSON format)')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    # Collect URLs
    urls = list(args.urls) if args.urls else []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found", file=sys.stderr)
            sys.exit(1)
    
    if not urls:
        parser.print_help()
        sys.exit(1)
    
    # Disable colors if requested
    if args.no_color:
        colorama.init(strip=True)
    
    # Analyze
    analyzer = JavaScriptAnalyzer()
    results = []
    
    print(f"{Fore.CYAN}Analyzing {len(urls)} JavaScript file(s)...{Style.RESET_ALL}\n")
    
    for url in urls:
        print(f"Fetching: {url}")
        result = analyzer.analyze(url)
        results.append(result)
    
    # Output results
    if args.json or args.output:
        output = OutputFormatter.format_json(results)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"\n{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
        else:
            print(output)
    else:
        print(OutputFormatter.format_text(results))


if __name__ == '__main__':
    # Disable SSL warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()


