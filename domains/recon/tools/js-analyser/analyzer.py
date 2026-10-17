#!/usr/bin/env python3
"""
Enhanced JavaScript Security Analyzer
Reduced false positives, better detection patterns
"""

import re
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class AnalysisResult:
    """Structure for analysis results"""
    url: str
    api_keys: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    emails: List[Dict[str, Any]]
    interesting_comments: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    xss_functions: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    paths_directories: List[Dict[str, Any]]
    errors: List[str]
    file_size: int
    analysis_timestamp: str


class JavaScriptAnalyzer:
    """Enhanced analyzer with reduced false positives"""
    
    def __init__(self):
        # Improved API key patterns - more specific to reduce false positives
        self.api_key_patterns = [
            # AWS - very specific
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', True),
            (r'(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key', True),
            
            # Google API - specific format
            (r'AIza[0-9A-Za-z\-]{35}', 'Google API Key', True),
            (r'(?i)google[_-]?api[_-]?key\s*[:=]\s*["\'](AIza[0-9A-Za-z\-]{35})["\']', 'Google API Key', True),
            
            # GitHub tokens - specific prefixes
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', True),
            (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained Token', True),
            
            # Stripe - specific prefixes
            (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Secret Key', True),
            (r'sk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Secret Key', True),
            (r'pk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Publishable Key', True),
            (r'pk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Publishable Key', True),
            
            # PayPal
            (r'access_token\$production\$[a-zA-Z0-9]{22}\$[a-zA-Z0-9]{86}', 'PayPal Access Token', True),
            
            # Slack
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,48}', 'Slack Token', True),
            
            # Firebase
            (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Cloud Messaging Token', True),
            
            # JWT - but filter out common false positives
            (r'\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]{10,}\b', 'JWT Token', False),
            
            # Generic - only if it looks like a real key (not just variable names)
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,})["\']', 'Generic API Key', False),
            (r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-/+=]{32,})["\']', 'Secret Key', False),
        ]
        
        # Credentials - more specific
        self.credential_patterns = [
            # Passwords - avoid common false positives like "password: false"
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', 'Password', False),
            (r'(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*["\']([^"\']{6,})["\']', 'Database Password', False),
            (r'(?i)(username|user[_-]?name|login)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Username', False),
        ]
        
        # Email patterns - more accurate
        self.email_patterns = [
            (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'Email Address', True),
        ]
        
        # Comments
        self.comment_patterns = [
            (r'//\s*(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING|TEMP)', 'Interesting Comment', True),
            (r'/\*[\s\S]{0,500}?(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING)[\s\S]{0,500}?\*/', 'Interesting Comment (Multi-line)', True),
            (r'//\s*(password|secret|key|token|admin|backdoor|debug|test|hardcoded)', 'Suspicious Comment', False),
        ]
        
        # XSS patterns - improved
        self.xss_patterns = [
            (r'\.innerHTML\s*=\s*([^;]+)', 'innerHTML Assignment', 'high'),
            (r'\.outerHTML\s*=\s*([^;]+)', 'outerHTML Assignment', 'high'),
            (r'document\.write\s*\(([^)]+)\)', 'document.write()', 'high'),
            (r'document\.writeln\s*\(([^)]+)\)', 'document.writeln()', 'high'),
            (r'eval\s*\([^)]*(\$|location|window\.|document\.|user|input|param|query|search)', 'eval() with User Input', 'critical'),
            (r'dangerouslySetInnerHTML\s*=\s*\{[^}]*\}', 'React dangerouslySetInnerHTML', 'high'),
            (r'\$\([^)]+\)\.html\s*\(([^)]+)\)', 'jQuery .html()', 'medium'),
            (r'\$\([^)]+\)\.append\s*\(([^)]+)\)', 'jQuery .append()', 'medium'),
            (r'location\.(href|hash|search)\s*=\s*([^;]+)', 'Location Manipulation', 'medium'),
            (r'innerHTML\s*[+\=]\s*["\']', 'innerHTML Concatenation', 'high'),
        ]
        
        # XSS function patterns - functions that might lead to XSS
        self.xss_function_patterns = [
            (r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML|write)', 'Function with innerHTML/write', 'high'),
            (r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*eval\s*\(', 'Function with eval()', 'critical'),
            (r'(\w+)\s*[:=]\s*function\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML)', 'Arrow function with DOM manipulation', 'high'),
            (r'\.(onclick|onerror|onload|onmouseover)\s*=\s*function', 'Event handler assignment', 'medium'),
        ]
        
        # API patterns
        self.api_patterns = [
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch()'),
            (r'fetch\s*\(\s*`([^`]+)`', 'fetch() (template)'),
            (r'\.open\s*\(\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']', 'XMLHttpRequest'),
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'axios (config)'),
            (r'\$\.(ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jQuery AJAX'),
            (r'\$\.(ajax|get|post)\s*\(\s*["\']([^"\']+)["\']', 'jQuery AJAX (short)'),
            (r'\$\.getJSON\s*\(\s*["\']([^"\']+)["\']', 'jQuery getJSON'),
            (r'["\'](/api/[^"\']+)["\']', 'API Path'),
            (r'["\'](/v\d+/[^"\']+)["\']', 'API Versioned Path'),
            (r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', 'Base URL'),
            (r'api[_-]?url\s*[:=]\s*["\']([^"\']+)["\']', 'API URL Variable'),
        ]
        
        # Parameter patterns - comprehensive detection of ALL parameters
        self.parameter_patterns = [
            # URL query parameters - ALL parameters (not just sensitive ones)
            # Pattern: ?param=value or &param=value
            (r'["\']([^"\']*[?&](\w+)\s*=\s*[^"\'&\s]+)["\']', 'URL Query Parameter'),
            (r'[?&](\w+)\s*=\s*([^&\s"\']+)', 'Query Parameter'),
            
            # Multiple parameters in URL: ?param1=value1&param2=value2
            (r'["\']([^"\']*[?&][\w\-]+\s*=\s*[^"\'&\s]+(?:\s*&\s*[\w\-]+\s*=\s*[^"\'&\s]+)+)["\']', 'URL with Multiple Parameters'),
            
            # URL patterns with any parameters
            (r'["\']([^"\']+[?&][^"\']+)["\']', 'URL with Query Parameters'),
            
            # Function parameters - ALL function definitions
            (r'function\s+(\w+)\s*\(([^)]+)\)', 'Function Parameters'),
            (r'function\s*\(([^)]+)\)', 'Anonymous Function Parameters'),
            (r'(\w+)\s*[:=]\s*function\s*\(([^)]+)\)', 'Function Expression Parameters'),
            (r'\(([^)]+)\)\s*=>', 'Arrow Function Parameters'),
            (r'const\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (const)'),
            (r'let\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (let)'),
            (r'var\s+\w+\s*=\s*\(([^)]+)\)\s*=>', 'Arrow Function (var)'),
            
            # Method parameters
            (r'\.(\w+)\s*\(([^)]+)\)', 'Method Call Parameters'),
            
            # URLSearchParams - extract all parameters
            (r'URLSearchParams\s*\([^)]*\)', 'URL Parameters Object'),
            (r'new\s+URLSearchParams\s*\(([^)]+)\)', 'URLSearchParams Constructor'),
            (r'\.get\s*\(["\']([^"\']+)["\']', 'URLSearchParams.get()'),
            (r'\.getAll\s*\(["\']([^"\']+)["\']', 'URLSearchParams.getAll()'),
            (r'\.has\s*\(["\']([^"\']+)["\']', 'URLSearchParams.has()'),
            
            # Request parameters - ALL HTTP methods
            (r'\.(get|post|put|delete|patch|head|options)\s*\([^,]+,\s*\{([^}]+)\}', 'Request Parameters'),
            (r'\.(get|post|put|delete|patch)\s*\([^,]+,\s*([^,)]+)\)', 'Request Parameters (short)'),
            (r'fetch\s*\([^,]+,\s*\{([^}]+)\}', 'Fetch Request Parameters'),
            (r'axios\s*\(\s*\{([^}]+)\}', 'Axios Request Parameters'),
            
            # URL constructor with parameters
            (r'new\s+URL\s*\([^,]+,\s*["\']([^"\']+)["\']', 'URL Constructor with Parameters'),
            
            # Location/search patterns - ALL location parameters
            (r'location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Location with Parameters'),
            (r'window\.location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Window Location with Parameters'),
            (r'document\.location\.(search|href)\s*[=:]\s*["\']([^"\']*[?&][^"\']+)["\']', 'Document Location with Parameters'),
            
            # Template literals with parameters
            (r'`([^`]*[?&]\w+\s*=\s*[^`&]+)`', 'Template Literal with Parameters'),
            
            # Object/JSON parameters
            (r'\{([^}]*:\s*[^,}]+(?:,\s*[^}]*:\s*[^,}]+)*)\}', 'Object Parameters'),
            
            # Destructuring parameters
            (r'const\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (const)'),
            (r'let\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (let)'),
            (r'var\s+\{([^}]+)\}\s*=', 'Destructuring Parameters (var)'),
            (r'function\s+\w+\s*\(\{([^}]+)\}\)', 'Function with Destructuring'),
            
            # Array destructuring
            (r'const\s+\[([^\]]+)\]\s*=', 'Array Destructuring (const)'),
            (r'let\s+\[([^\]]+)\]\s*=', 'Array Destructuring (let)'),
            
            # Event handler parameters
            (r'\.(on\w+)\s*=\s*function\s*\(([^)]+)\)', 'Event Handler Parameters'),
            (r'\.addEventListener\s*\(["\']([^"\']+)["\'],\s*function\s*\(([^)]+)\)', 'EventListener Parameters'),
            (r'\.addEventListener\s*\(["\']([^"\']+)["\'],\s*\(([^)]+)\)\s*=>', 'EventListener Arrow Parameters'),
            
            # Callback parameters
            (r'\.(then|catch|finally)\s*\(([^)]+)\)', 'Promise Callback Parameters'),
            (r'\.(map|filter|reduce|forEach|find)\s*\(([^)]+)\)', 'Array Method Parameters'),
        ]
        
        # Path and directory patterns
        self.path_patterns = [
            (r'["\'](/[a-zA-Z0-9_\-/]+)["\']', 'Path'),
            (r'["\'](\.\.?/[a-zA-Z0-9_\-/]+)["\']', 'Relative Path'),
            (r'path\s*[:=]\s*["\']([^"\']+)["\']', 'Path Variable'),
            (r'dir\s*[:=]\s*["\']([^"\']+)["\']', 'Directory Variable'),
            (r'["\']([a-zA-Z0-9_\-/]+\.(js|json|html|css|png|jpg|svg))["\']', 'File Path'),
        ]
    
    def fetch_js_file(self, url: str) -> Optional[str]:
        """
        Fetch JavaScript file from URL
        
        NOTE: This runs on the SERVER, not in the browser.
        The server downloads the JavaScript file for analysis.
        """
        try:
            # Fix 0.0.0.0 to localhost for local connections
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/javascript, text/javascript, */*',
            }
            
            # Increased timeout for large files
            response = requests.get(url, headers=headers, timeout=60, verify=False, stream=True, allow_redirects=True)
            response.raise_for_status()
            
            # Check content type - some servers return wrong content type
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Check content length
            content_length = response.headers.get('Content-Length')
            if content_length:
                try:
                    size_mb = int(content_length) / (1024 * 1024)
                    if size_mb > 10:  # Limit to 10MB
                        return None
                except (ValueError, TypeError):
                    pass
            
            # Read content in chunks for large files
            content = ""
            max_size = 10 * 1024 * 1024  # 10MB limit
            try:
                # Try to decode as text
                response.encoding = response.apparent_encoding or 'utf-8'
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                    if chunk:
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode('utf-8', errors='ignore')
                        content += chunk
                        if len(content) > max_size:
                            # Truncate if too large
                            content = content[:max_size]
                            break
            except UnicodeDecodeError:
                # Fallback: decode as bytes then decode to string
                content = response.content.decode('utf-8', errors='ignore')
                if len(content) > max_size:
                    content = content[:max_size]
            
            return content if content else None
        except requests.exceptions.Timeout as e:
            return None
        except requests.exceptions.ConnectionError as e:
            return None
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None
    
    def is_false_positive(self, match: str, pattern_type: str) -> bool:
        """Filter out common false positives"""
        match_lower = match.lower()
        
        # Common false positives
        false_positives = [
            'example.com', 'example.org', 'localhost', '127.0.0.1',
            'test', 'demo', 'sample', 'placeholder', 'your_api_key',
            'your_secret', 'api_key_here', 'secret_here', 'password: false',
            'password: true', 'password: null', 'password: undefined',
            'api_key: null', 'api_key: undefined', 'api_key: false',
        ]
        
        for fp in false_positives:
            if fp in match_lower:
                return True
        
        # Filter out JWT tokens that are too short or look like base64 encoded data structures
        if pattern_type == 'JWT Token':
            parts = match.split('.')
            if len(parts) < 3:
                return True
            if len(match) < 50:  # Too short to be a real JWT
                return True
        
        return False
    
    def find_patterns(self, content: str, patterns: List[tuple], context_lines: int = 5) -> List[Dict[str, Any]]:
        """Find patterns with context and false positive filtering"""
        findings = []
        if not content:
            return findings
        
        # Handle minified files (single line) - limit context
        lines = content.split('\n')
        if len(lines) == 1 and len(content) > 10000:
            # Very long single line - likely minified, reduce context
            context_lines = 0
        
        for pattern_info in patterns:
            try:
                if len(pattern_info) == 3:
                    pattern, label, is_strict = pattern_info
                else:
                    pattern, label = pattern_info[:2]
                    is_strict = False
                
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    try:
                        match_text = match.group(0)
                        
                        # Filter false positives
                        if not is_strict and self.is_false_positive(match_text, label):
                            continue
                        
                        start_pos = match.start()
                        line_num = content[:start_pos].count('\n') + 1
                        
                        # Get context with more lines
                        start_line = max(0, line_num - context_lines - 1)
                        end_line = min(len(lines), line_num + context_lines)
                        context_lines_list = lines[start_line:end_line]
                        context = '\n'.join(context_lines_list)
                        
                        # For very long lines (minified), truncate context
                        if len(context) > 1000:
                            # Show snippet around the match position
                            match_start_in_line = start_pos - content[:start_pos].rfind('\n', max(0, start_pos - 500), start_pos)
                            context_start = max(0, match_start_in_line - 200)
                            context_end = min(len(context), match_start_in_line + len(match_text) + 200)
                            context = context[context_start:context_end]
                        
                        # Get exact code snippet
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        # Truncate very long lines
                        if len(line_content) > 500:
                            line_content = line_content[:200] + "..." + line_content[-200:]
                        
                        finding = {
                            'type': str(label),
                            'match': str(match_text[:200]),
                            'line': int(line_num),
                            'line_content': str(line_content.strip()),
                            'context': str(context),
                            'context_start_line': int(start_line + 1),
                            'context_end_line': int(end_line),
                        }
                        
                        if len(pattern_info) > 2 and isinstance(pattern_info[2], str):
                            finding['severity'] = str(pattern_info[2])
                        
                        findings.append(finding)
                    except Exception as e:
                        # Skip problematic matches
                        continue
            except Exception as e:
                # Skip problematic patterns
                continue
        
        return findings
    
    def extract_api_endpoints(self, content: str) -> List[Dict[str, Any]]:
        """Extract API endpoints"""
        endpoints = []
        lines = content.split('\n')
        
        for pattern, method in self.api_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                url_path = match.group(1) if match.lastindex >= 1 else match.group(0)
                if len(match.groups()) > 1:
                    url_path = match.group(2) if match.lastindex >= 2 else match.group(1)
                
                # Filter out common false positives
                if any(fp in url_path.lower() for fp in ['example.com', 'localhost', 'placeholder']):
                    continue
                
                endpoint = {
                    'method': method,
                    'path': url_path[:200],
                    'line': line_num,
                    'full_match': match.group(0)[:150],
                    'line_content': lines[line_num - 1].strip() if line_num <= len(lines) else "",
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
    
    def extract_parameters(self, content: str) -> List[Dict[str, Any]]:
        """Extract parameters from JavaScript including URL query parameters"""
        params = []
        if not content:
            return params
        
        lines = content.split('\n')
        
        for pattern, label in self.parameter_patterns:
            try:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    try:
                        start_pos = match.start()
                        line_num = content[:start_pos].count('\n') + 1
                        
                        # Extract parameter information
                        full_match = match.group(0)
                        param_text = full_match
                        
                        # Try to extract parameter name and value
                        param_name = None
                        param_value = None
                        
                        if len(match.groups()) >= 1:
                            # For URL query parameters like ?key=value or &email=test
                            if '?' in full_match or '&' in full_match:
                                # Extract the parameter part
                                param_part = match.group(1) if match.lastindex >= 1 else full_match
                                if '=' in param_part:
                                    # Handle multiple parameters: param1=val1&param2=val2
                                    if '&' in param_part:
                                        # Extract first parameter for display
                                        first_param = param_part.split('&')[0]
                                        if '=' in first_param:
                                            parts = first_param.split('=', 1)
                                            if len(parts) == 2:
                                                param_name = parts[0].lstrip('?&').strip()
                                                param_value = parts[1].strip()
                                                param_text = f"{param_name}={param_value[:50]}..."
                                    else:
                                        parts = param_part.split('=', 1)
                                        if len(parts) == 2:
                                            # Remove ? or & from param name
                                            param_name = parts[0].lstrip('?&').strip()
                                            param_value = parts[1].strip()
                                            param_text = f"{param_name}={param_value[:50]}"
                            # For function parameters
                            elif '(' in full_match and ')' in full_match:
                                # Extract parameters from function definition
                                param_text = match.group(2) if len(match.groups()) > 1 and match.lastindex >= 2 else (match.group(1) if match.lastindex >= 1 else full_match)
                                # Try to extract first parameter name
                                params_str = param_text.split(',')[0] if ',' in param_text else param_text
                                if '=' in params_str:
                                    # Default parameter value
                                    param_name = params_str.split('=')[0].strip()
                                elif ':' in params_str:
                                    # Type annotation or object property
                                    param_name = params_str.split(':')[0].strip()
                                else:
                                    param_name = params_str.strip()
                            # For object/destructuring parameters
                            elif '{' in full_match:
                                param_text = match.group(1) if match.lastindex >= 1 else full_match
                                # Extract first property name
                                if ':' in param_text:
                                    param_name = param_text.split(':')[0].strip()
                                else:
                                    param_name = param_text.split(',')[0].strip() if ',' in param_text else param_text.strip()
                            else:
                                param_text = match.group(1) if match.lastindex >= 1 else (match.group(2) if len(match.groups()) > 1 and match.lastindex >= 2 else full_match)
                                # Try to extract parameter name from various patterns
                                if '=' in param_text:
                                    param_name = param_text.split('=')[0].strip()
                                elif ':' in param_text:
                                    param_name = param_text.split(':')[0].strip()
                                else:
                                    param_name = param_text.split(',')[0].strip() if ',' in param_text else param_text.strip()
                        
                        # Get line content
                        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        
                        # Truncate very long lines
                        if len(line_content) > 500:
                            line_content = line_content[:200] + "..." + line_content[-200:]
                        
                        # Get context for parameters (like other findings)
                        start_line = max(0, line_num - 5 - 1)
                        end_line = min(len(lines), line_num + 5)
                        context_lines_list = lines[start_line:end_line]
                        context = '\n'.join(context_lines_list)
                        
                        # For very long lines (minified), truncate context
                        if len(context) > 1000:
                            # Show snippet around the match
                            match_start = max(0, start_pos - 200)
                            match_end = min(len(content), start_pos + len(full_match) + 200)
                            context = content[match_start:match_end]
                        
                        param = {
                            'type': label,
                            'parameter': param_text[:200],
                            'param_name': param_name[:100] if param_name else None,
                            'param_value': param_value[:100] if param_value else None,
                            'line': line_num,
                            'full_match': full_match[:200],
                            'line_content': line_content,
                            'context': context,
                            'context_start_line': start_line + 1,
                            'context_end_line': end_line,
                        }
                        
                        params.append(param)
                    except Exception as e:
                        # Skip problematic matches
                        continue
            except Exception as e:
                # Skip problematic patterns
                continue
        
        # Remove duplicates based on line and parameter
        seen = set()
        unique_params = []
        for param in params:
            key = (param['line'], param['parameter'])
            if key not in seen:
                seen.add(key)
                unique_params.append(param)
        
        return unique_params
    
    def extract_paths(self, content: str) -> List[Dict[str, Any]]:
        """Extract paths and directories"""
        paths = []
        lines = content.split('\n')
        
        for pattern, label in self.path_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1
                
                path_text = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Filter out common false positives
                if any(fp in path_text.lower() for fp in ['http://', 'https://', 'www.', 'example.com']):
                    continue
                
                path = {
                    'type': label,
                    'path': path_text[:200],
                    'line': line_num,
                    'full_match': match.group(0)[:150],
                    'line_content': lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
                
                paths.append(path)
        
        # Remove duplicates
        seen = set()
        unique_paths = []
        for path in paths:
            key = (path['path'], path['line'])
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)
        
        return unique_paths
    
    def analyze(self, url: str) -> AnalysisResult:
        """
        Analyze JavaScript file for security issues
        
        ALL ANALYSIS HAPPENS SERVER-SIDE:
        - Fetches JavaScript file from URL (server-side HTTP request)
        - Runs regex patterns to find sensitive data
        - Extracts API endpoints, parameters, paths
        - Detects XSS vulnerabilities
        - Returns structured results
        
        No processing happens in the browser - only results are sent back.
        """
        errors = []
        
        try:
            # Try to fetch the file
            original_url = url
            # Fix 0.0.0.0 to localhost
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            
            content = self.fetch_js_file(url)
            if content is None:
                # Try with 127.0.0.1 if localhost failed
                if 'localhost' in url:
                    url_alt = url.replace('localhost', '127.0.0.1')
                    content = self.fetch_js_file(url_alt)
                    if content:
                        url = url_alt
                
                if content is None:
                    error_msg = f"Failed to fetch {original_url}. "
                    if '0.0.0.0' in original_url:
                        error_msg += "Note: 0.0.0.0 is not a valid address to connect to. Please use 'localhost' or '127.0.0.1' instead. "
                    error_msg += "The file may be too large, inaccessible, or the server timed out."
                    errors.append(error_msg)
                    return AnalysisResult(
                    url=url,
                    api_keys=[],
                    credentials=[],
                    emails=[],
                    interesting_comments=[],
                    xss_vulnerabilities=[],
                    xss_functions=[],
                    api_endpoints=[],
                    parameters=[],
                    paths_directories=[],
                    errors=errors,
                    file_size=0,
                    analysis_timestamp=datetime.now().isoformat()
                )
        except Exception as e:
            errors.append(f"Error fetching {url}: {str(e)}")
            return AnalysisResult(
                url=url,
                api_keys=[],
                credentials=[],
                emails=[],
                interesting_comments=[],
                xss_vulnerabilities=[],
                xss_functions=[],
                api_endpoints=[],
                parameters=[],
                paths_directories=[],
                errors=errors,
                file_size=0,
                analysis_timestamp=datetime.now().isoformat()
            )
        
        file_size = len(content)
        
        # Run all analyses with error handling
        try:
            api_keys = self.find_patterns(content, self.api_key_patterns)
        except Exception as e:
            errors.append(f"Error analyzing API keys: {str(e)}")
            api_keys = []
        
        try:
            credentials = self.find_patterns(content, self.credential_patterns)
        except Exception as e:
            errors.append(f"Error analyzing credentials: {str(e)}")
            credentials = []
        
        try:
            emails = self.find_patterns(content, self.email_patterns)
        except Exception as e:
            errors.append(f"Error analyzing emails: {str(e)}")
            emails = []
        
        try:
            comments = self.find_patterns(content, self.comment_patterns)
        except Exception as e:
            errors.append(f"Error analyzing comments: {str(e)}")
            comments = []
        
        try:
            xss_vulns = self.find_patterns(content, self.xss_patterns)
        except Exception as e:
            errors.append(f"Error analyzing XSS vulnerabilities: {str(e)}")
            xss_vulns = []
        
        try:
            xss_funcs = self.find_patterns(content, self.xss_function_patterns)
        except Exception as e:
            errors.append(f"Error analyzing XSS functions: {str(e)}")
            xss_funcs = []
        
        try:
            api_endpoints = self.extract_api_endpoints(content)
        except Exception as e:
            errors.append(f"Error extracting API endpoints: {str(e)}")
            api_endpoints = []
        
        try:
            parameters = self.extract_parameters(content)
        except Exception as e:
            errors.append(f"Error extracting parameters: {str(e)}")
            parameters = []
        
        try:
            paths = self.extract_paths(content)
        except Exception as e:
            errors.append(f"Error extracting paths: {str(e)}")
            paths = []
        
        return AnalysisResult(
            url=url,
            api_keys=api_keys,
            credentials=credentials,
            emails=emails,
            interesting_comments=comments,
            xss_vulnerabilities=xss_vulns,
            xss_functions=xss_funcs,
            api_endpoints=api_endpoints,
            parameters=parameters,
            paths_directories=paths,
            errors=errors,
            file_size=file_size,
            analysis_timestamp=datetime.now().isoformat()
        )

