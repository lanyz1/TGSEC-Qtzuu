import requests
import concurrent.futures
import argparse
import sys
import json
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from colorama import Fore, init

console = Console()
init(autoreset=True)

# Banner_One
PURPLE = '\033[0;35m' 
END = "\033[0m"

banner = f"""
  {PURPLE}
███╗   ██╗ ██████╗  █████╗ ███████╗██╗██╗  ██╗███████╗███████╗███████╗██╗   ██╗
████╗  ██║██╔═████╗██╔══██╗╚══███╔╝██║╚██╗██╔╝██╔════╝██╔════╝██╔════╝██║   ██║
██╔██╗ ██║██║██╔██║███████║  ███╔╝ ██║ ╚███╔╝ ███████╗███████╗███████╗██║   ██║
██║╚██╗██║████╔╝██║██╔══██║ ███╔╝  ██║ ██╔██╗ ╚════██║╚════██║╚════██║██║   ██║
██║ ╚████║╚██████╔╝██║  ██║███████╗██║██╔╝ ██╗███████║███████║███████║╚██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ 
                                                                               
██████╗ ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗              
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝              
██████╔╝███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗                
██╔══██╗╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝                
██████╔╝███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗              
╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ 
{Fore.YELLOW}
╔══════════════════════════════════════════════════════╗
║             Subdomain Scanner v2.0           ║
║         Complete Subdomain Discovery + Status        ║
╚══════════════════════════════════════════════════════╝
{Fore.RESET}"""

print(banner)

def show_status_code_table():
    """Display important status codes using rich table"""
    console.print("\n")
    console.print(Panel.fit("✨[bold yellow]IMPORTANT HTTP STATUS CODES FOR PENETRATION TESTING✨[/bold yellow]", border_style="white"))
    
    table = Table(show_header=True, header_style="bold magenta", border_style="cyan")
    table.add_column("Code", style="bold green", width=6)
    table.add_column("Name", style="bold yellow", width=15)
    table.add_column("Description", style="white", width=40)
    table.add_column("Importance", style="bold", width=12)
    table.add_column("Use Case", style="cyan", width=30)
    
    status_codes = [
        ("200", "OK", "Request successful - Resource found", "🟩 Critical", "Active and accessible pages"),
        ("201", "Created", "Resource created successfully", "🟩 Critical", "Successful POST operations"),
        ("204", "No Content", "Success but no content", "🟨 Medium", "API endpoints"),
        ("301", "Moved", "Permanent redirect", "🟪 Important", "Redirect tracking"),
        ("302", "Found", "Temporary redirect", "🟪 Important", "Session management"),
        ("304", "Not Modified", "Not modified", "🟨 Medium", "Cache testing"),
        ("400", "Bad Request", "Invalid request", "🟥 Important", "Input validation"),
        ("401", "Unauthorized", "Auth required", "🟥 Critical", "Auth bypass testing"),
        ("403", "Forbidden", "Access forbidden", "🟥 Critical", "Directory traversal"),
        ("404", "Not Found", "Resource not found", "🟥 Important", "Information gathering"),
        ("405", "Not Allowed", "Method not allowed", "🟥 Important", "HTTP method test"),
        ("500", "Server Error", "Internal server error", "🔥 Critical", "SQLi/XSS/RCE testing"),
        ("502", "Bad Gateway", "Invalid gateway", "🔥 Medium", "Load balancer"),
        ("503", "Unavailable", "Service unavailable", "🔥 Medium", "DoS detection")
    ]
    
    for code, name, desc, imp, use in status_codes:
        table.add_row(code, name, desc, imp, use)
    
    console.print(table)
    
    # Key insights
    console.print("\n[bold yellow]📌 KEY INSIGHTS FOR PENETRATION TESTERS:[/bold yellow]")
    console.print("  • [green]200-299:[/green] Successful requests - Target is accessible")
    console.print("  • [yellow]300-399:[/yellow] Redirection - Check for open redirects")
    console.print("  • [red]400-499:[/red] Client errors - Auth/Authorization issues")
    console.print("  • [magenta]500-599:[/magenta] Server errors - Exploitation potential")
    console.print("\n" + "="*118)

class SubdomainScanner:
    def __init__(self, timeout=5, threads=20):
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.discovered_subdomains = []
    
    def resolve_subdomain(self, subdomain):
        """Resolve subdomain using DNS"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                return subdomain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            return None
        return None
    
    def check_subdomain_status(self, subdomain):
        """Check HTTP/HTTPS status of subdomain"""
        results = []
        
        for protocol in ['http', 'https']:
            url = f"{protocol}://{subdomain}"
            try:
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                result = {
                    'subdomain': subdomain,
                    'url': url,
                    'protocol': protocol,
                    'status_code': response.status_code,
                    'final_url': response.url,
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds(),
                    'ip': self.get_ip(subdomain)
                }
                results.append(result)
                break  # Stop if one protocol works
                
            except (requests.exceptions.RequestException, requests.exceptions.Timeout):
                continue
        
        return results if results else None
    
    def get_ip(self, subdomain):
        """Get IP address of subdomain"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            return str(answers[0])
        except:
            return "N/A"
    
    def brute_force_subdomains(self, domain, wordlist=None):
        """Brute force subdomains using DNS resolution"""
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    subdomains = [f"{line.strip()}.{domain}" for line in f]
            except FileNotFoundError:
                print(f"[!] Error: Wordlist file {wordlist} not found")
                sys.exit(1)
        else:
            # Common subdomains list (expanded)
            common_subdomains = [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'admin', 'administrator',
                'blog', 'api', 'test', 'dev', 'development', 'staging', 'prod', 'production',
                'secure', 'login', 'signin', 'dashboard', 'portal', 'cpanel', 'whm', 'webdisk',
                'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'mysql', 'phpmyadmin', 'static', 'cdn',
                'media', 'images', 'img', 'video', 'assets', 'download', 'uploads', 'files',
                'mobile', 'm', 'wap', 'support', 'help', 'kb', 'wiki', 'forum', 'community',
                'shop', 'store', 'cart', 'checkout', 'payment', 'billing', 'invoice', 'account',
                'email', 'web', 'server', 'vpn', 'remote', 'ssh', 'ftp', 'sftp', 'git', 'svn',
                'beta', 'alpha', 'demo', 'stage', 'test1', 'test2', 'test3', 'lab', 'labs',
                'app', 'application', 'apps', 'services', 'service', 'tools', 'tool', 'status',
                'monitor', 'monitoring', 'stats', 'statistics', 'analytics', 'tracking',
                'search', 'find', 'query', 'db', 'database', 'sql', 'nosql', 'redis', 'cache',
                'proxy', 'firewall', 'router', 'switch', 'gateway', 'vhost', 'virtual',
                'cloud', 'aws', 'azure', 'gcp', 'digitalocean', 'linode', 'vultr',
                'old', 'new', 'legacy', 'archive', 'backup', 'backups', 'temp', 'tmp',
                'localhost', 'local', '127.0.0.1', '0.0.0.0', 'home', 'host', 'hosting'
            ]
            subdomains = [f"{sub}.{domain}" for sub in common_subdomains]
        
        discovered = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]DNS Resolving subdomains...", total=len(subdomains))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {executor.submit(self.resolve_subdomain, sub): sub for sub in subdomains}
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    result = future.result()
                    if result:
                        discovered.append(result)
                    progress.update(task, advance=1)
        
        return discovered
    
    def scan(self, domain, wordlist=None):
        """Main scanning function - DNS brute force + HTTP status check"""
        console.print(f"\n[bold cyan][+] Target Domain:[/bold cyan] [yellow]{domain}[/yellow]")
        
        # Step 1: DNS brute force
        console.print("[bold cyan][+] Step 1: DNS Subdomain Discovery[/bold cyan]")
        discovered = self.brute_force_subdomains(domain, wordlist)
        
        if not discovered:
            console.print("[bold red][!] No subdomains found via DNS resolution[/bold red]")
            return []
        
        console.print(f"[bold green][+] Found {len(discovered)} subdomains via DNS[/bold green]")
        
        # Step 2: HTTP status check
        console.print("[bold cyan][+] Step 2: HTTP/HTTPS Status Checking[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Checking HTTP status...", total=len(discovered))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {executor.submit(self.check_subdomain_status, sub): sub for sub in discovered}
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    results = future.result()
                    if results:
                        self.results.extend(results)
                    progress.update(task, advance=1)
        
        return self.results
    
    def save_results(self, filename="subdomain_scan_results.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        console.print(f"[bold green][+] Results saved to {filename}[/bold green]")
    
    def generate_report(self):
        """Generate comprehensive report"""
        if not self.results:
            console.print("[bold red][!] No results to report[/bold red]")
            return
        
        # Summary table
        console.print("\n")
        console.print(Panel.fit("📊 [bold green]SCAN RESULTS SUMMARY[/bold green]", border_style="white"))
        
        summary_table = Table(show_header=True, header_style="bold yellow", border_style="cyan")
        summary_table.add_column("Status", style="bold", width=10)
        summary_table.add_column("Count", style="bold cyan", width=8)
        summary_table.add_column("Percentage", style="bold", width=12)
        
        total = len(self.results)
        status_counts = {}
        
        for result in self.results:
            status = result['status_code']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Sort by count
        for status, count in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100
            emoji = "✅" if status == 200 else "🔀" if 300 <= status < 400 else "❌" if 400 <= status < 500 else "🔥"
            summary_table.add_row(f"{emoji} {status}", str(count), f"{percentage:.1f}%")
        
        console.print(summary_table)
        
        # Detailed results table
        console.print("\n")
        console.print(Panel.fit("🔍 [bold yellow]DETAILED RESULTS[/bold yellow]", border_style="white"))
        
        details_table = Table(show_header=True, header_style="bold magenta", border_style="cyan")
        details_table.add_column("Subdomain", style="bold green", width=25)
        details_table.add_column("Protocol", style="cyan", width=10)
        details_table.add_column("Status", style="bold", width=10)
        details_table.add_column("IP", style="yellow", width=15)
        details_table.add_column("Response Time", style="white", width=15)
        details_table.add_column("Size", style="white", width=10)
        
        for result in sorted(self.results, key=lambda x: x['subdomain']):
            status = result['status_code']
            emoji = "✅" if status == 200 else "🔀" if 300 <= status < 400 else "❌" if 400 <= status < 500 else "🔥"
            color = "green" if status == 200 else "yellow" if 300 <= status < 400 else "red" if 400 <= status < 500 else "magenta"
            
            details_table.add_row(
                result['subdomain'],
                result['protocol'],
                f"[{color}]{emoji} {status}[/{color}]",
                result['ip'],
                f"{result['response_time']:.2f}s",
                f"{result['content_length']:,}"
            )
        
        console.print(details_table)
        
        # Statistics
        console.print("\n")
        console.print(Panel.fit("📈 [bold cyan]STATISTICS[/bold cyan]", border_style="yellow"))
        console.print(f"  • [bold]Total Subdomains Found:[/bold] {len(set(r['subdomain'] for r in self.results))}")
        console.print(f"  • [bold]Total HTTP Requests:[/bold] {len(self.results)}")
        console.print(f"  • [bold]Unique Status Codes:[/bold] {len(status_counts)}")
        
        # Categorize by status
        success = sum(1 for r in self.results if r['status_code'] == 200)
        redirects = sum(1 for r in self.results if 300 <= r['status_code'] < 400)
        client_errors = sum(1 for r in self.results if 400 <= r['status_code'] < 500)
        server_errors = sum(1 for r in self.results if r['status_code'] >= 500)
        
        console.print(f"\n  • [green]🟩 Successful (200):[/green] {success}")
        console.print(f"  • [yellow]🟪 Redirects (3xx):[/yellow] {redirects}")
        console.print(f"  • [red]🟥 Client Errors (4xx):[/red] {client_errors}")
        console.print(f"  • [magenta]🔥 Server Errors (5xx):[/magenta] {server_errors}")

def main():
    # Show important status codes table
    show_status_code_table()
    
    parser = argparse.ArgumentParser(description='Advanced Subdomain Scanner Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain (example.com)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for subdomains')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    
    args = parser.parse_args()
    
    scanner = SubdomainScanner(timeout=args.timeout, threads=args.threads)
    results = scanner.scan(args.domain, args.wordlist)
    
    if results:
        scanner.generate_report()
        
        output_file = args.output or f"{args.domain}_scan_results.json"
        scanner.save_results(output_file)
    else:
        console.print("[bold red][!] No results found. Try with a different wordlist.[/bold red]")

if __name__ == "__main__":
    main()