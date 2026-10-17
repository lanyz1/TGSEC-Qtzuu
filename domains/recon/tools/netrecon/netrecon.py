import socket
import argparse
import re
import json
import tldextract
import logging
import dns.resolver
import requests
import random
from colorama import Fore, init
from pyfiglet import Figlet
from ratelimit import limits, sleep_and_retry
from rich.console import Console
from rich.table import Table

# Initialize
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
                                                                          
    ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Fore.YELLOW}
╔══════════════════════════════════════════════════════╗
║    Professional NetRecon Tool - Secure & Ethical     ║
╚══════════════════════════════════════════════════════╝
{Fore.RESET}"""

print(banner)

class WhoisClient:
    def __init__(self, timeout=5, proxy=None):
        self.timeout = timeout
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.WhoisServers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'ir': 'whois.nic.ir',
            'io': 'whois.nic.io',
            'ai': 'whois.nic.ai',
            'cloud': 'whois.nic.cloud',
            'gov': 'whois.dotgov.gov',
        }
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
            'Mozilla/5.0 (Linux; Android 10; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'
        ]

    def GetWhoisServer(self, TLD):
        return self.WhoisServers.get(TLD, 'whois.iana.org')

    @sleep_and_retry
    @limits(calls=3, period=60)
    def Query(self, target):
        """Query for domain or IP"""
        try:
            if self.IsIP(target):
                return self.IPLookup(target)
            return self.DomainLookup(target)
        except Exception as e:
            logging.error(f"Query failed: {str(e)}")
            raise ValueError(f"{Fore.RED}Query Error: {str(e)}")

    def DomainLookup(self, domain):
        """WHOIS query for domain"""
        domain = self.ValidateDomain(domain)
        TLD = tldextract.extract(domain).suffix
        WhoisServer = self.GetWhoisServer(TLD)
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((WhoisServer, 43))
                s.send(f"{domain}\r\n".encode())
                response = b''
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                parsed = self.ParseWhoisResponse(response.decode())
                logging.info(f"WHOIS query for {domain}")
                return parsed
        except Exception as e:
            logging.error(f"WHOIS failed for {domain}: {str(e)}")
            raise ValueError(f"{Fore.RED}WHOIS query failed: {str(e)}")

    def IPLookup(self, ip):
        """Complete IP information lookup"""
        try:
            if not self.IsValidIP(ip):
                raise ValueError("Invalid IP address format")

            result = {
                "IP Address": ip,
                "PTR Record": self.GetPTRRecord(ip),
                "WHOIS Info": self.GetIPWhois(ip),
                "Associated Domains": self.FindAssociatedDomains(ip),
                "Open Ports": self.CheckCommonPorts(ip),
                "CDN Detection": self.DetectCDN(ip)
            }
            
            return result
            
        except Exception as e:
            logging.error(f"IP lookup failed: {str(e)}")
            raise ValueError(f"{Fore.RED}IP lookup failed: {str(e)}")

    def GetPTRRecord(self, ip):
        """Get PTR record for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Not found"

    def GetIPWhois(self, ip):
        """Get WHOIS information for IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(("whois.arin.net", 43))
                s.send(f"{ip}\r\n".encode())
                response = b''
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                return self.ParseIPWhois(response.decode())
        except Exception as e:
            logging.warning(f"IP WHOIS failed: {str(e)}")
            return "WHOIS lookup failed"

    def FindAssociatedDomains(self, ip):
        """Find domains associated with IP"""
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            response = requests.get(
                url,
                proxies=self.proxy,
                timeout=10,
                headers=headers
            )
            
            if response.status_code == 200:
                domains = [d.strip() for d in response.text.split('\n') if d.strip()]
                return {
                    "Domain Count": len(domains),
                    "Sample Domains": domains[:10]
                }
            return "No domains found"
        except Exception as e:
            logging.warning(f"Reverse IP lookup failed: {str(e)}")
            return "Reverse lookup failed"

    def CheckCommonPorts(self, ip):
        """Check common open ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 8080, 8443, 8888]
        open_ports = []
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
            except socket.error as e:
                logging.warning(f"Port {port} scan failed: {str(e)}")
                continue
                
        return open_ports if open_ports else "No common ports open"

    def DetectCDN(self, target):
        """Detect CDN/WAF"""
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = requests.get(
                f"http://{target}",
                headers=headers,
                timeout=5,
                allow_redirects=False
            )
            server_header = response.headers.get('Server', '').lower()
            cdn_clues = ['cloudflare', 'akamai', 'fastly', 'sucuri']
            for clue in cdn_clues:
                if clue in server_header:
                    return f"Detected: {clue.upper()}"
            return "No CDN detected"
        except:
            return "CDN check failed"

    def IsIP(self, target):
        return self.IsValidIP(target)

    def IsValidIP(self, address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def ValidateDomain(self, domain):
        domain_pattern = r'''^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.(?!-)[A-Za-z0-9-]{2,63}(?<!-)$'''
        cleaned_domain = re.sub(r'^https?://|/.*$', '', domain.strip().lower())

        if not re.fullmatch(domain_pattern, cleaned_domain, re.VERBOSE):
            raise ValueError(f"{Fore.RED}Invalid domain format")
        
        extracted = tldextract.extract(cleaned_domain)
        if not extracted.suffix:
            raise ValueError(f"{Fore.RED}Invalid TLD")
        
        return cleaned_domain

    def GetDNSRecords(self, domain, record_type='A'):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            answers = resolver.resolve(domain, record_type)
            
            if record_type == 'TXT':
                records = [' '.join(txt.decode() for txt in answer.strings) for answer in answers]
            elif record_type == 'SOA':
                records = [str(answer).replace('\n', ' ') for answer in answers]
            else:
                records = [str(answer) for answer in answers]
            
            logging.info(f"DNS query success for {domain} ({record_type})")
            return {record_type: records}
            
        except dns.resolver.NoNameservers:
            return {record_type: ["No nameservers found"]}
        except dns.resolver.NoAnswer:
            return {record_type: ["No records found"]}
        except dns.exception.Timeout:
            return {record_type: ["DNS timeout"]}
        except Exception as e:
            logging.error(f"DNS Error ({record_type}): {str(e)}")
            return {record_type: [f"DNS Error: {str(e)}"]}

    def ParseWhoisResponse(self, response):
        """Parse WHOIS response with all data"""
        parsed = {}
        contact_fields = {
            'organization': 'Organization',
            'city': 'City',
            'country': 'Country',
            'email': 'Email',
            'phone': 'Phone',
            'street': 'Address'
        }
        
        registrant_section = False
        for line in response.split('\n'):
            line = line.strip()
            
            if 'registrant' in line.lower():
                registrant_section = True
            elif 'admin' in line.lower() or 'tech' in line.lower():
                registrant_section = False
                
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if 'domain name' in key:
                    parsed['Domain Name'] = value
                elif 'registrar' in key:
                    parsed['Registrar'] = value
                elif 'creation date' in key:
                    parsed['Creation Date'] = value
                elif 'updated date' in key:
                    parsed['Update'] = value
                elif 'expiration date' in key or 'expiry date' in key:
                    parsed['Expiry Date'] = value
                elif 'name server' in key:
                    parsed.setdefault('Name Servers', []).append(value)
                elif 'status' in key:
                    parsed['Status'] = value
                
                if registrant_section:
                    for field, display_name in contact_fields.items():
                        if field in key:
                            parsed[display_name] = value
                            break
        
        return parsed

    def ParseIPWhois(self, response):
        parsed = {}
        important_fields = {
            'netname': 'Network Name',
            'orgname': 'Organization',
            'country': 'Country',
            'descr': 'Description',
            'originas': 'AS Number',
            'last-modified': 'Last Updated'
        }
        
        for line in response.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key in important_fields:
                    parsed[important_fields[key]] = value
        
        return parsed if parsed else "No WHOIS information found"

def PrintResults(data, title="WHOIS Results"):
    if "IP Address" in data:
        ip_table = Table(title=f"IP Information for {data['IP Address']}", show_header=True, header_style="bold magenta")
        ip_table.add_column("Field", style="cyan", width=20)
        ip_table.add_column("Value", style="white")
        
        ip_table.add_row("IP Address", data["IP Address"])
        ip_table.add_row("PTR Record", data.get("PTR Record", "Not found"))
        ip_table.add_row("CDN Detection", data.get("CDN Detection", "Not checked"))
        
        whois_info = data.get("WHOIS Info", {})
        if isinstance(whois_info, dict):
            for key, value in whois_info.items():
                ip_table.add_row(key, value)
        else:
            ip_table.add_row("WHOIS Info", str(whois_info))
        
        domains_info = data.get("Associated Domains", {})
        if isinstance(domains_info, dict):
            ip_table.add_row("Domain Count", str(domains_info.get("Domain Count", 0)))
            sample_domains = domains_info.get("Sample Domains", [])
            if sample_domains:
                ip_table.add_row("Sample Domains", "\n".join(sample_domains))
        
        open_ports = data.get("Open Ports", [])
        if isinstance(open_ports, list):
            ip_table.add_row("Open Ports", ", ".join(map(str, open_ports)) if open_ports else "None")
        
        console.print(ip_table)
    else:
        whois_table = Table(title=title, show_header=True, header_style="bold magenta")
        whois_table.add_column("Field", style="cyan", width=20)
        whois_table.add_column("Value", style="white")

        dns_table = None
        if "DNS Records" in data:
            dns_table = Table(title="DNS Records", show_header=True, header_style="bold magenta")
            dns_table.add_column("Record Type", style="cyan", width=15)
            dns_table.add_column("Value", style="white")

        for key, value in data.items():
            if key == "DNS Records":
                for record_type, records in value.items():
                    for record in records:
                        dns_table.add_row(record_type, record)
            else:
                if isinstance(value, list):
                    whois_table.add_row(key, "\n".join(value))
                else:
                    whois_table.add_row(key, value)

        console.print(whois_table)
        if dns_table:
            console.print("\n")
            console.print(dns_table)

def ExportToCSV(data, filename):
    try:
        import csv
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            if "IP Address" in data:
                writer.writerow(["Field", "Value"])
                for key, value in data.items():
                    if isinstance(value, dict):
                        for k, v in value.items():
                            writer.writerow([f"{key}.{k}", v])
                    else:
                        writer.writerow([key, value])
            else:
                writer.writerow(["Field", "Value"])
                for key, value in data.items():
                    writer.writerow([key, value])
        console.print(f"[+] CSV saved to {filename}", style="green")
    except Exception as e:
        console.print(f"CSV Error: {str(e)}", style="red")

def Main():
    parser = argparse.ArgumentParser(description=' NetRecon Tool')
    parser.add_argument('-d', '--domain', help='Target (domain or IP address)')
    parser.add_argument('-o', '--output', help='Save result to file (JSON/CSV)')
    parser.add_argument('--raw', action='store_true', help='Show raw response')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://user:pass@host:port)')
    parser.add_argument('--dns', nargs='+', help='Get DNS records (e.g., A, MX, TXT, SOA, CNAME, AAAA)')
    parser.add_argument('--ethics', action='store_true', help='Show ethical guidelines')
    parser.add_argument('--no-log', action='store_true', help='Disable logging')
    args = parser.parse_args()

    if args.ethics:
        console.print(Fore.YELLOW + """
        [ Ethical Guidelines ]
        1. Use this tool ONLY for authorized security assessments.
        2. Never scan domains/IPs without explicit permission.
        3. Respect data privacy laws (GDPR, HIPAA).
        4. Do not use for malicious purposes.
        5. Limit query rates to avoid overloading servers.
        """)
        return

    if not args.no_log:
        logging.basicConfig(
            filename='whois_audit.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            datefmt='%d-%b-%y %H:%M:%S'
        )

    client = WhoisClient(proxy=args.proxy)
    
    try:
        if args.domain:
            result = client.Query(args.domain)
            
            if args.dns and not client.IsIP(args.domain):
                dns_records = {}
                for record in args.dns:
                    dns_data = client.GetDNSRecords(args.domain, record.upper())
                    dns_records.update(dns_data)
                result["DNS Records"] = dns_records
            
            if args.raw:
                console.print_json(json.dumps(result))
            else:
                PrintResults(result)
        
            if args.output:
                if args.output.endswith('.csv'):
                    ExportToCSV(result, args.output)
                else:
                    with open(args.output, 'w') as f:
                        json.dump(result, f, indent=2)
                    console.print(f"\n[+] Results saved to {args.output}", style="green")
                    
    except Exception as e:
        console.print(f"Error: {str(e)}", style="bold red")
        if "IP lookup failed" in str(e):
            console.print(f"\nTip: Try manual lookup methods:", style="yellow")
            console.print(f"1. whois {args.domain}", style="yellow")
            console.print(f"2. dig -x {args.domain}", style="yellow")

if __name__ == "__main__":
    Main()