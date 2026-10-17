import socket
import argparse
import re
import json
import tldextract
import dns.resolver
import requests
import socks
from urllib.parse import urlparse
from colorama import Fore, init
from ratelimit import limits, sleep_and_retry
from rich.console import Console
from rich.table import Table
from datetime import datetime
import warnings
import urllib3

# Initialize
init(autoreset=True)
console = Console()
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Banner_One
PURPLE = '\033[0;35m' 
END = "\033[0m"

banner = f"""
  {END}
    ███╗   ██╗ █████╗ ███████╗██╗██╗  ██╗███████╗███████╗
    ████╗  ██║██╔══██╗╚══███╔╝██║╚██╗██╔╝██╔════╝██╔════╝
    ██╔██╗ ██║███████║  ███╔╝ ██║ ╚███╔╝ ███████╗███████╗
    ██║╚██╗██║██╔══██║ ███╔╝  ██║ ██╔██╗ ╚════██║╚════██║
    ██║ ╚████║██║  ██║███████╗██║██╔╝ ██╗███████║███████║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
                                                         
    ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗    
    ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║    
    ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║    
    ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║    
    ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║    
    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝    
                                                         
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗          
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║          
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║          
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║          
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║          
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Fore.YELLOW}
╔══════════════════════════════════════════════════════╗
║   Professional Domain Recon Tool - Secure & Ethical  ║
╚══════════════════════════════════════════════════════╝
{Fore.RESET}"""

print(banner)


class WhoisClient:
    def __init__(self, timeout=5, proxies=None, strict_ssl=False):
        self.timeout = timeout
        self.proxies = proxies
        self.strict_ssl = strict_ssl
        self.WhoisServers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'ir': 'whois.nic.ir',
        }
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        })
        if proxies:
            self.session.proxies.update(proxies)

        # FIX: --proxies previously only affected the crt.sh HTTP lookups
        # (via self.session). The actual WHOIS query uses a raw TCP socket
        # on port 43, which ignored the proxy entirely and connected
        # directly - defeating the point of routing through Tor/a proxy.
        # This parses the same proxy URL so the raw socket can be tunneled
        # through it too.
        self.socket_proxy = self._ParseSocketProxy(proxies)

    def _ParseSocketProxy(self, proxies):
        if not proxies:
            return None
        proxy_url = proxies.get('https') or proxies.get('http')
        if not proxy_url:
            return None

        parsed = urlparse(proxy_url)
        scheme = parsed.scheme.lower()
        proxy_type_map = {
            'socks5': socks.SOCKS5,
            'socks5h': socks.SOCKS5,
            'socks4': socks.SOCKS4,
            'http': socks.HTTP,
            'https': socks.HTTP,
        }

        if scheme not in proxy_type_map:
            print(Fore.YELLOW + f"⚠️ Unsupported proxy scheme '{scheme}', WHOIS socket query will not be proxied (only crt.sh lookups will be)")
            return None
        if not parsed.hostname or not parsed.port:
            print(Fore.YELLOW + "⚠️ Could not parse proxy host/port, WHOIS socket query will not be proxied")
            return None

        return (proxy_type_map[scheme], parsed.hostname, parsed.port)

    def _CreateSocket(self):
        """Create a plain or proxy-tunneled socket depending on --proxies."""
        if self.socket_proxy:
            proxy_type, host, port = self.socket_proxy
            s = socks.socksocket()
            s.set_proxy(proxy_type, host, port)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        return s

    def GetWhoisServer(self, TLD):
        return self.WhoisServers.get(TLD, 'whois.iana.org')

    def _RawWhoisQuery(self, server, domain):
        with self._CreateSocket() as s:
            s.connect((server, 43))
            s.send(f"{domain}\r\n".encode())
            response = b''
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        return response.decode(errors='replace')

    def _ExtractReferral(self, response):
        """
        NEW: many TLDs (anything not in self.WhoisServers) fall back to
        whois.iana.org, which only returns a referral pointer rather than
        real registration data. This looks for that referral so Query()
        can follow it and get the actual WHOIS record.
        """
        referral_fields = ('refer:', 'whois server:', 'whois:', 'registrar whois server:')
        for line in response.lower().split('\n'):
            line = line.strip()
            for field in referral_fields:
                if line.startswith(field):
                    value = line.split(':', 1)[1].strip()
                    value = value.replace('whois://', '').strip('/')
                    if value:
                        return value
        return None

    @sleep_and_retry
    @limits(calls=3, period=60)
    def Query(self, domain):
        domain = self.ValidateDomain(domain)
        TLD = tldextract.extract(domain).suffix
        WhoisServer = self.GetWhoisServer(TLD)

        try:
            raw_response = self._RawWhoisQuery(WhoisServer, domain)

            # Follow a one-hop referral (e.g. iana.org -> the registry's own
            # server) so non-hardcoded TLDs still get real WHOIS data.
            referral = self._ExtractReferral(raw_response)
            if referral and referral.lower() != WhoisServer.lower():
                try:
                    referred_response = self._RawWhoisQuery(referral, domain)
                    if referred_response.strip():
                        raw_response = referred_response
                except Exception:
                    pass  # keep the original response if the referral fails

            parsed_data = self.ParseWhoisResponse(raw_response)
            parsed_data.update({
                "Subdomains": self.FindSubdomains(domain),
                "IP Addresses": self.GetIPs(domain),
                "TXT Records": self.GetTXTRecords(domain),
            })
            self.CheckExpiryWarning(parsed_data)
            return parsed_data
        except Exception as e:
            raise ValueError(f"{Fore.RED}WHOIS query failed: {str(e)}")

    def FindSubdomains(self, domain):
        subdomains = set()

        # Method 1: Certificate Transparency Logs (with improved error handling)
        try:
            response = self.session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15,
                verify=self.strict_ssl
            )
            if response.status_code == 200:
                for entry in response.json():
                    name = entry['name_value']
                    if name.startswith('*.'):
                        subdomains.add(name[2:])
                    else:
                        subdomains.add(name)
        except requests.exceptions.RequestException as e:
            if "SOCKSHTTPSConnectionPool" in str(e):
                # Retry without proxy if SOCKS fails
                try:
                    response = requests.get(
                        f"https://crt.sh/?q=%25.{domain}&output=json",
                        headers={'User-Agent': 'Mozilla/5.0'},
                        timeout=15,
                        verify=self.strict_ssl
                    )
                    if response.status_code == 200:
                        for entry in response.json():
                            name = entry['name_value']
                            subdomains.add(name.replace('*.', ''))
                except Exception:
                    pass
            else:
                pass

        # Method 2: Common Subdomain Brute-forcing
        common_subs = ['www', 'mail', 'ftp', 'admin', 'webmail', 'ns1', 'ns2']
        for sub in common_subs:
            try:
                self.resolver.resolve(f"{sub}.{domain}", 'A')
                subdomains.add(f"{sub}.{domain}")
            except Exception:
                continue

        return sorted(subdomains) if subdomains else ["No subdomains found"]

    def GetIPs(self, domain):
        ips = set()
        record_types = ['A', 'AAAA', 'CNAME', 'MX']

        for rt in record_types:
            try:
                answers = self.resolver.resolve(domain, rt)
                for rdata in answers:
                    if rt in ['A', 'AAAA']:
                        ips.add(rdata.address)
                    elif rt == 'CNAME':
                        ips.add(str(rdata.target))
                    elif rt == 'MX':
                        ips.add(str(rdata.exchange))
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                continue
            except Exception:
                continue

        return sorted(ips) if ips else ["No IP records found"]

    def GetTXTRecords(self, domain):
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(rdata).strip('"') for rdata in answers]
        except dns.resolver.NoAnswer:
            return ["No TXT records found"]
        except Exception:
            return ["TXT records unavailable"]

    def ValidateDomain(self, domain):
        # FIX: validation used to run before strip(), so a domain with
        # stray leading/trailing whitespace (common when copy-pasted) was
        # rejected even though stripping it would have made it valid.
        domain = domain.lower().strip()
        pattern = r'^([a-z0-9-]+\.)+[a-z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError(f"{Fore.RED}Invalid domain format!")
        return domain

    def ParseWhoisResponse(self, response):
        parsed = {}
        important_fields = {
            'domain name': 'Domain Name',
            'registrar': 'Registrar',
            'creation date': 'Creation Date',
            'expiry date': 'Expiry Date',
            'name server': 'Name Servers',
            'registrant': 'Registrant',
            'status': 'Status'
        }

        for line in response.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                if key in important_fields:
                    clean_key = important_fields[key]
                    if clean_key == 'Name Servers':
                        parsed.setdefault(clean_key, []).append(value.strip().lower())
                    else:
                        parsed[clean_key] = value.strip()
        return parsed

    def CheckExpiryWarning(self, data):
        if 'Expiry Date' in data:
            expiry_date = data['Expiry Date']
            try:
                expiry = datetime.strptime(expiry_date, '%Y-%m-%d')
                if (expiry - datetime.now()).days < 30:
                    data['Expiry Warning'] = "⚠️ Domain expires soon!"
            except ValueError:
                pass


def PrintResults(data):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="white")

    main_fields = [
        'Domain Name', 'Registrar', 'Creation Date',
        'Expiry Date', 'Name Servers', 'Status', 'Expiry Warning'
    ]
    for field in main_fields:
        if field in data:
            value = data[field]
            table.add_row(
                field,
                "\n".join(value) if isinstance(value, list) else str(value),
                style="bold red" if field == 'Expiry Warning' else None
            )

    table.add_row("Subdomains", "\n".join(data.get('Subdomains', ['Not found'])))
    table.add_row("IP/DNS Records", "\n".join(data.get('IP Addresses', ['Not found'])))
    table.add_row("TXT Records", "\n".join(data.get('TXT Records', ['Not found'])))

    console.print(table)


def Main():
    parser = argparse.ArgumentParser(description=' WHOIS Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Save result to JSON file')
    parser.add_argument('--csv', help='Export results to CSV')
    parser.add_argument('--raw', action='store_true', help='Show raw response')
    parser.add_argument('--proxies', help='Proxy settings, e.g. socks5://127.0.0.1:9050 or http://proxy:port (applies to both the WHOIS query and crt.sh lookups)')
    parser.add_argument('--strict-ssl', action='store_true', help='Enable strict SSL certificate verification for crt.sh lookups')
    args = parser.parse_args()

    proxies = {'http': args.proxies, 'https': args.proxies} if args.proxies else None
    client = WhoisClient(proxies=proxies, strict_ssl=args.strict_ssl)

    try:
        result = client.Query(args.domain)
        if args.raw:
            console.print_json(json.dumps(result))
        else:
            PrintResults(result)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            console.print(f"\n[+] Results saved to {args.output}", style="green")

        if args.csv:
            import pandas as pd
            # Flatten list fields (Subdomains, IP Addresses, TXT Records, Name
            # Servers) into a single "; "-joined string so the CSV cells hold
            # readable text instead of a Python list repr.
            csv_result = {
                k: ("; ".join(v) if isinstance(v, list) else v)
                for k, v in result.items()
            }
            pd.DataFrame([csv_result]).to_csv(args.csv, index=False)
            console.print(f"\n[+] CSV exported to {args.csv}", style="green")

    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        exit(1)


if __name__ == "__main__":
    Main()
