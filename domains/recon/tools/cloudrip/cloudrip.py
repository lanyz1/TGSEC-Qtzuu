#!/usr/bin/env python3
"""
CloudRip - Cloudflare Bypasser
Find real IP addresses behind Cloudflare protection by scanning subdomains.
"""

import argparse
import csv
import json
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    AddressValueError,
)
from pathlib import Path
from typing import Optional, TextIO

import dns.resolver
import pyfiglet
import requests
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)


class Colors:
    """Terminal color constants."""
    RED = Fore.RED
    GREEN = Fore.GREEN
    BLUE = Fore.LIGHTBLUE_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    WHITE = Fore.WHITE
    CYAN = Fore.CYAN


class OutputFormat(Enum):
    """Output format types."""
    NORMAL = "normal"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"


@dataclass
class ResolveResult:
    """Result of a DNS resolution attempt."""
    domain: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    status: str = "unknown"
    ipv4_cloudflare: list[str] = field(default_factory=list)  # IPs behind CF
    ipv6_cloudflare: list[str] = field(default_factory=list)  # IPs behind CF
    error: Optional[str] = None

    @property
    def ipv4_non_cf(self) -> list[str]:
        """Get IPv4 addresses not behind Cloudflare."""
        return [ip for ip in self.ipv4 if ip not in self.ipv4_cloudflare]

    @property
    def ipv6_non_cf(self) -> list[str]:
        """Get IPv6 addresses not behind Cloudflare."""
        return [ip for ip in self.ipv6 if ip not in self.ipv6_cloudflare]

    @property
    def has_non_cf_ip(self) -> bool:
        """Check if at least one IP is not behind Cloudflare."""
        return bool(self.ipv4_non_cf or self.ipv6_non_cf)

    @property
    def all_cloudflare(self) -> bool:
        """Check if all resolved IPs are Cloudflare."""
        if not self.ipv4 and not self.ipv6:
            return False
        all_v4_cf = (
            all(ip in self.ipv4_cloudflare for ip in self.ipv4) if self.ipv4 else True
        )
        all_v6_cf = (
            all(ip in self.ipv6_cloudflare for ip in self.ipv6) if self.ipv6 else True
        )
        return all_v4_cf and all_v6_cf


@dataclass
class ScanReport:
    """Complete scan report."""
    target_domain: str
    scan_date: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_checked: int = 0
    found: list[ResolveResult] = field(default_factory=list)
    cloudflare: list[ResolveResult] = field(default_factory=list)
    not_found: list[ResolveResult] = field(default_factory=list)
    errors: list[ResolveResult] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        """Get scan summary statistics."""
        return {
            "found": len(self.found),
            "cloudflare": len(self.cloudflare),
            "not_found": len(self.not_found),
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict:
        """Convert report to dictionary."""
        return {
            "target_domain": self.target_domain,
            "scan_date": self.scan_date,
            "total_checked": self.total_checked,
            "summary": self.summary,
            "results": {
                "found": [asdict(r) for r in self.found],
                "cloudflare": [asdict(r) for r in self.cloudflare],
                "not_found": [asdict(r) for r in self.not_found],
                "errors": [asdict(r) for r in self.errors],
            },
        }


class CloudflareIPRanges:
    """Manages Cloudflare IP ranges with dynamic fetching."""

    API_V4 = "https://www.cloudflare.com/ips-v4"
    API_V6 = "https://www.cloudflare.com/ips-v6"

    # Fallback ranges if API is unreachable
    FALLBACK_V4 = [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ]

    FALLBACK_V6 = [
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._v4_ranges: Optional[list[IPv4Network]] = None
        self._v6_ranges: Optional[list[IPv6Network]] = None
        self._fetched_from_api = False

    def _fetch_from_api(self, url: str) -> list[str]:
        """Fetch IP ranges from Cloudflare API."""
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            return [
                line.strip()
                for line in response.text.strip().split("\n")
                if line.strip()
            ]
        except requests.RequestException:
            return []

    def _load_ranges(self) -> None:
        """Load Cloudflare IP ranges (lazy loading)."""
        if self._v4_ranges is not None and self._v6_ranges is not None:
            return

        # Try fetching from API first
        v4_cidrs = self._fetch_from_api(self.API_V4)
        v6_cidrs = self._fetch_from_api(self.API_V6)

        if v4_cidrs and v6_cidrs:
            self._fetched_from_api = True
        else:
            # Fallback to hardcoded ranges
            v4_cidrs = self.FALLBACK_V4
            v6_cidrs = self.FALLBACK_V6

        self._v4_ranges = [IPv4Network(cidr) for cidr in v4_cidrs]
        self._v6_ranges = [IPv6Network(cidr) for cidr in v6_cidrs]

    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if an IP belongs to Cloudflare."""
        self._load_ranges()

        try:
            ip_obj = IPv4Address(ip)
            return any(ip_obj in network for network in self._v4_ranges)
        except AddressValueError:
            pass

        try:
            ip_obj = IPv6Address(ip)
            return any(ip_obj in network for network in self._v6_ranges)
        except AddressValueError:
            pass

        return False

    @property
    def fetched_from_api(self) -> bool:
        """Check if ranges were fetched from API."""
        self._load_ranges()
        return self._fetched_from_api


class ReportWriter:
    """Handles writing reports in multiple formats."""

    @staticmethod
    def write(report: ScanReport, output_path: Path, fmt: OutputFormat) -> None:
        """Write report to file in specified format."""
        with open(output_path, "w", encoding="utf-8") as f:
            if fmt == OutputFormat.JSON:
                ReportWriter._write_json(report, f)
            elif fmt == OutputFormat.YAML:
                ReportWriter._write_yaml(report, f)
            elif fmt == OutputFormat.CSV:
                ReportWriter._write_csv(report, f)
            else:
                ReportWriter._write_normal(report, f)

    @staticmethod
    def _write_normal(report: ScanReport, output: TextIO) -> None:
        """Write normal text format."""
        output.write("CloudRip Scan Report\n")
        output.write("=" * 60 + "\n")
        output.write(f"Target: {report.target_domain}\n")
        output.write(f"Date: {report.scan_date}\n")
        output.write(f"Total checked: {report.total_checked}\n\n")

        if report.found:
            output.write(f"[FOUND] Non-Cloudflare IPs ({len(report.found)}):\n")
            for r in report.found:
                output.write(f"  {r.domain}\n")
                output.write(f"    {ReportWriter._format_ips(r)}\n")
            output.write("\n")

        if report.cloudflare:
            output.write(f"[CLOUDFLARE] Behind Cloudflare ({len(report.cloudflare)}):\n")
            for r in report.cloudflare:
                output.write(f"  {r.domain}\n")
                output.write(f"    {ReportWriter._format_ips(r)}\n")
            output.write("\n")

        if report.not_found:
            output.write(f"[NOT FOUND] ({len(report.not_found)}):\n")
            for r in report.not_found:
                output.write(f"  {r.domain}\n")
            output.write("\n")

        if report.errors:
            output.write(f"[ERRORS] ({len(report.errors)}):\n")
            for r in report.errors:
                output.write(f"  {r.domain}: {r.error}\n")

    @staticmethod
    def _format_ips(result: ResolveResult) -> str:
        """Format IPs with Cloudflare status indicators."""
        parts = []
        if result.ipv4:
            v4_formatted = []
            for ip in result.ipv4:
                cf_tag = " [CF]" if ip in result.ipv4_cloudflare else ""
                v4_formatted.append(f"{ip}{cf_tag}")
            parts.append(f"v4:[{', '.join(v4_formatted)}]")
        if result.ipv6:
            v6_formatted = []
            for ip in result.ipv6:
                cf_tag = " [CF]" if ip in result.ipv6_cloudflare else ""
                v6_formatted.append(f"{ip}{cf_tag}")
            parts.append(f"v6:[{', '.join(v6_formatted)}]")
        return " | ".join(parts) if parts else "N/A"

    @staticmethod
    def _write_json(report: ScanReport, output: TextIO) -> None:
        """Write JSON format."""
        json.dump(report.to_dict(), output, indent=2)

    @staticmethod
    def _write_yaml(report: ScanReport, output: TextIO) -> None:
        """Write YAML format (custom serializer, no external dependency)."""
        data = report.to_dict()
        ReportWriter._dict_to_yaml(data, output)

    @staticmethod
    def _dict_to_yaml(data: dict, output: TextIO, indent: int = 0) -> None:
        """Convert dict to YAML format recursively."""
        space = "  " * indent
        for key, value in data.items():
            if isinstance(value, dict):
                output.write(f"{space}{key}:\n")
                ReportWriter._dict_to_yaml(value, output, indent + 1)
            elif isinstance(value, list):
                output.write(f"{space}{key}:\n")
                for item in value:
                    if isinstance(item, dict):
                        output.write(f"{space}  -\n")
                        ReportWriter._dict_to_yaml(item, output, indent + 2)
                    else:
                        output.write(f"{space}  - {item}\n")
            else:
                output.write(f"{space}{key}: {value}\n")

    @staticmethod
    def _write_csv(report: ScanReport, output: TextIO) -> None:
        writer = csv.writer(output)
        writer.writerow(
            [
                "domain",
                "ipv4",
                "ipv4_cloudflare",
                "ipv6",
                "ipv6_cloudflare",
                "status",
                "error",
            ]
        )

        for r in report.found + report.cloudflare + report.not_found + report.errors:
            writer.writerow(
                [
                    r.domain,
                    ";".join(r.ipv4) if r.ipv4 else "",
                    ";".join(r.ipv4_cloudflare) if r.ipv4_cloudflare else "",
                    ";".join(r.ipv6) if r.ipv6 else "",
                    ";".join(r.ipv6_cloudflare) if r.ipv6_cloudflare else "",
                    r.status,
                    r.error or "",
                ]
            )


class CloudRip:
    """Main scanner class."""

    def __init__(
        self,
        domain: str,
        wordlists: list[str],
        threads: int = 10,
        output: Optional[str] = None,
        output_format: OutputFormat = OutputFormat.NORMAL,
        verbose: bool = False,
        quiet: bool = False,
    ):
        self.domain = domain
        self.wordlists = wordlists if wordlists else ["dom.txt"]
        self.threads = threads
        self.output = Path(output) if output else None
        self.output_format = output_format
        self.verbose = verbose
        self.quiet = quiet

        self.cf_ranges = CloudflareIPRanges()
        self.report = ScanReport(target_domain=domain)
        self.stop_requested = False

    def log(self, message: str, level: str = "info") -> None:
        """Log a message based on verbosity settings."""
        if self.quiet and level != "error":
            return
        if level == "verbose" and not self.verbose:
            return

        tqdm.write(message)

    def display_banner(self) -> None:
        if self.quiet:
            return

        figlet_text = pyfiglet.Figlet(font="slant").renderText("CloudRip")
        tqdm.write(f"{Colors.BLUE}{figlet_text}")
        tqdm.write(
            f"{Colors.RED}CloudFlare Bypasser - Find Real IP Addresses Behind Cloudflare"
        )
        tqdm.write(f'{Colors.YELLOW}"Ripping through the clouds to expose the truth"')
        tqdm.write(
            f"{Colors.WHITE}GitHub: {Colors.BLUE}https://github.com/moscovium-mc/CloudRip\n"
        )

    def load_wordlists(self) -> list[str]:
        """Load and merge all wordlists."""
        subdomains = set()

        for wordlist in self.wordlists:
            wordlist_path = Path(wordlist)
            if not wordlist_path.exists():
                self.log(f"{Colors.RED}[ERROR] Wordlist not found: {wordlist}", "error")
                sys.exit(1)

            with open(wordlist_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        subdomains.add(stripped)

            self.log(f"{Colors.YELLOW}[INFO] Loaded wordlist: {wordlist_path}")

        self.log(f"{Colors.YELLOW}[INFO] Total unique subdomains: {len(subdomains)}")

        return sorted(subdomains)

    def _resolve_record(self, domain: str, record_type: str) -> list[str]:
        """Resolve a DNS record type and return all IPs."""
        ips = []
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                ips.append(rdata.address)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.resolver.LifetimeTimeout,
        ):
            pass
        except Exception:
            pass
        return ips

    def resolve_domain(self, subdomain: Optional[str] = None) -> ResolveResult:
        """Resolve a domain or subdomain for both A and AAAA records."""
        full_domain = f"{subdomain}.{self.domain}" if subdomain else self.domain

        result = ResolveResult(domain=full_domain)

        # Resolve IPv4 (A records) - get ALL IPs
        ipv4_list = self._resolve_record(full_domain, "A")
        result.ipv4 = ipv4_list
        result.ipv4_cloudflare = [
            ip for ip in ipv4_list if self.cf_ranges.is_cloudflare_ip(ip)
        ]

        # Resolve IPv6 (AAAA records) - get ALL IPs
        ipv6_list = self._resolve_record(full_domain, "AAAA")
        result.ipv6 = ipv6_list
        result.ipv6_cloudflare = [
            ip for ip in ipv6_list if self.cf_ranges.is_cloudflare_ip(ip)
        ]

        # Determine status
        if not result.ipv4 and not result.ipv6:
            result.status = "not_found"
        elif result.has_non_cf_ip:
            result.status = "found"
        elif result.all_cloudflare:
            result.status = "cloudflare"

        return result

    def _log_found(self, result: ResolveResult) -> None:
        """Log a found (non-CF) result."""
        parts = []
        if result.ipv4:
            v4_parts = []
            for ip in result.ipv4:
                if ip in result.ipv4_cloudflare:
                    v4_parts.append(f"{ip}{Colors.YELLOW}[CF]{Colors.WHITE}")
                else:
                    v4_parts.append(ip)
            parts.append(f"v4:[{', '.join(v4_parts)}]")
        if result.ipv6:
            v6_parts = []
            for ip in result.ipv6:
                if ip in result.ipv6_cloudflare:
                    v6_parts.append(f"{ip}{Colors.YELLOW}[CF]{Colors.WHITE}")
                else:
                    v6_parts.append(ip)
            parts.append(f"v6:[{', '.join(v6_parts)}]")

        ips_str = f"{Colors.WHITE} | ".join(parts)
        self.log(f"{Colors.GREEN}[FOUND] {result.domain} -> {ips_str}")

    def _log_cloudflare(self, result: ResolveResult) -> None:
        """Log a Cloudflare result."""
        parts = []
        if result.ipv4:
            parts.append(f"v4:[{', '.join(result.ipv4)}]")
        if result.ipv6:
            parts.append(f"v6:[{', '.join(result.ipv6)}]")

        ips_str = " | ".join(parts)
        self.log(f"{Colors.YELLOW}[CLOUDFLARE] {result.domain} -> {ips_str}")

    def add_result(self, result: ResolveResult) -> None:
        """Add a result to the appropriate category and log it."""
        if result.status == "found":
            self.report.found.append(result)
            self._log_found(result)
        elif result.status == "cloudflare":
            self.report.cloudflare.append(result)
            self._log_cloudflare(result)
        elif result.status == "not_found":
            self.report.not_found.append(result)
            self.log(f"{Colors.RED}[NOT FOUND] {result.domain}", "verbose")
        elif result.error:
            self.report.errors.append(result)
            self.log(f"{Colors.YELLOW}[ERROR] {result.domain}: {result.error}", "verbose")

    def save_report(self) -> None:
        """Save the scan report to file."""
        if not self.output:
            return

        try:
            ReportWriter.write(self.report, self.output, self.output_format)
            self.log(f"{Colors.GREEN}[INFO] Results saved to {self.output}")
        except Exception as e:
            self.log(f"{Colors.RED}[ERROR] Failed to save report: {e}", "error")

    def handle_interrupt(self, signum: int, frame) -> None:
        """Handle Ctrl+C gracefully."""
        if self.stop_requested:
            tqdm.write(f"{Colors.RED}\n[INFO] Force quitting...")
            sys.exit(0)

        tqdm.write(f"{Colors.RED}\n[INFO] Ctrl+C detected. Quit? (y/n): ")

        try:
            if input().strip().lower() == "y":
                self.stop_requested = True
            else:
                tqdm.write(f"{Colors.YELLOW}[INFO] Resuming...")
        except EOFError:
            self.stop_requested = True

    def run(self) -> ScanReport:
        """Run the scan."""
        signal.signal(signal.SIGINT, self.handle_interrupt)

        self.display_banner()

        # Show CF IP ranges status
        if self.cf_ranges.fetched_from_api:
            self.log(f"{Colors.GREEN}[INFO] Using Cloudflare IP ranges from API")
        else:
            self.log(f"{Colors.YELLOW}[INFO] Using fallback Cloudflare IP ranges")

        # Load wordlists
        subdomains = self.load_wordlists()

        # Check root domain first
        self.log(f"{Colors.YELLOW}[INFO] Checking root domain: {self.domain}")
        root_result = self.resolve_domain()
        self.add_result(root_result)
        self.report.total_checked += 1

        # Scan subdomains
        self.log(f"{Colors.YELLOW}[INFO] Starting subdomain scan...\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.resolve_domain, sub): sub for sub in subdomains
            }

            # Progress bar (disabled in quiet mode)
            with tqdm(
                total=len(futures),
                desc=f"{Colors.CYAN}Scanning",
                unit="sub",
                disable=self.quiet,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
                ncols=80,
                leave=False,
            ) as pbar:
                for future in as_completed(futures):
                    if self.stop_requested:
                        self.log(f"{Colors.RED}[INFO] Scan interrupted.")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    result = future.result()
                    self.add_result(result)
                    self.report.total_checked += 1
                    pbar.update(1)

                    # Update progress bar with current stats
                    found = len(self.report.found)
                    cf = len(self.report.cloudflare)
                    pbar.set_postfix_str(f"found:{found} cf:{cf}")

                    time.sleep(0.05)

        # Summary
        self.log(f"\n{Colors.WHITE}{'=' * 60}")
        self.log(f"{Colors.CYAN}Scan Summary:")
        self.log(f"{Colors.GREEN}  Found (non-CF): {len(self.report.found)}")
        self.log(f"{Colors.YELLOW}  Cloudflare: {len(self.report.cloudflare)}")
        self.log(f"{Colors.RED}  Not found: {len(self.report.not_found)}")
        if self.report.errors:
            self.log(f"{Colors.RED}  Errors: {len(self.report.errors)}")
        self.log(f"{Colors.WHITE}{'=' * 60}\n")

        # Save report
        self.save_report()

        self.log(f"{Colors.WHITE}Scan complete.")
        return self.report


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="CloudRip - Cloudflare Bypasser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cloudrip.py example.com
  python3 cloudrip.py example.com -w subs.txt -t 20 -o report.json -f json
  python3 cloudrip.py example.com -w list1.txt -w list2.txt -v
  python3 cloudrip.py example.com -q -o found.txt
        """,
    )

    parser.add_argument("domain", help="Target domain (e.g., example.com)")

    parser.add_argument(
        "-w",
        "--wordlist",
        action="append",
        dest="wordlists",
        default=[],
        help="Wordlist file(s). Can be specified multiple times.",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Concurrent threads (default: 10)",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file for report",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["normal", "json", "yaml", "csv"],
        default="normal",
        help="Output format (default: normal)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all results including not found",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Minimal output (only found IPs)",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    scanner = CloudRip(
        domain=args.domain,
        wordlists=args.wordlists,
        threads=args.threads,
        output=args.output,
        output_format=OutputFormat(args.format),
        verbose=args.verbose,
        quiet=args.quiet,
    )

    scanner.run()


if __name__ == "__main__":
    main()
