#!/usr/bin/env python3

import requests
from markdown import markdown
from bs4 import BeautifulSoup as bsoup
from rich import print as rprint
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from dotenv import load_dotenv, set_key

import argparse
import argcomplete
import sys
import platform
import subprocess
import re
import os
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

from CVE2PoC.core.user_agent import get_user_agent
from CVE2PoC.core.banner import banner
from CVE2PoC.core.report import (
    generate_json_report,
    generate_html_report,
    get_cve_record_and_exploits,
)
from CVE2PoC.core.bug_bounty import search_bug_bounty_reports
from CVE2PoC.core.cpe import cpe_to_cveid, cveid_to_cpe
from CVE2PoC.core.labs import (
    search_pre_built_vulnerable_docker_environments,
    search_ctf_labs,
)
from CVE2PoC.core.exploits import (
    download_exploits_db,
    search_exploits_from_other_sources,
    search_github_exploits,
    get_exploit_programming_language,
)
from CVE2PoC.core.display import display_cve_info, display_poc_info
from CVE2PoC.core.cve import (
    check_cve_id_format,
    check_ransomware_group_usage,
    get_cve_description,
    retrieve_cve_info_from_cve_org,
    download_first_epss,
    get_epss,
    is_kev,
    download_cisa_kev,
    get_cve_references,
)
from CVE2PoC.core.mitigations import (
    get_cveid_nuclei_template,
    get_nuclei_remediations,
    get_sentinelone_vulnerability_database_mitigations,
)
from CVE2PoC.core.config import BASE_DIR


def main():
    parser = argparse.ArgumentParser(
        prog="cve2poc.py",
        description="A simple yet powerful tool to quickly find PoCs related to a CVE ID",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, width=120, max_help_position=50
        ),
    )
    parser.add_argument("cve", type=str, nargs="?", help="CVE ID")
    parser.add_argument(
        "-x",
        "--examine",
        metavar="",
        type=str,
        nargs=1,
        help="Examine an exploit's README file",
    )
    parser.add_argument(
        "-d", "--description", action="store_true", help="Display a CVE ID description"
    )
    parser.add_argument(
        "-f", "--file", type=str, help="Specify a file containing a list of CVE IDs"
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Output directory to store the reports"
    )
    parser.add_argument("-l", "--language", help="Filter PoCs by programming language")
    parser.add_argument(
        "--limit", type=int, default=10, help="Number of PoCs to display"
    )
    parser.add_argument(
        "-t",
        "--threads",
        metavar="",
        type=int,
        default=10,
        help="Number of concurrent threads",
    )
    parser.add_argument(
        "--labs",
        type=str,
        metavar="CVE ID",
        help="Search pre-built docker environments and Hands-on labs related to a CVE ID",
    )
    parser.add_argument(
        "--bugbounty-reports",
        type=str,
        metavar="CVE ID",
        help="Search Bug Bounty reports related to a CVE ID",
    )
    parser.add_argument(
        "--mitigations",
        type=str,
        metavar="CVE ID",
        help="Remediation steps to fix a vulnerability",
    )
    parser.add_argument(
        "--cve2cpe",
        type=str,
        metavar="CVE ID",
        help="Retrieve CPEs related to a CVE ID",
    )
    parser.add_argument(
        "--cpe2cve", type=str, metavar="CPE", help="Retrieve CVEs related to a CPE"
    )
    parser.add_argument(
        "-s",
        "--save",
        type=str,
        metavar="FILE",
        help="Output file to save CPE2CVE results",
    )
    parser.add_argument(
        "--api-keys",
        action="store_true",
        help="Configure your GitHub and NVD API keys (Not required)",
    )
    parser.add_argument("--no-banner", action="store_true", help="Remove banner")
    # Enable argcomplete
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    # API keys configuration (This is not required)
    load_dotenv()
    env_path = os.path.join(BASE_DIR, ".env")
    if args.api_keys is True:
        # Github API token Configuration
        print(
            f"\nGitHub API Token Configuration\n{'-' * len('GitHub API Token Configuration')}"
        )
        if os.getenv("GITHUB_API_TOKEN") is None:
            rprint("[bright_blue][*][/bright_blue] Enter your GitHub token: ", end="")
            gh_api_token = getpass("")
            # Create or update the .env file
            success, _, _ = set_key(env_path, "GITHUB_API_TOKEN", gh_api_token)
            # Check if the token was successfully added to the .env file
            if success:
                rprint(
                    "[spring_green2][+][/spring_green2] Your token was successfully added!"
                )
            else:
                rprint("[red3][-][/red3] Failed to write the token! Try again!")
                sys.exit(1)
        else:
            rprint(
                "[gold1][!][/gold1] A GitHub access token already exists!\n[bright_blue][*][/bright_blue] Would you like to overwritte it? [Y/n] ",
                end="",
            )

            user_choice = input("")
            if user_choice.lower() in ["", "y", "yes"]:
                rprint(
                    "[bright_blue][*][/bright_blue] Enter your GitHub token: ", end=""
                )
                gh_api_token = getpass("")
                success, _, _ = set_key(env_path, "GITHUB_API_TOKEN", gh_api_token)
                if success:
                    rprint(
                        "[spring_green2][+][/spring_green2] Your token was successfully added!"
                    )
                else:
                    rprint("[red3][-][/red3] Failed to write the token! Try again!")
                    sys.exit(1)

        # NVD API Key Configuration
        print(f"\nNVD API Key Configuration\n{'-' * len('NVD API Key Configuration')}")
        if os.getenv("NVD_API_KEY") is None:
            rprint("[bright_blue][*][/bright_blue] Enter your new API key: ", end="")
            nvd_api_key = getpass("")
            success, _, _ = set_key(env_path, "NVD_API_KEY", nvd_api_key)
            if success:
                rprint(
                    "[spring_green2][+][/spring_green2] Your API key was successfully added!"
                )
                sys.exit(0)
            else:
                rprint("[red3][-][/red3] Failed to write the API key! Try again!")
                sys.exit(1)
        else:
            rprint(
                "[gold1][!][/gold1] An API key already exists for NVD!\n[bright_blue][*][/bright_blue] Would you like to overwritte it? [Y/n] ",
                end="",
            )
            user_choice = input("")
            if user_choice.lower() in ["", "y", "yes"]:
                rprint(
                    "[bright_blue][*][/bright_blue] Enter your new API key: ", end=""
                )
                nvd_api_key = getpass("")
                success, _, _ = set_key(env_path, "NVD_API_KEY", nvd_api_key)
                if success:
                    rprint(
                        "[spring_green2][+][/spring_green2] Your API key was successfully added!"
                    )
                    sys.exit(0)
                else:
                    rprint("[red3][-][/red3] Failed to write the API key! Try again!")
                    sys.exit(1)
            else:
                sys.exit(0)

    # Check if API keys were submitted, and update the headers accordingly
    headers = []
    github_headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-agent": f"{get_user_agent()}",
    }
    nvd_headers = {"User-agent": f"{get_user_agent()}"}

    gh_api_token = os.getenv("GITHUB_API_TOKEN")
    if gh_api_token:
        github_headers["Authorization"] = f"Bearer {gh_api_token}"

    nvd_api_key = os.getenv("NVD_API_KEY")
    if nvd_api_key:
        nvd_headers["apiKey"] = nvd_api_key

    headers.extend([github_headers, nvd_headers])

    # Display the README.md file for a repository
    if args.examine is not None:
        # Try first to retrieve the README.md using the main branch
        if not args.examine[0].lower().startswith("https://github.com/"):
            rprint("[red3][-][/red3] Please submit a GitHub repository link!\n")
            parser.print_help(sys.stderr)
            sys.exit(1)
        readme = requests.get(
            f"https://raw.githubusercontent.com/{args.examine[0].split('https://github.com/')[-1]}/refs/heads/main/README.md",
            headers=github_headers,
        )
        if readme.status_code == 404:
            # Fallback on the master branch if the script failed to retrieve the README.md file from the main branch
            readme = requests.get(
                f"https://raw.githubusercontent.com/{args.examine[0].split('https://github.com/')[-1]}/refs/heads/master/README.md",
                headers=github_headers,
            )
        if readme.status_code == 200:
            md_response = markdown(readme.text)
            soup = bsoup(md_response, "html.parser")
            # Display the README.md content using "less" command to avoid rendering lots of text on the terminal (Only works for Linux and MacOS)
            if platform.system() == "Linux" or platform.system() == "Darwin":
                subprocess.run(["less"], input=soup.get_text(), text=True)
            else:
                print(soup.get_text())
            sys.exit(0)
        else:
            rprint("[red3][-][/red3] README.md was not found!")
            sys.exit(1)
    
    # Remediation steps to fix a vulnerability
    if args.mitigations:
        cve_id = args.mitigations
        if not check_cve_id_format(cve_id):
            rprint("[red3][-][/red3] The CVE ID format is incorrect (e.g: CVE-2025-55182)")
            sys.exit(1)
        # Retrieve remediation steps from Nuclei
        nuclei_template = get_cveid_nuclei_template(cve_id)
        if nuclei_template:
            nuclei_remediation_steps = get_nuclei_remediations(nuclei_template)
        else:
            nuclei_remediation_steps = 'N/A'
        # Retrieve remediation steps from SentinelOne Vulnerability Database
        sentinelone_vulnerability_database_mitigations_url = get_sentinelone_vulnerability_database_mitigations(cve_id)
        # Display remediation steps
        if nuclei_remediation_steps != 'N/A':
            print(f'- {nuclei_remediation_steps.strip()}')
        if sentinelone_vulnerability_database_mitigations_url != 'N/A':
            print(f"- For more information, refer here: {sentinelone_vulnerability_database_mitigations_url}")
        if nuclei_remediation_steps == 'N/A' and sentinelone_vulnerability_database_mitigations_url == 'N/A':
            rprint(f'[red3][-][/red3] No remediation steps found for {cve_id}!')
        sys.exit(0)
    
    # Return all CVE IDs related to a CPE
    if args.cpe2cve:
        cpe = args.cpe2cve
        cve_ids = cpe_to_cveid(cpe)
        if cve_ids == "Incorrect Format":
            rprint(
                "[red3][-][/red3] The CPE format is incorrect (e.g: cpe:2.3:o:microsoft:windows_10:1607)"
            )
            sys.exit(1)
        elif cve_ids == "N/A":
            rprint("[red3][-][/red3] No CVE ID found for this CPE!")
            sys.exit(0)
        else:
            if args.save:
                with open(args.save, "w") as f:
                    f.write(cve_ids)
                    rprint(f"The CVE IDs have been successfully written in {f.name}")
                    sys.exit(0)
            else:
                rprint(
                    f"List of Affected CVE IDs\n{'-' * len('List of affected CVE IDs')}"
                )
                print(cve_ids)
                sys.exit(0)

    # Return all CPEs related to a CVE ID (Pipe the output to grep to avoid being overload with lots of CPEs)
    if args.cve2cpe:
        cpes = cveid_to_cpe(args.cve2cpe)
        if cpes != "N/A":
            print(
                f"\nKnown Affected Software Configurations (CPE2.3)\n{'-' * len('Known Affected Software Configurations (CPE2.3)')}"
            )
            for cpe in cpes:
                namespace, cpe_version, asset_type, vendor, product, product_version = (
                    cpe.split(":")
                )
                rprint(
                    f"[bright_blue]{namespace}[/bright_blue][bright_white]:[/bright_white][bright_cyan]{cpe_version}[/bright_cyan][bright_white]:[/bright_white][dark_orange]{asset_type}[/dark_orange][bright_white]:[/bright_white][spring_green2]{vendor}[/spring_green2][bright_white]:[/bright_white][bright_yellow]{product}[/bright_yellow][bright_white]:[/bright_white][bright_red]{product_version}[/bright_red]"
                )
            sys.exit(0)
        else:
            rprint("[red3][-][/red3] No CPEs found for this CVE ID!")
            sys.exit(1)

    if args.labs:
        cve_id = args.labs
        pre_built_vulnerable_docker_environments = (
            search_pre_built_vulnerable_docker_environments(cve_id)
        )
        if pre_built_vulnerable_docker_environments != "N/A":
            print(
                f"\nPre-Built Docker Environments\n{'-' * len('Pre-Built Docker Environments')}"
            )
            rprint(pre_built_vulnerable_docker_environments)
        # Search THM rooms and HTB machines related to a CVE ID
        labs = search_ctf_labs(cve_id)
        if labs:
            print(f"\nHands-On Labs\n{'-' * len('Hands-On Labs')}")
            table = Table(show_lines=True, header_style="bold")
            table.add_column("Platform")
            table.add_column("Room/Machine")
            if labs.get("htb"):
                table.add_row("HackTheBox", labs["htb"])
            if labs.get("thm"):
                table.add_row("TryHackMe", labs["thm"])
            rprint(table)
        if not labs and pre_built_vulnerable_docker_environments == "N/A":
            rprint("\n[red3][-][/red3] No labs found for this CVE ID!")
        sys.exit(0)

    if args.bugbounty_reports:
        cve_id = args.bugbounty_reports
        bug_bounty_reports = search_bug_bounty_reports(args.bugbounty_reports)
        if bug_bounty_reports:
            print(f"\nBug Bounty Reports\n{'-' * len('Bug Bounty Reports')}")
            table = Table(show_lines=True, header_style="bold")
            table.add_column("Source")
            table.add_column("PoC")
            table.add_column("Report")
            if bug_bounty_reports.get("h1"):
                poc_is_available, report_link = bug_bounty_reports["h1"]
                table.add_row("HackerOne", poc_is_available, report_link)
            if bug_bounty_reports.get("pentesterland"):
                poc_is_available, report_link = bug_bounty_reports["pentesterland"]
                table.add_row("pentesterland", poc_is_available, report_link)
            if bug_bounty_reports.get("bug_bounty_hunting_search_engine"):
                poc_is_available, report_link = bug_bounty_reports[
                    "bug_bounty_hunting_search_engine"
                ]
                table.add_row(
                    "Bug Bounty Hunting Search Engine", poc_is_available, report_link
                )

            rprint(table)
        else:
            rprint("\n[red3][-][/red3] No reports found for this CVE ID!")
        sys.exit(0)

    # Display banner
    if not args.no_banner:
        banner()

    if args.limit < 1:
        parser.error("--limit must be >= 1")

    if args.file:
        # Check if the submitted file exists
        cve_ids_file_path = args.file
        if not os.path.exists(cve_ids_file_path):
            rprint("[red3][-][/red3] File not found!")
            sys.exit(-1)
        # Check if the user specified an output directory to store the report
        if args.output:
            output_dir = args.output
            if not os.path.exists(output_dir):
                rprint("[red3][-][/red3] Output directory not found!")
                sys.exit(-1)
        else:
            # The report will be saved in the current working directory by default
            output_dir = os.getcwd()

        # Download CISA KEVs and First EPSS data
        kevs = download_cisa_kev()
        epss_data = download_first_epss()

        with open(cve_ids_file_path) as f:
            cve_ids = [file.strip() for file in f.readlines()]
            # json_report stores the report information in a json format
            json_report = {}
            progress_bar = Progress(
                TextColumn("[bold gold1]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("•"),
                MofNCompleteColumn(),
                TextColumn("•"),
                TimeElapsedColumn(),
                TextColumn("•"),
                TimeRemainingColumn(),
            )
            with progress_bar as p:
                exploits_db = download_exploits_db()
                with ThreadPoolExecutor(max_workers=args.threads) as executor:
                    futures = {
                        executor.submit(
                            get_cve_record_and_exploits,
                            cve_id,
                            headers,
                            kevs,
                            epss_data,
                            exploits_db,
                        ): cve_id
                        for cve_id in cve_ids
                    }

                    for future in p.track(
                        as_completed(futures),
                        total=len(futures),
                        description="Generating the report",
                    ):
                        result, error = future.result()

                        if error:
                            rprint(f"[gold1][!][/gold1] {error}")
                            continue

                        cve_id = result["cve_id"]
                        cve_record = result["cve_record"]
                        pocs_from_other_sources = result["pocs_from_other_sources"]
                        gh_exploits, poc_url = result["github_pocs"]

                        # Check the state of the CVE ID
                        if cve_record is None:
                            rprint(
                                f"[gold1][!][/gold1] Skipping {cve_id}: No record found"
                            )
                            continue
                        elif cve_record["state"] == "RESERVED":
                            rprint(
                                f"{cve_id.upper()} is [bold]reserved[/bold]. No entry is available in the NVD. Refer to CVE.org for more information."
                            )
                            continue
                        elif cve_record["state"] == "REJECTED":
                            rprint(
                                f"[gold1][!][/gold1] Skipping {cve_id}: The CVE ID was rejected for the following reason: [gold1]{cve_record['rejectedReasons']}[/gold1]"
                            )
                            continue
                        else:
                            json_report[cve_id.upper()] = {}
                            json_report[cve_id.upper()]["Publication Date"] = (
                                cve_record["publication_date"]
                            )
                            json_report[cve_id.upper()]["Severity"] = cve_record.get(
                                "severity", "N/A"
                            )
                            json_report[cve_id.upper()]["Base Score"] = cve_record.get(
                                "base_score", "N/A"
                            )
                            json_report[cve_id.upper()]["EPSS"] = cve_record.get(
                                "epss", "N/A"
                            )
                            json_report[cve_id.upper()]["KEV"] = cve_record.get(
                                "kev", "N/A"
                            )
                            json_report[cve_id.upper()]["Vendor"] = cve_record.get(
                                "vendor", "N/A"
                            )
                            json_report[cve_id.upper()]["Affected Product"] = (
                                cve_record.get("affected_product")
                            )
                            if cve_record.get("cwe") is not None:
                                if cve_record["cwe"]:
                                    cwes = []
                                    for cwe in cve_record["cwe"]:
                                        cwes.append(cwe)
                                    cwe = ",".join(cwes)
                                else:
                                    cwe = "N/A"
                            else:
                                cwe = "N/A"
                            json_report[cve_id.upper()]["CWE"] = cwe
                            json_report[cve_id.upper()]["Vector String"] = (
                                cve_record.get("vector_string", "N/A")
                            )
                            json_report[cve_id.upper()]["PoCs"] = {}

                        # GitHub PoCs
                        if len(gh_exploits):
                            json_report[cve_id.upper()]["PoCs"]["GitHub"] = (
                                poc_url,
                                len(gh_exploits),
                            )
                        else:
                            json_report[cve_id.upper()]["PoCs"]["GitHub"] = "No"
                        if len(pocs_from_other_sources):
                            # Metasploit PoCs
                            if (
                                pocs_from_other_sources.get("metasploit", None)
                                is not None
                            ):
                                metasploit_link = (
                                    "https://www.rapid7.com/db/modules/"
                                    + pocs_from_other_sources["metasploit"][0]
                                )
                                json_report[cve_id.upper()]["PoCs"]["Metasploit"] = (
                                    metasploit_link
                                )
                            else:
                                json_report[cve_id.upper()]["PoCs"]["Metasploit"] = "No"
                            # ExploitDB PoCs
                            if (
                                pocs_from_other_sources.get("exploitdb", None)
                                is not None
                            ):
                                exploit_db_link = (
                                    "https://www.exploit-db.com/exploits/"
                                    + pocs_from_other_sources["exploitdb"][-1]
                                )
                                json_report[cve_id.upper()]["PoCs"]["ExploitDB"] = (
                                    exploit_db_link
                                )
                            else:
                                json_report[cve_id.upper()]["PoCs"]["ExploitDB"] = "No"
                            # Nuclei PoCs
                            if pocs_from_other_sources.get("nuclei", None) is not None:
                                json_report[cve_id.upper()]["PoCs"]["Nuclei"] = (
                                    pocs_from_other_sources["nuclei"][-1]
                                )
                            else:
                                json_report[cve_id.upper()]["PoCs"]["Nuclei"] = "No"
                        else:
                            # No PoCs found for Metasploit, ExploitDB and Nuclei
                            json_report[cve_id.upper()]["PoCs"]["Metasploit"] = "No"
                            json_report[cve_id.upper()]["PoCs"]["ExploitDB"] = "No"
                            json_report[cve_id.upper()]["PoCs"]["Nuclei"] = "No"

                    if generate_json_report(json_report, output_dir):
                        rprint(
                            "[green1][+][/green1] The json report was successfully generated."
                        )
                    else:
                        rprint("[red3][-][/red3] An error occured!")

                    if generate_html_report(json_report, output_dir):
                        rprint(
                            "[green1][+][/green1] The html report was successfully generated."
                        )
                    else:
                        rprint("[red3][-][/red3] An error occured!")
        sys.exit(0)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        if args.cve:
            cve_id = args.cve
            # Check CVE ID format
            if not check_cve_id_format(cve_id):
                rprint(
                    "[red3][-][/red3] The CVE ID format is incorrect (e.g: CVE-2025-55182)"
                )
                sys.exit(1)

            # Get CVE ID's record
            cve_record = retrieve_cve_info_from_cve_org(cve_id, headers)
            if cve_record is None:
                rprint(f"[red3][-][/red3] No CVE record found for {args.cve.upper()}")
                sys.exit(1)
            # Check the state of the CVE ID
            elif cve_record["state"] == "RESERVED":
                rprint(
                    f"{cve_id.upper()} is [bold]reserved[/bold]. No entry is available in the NVD. Refer to CVE.org for more information."
                )
                sys.exit(0)
            elif cve_record["state"] == "REJECTED":
                rprint(
                    f"{cve_id.upper()} was rejected for the following reason: [gold1]{cve_record['rejectedReasons']}[/gold1]"
                )
                sys.exit(0)
            else:
                # EPSS
                epss_dict = download_first_epss()
                cve_record["epss_score"] = get_epss(cve_id, epss_dict)
                # KEV
                kevs = download_cisa_kev()
                if kevs is not None:
                    kev_status, kev_record = is_kev(kevs, cve_id)
                    if kev_status == "Yes":
                        cve_record["kev"] = "Yes"
                        cve_record["references"] = re.findall(
                            "https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)",
                            kev_record["notes"],
                        )
                    else:
                        cve_record["kev"] = "No"
                rprint(display_cve_info(cve_record))

            # Display additional information if description flag was specified
            if args.description:
                cve_description = get_cve_description(cve_id.upper())
                if cve_description != "N/A":
                    cve_description = re.sub(r"\s+", " ", cve_description)
                    rprint(
                        f"\nDescription\n{'-' * len('Description')}\n{cve_description}"
                    )
                else:
                    rprint(
                        f"\nDescription\n{'-' * len('Description')}\n[red3][-][/red3] No description found!"
                    )

                # Check whether CVE ID is a KEV and if it's being used in ransomware campaigns
                if cve_record["kev"] == "Yes":
                    known_to_be_used_in_ransomware_campaigns = (
                        check_ransomware_group_usage(cve_id)
                    )
                    if known_to_be_used_in_ransomware_campaigns == "Known":
                        known_to_be_used_in_ransomware_campaigns = "[red3]Known[/red3]"
                    rprint(
                        f"\nKnown To Be Used in Ransomware Campaigns?\n{'-' * len('Known To Be Used in Ransomware Campaigns?')}\n{known_to_be_used_in_ransomware_campaigns}"
                    )

                # References
                references = get_cve_references(cve_id, cve_record)
                rprint(f"\nReferences\n{'-' * len('References')}")
                reference_table = Table(show_lines=True, header_style="bold")
                reference_table.add_column("Source", overflow="fold", justify="center")
                reference_table.add_column("URL", overflow="fold", justify="center")
                for reference, url in references.items():
                    reference_table.add_row(reference, url)
                rprint(reference_table)
                sys.exit(0)

            # Search PoCs
            progress.add_task(
                description="[bright_blue][*][/bright_blue] Searching Exploits...",
                total=None,
            )
            gh_api_key = github_headers.get("Authorization", None)
            # Nomi-sec GitHub PoCs
            gh_pocs, poc_url = search_github_exploits(cve_id, github_headers)
            if poc_url.endswith(".json"):
                # Ranking PoCs by their number of stars and forks. Make sure to always read the code though
                sorted_pocs = sorted(
                    gh_pocs,
                    key=lambda x: (x["stargazers_count"], x["forks"]),
                    reverse=True,
                )
                n_pocs = len(sorted_pocs)
                for i in range(n_pocs):
                    # By default, the program will return the first 10 exploits. This behavior can be changed by specifying the args.limit option
                    if i < args.limit:
                        sorted_pocs[i]["programming_language"] = (
                            get_exploit_programming_language(
                                sorted_pocs[i]["full_name"], github_headers
                            )
                        )

                # Filtering PoCs by programming language (This is generally useful for LPE)
                if not args.language:
                    for counter, poc in enumerate(sorted_pocs, start=1):
                        if counter > args.limit:
                            break
                        poc_title = f"PoC n°{counter}"
                        rprint(display_poc_info(poc, poc_title, gh_api_key))
                else:
                    poc_number = 1
                    programming_language_found = False
                    for counter, poc in enumerate(sorted_pocs, start=1):
                        if counter > args.limit:
                            break
                        if (
                            poc["programming_language"].capitalize()
                            == args.language.capitalize()
                        ):
                            poc_title = f"PoC n°{poc_number}"
                            rprint(display_poc_info(poc, poc_title, gh_api_key))
                            poc_number += 1
                            programming_language_found = True
                    if not programming_language_found:
                        rprint(
                            f"\n[red3][-][/red3] No PoCs found in [orange_red1]{args.language}[/orange_red1]!"
                        )
            elif poc_url.endswith(".md"):
                # TrickestCVE GitHub PoCs
                if len(gh_pocs):
                    trickest_cve_pocs = []
                    # If a PoC does not start with https://github.com/, this means that TrickestCVE returns references
                    pocs_references = not all(
                        x.text.startswith("https://github.com/") for x in gh_pocs
                    )
                    for counter, poc in enumerate(gh_pocs, start=1):
                        if counter > args.limit:
                            break
                        html_url = poc.text
                        # Deal with false positives
                        if not pocs_references and html_url not in [
                            "https://github.com/fkie-cad/nvd-json-data-feeds",
                            "https://github.com/nomi-sec/PoC-in-GitHub",
                            "https://github.com/ARPSyndicate/cvemon",
                            "https://github.com/ARPSyndicate/cve-scores",
                        ]:
                            full_name = html_url.split("https://github.com/")[-1]
                            # Check GitHub API rate limit (https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) for more information (By default, you have a limit of 60 requests)
                            gh_poc_repo_info = requests.get(
                                f"https://api.github.com/repos/{full_name}",
                                headers=github_headers,
                            )
                            if gh_poc_repo_info.status_code == 200:
                                trickest_cve_pocs.append(
                                    {
                                        "description": gh_poc_repo_info.json()[
                                            "description"
                                        ],
                                        "created_at": gh_poc_repo_info.json()[
                                            "created_at"
                                        ],
                                        "updated_at": gh_poc_repo_info.json()[
                                            "updated_at"
                                        ],
                                        "stargazers_count": gh_poc_repo_info.json()[
                                            "stargazers_count"
                                        ],
                                        "forks": gh_poc_repo_info.json()["forks_count"],
                                        "html_url": gh_poc_repo_info.json()["html_url"],
                                        "programming_language": gh_poc_repo_info.json()[
                                            "language"
                                        ]
                                        if gh_poc_repo_info.json()["language"]
                                        else "N/A",
                                    }
                                )
                        elif html_url not in [
                            "https://github.com/fkie-cad/nvd-json-data-feeds",
                            "https://github.com/nomi-sec/PoC-in-GitHub",
                            "https://github.com/ARPSyndicate/cvemon",
                            "https://github.com/ARPSyndicate/cve-scores",
                        ]:
                            trickest_cve_pocs.append(html_url)

                    if (
                        isinstance(trickest_cve_pocs, list)
                        and all(isinstance(x, dict) for x in trickest_cve_pocs)
                        and len(trickest_cve_pocs) > 0
                    ):
                        sorted_pocs = sorted(
                            trickest_cve_pocs,
                            key=lambda x: (x["stargazers_count"], x["forks"]),
                            reverse=True,
                        )
                        if not args.language:
                            for counter, poc in enumerate(sorted_pocs, start=1):
                                if counter > args.limit:
                                    break
                                poc_title = f"PoC n°{counter}"
                                rprint(
                                    display_poc_info(poc, poc_title, gh_api_key), end=""
                                )
                        else:
                            poc_number = 1
                            programming_language_found = False
                            for counter, poc in enumerate(sorted_pocs, start=1):
                                if counter > args.limit:
                                    break
                                if (
                                    poc["programming_language"].capitalize()
                                    == args.language.capitalize()
                                ):
                                    poc_title = f"PoC n°{poc_number}"
                                    rprint(display_poc_info(poc, poc_title, gh_api_key))
                                    poc_number += 1
                                    programming_language_found = True
                            if not programming_language_found:
                                rprint(
                                    f"\n[red3][-][/red3] No PoCs found in [orange_red1]{args.language}[/orange_red1]!"
                                )
                    else:
                        for counter, poc in enumerate(trickest_cve_pocs, start=1):
                            poc_title = f"PoC n°{counter}"
                            if counter > args.limit:
                                break
                            rprint(
                                f"[red3]{' ' * 46}┌{len(f'{poc_title}') * '─'}┐\n{'─' * 46}│{poc_title.center(len(poc_title))}│{'─' * 46}\n{' ' * 46}└{len(poc_title) * '─'}┘[/red3]\n{poc}"
                            )
                    if not trickest_cve_pocs:
                        rprint(
                            f"\n[red3][-][/red3] No PoCs found on GitHub for {cve_id.upper()}!"
                        )
            else:
                # No PoCs found on Nomi-sec and TrickestCVE
                rprint(
                    f"\n[red3][-][/red3] No PoCs found on GitHub for {cve_id.upper()}!"
                )
        else:
            rprint("[red3][-][/red3] Please specify a CVE ID!\n")
            parser.print_help(sys.stderr)
            sys.exit(1)

    # Search exploits on ExploitDB, Metasploit and Nuclei
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(
            description="[bright_blue][*][/bright_blue] Searching for exploits on other sources...",
            total=None,
        )
        rprint(
            f"[red3]{' ' * 38}┌{len('PoCs From Other Sources') * '─'}┐\n{'─' * 38}│{'PoCs From Other Sources'.center(len('PoCs From Other Sources'))}│{'─' * 38}\n{' ' * 38}└{len('PoCs From Other Sources') * '─'}┘[/red3]"
        )
        # Download exploit_db, msfconsole and nuclei databases
        msf_modules_db_json, exploit_db_csv, nuclei_db_json = download_exploits_db()
        sources = search_exploits_from_other_sources(
            cve_id.upper(), msf_modules_db_json, exploit_db_csv, nuclei_db_json
        )
        if sources:
            for source, exploit in sources.items():
                if source == "metasploit":
                    rprint(
                        f"Metasploit:[magenta3] msfconsole -q -x 'use {exploit[0]}'[/magenta3] (Rank: {exploit[-1]})\n"
                    )
                elif source == "exploitdb":
                    rprint(
                        f"ExploitDB:[magenta3] searchsploit -m {exploit[0]}[/magenta3]\n"
                    )
                elif source == "nuclei":
                    nuclei_template_path, nuclei_template_url = exploit
                    if nuclei_template_path:
                        rprint(
                            f"Nuclei:[magenta3] nuclei -t {nuclei_template_path} [-u <target>] [-l <hosts.txt>][/magenta3]\n"
                        )
                    else:
                        rprint(f"Nuclei:[magenta3] {nuclei_template_url}[/magenta3]\n")
                else:
                    rprint(f"GHSA:[magenta3] {exploit[0]}[/magenta3] [spring_green2]{exploit[-1]}[spring_green2]\n")
        else:
            rprint("[red3][-][/red3] No Pocs found on other sources!\n")

    # Search pre-built vulnerable Docker environments in Vulhub
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(
            description="[bright_blue][*][/bright_blue] Searching pre-built vulnerable Docker environments...",
            total=None,
        )
        rprint(
            f"[bright_cyan]{' ' * 30}┌{len('Pre-Built Vulnerable Docker Environment') * '─'}┐\n{'─' * 30}│{'Pre-Built Vulnerable Docker Environment'.center(len('Pre-Built Vulnerable Docker Environment'))}│{'─' * 30}\n{' ' * 30}└{len('Pre-Built Vulnerable Docker Environment') * '─'}┘[/bright_cyan]"
        )
        vulnerable_docker_environment_setup = (
            search_pre_built_vulnerable_docker_environments(cve_id)
        )
        if vulnerable_docker_environment_setup != "N/A":
            rprint(vulnerable_docker_environment_setup)
        else:
            rprint(
                "[red3][-][/red3] No pre-built vulnerable Docker environment found!\n"
            )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
