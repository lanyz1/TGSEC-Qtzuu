import requests

import csv
import re

from CVE2PoC.core.user_agent import get_user_agent


def search_bug_bounty_reports(cve_id):
    """
    This function returns the Bug Bounty write-ups related to a CVE ID
    
    :param cve_record: This is a dictionary containing the CVE ID's information
    """

    bug_bounty_reports = {}
    poc_is_available = "N/A"

    h1_reports_url = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/refs/heads/master/data.csv"
    h1_reports_pocs = requests.get(
        "https://reports.fortisec.co.uk/data/poc-flags.json",
        headers={"User-Agent": get_user_agent()},
    )
    h1_reports_data = requests.get(
        h1_reports_url, headers={"User-Agent": get_user_agent()}
    )
    if h1_reports_data.status_code == 200:
        h1_reports = list(csv.DictReader(h1_reports_data.text.splitlines()))
        for report in h1_reports:
            if re.search(cve_id, report["title"], re.I):
                h1_report_link = f"https://{report['link']}"
                if h1_reports_pocs.status_code == 200:
                    h1_report_id = h1_report_link.split("/")[-1]
                    report_contains_poc = h1_reports_pocs.json().get(h1_report_id)
                    if report_contains_poc:
                        poc_is_available = h1_reports_pocs.json()[h1_report_id]
                        if poc_is_available:
                            poc_is_available = "[spring_green2]Yes[/spring_green2]"
                        else:
                            poc_is_available = "[red3]No[/red3]"
                    else:
                        poc_is_available = "N/A"
                bug_bounty_reports["h1"] = poc_is_available, h1_report_link
                break

    pentesterland = requests.get(
        "https://pentester.land/writeups.json", headers={"User-Agent": get_user_agent()}
    )
    if pentesterland.status_code == 200:
        pentesterland_writeups = pentesterland.json()["data"]
        for writeup in pentesterland_writeups:
            if re.search(cve_id, writeup["Links"][0]["Title"], re.I):
                # There is no feature in PentesterLand nor The Bug Bounty Hunting Search Engine that can allow us to retrieve PoCs related to a CVE
                bug_bounty_reports["pentesterland"] = "N/A", writeup["Links"][0]["Link"]
                break

    if not bug_bounty_reports.get("pentesterland"):
        # PentesterLand and Bug Bounty Hunting Search Engine share almost the same reports. That's why I used the Bug Bounty Hunting Search Engine as a fallback
        bug_bounty_search_engine = requests.get(
            "https://www.bugbountyhunting.com/script.js",
            headers={"User-Agent": get_user_agent()},
        )
        if bug_bounty_search_engine.status_code == 200:
            if re.search(cve_id, bug_bounty_search_engine.text, re.I):
                bug_bounty_reports["bug_bounty_hunting_search_engine"] = (
                    "N/A",
                    f"https://www.bugbountyhunting.com/?q={cve_id.upper()}",
                )

    return bug_bounty_reports
