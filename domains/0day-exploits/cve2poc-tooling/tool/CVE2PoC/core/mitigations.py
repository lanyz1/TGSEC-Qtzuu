import yaml
import requests
from bs4 import BeautifulSoup as bsoup
from rich import print as rprint

import re
import json
import html
import sys
import random
import os

from CVE2PoC.core.user_agent import get_user_agent


def get_cveid_nuclei_template(cve_id):
    """
    This function returns a Nuclei template for a CVE ID

    :param cve_id: The CVE ID specified by the user
    """ 
    nuclei_cves_db = requests.get("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json", headers={'User-Agent': get_user_agent()})
    nuclei_db_json = nuclei_cves_db.text.split("\n")
    for cve_info in nuclei_db_json:
        if cve_info:
            cve_info_dict = json.loads(cve_info)
            if cve_info_dict['ID'] == cve_id:
                template_path = cve_info_dict['file_path']
                yaml_template = requests.get("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main" + template_path, headers={'User-Agent': get_user_agent()})
                if yaml_template.status_code == 200:
                    return yaml.safe_load(yaml_template.text)
        else:
            # Checking https://cloud.projectdiscovery.io/library see that this stores more templates than the GitHub repo
            response = requests.get(f"https://cloud.projectdiscovery.io/library/{cve_id.upper()}", headers={'User-Agent': get_user_agent()})
            if re.search("Template Not Found", response.text, re.I) is None and response.status_code != 403:
                soup = bsoup(response.text, 'html.parser')
                pre_tag = soup.find("pre", attrs={"data-lang": "yaml"})
                yaml_template = html.unescape(pre_tag.get_text())
                yaml_template = yaml_template.split("# digest:")[0].strip()
                return yaml.safe_load(yaml_template)
    return None


def get_nuclei_remediations(nuclei_template):
    """
    This function retrieve the remediation steps to fix a vulnerability from a Nuclei tempalte

    :param nuclei_template: The Nuclei template for a CVE ID
    """
    # Some templates may not have remediation steps. In such scenario, N/A is returned
    if nuclei_template['info'].get('remediation') is not None:
        return nuclei_template['info']['remediation']
    return 'N/A'
    

def get_sentinelone_vulnerability_database_mitigations(cve_id):
    """
    This function returns SentinelOne's remediation steps for a CVE ID

    :param cve_id: The CVE ID specified by the user
    """
    # SentinelOne Vulnerability Database suggests handy mitigations and workarounds
    sentinel_one_vulnerability_database_url = f"https://www.sentinelone.com/vulnerability-database/{cve_id.upper()}"
    response_sentinel_one = requests.get(sentinel_one_vulnerability_database_url, headers={'User-Agent': get_user_agent()})
    if response_sentinel_one.status_code == 200:
        return sentinel_one_vulnerability_database_url
    return 'N/A'
