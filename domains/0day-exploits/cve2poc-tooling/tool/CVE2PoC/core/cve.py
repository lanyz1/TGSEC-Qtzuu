import requests
from bs4 import BeautifulSoup as bsoup

import re
import csv
import math
from datetime import datetime

from CVE2PoC.core.user_agent import get_user_agent


def download_cisa_kev():
    """
    This function downloads and returns CISA KEV
    """
    known_exploited_vulnerabilities = requests.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        headers={"User-Agent": get_user_agent()},
    )
    if known_exploited_vulnerabilities.status_code == 200:
        kevs = known_exploited_vulnerabilities.json()["vulnerabilities"]
        return kevs
    else:
        return None


def is_kev(kevs, cve_id):
    """
    This function checks if a CVE ID is part of the CISA KEVs

    :param cve_id: The CVE ID specified by the user
    :param kevs: A dictionary containing KEVs
    """
    for kev in kevs:
        if cve_id.upper() == kev["cveID"]:
            return "Yes", kev
    return "No", None


def get_cvss_2_0_base_severity(base_score):
    """
    This function returns a severity for CVSS2.0
    
    :param base_score: The CVSS2.0 score of a CVE ID
    """
    if base_score < 4.0:
        return "LOW"
    elif base_score < 7.0:
        return "MEDIUM"
    else:
        return "HIGH"


def download_first_epss():
    """
    This function downloads and returns FIRST EPSS data using a CI (CVE2PoC-CI) running on my GitHub repository
    """
    epss_data = requests.get(
        "https://raw.githubusercontent.com/0liverFlow/CVE2PoC-CI/refs/heads/main/epss_scores-current.csv",
        headers={"User-Agent": get_user_agent()},
    )
    if epss_data.status_code == 200:
        return list(csv.DictReader(epss_data.text.splitlines()))
    else:
        return None


def get_epss(cve_id, epss_dict):
    """
    The function returns the EPSS score for a CVE ID
    
    :param cve_id: The CVE ID specified by the user
    :param epss_dict: A dictionary containing EPSS data
    """
    if epss_dict is not None:
        for epss in epss_dict:
            if epss["cve"].upper() == cve_id.upper():
                epss_score = math.trunc(float(epss["epss"]) * 10000) / 100
                break
        else:
            # Query First API directly especially for new CVEs that are not included in my EPSS database yet
            epss = requests.get(
                f"https://api.first.org/data/v1/epss?cve={cve_id.upper()}",
                headers={"User-Agent": get_user_agent()},
            )
            if epss.json()["data"]:
                epss_score = (
                    math.trunc(float(epss.json()["data"][0]["epss"]) * 1000) / 100
                )
            else:
                epss_score = "N/A"
    else:
        epss = requests.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id.upper()}",
            headers={"User-Agent": get_user_agent()},
        )
        if epss.json()["data"]:
            epss_score = math.trunc(float(epss.json()["data"][0]["epss"]) * 10000) / 100
        else:
            epss_score = "N/A"

    return epss_score


def retrieve_cve_info_from_nvd(cve_id, nvd_headers):
    """
    This function retrieves a CVE information (CVSS, CWE, Vector String, etc) using the NVD

    :param cve_id: The CVE ID specified by the user
    :param nvd_headers: NVD HTTP headers (useful when an API key is provided)
    """
    cve_info = {}
    cve_info["cwe"] = []
    nvd_response = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}",
        headers=nvd_headers,
    )
    if nvd_response.status_code == 200 and nvd_response.json()["totalResults"] != 0:
        # Return the correct CVSS vector string based on the CVSS version
        if (
            nvd_response.json()["vulnerabilities"][0]["cve"]["metrics"].get(
                "cvssMetricV40", None
            )
            is not None
        ):
            cve_info["vector_string"] = nvd_response.json()["vulnerabilities"][0][
                "cve"
            ]["metrics"]["cvssMetricV40"][0]["cvssData"]["vectorString"]
            cve_info["base_score"] = nvd_response.json()["vulnerabilities"][0]["cve"][
                "metrics"
            ]["cvssMetricV40"][0]["cvssData"]["baseScore"]
            cve_info["severity"] = nvd_response.json()["vulnerabilities"][0]["cve"][
                "metrics"
            ]["cvssMetricV40"][0]["cvssData"]["baseSeverity"]
        elif (
            nvd_response.json()["vulnerabilities"][0]["cve"]["metrics"].get(
                "cvssMetricV31", None
            )
            is not None
        ):
            cve_info["vector_string"] = nvd_response.json()["vulnerabilities"][0][
                "cve"
            ]["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]
            cve_info["base_score"] = nvd_response.json()["vulnerabilities"][0]["cve"][
                "metrics"
            ]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            cve_info["severity"] = nvd_response.json()["vulnerabilities"][0]["cve"][
                "metrics"
            ]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif (
            nvd_response.json()["vulnerabilities"][0]["cve"]["metrics"].get(
                "cvssMetricV30", None
            )
            is not None
        ):
            cve_info["vector_string"] = nvd_response.json()["vulnerabilities"][0][
                "cve"
            ]["metrics"]["cvssMetricV30"][0]["cvssData"]["vectorString"]
            cve_info["base_score"] = nvd_response.json()["vulnerabilities"][0]["cve"][
                "metrics"
            ]["cvssMetricV30"][0]["cvssData"]["baseScore"]
            cve_info["severity"] = nvd_response.json()["vulnerabilities"][0]["cve"][
                "metrics"
            ]["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
        elif (
            nvd_response.json()["vulnerabilities"][0]["cve"]["metrics"].get(
                "cvssMetricV2", None
            )
            is not None
        ):
            cve_info["vector_string"] = nvd_response.json()["vulnerabilities"][0][
                "cve"
            ]["metrics"]["cvssMetricV2"][0]["cvssData"]["vectorString"]
            cve_info["base_score"] = nvd_response.json()["vulnerabilities"][0]["cve"][
                "metrics"
            ]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            # NVD's API doesn't return the CVSS base severity for CVSS V2.0. It only provides the base score. To find that information, I used the vuln metrics at this URL https://nvd.nist.gov/vuln-metrics/cvss
            cve_info["severity"] = get_cvss_2_0_base_severity(cve_info["base_score"])
        else:
            cve_info["vector_string"] = "N/A"
            cve_info["base_score"] = "N/A"
            cve_info["severity"] = "N/A"

        # Retrieve CWE ID
        if (
            nvd_response.json()["vulnerabilities"][0]["cve"].get("weaknesses", None)
            is not None
        ):
            weaknesses = nvd_response.json()["vulnerabilities"][0]["cve"]["weaknesses"]
            for weakness in weaknesses:
                # Check if CWE ID format is correct
                if re.search("^CWE-[0-9]+$", weakness["description"][0]["value"], re.I):
                    cve_info["cwe"].append(weakness["description"][0]["value"])
            # Remove duplicated CWE IDs
            cve_info["cwe"] = list(set(cve_info["cwe"]))
        return cve_info
    else:
        # No CVE record found on NVD
        return None


def get_cve_info_from_adp(adps):
    """
    This function retrieve a CVE ID information using Cve.org's adps

    :param adps: A dictionary that stores information about a CVE ID
    """
    for adp in adps:
        if adp.get("metrics") is not None:
            if adp["metrics"][0].get("cvssV3_1") is not None:
                vector_string = adp["metrics"][0]["cvssV3_1"].get("vectorString", "N/A")
                base_score = adp["metrics"][0]["cvssV3_1"].get("baseScore", "N/A")
                severity = adp["metrics"][0]["cvssV3_1"].get("baseSeverity", "N/A")
                break
            elif adp["metrics"][0].get("cvssV4_0") is not None:
                vector_string = adp["metrics"][0]["cvssV4_0"].get("vectorString", "N/A")
                base_score = adp["metrics"][0]["cvssV4_0"].get("baseScore", "N/A")
                severity = adp["metrics"][0]["cvssV4_0"].get("baseSeverity", "N/A")
                break
            elif adp["metrics"][0].get("cvssV3_0") is not None:
                vector_string = adp["metrics"][0]["cvssV3_0"].get("vectorString", "N/A")
                base_score = adp["metrics"][0]["cvssV3_0"].get("baseScore", "N/A")
                severity = adp["metrics"][0]["cvssV3_0"].get("baseSeverity", "N/A")
                break
            elif adp["metrics"][0].get("cvssV2_0") is not None:
                vector_string = adp["metrics"][0]["cvssV2_0"].get("vectorString", "N/A")
                base_score = adp["metrics"][0]["cvssV2_0"].get("baseScore", "N/A")
                severity = (
                    get_cvss_2_0_base_severity(base_score)
                    if base_score != "N/A"
                    else "N/A"
                )
                break
    else:
        vector_string = "N/A"
        base_score = "N/A"
        severity = "N/A"

    return vector_string, base_score, severity


def retrieve_cve_info_from_cve_org(cve_id, headers):
    """
    This function retrieve a CVE ID information using Cve.org

    :param cve_id: The CVE ID submitted by the user
    :param headers: The NVD and CVE.org headers
    """
    publication_year = cve_id.split("-")[1]
    sequence_number = cve_id.split("-")[-1]
    github_headers, nvd_headers = headers[0], headers[-1]

    # Retrieve CVE ID's State, CNA, publication date, vendor and affected product from CVE.org
    cve_org_response = requests.get(
        f"https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/{publication_year}/{sequence_number[:-3] + 'xxx'}/{cve_id.upper()}.json",
        headers=github_headers,
    )

    cve_info = {}
    cve_info["cve_id"] = cve_id.upper()
    if cve_org_response.status_code == 200:
        cve_org_json_response = cve_org_response.json()
        cve_info["state"] = cve_org_json_response["cveMetadata"]["state"]
        if cve_info["state"] == "REJECTED":
            # No information is returned if the CVE is rejected
            cve_info["rejectedReasons"] = cve_org_json_response["containers"]["cna"][
                "rejectedReasons"
            ][0]["value"]
            return cve_info
        cve_info["publication_date"] = (
            f"{datetime.fromisoformat(cve_org_json_response['cveMetadata']['datePublished']).strftime('%d %b %Y')}"
        )
        cve_info["vendor"] = (
            f"{cve_org_json_response['containers']['cna']['affected'][0].get('vendor', 'N/A')}"
        )
        cve_info["affected_product"] = (
            f"{cve_org_json_response['containers']['cna']['affected'][0].get('product', 'N/A')}"
        )
        cve_info["state"] = f"{cve_org_json_response['cveMetadata']['state']}"
        cve_info["cwe"] = []

        if cve_org_json_response.get("containers") is not None:
            if cve_org_json_response["containers"].get("cna") is not None:
                cna_metrics = cve_org_json_response["containers"]["cna"].get("metrics")
                if cna_metrics is not None:
                    if cna_metrics[0].get("cvssV3_1", None) is not None:
                        cve_info["vector_string"] = cna_metrics[0]["cvssV3_1"].get(
                            "vectorString"
                        )
                        cve_info["base_score"] = cna_metrics[0]["cvssV3_1"].get(
                            "baseScore", "N/A"
                        )
                        cve_info["severity"] = cna_metrics[0]["cvssV3_1"].get(
                            "baseSeverity", "N/A"
                        )
                    elif cna_metrics[0].get("cvssV4_0", None) is not None:
                        cve_info["vector_string"] = cna_metrics[0]["cvssV4_0"].get(
                            "vectorString"
                        )
                        cve_info["base_score"] = cna_metrics[0]["cvssV4_0"].get(
                            "baseScore", "N/A"
                        )
                        cve_info["severity"] = cna_metrics[0]["cvssV4_0"].get(
                            "baseSeverity", "N/A"
                        )
                    elif cna_metrics[0].get("cvssV3_0", None) is not None:
                        cve_info["vector_string"] = cna_metrics[0]["cvssV3_0"].get(
                            "vectorString"
                        )
                        cve_info["base_score"] = cna_metrics[0]["cvssV3_0"].get(
                            "baseScore", "N/A"
                        )
                        cve_info["severity"] = cna_metrics[0]["cvssV3_0"].get(
                            "baseSeverity", "N/A"
                        )
                    elif cna_metrics[0].get("cvssV2_0", None) is not None:
                        cve_info["vector_string"] = cna_metrics[0]["cvssV2_0"].get(
                            "vectorString"
                        )
                        cve_info["base_score"] = cna_metrics[0]["cvssV2_0"].get(
                            "baseScore", "N/A"
                        )
                        if cve_info["base_score"] != "N/A":
                            cve_info["severity"] = get_cvss_2_0_base_severity(
                                cve_info["base_score"]
                            )
                        else:
                            cve_info["severity"] = "N/A"

                    elif (
                        cve_org_json_response["containers"].get("adp") is not None
                        and cve_info.get("Vector String") is None
                    ):
                        adps = cve_org_json_response["containers"]["adp"]
                        (
                            cve_info["vector_string"],
                            cve_info["base_score"],
                            cve_info["severity"],
                        ) = get_cve_info_from_adp(adps)
                        if (
                            cve_info["vector_string"]
                            == cve_info["base_score"]
                            == cve_info["severity"]
                            == "N/A"
                        ):
                            # Fallback on NVD
                            nvd_cve_info = retrieve_cve_info_from_nvd(
                                cve_id, nvd_headers
                            )
                            if nvd_cve_info is not None:
                                (
                                    cve_info["base_score"],
                                    cve_info["severity"],
                                    cve_info["vector_string"],
                                    cve_info["cwe"],
                                ) = (
                                    nvd_cve_info["base_score"],
                                    nvd_cve_info["severity"],
                                    nvd_cve_info["vector_string"],
                                    nvd_cve_info["cwe"],
                                )
                    else:
                        nvd_cve_info = retrieve_cve_info_from_nvd(cve_id, nvd_headers)
                        if nvd_cve_info is not None:
                            (
                                cve_info["base_score"],
                                cve_info["severity"],
                                cve_info["vector_string"],
                                cve_info["cwe"],
                            ) = (
                                nvd_cve_info["base_score"],
                                nvd_cve_info["severity"],
                                nvd_cve_info["vector_string"],
                                nvd_cve_info["cwe"],
                            )

                elif (
                    cve_org_json_response["containers"].get("adp") is not None
                    and cve_info.get("Vector String") is None
                ):
                    adps = cve_org_json_response["containers"]["adp"]
                    (
                        cve_info["vector_string"],
                        cve_info["base_score"],
                        cve_info["severity"],
                    ) = get_cve_info_from_adp(adps)
                    if (
                        cve_info["vector_string"]
                        == cve_info["base_score"]
                        == cve_info["severity"]
                        == "N/A"
                    ):
                        nvd_cve_info = retrieve_cve_info_from_nvd(cve_id, nvd_headers)
                        if nvd_cve_info is not None:
                            (
                                cve_info["base_score"],
                                cve_info["severity"],
                                cve_info["vector_string"],
                                cve_info["cwe"],
                            ) = (
                                nvd_cve_info["base_score"],
                                nvd_cve_info["severity"],
                                nvd_cve_info["vector_string"],
                                nvd_cve_info["cwe"],
                            )

                # Retrieve CWE ID
                if (
                    not cve_info["cwe"]
                    and cve_org_json_response["containers"]["cna"].get("problemTypes")
                    is not None
                ):
                    if (
                        cve_org_json_response["containers"]["cna"]["problemTypes"][0][
                            "descriptions"
                        ][0].get("cweId", None)
                        is not None
                    ):
                        cve_info["cwe"].append(
                            cve_org_json_response["containers"]["cna"]["problemTypes"][
                                0
                            ]["descriptions"][0]["cweId"]
                        )
                    elif (
                        cve_org_json_response["containers"]["cna"]["problemTypes"][0][
                            "descriptions"
                        ][0].get("description", None)
                        is not None
                    ):
                        cwe_description = cve_org_json_response["containers"]["cna"][
                            "problemTypes"
                        ][0]["descriptions"][0]["description"]
                        cwe_id = re.findall("CWE-[0-9]+", cwe_description, re.I)
                        if cwe_id:
                            cve_info["cwe"].append(cwe_id[0])
                    elif cve_org_json_response["containers"].get("adp"):
                        adps = cve_org_json_response["containers"]["adp"]
                        for adp in adps:
                            if adp.get("problemTypes") is not None:
                                if (
                                    adp["problemTypes"][0]["descriptions"][0].get(
                                        "cweId", None
                                    )
                                    is not None
                                ):
                                    cve_info["cwe"].append(
                                        adp["problemTypes"][0]["descriptions"][0][
                                            "cweId"
                                        ]
                                    )
                                elif (
                                    adp["problemTypes"][0]["descriptions"][0].get(
                                        "description", None
                                    )
                                    is not None
                                ):
                                    cwe_description = adp["problemTypes"][0][
                                        "descriptions"
                                    ][0]["description"]
                                    cwe_id = re.findall(
                                        "CWE-[0-9]+", cwe_description, re.I
                                    )
                                    if cwe_id:
                                        cve_info["cwe"].append(cwe_id[0])
                    elif (
                        cve_org_json_response["containers"]["cna"]["problemTypes"][0][
                            "descriptions"
                        ][0].get("description", None)
                        is not None
                    ):
                        cwe_description = cve_org_json_response["containers"]["cna"][
                            "problemTypes"
                        ][0]["descriptions"][0]["description"]
                        cwe_id = re.findall("CWE-[0-9]+", cwe_description, re.I)
                        if cwe_id:
                            cve_info["cwe"].append(cwe_id[0])

                elif cve_org_json_response["containers"].get("adp"):
                    adps = cve_org_json_response["containers"]["adp"]
                    for adp in adps:
                        if adp.get("problemTypes") is not None:
                            if (
                                adp["problemTypes"][0]["descriptions"][0].get(
                                    "cweId", None
                                )
                                is not None
                            ):
                                cve_info["cwe"].append(
                                    adp["problemTypes"][0]["descriptions"][0]["cweId"]
                                )
                            elif (
                                adp["problemTypes"][0]["descriptions"][0].get(
                                    "description", None
                                )
                                is not None
                            ):
                                cwe_description = adp["problemTypes"][0][
                                    "descriptions"
                                ][0]["description"]
                                cwe_id = re.findall("CWE-[0-9]+", cwe_description, re.I)
                                if cwe_id:
                                    cve_info["cwe"].append(cwe_id[0])
            elif (
                cve_org_json_response["containers"].get("adp") is not None
                and cve_info.get("Vector String") is None
            ):
                adps = cve_org_json_response["containers"]["adp"]
                (
                    cve_info["vector_string"],
                    cve_info["base_score"],
                    cve_info["severity"],
                ) = get_cve_info_from_adp(adps)
                if (
                    cve_info["vector_string"]
                    == cve_info["base_score"]
                    == cve_info["severity"]
                    == "N/A"
                ):
                    # Fallback on NVD
                    nvd_cve_info = retrieve_cve_info_from_nvd(cve_id, nvd_headers)
                    if nvd_cve_info is not None:
                        (
                            cve_info["base_score"],
                            cve_info["severity"],
                            cve_info["vector_string"],
                            cve_info["cwe"],
                        ) = (
                            nvd_cve_info["base_score"],
                            nvd_cve_info["severity"],
                            nvd_cve_info["vector_string"],
                            nvd_cve_info["cwe"],
                        )
                # Retrieve CWE ID
                if adp.get("problemTypes") is not None and not cve_info["cwe"]:
                    if (
                        adp["problemTypes"][0]["descriptions"][0].get("cweId", None)
                        is not None
                    ):
                        cve_info["cwe"].append(
                            adp["problemTypes"][0]["descriptions"][0]["cweId"]
                        )
                    elif (
                        adp["problemTypes"][0]["descriptions"][0].get(
                            "description", None
                        )
                        is not None
                    ):
                        cwe_description = adp["problemTypes"][0]["descriptions"][0][
                            "description"
                        ]
                        cwe_id = re.findall("CWE-[0-9]+", cwe_description, re.I)
                        if cwe_id:
                            cve_info["cwe"].append(cwe_id[0])
            return cve_info

        else:
            # Fallback on NVD to retrieve CVE ID record (base score, severity, vector string and CWE)
            nvd_cve_info = retrieve_cve_info_from_nvd(cve_id, nvd_headers)
            if nvd_cve_info is not None:
                (
                    cve_info["base_score"],
                    cve_info["severity"],
                    cve_info["vector_string"],
                    cve_info["cwe"],
                ) = (
                    nvd_cve_info["base_score"],
                    nvd_cve_info["severity"],
                    nvd_cve_info["vector_string"],
                    nvd_cve_info["cwe"],
                )
            return cve_info
    else:
        cve_info["publication_date"] = "N/A"
        cve_info["affected_product"] = "N/A"
        cve_info["state"] = "N/A"
        # Fallback on NVD to retrieve CVE ID record (base score, severity, vector string and CWE)
        nvd_cve_info = retrieve_cve_info_from_nvd(cve_id, nvd_headers)
        if nvd_cve_info is not None:
            (
                cve_info["base_score"],
                cve_info["severity"],
                cve_info["vector_string"],
                cve_info["cwe"],
            ) = (
                nvd_cve_info["base_score"],
                nvd_cve_info["severity"],
                nvd_cve_info["vector_string"],
                nvd_cve_info["cwe"],
            )
            return cve_info
        else:
            # Check if the CVE ID is not reserved
            response = requests.get(
                f"https://cveawg.mitre.org/api/cve-id/{cve_id.upper()}",
                headers={"User-Agent": get_user_agent()},
            )
            if response.status_code == 200:
                cve_state = response.json()["state"]
                if cve_state == "RESERVED":
                    cve_info["state"] = "RESERVED"
                    return cve_info
            # No information was neither found on Cve.org nor on NVD for the specified CVE ID
            return None


def get_cve_description(cve_id):
    """
    This function returns a CVE ID's description

    :param cve_id: The CVE ID specified by the user
    """
    publication_year = cve_id.split("-")[1]
    sequence_number = cve_id.split("-")[-1]
    cve_org_response = requests.get(
        f"https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/{publication_year}/{sequence_number[:-3] + 'xxx'}/{cve_id.upper()}.json",
        headers={"User-Agent": get_user_agent()},
    )
    # Retrieve description from cve.org
    if cve_org_response.status_code == 200:
        return cve_org_response.json()["containers"]["cna"]["descriptions"][0]["value"]

    # Retrieve description from nvd
    nvd_response = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}",
        headers={"User-Agent": get_user_agent()},
    )
    if nvd_response.status_code == 200:
        return nvd_response.json()["vulnerabilities"][0]["cve"]["descriptions"][0][
            "value"
        ]
    
    return "N/A"

def check_ransomware_group_usage(cve_id):
    """
    This function checks whether a CVE ID is being used by ransomware groups or not

    :param cveid: The CVE ID specified by the user
    """
    response = requests.get(
        f"https://cvedb.shodan.io/cve/{cve_id}",
        headers={"User-Agent": get_user_agent()},
    )
    if response.status_code == 200 and response.json()["ransomware_campaign"]:
        return response.json()["ransomware_campaign"]
    else:
        return "N/A"


def check_cve_id_format(cve_id):
    """
    This function checks the format of a CVE ID 

    :param cve_id: The CVE ID specified by the user
    """
    if re.search("^CVE-[0-9]+-[0-9]+$", cve_id, re.I) is None:
        return False
    else:
        return True


def get_cve_references(cve_id, cve_record):
    """
    This function returns a CVE ID's references 

    :param cve_id: The CVE ID specified by the user
    """
    # NVD and CVEDetails
    reference_urls = {
        "NVD": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}",
        "CVEdetails": f"https://www.cvedetails.com/cve/{cve_id.upper()}",
    }

    # Github Advisory Database
    ghsa_url = "https://github.com/advisories?query=" + cve_id.upper()
    response_ghsa = requests.get(ghsa_url, headers={"User-Agent": get_user_agent()})
    soup = bsoup(response_ghsa.text, "html.parser")
    if response_ghsa.status_code == 200:
        ghsa_links = []
        for row in soup.select("div.Box-row"):
            cve = row.select_one("span.text-bold")
            if cve and cve.text.strip().upper() == cve_id.upper():
                link = row.select_one("a[href]")
                ghsa_links.append("https://github.com" + link["href"])
                reference_urls["GHSA"] = "\n".join(ghsa_links)

    # Retrieve advisories from CISA KEV
    if cve_record["kev"] == "Yes":
        additional_references = cve_record["references"]
        if additional_references:
            for reference in additional_references:
                if reference.startswith("https://nvd.nist.gov"):
                    # Remove NVD from the other references see that it was already mentioned in the reference_urls above
                    additional_references.remove(reference)
            # Check again the value of additional_references because it will be empty if it only contains the NVD as a reference
            if additional_references:
                reference_urls["Advisories"] = "\n".join(additional_references)
    # Include additional references in situation where only NVD and CVEDetails references were returned
    if len(reference_urls) < 3:
        publication_year = cve_id.split("-")[1]
        sequence_number = cve_id.split("-")[-1]
        cve_org_response = requests.get(
            f"https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/{publication_year}/{sequence_number[:-3] + 'xxx'}/{cve_id.upper()}.json",
            headers={"User-Agent": get_user_agent()},
        )
        if cve_org_response.status_code == 200:
            reference_urls["Advisories"] = "\n".join(
                [
                    ref["url"]
                    for ref in cve_org_response.json()["containers"]["cna"][
                        "references"
                    ]
                ]
            )

    return reference_urls
