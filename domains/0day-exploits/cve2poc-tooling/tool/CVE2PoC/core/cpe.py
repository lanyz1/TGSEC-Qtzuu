import requests

from CVE2PoC.core.user_agent import get_user_agent


def cveid_to_cpe(cve_id):
    """
    Thus function returns the CPEs related to a CVE ID

    :param cve_id: The CVE ID
    """

    response = requests.get(
        f"https://cvedb.shodan.io/cve/{cve_id}",
        headers={"User-Agent": get_user_agent()},
    )
    if response.status_code == 200 and response.json()["cpes"]:
        return response.json()["cpes"]
    else:
        return "N/A"


def cpe_to_cveid(cpe_name):

    if not cpe_name.startswith("cpe:"):
        return "Incorrect Format"
    else:
        response = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}",
            headers={"User-Agent": get_user_agent()},
        )
        if response.status_code == 200:
            cve_ids = [
                cve_id["cve"]["id"] for cve_id in response.json()["vulnerabilities"]
            ]
            if not cve_ids:
                # No CVEs found for the specified CPE
                return "N/A"
        else:
            return "N/A"
    return "\n".join(cve_ids)
