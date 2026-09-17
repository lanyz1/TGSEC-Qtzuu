import requests
from bs4 import BeautifulSoup as bsoup
import tomli

from CVE2PoC.core.user_agent import get_user_agent


def search_ctf_labs(cve_id):
    """
    This function returns HackTheBox and TryHackMe hands-on labs related to a CVE ID

    :param cve_id: The CVE ID specified by the user
    """
    labs = {}
    # Searching HTB machines related to CVE ID
    xdf = requests.get("https://0xdf.gitlab.io/tags", {"User-Agent": get_user_agent()})
    soup = bsoup(xdf.text, "html.parser")
    cve_selector = soup.select(f'h2[id="{cve_id}" i] + ul')
    if cve_selector:
        # xdf_writeup = "https://0xdf.gitlab.io" + cve_lookup[0].select('a')[0].get('href')
        labs["htb"] = (
            "https://www.hackthebox.com/machines/"
            + cve_selector[0].select("a")[0].text.split()[1].lower()
        )
    # Searching THM machines related to CVE ID
    response = requests.get(
        "https://raw.githubusercontent.com/0liverFlow/CVE2PoC-CI/refs/heads/main/latest_thm_rooms.txt",
        {"User-Agent": get_user_agent()},
    )
    thm_machines = response.text.split("\n")
    for machine in thm_machines:
        if machine.split(":", 1)[0].upper() == cve_id.upper():
            labs["thm"] = machine.split(":", 1)[-1]
            break
    return labs


def search_pre_built_vulnerable_docker_environments(cve_id):
    """
    This function will search for pre-built Docker environment in Vulhub using the CVE ID specified by the user.
    This is handy in situations where users would like to better understand a vulnerability or check the impact of an exploit before running it in a production environment.

    :param cve_id: The CVE ID specified by the user
    """
    response = requests.get(
        "https://raw.githubusercontent.com/vulhub/vulhub/refs/heads/master/environments.toml",
        headers={"User-Agent": get_user_agent()},
    )
    config = tomli.loads(response.text)
    vulnerable_environments = config["environment"]
    for vulnerable_docker_environment in vulnerable_environments:
        if vulnerable_docker_environment["cve"]:
            if vulnerable_docker_environment["cve"][0].casefold() == cve_id.casefold():
                vulnerable_docker_environment_setup = f"""Follow the steps below to setup your vulnerable docker environment
1/ Clone the Vulhub repository: [bright_cyan]git clone --depth 1 https://github.com/vulhub/vulhub.git[/bright_cyan]
2/ Move to the vulnerability directory: [bright_cyan]cd vulhub/{vulnerable_docker_environment["path"]}[/bright_cyan]
3/ Start the vulnerable environment: [bright_cyan]docker compose up -d[/bright_cyan]
4/ Use this resource for reproduction steps: https://github.com/vulhub/vulhub/tree/master/{vulnerable_docker_environment["path"]}
5/ Clean up after testing: [bright_cyan]docker compose down[/bright_cyan]"""
                break
    else:
        return "N/A"
    return vulnerable_docker_environment_setup
