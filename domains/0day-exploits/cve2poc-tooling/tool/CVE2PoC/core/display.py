from rich.table import Table


def display_cve_info(cve_record):
    """
    This function takes the cve_record and returns a table containing the different information related to the CVE ID submitted by the user.

    :param cve_record: This is a dictionary containing the CVE ID's information
    """

    SEVERITY_STYLES = {
        "LOW": "spring_green2",
        "MEDIUM": "gold1",
        "HIGH": "dark_orange",
        "CRITICAL": "red1",
    }

    base_score = cve_record["base_score"]
    if base_score != "N/A":
        if base_score < 4:
            base_score = f"[spring_green2]{cve_record['base_score']}[/spring_green2]"
        elif base_score < 7:
            base_score = f"[gold1]{cve_record['base_score']}[/gold1]"
        elif base_score < 9:
            base_score = f"[dark_orange]{cve_record['base_score']}[/dark_orange]"
        else:
            base_score = f"[red1]{cve_record['base_score']}[/red1]"

    epss_score = cve_record["epss_score"]
    if epss_score != "N/A":
        if epss_score >= 70:
            epss_score = f"[red1]{cve_record['epss_score']}%[/red1]"
        elif epss_score >= 40:
            epss_score = f"[dark_orange]{cve_record['epss_score']}%[/dark_orange]"
        else:
            epss_score = f"[spring_green2]{cve_record['epss_score']}%[/spring_green2]"

    severity_style = SEVERITY_STYLES.get(cve_record["severity"], "")
    if severity_style:
        severity = f"[{severity_style}]{cve_record['severity']}[/{severity_style}]"
    else:
        severity = cve_record["severity"]

    if cve_record.get("cwe", None) is not None:
        if cve_record["cwe"]:
            cwes = []
            for cwe in cve_record["cwe"]:
                # Checking if a CWE is part of the 2025 CWE Top 25 Most Dangerous Software Weaknesses
                if cwe in [
                    "CWE-79",
                    "CWE-89",
                    "CWE-352",
                    "CWE-862",
                    "CWE-787",
                    "CWE-22",
                    "CWE-416",
                    "CWE-125",
                    "CWE-78",
                    "CWE-94",
                    "CWE-120",
                    "CWE-434",
                    "CWE-476",
                    "CWE-121",
                    "CWE-502",
                    "CWE-122",
                    "CWE-863",
                    "CWE-20",
                    "CWE-284",
                    "CWE-200",
                    "CWE-306",
                    "CWE-918",
                    "CWE-77",
                    "CWE-639",
                    "CWE-770",
                ]:
                    cwes.append(f"[bright_blue]{cwe}[/bright_blue]")
                else:
                    cwes.append(f"[bright_cyan]{cwe}[/bright_cyan]")
            cwe = ",".join(cwes)
        else:
            cwe = "N/A"
    else:
        cwe = "N/A"

    if cve_record["kev"] == "Yes":
        kev = "[red1]Yes[/red1]"
    else:
        kev = cve_record["kev"]

    table = Table(
        show_lines=True,
        header_style="bold",
        title=cve_record["cve_id"],
        title_style="bold",
        title_justify="center",
    )
    table.add_column("Publication Date", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Base Score", justify="center")
    table.add_column("EPSS", justify="center")
    table.add_column("Vendor", justify="center")
    table.add_column("Affected Product", justify="center")
    table.add_column("CISA KEV", justify="center")
    table.add_column("CWE", justify="center")
    table.add_column("Vector String", overflow="fold", justify="center")
    table.add_row(
        cve_record["publication_date"],
        severity,
        base_score,
        epss_score,
        cve_record["vendor"],
        cve_record["affected_product"],
        kev,
        cwe,
        cve_record["vector_string"],
    )
    return table


def display_poc_info(poc, poc_title, gh_api_key):
    """
    This function returns a PoC's information (description, clone URL, stargazers, forks, programming language) in a nice format

    :param poc: This is a dictionary containing the exploit/PoC's information like its description, clone url, stars, forks, programming language, etc.
    :param poc_title: This is the PoC title to display
    :param gh_api_key: This is your GitHub API key
    """
    if poc["programming_language"] == "N/A" and gh_api_key is None:
        return f"""[red3]{" " * 46}┌{len(f"{poc_title}") * "─"}┐\n{"─" * 46}│{poc_title.center(len(poc_title))}│{"─" * 46}\n{" " * 46}└{len(poc_title) * "─"}┘[/red3]\nDescription: {poc["description"] if poc["description"] is not None else "N/A"}\nClone URL: {poc["html_url"]}\nStars: [gold1]{poc["stargazers_count"]}[/gold1]\nForks: [gold1]{poc["forks"]}[/gold1]\n"""
    else:
        # The programming language will be returned only if the user submitted a correct API key or did not reach the GitHub API rate limit which is 60 requests/hour (https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
        return f"""[red3]{" " * 46}┌{len(f"{poc_title}") * "─"}┐\n{"─" * 46}│{poc_title.center(len(poc_title))}│{"─" * 46}\n{" " * 46}└{len(poc_title) * "─"}┘[/red3]\nDescription: {poc["description"] if poc["description"] is not None else "N/A"}\nClone URL: {poc["html_url"]}\nStars: [gold1]{poc["stargazers_count"]}[/gold1]\nForks: [gold1]{poc["forks"]}[/gold1]\nProgramming Language: [orange_red1]{poc["programming_language"]}[/orange_red1]"""
