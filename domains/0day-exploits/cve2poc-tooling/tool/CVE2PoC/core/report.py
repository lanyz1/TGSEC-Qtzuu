import json
from datetime import datetime

from CVE2PoC.core.cve import (
    is_kev,
    check_cve_id_format,
    retrieve_cve_info_from_cve_org,
    get_epss,
)
from CVE2PoC.core.exploits import (
    search_github_exploits,
    search_exploits_from_other_sources,
)


def generate_json_report(data, output_dir_path):
    """
    This function generates a JSON report containing CVE IDs information

    :param data: A dictionary containing CVE IDs information
    :param output_dir_path: Ouptut directory to store the JSON report
    """
    with open(
        f"{output_dir_path}/cve2poc_report_{str(datetime.now().date()).replace('-', '_')}_{datetime.now().strftime('%H:%M:%S').replace(':', '_')}.json",
        "w",
    ) as f:
        json.dump(data, f, indent=4)
        return True
    return False


def generate_html_report(data, output_dir_path):
    """
    This function generates a HTML report containing CVE IDs information

    :param data: A dictionary containing CVE IDs information
    :param output_dir_path: Ouptut directory to store the HTML report
    """
    report_date, report_time = (
        datetime.now().date(),
        datetime.now().strftime("%H:%M:%S"),
    )
    head_and_body = (
        """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CVE2PoC Report</title>

        <!-- jQuery -->
        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

        <!-- DataTables CSS & JS -->
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
        <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        
        <!-- Custom CSS -->
    """
        + """
        <style>
            :root {
                --bg: #f4f6f9;
                --text: #1f2937;
                --card: #ffffff;
                --border: #e5e7eb;
                --header: #f9fafb;
            }

            body.dark {
                --bg: #111827;
                --text: #e5e7eb;
                --card: #1f2937;
                --border: #374151;
                --header: #1f2937;
            }

            body {
                font-family: 'Inter', sans-serif;
                background-color: var(--bg);
                color: var(--text);
                margin: 0;
                padding: 0 40px 60px;
            }

            a {
                text-decoration: none;
                color: black;
            }

            body.dark a {
                color: white;
            }

            .report-header {
                margin: 40px 0 30px;
            }

            .report-title {
                font-size: 30px;
                font-weight: 700;
                margin: 0;
            }

            .report-subtitle {
                font-size: 15px;
                color: #6b7280;
                margin-top: 6px;
            }

            #pageFooter {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                text-align: center;
                padding: 10px 0;
                font-size: 0.85em;
                background-color: var(--card);
                color: var(--text);
                border-top: 1px solid var(--border);
            }

            .badge {
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 14px;
                color: white;
                font-weight: 500;
            }

            .badge a {
                color: inherit;
                text-decoration: none;
                font-weight: inherit;
            }

            .yes { background-color: #28a745; }
            .no { background-color: #dc3545; }

            .cvss-badge {
                padding: 4px 8px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
                display: inline-block;
                min-width: 40px;
                text-align: center;
            }

            .cvss-low { background: #66c240; color: white; }
            .cvss-medium { background: #f59e0b; color: white; }
            .cvss-high { background: #f97316; color: white; }
            .cvss-critical { background: #dc2626; color: white; }
            .cvss-na { background: #9ca3af; color: white; }

            .epss-badge {
                padding: 4px 8px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
                min-width: 40px;
                text-align: center;
            }

            .epss-high {
                background: #dc2626;
                color: white;
            }

            .epss-medium {
                background: #f97316;
                color: white;
            }

            .epss-low {
                background: #66c240;
                color: white;
            }

            table.dataTable {
                border: none !important;
                background-color: var(--card) !important;
            }

            table.dataTable thead th {
                cursor: pointer;
            }

            thead th {
                position: sticky;
                top: 0;
                z-index: 1;
                background: var(--header) !important;
                color: var(--text);
            }

            tfoot {
                display: table-header-group;
            }

            .filter-bar {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
            }

            .filter-bar input,
            .filter-bar select {
                padding: 8px 10px;
                border: 1px solid #d1d5db;
                border-radius: 6px;
                font-size: 14px;
            }

            .filter-bar input {
                flex: 1;
            }

            .filter-bar button {
                padding: 8px 14px;
                background: #111827;
                color: white;
                border: none;
                border-radius: 6px;
                cursor: pointer;
            }

            .filter-bar button:hover {
                background: #374151;
            }

            .vector-filter {
                margin-bottom: 15px;
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
                font-size: 14px;
            }

            .filter-row th {
                background: var(--header);
                padding: 8px;
                border-bottom: 1px solid var(--border);
            }

            .filter-row input,
            .filter-row select {
                width: 100%;
                padding: 6px 8px;
                font-size: 12px;
                border: 1px solid var(--border);
                border-radius: 6px;
                background: var(--card);
                color: var(--text);
            }

            .filter-row input:focus,
            .filter-row select:focus {
                outline: none;
                border-color: #9ca3af;
            }

            .filter-row input::placeholder {
                color: #9ca3af;
            }

            body.dark .filter-row input::placeholder {
                color: #6b7280;
            }

            .clear-btn,
            .reset-btn {
                padding: 6px 12px;
                font-size: 14px;
                cursor: pointer;
                border-radius: 6px;
            }

            .clear-btn {
                margin-left: 10px;
            }

            .reset-btn {
                font-weight: 500;
                background-color: #111827;
                color: white;
                border: none;
                margin-left: 10px;
            }

            .reset-btn:hover {
                background-color: #374151;
            }

            .reset-container {
                display: flex;
                justify-content: flex-end;
                align-items: center;
            }

            .theme-btn {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 6px 12px;
                border-radius: 8px;
                border: 1px solid var(--border);
                background: var(--card);
                color: var(--text);
                font-size: 13px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s ease;
            }

            .theme-btn:hover {
                background: #e5e7eb;
            }

            body.dark .theme-btn:hover {
                background: #374151;
            }

            .dataTables_wrapper .dataTables_length {
                color: var(--text);
            }

            .dataTables_wrapper .dataTables_length select {
                background: var(--card);
                color: var(--text);
                border: 1px solid var(--border);
                border-radius: 6px;
                padding: 4px 6px;
            }

            .dataTables_wrapper .dataTables_length select:focus {
                outline: none;
                border-color: #9ca3af;
            }

            td.vector-string {
                word-break: break-all;
                max-width: 350px;
                white-space: normal;
            }

            tfoot select {
                width: 100%;
                padding: 4px;
                border-radius: 4px;
                font-family: Inter, sans-serif;
            }

            body:not(.dark) tfoot select {
                background: #fff;
                color: #111;
                border: 1px solid #ccc;
            }

            /* Dark theme */
            body.dark tfoot select {
                background: #1f2937;
                color: #f1f1f1;
                border: 1px solid #444;
            }      
        </style> 
    """
        + f"""
    </head>
    <body>
        <div class="report-header">
            <h1 class="report-title">CVE2POC Report</h1>
            <div class="report-subtitle">
                This report was generated on {report_date} at {report_time}
            </div>
        </div>  
        <div style="position:absolute; top:40px; right:40px;">
            <button id="themeToggle" class="theme-btn"></button>
        </div>
        <table id="report" class="display" style="width:100%">
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>CVSS</th>
                    <th>EPSS</th>
                    <th>KEV</th>
                    <th>CWE</th>
                    <th>Vector String</th>
                    <th>GitHub</th>
                    <th>ExploitDB</th>
                    <th>Metasploit</th>
                    <th>Nuclei</th>
                </tr>
            </thead>
            <tfoot>
            <tr class="filter-row">
                <th><input type="text" placeholder="CVE..." /></th>
                <th>
                    <select class="cvss-filter-footer">
                        <option value="">CVSS</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                 </th>
                <th>
                    <select class="epss-filter-footer">
                        <option value="">EPSS</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </th>
                <th>
                    <select>
                        <option value="">All</option>
                        <option value="Yes">Yes</option>
                        <option value="No">No</option>
                    </select>
                </th>
                <th><input type="text" placeholder="CWE..." /></th>
                <th><input type="text" placeholder="Vector..." /></th>
                <th><select><option value="">All</option><option>Yes</option><option>No</option></select></th>
                <th><select><option value="">All</option><option>Yes</option><option>No</option></select></th>
                <th><select><option value="">All</option><option>Yes</option><option>No</option></select></th>
                <th><select><option value="">All</option><option>Yes</option><option>No</option></select></th>
            </tr>
            </tfoot>
            <tbody>
    """
    )

    footer = """
    </tbody>
    </table>
    <div id="pageFooter">
        Made with <span style="color: red;">&#10084;</span> by 0liverFlow
    </div>
    <!-- Custom JS -->
    <script>
        $.fn.dataTable.ext.search.push(function(settings, data) {

        let cvss = parseFloat(data[1]);
        let epss = parseFloat(data[2]);

        let cvssFilter = $('.cvss-filter-footer').val();
        let epssFilter = $('.epss-filter-footer').val();

        if (cvssFilter) {

            if (!isNaN(cvss)) {
                if (cvssFilter === "critical" && cvss < 9) return false;
                if (cvssFilter === "high" && (cvss < 7 || cvss >= 9)) return false;
                if (cvssFilter === "medium" && (cvss < 4 || cvss >= 7)) return false;
                if (cvssFilter === "low" && cvss >= 4) return false;
            }
        }

        if (epssFilter) {
            if (epssFilter === "high" && epss < 70) return false;
            if (epssFilter === "medium" && (epss < 40 || epss >= 70)) return false;
            if (epssFilter === "low" && epss >= 40) return false;
        }

        return true;
    });

    $(document).ready(function() {
        var table = $('#report').DataTable({
            pageLength: 50,
            lengthMenu: [25, 50, 100, 200, 500],
            order: [[1, "desc"]],

            dom: '<"top"l<"reset-container">>rt<"bottom"ip><"clear">',

            autoWidth: false,

            columnDefs: [
                {
                    targets: 0,
                    render: function(data, type) {
                        if (type === 'sort' || type === 'type') {
                            let parts = data.split('-');
                            let year = parseInt(parts[1]) || 0;
                            let id = parseInt(parts[2]) || 0;
                            return year * 100000 + id;
                        }
                        return data;
                    }
                },
                {
                    targets: 1,
                    width: "60px",
                    render: function(data, type) {
                        if (type === 'sort' || type === 'type') {
                            return data === "N/A" ? -1 : parseFloat(data);
                        }
                        let cls = getCvssClass(data);
                        return `<span class="cvss-badge ${cls}">${data}</span>`;
                    }
                },
                {
                targets: 2,
                width: "60px",
                    render: function(data, type) {

                        let value = parseFloat(data);

                        if (type === 'sort' || type === 'type') {
                            return isNaN(value) ? -1 : value;
                        }

                        let cls = "";

                        if (value >= 70) {
                            cls = "epss-high";
                        } else if (value >= 40) {
                            cls = "epss-medium";
                        } else {
                            cls = "epss-low";
                        }

                        return `<span class="epss-badge ${cls}">${data}</span>`;
                    }
                },
                {
                    targets: 4,
                    width: "75px",
                        render: function(data, type) {

                            if (type === 'filter') {
                                return data.replace(/<[^>]*>/g, '');
                            }

                            if (type === 'sort' || type === 'type') {
                                let clean = data.replace(/<[^>]*>/g, '');
                                return parseInt(clean.replace('CWE-', '')) || 0;
                            }

                            return data;
                        }
                },
                {
                    targets: 6,
                    render: function(data, type) {

                        let match = data.match(/\((\d+)\)/);
                        let num = match ? parseInt(match[1]) : 0;

                        if (type === 'sort' || type === 'type') {
                            return num;
                        }

                        if (type === 'filter') {
                            return num > 0 ? 'Yes' : 'No';
                        }

                        return data;
                    }
                }
            
            ],

            initComplete: function () {
                var api = this.api();

                api.columns().every(function () {
                    var column = this;

                    $('input, select', column.footer()).on('keyup change', function () {
                        column.search(this.value).draw();
                    });
                });

                $(document).on('change', '.cvss-filter-footer, .epss-filter-footer', function () {
                    api.draw();
                });

                $('.reset-container').html(`
                    <button id="resetFilters" class="reset-btn">Reset</button>
                `);

                $('#resetFilters').on('click', function() {

                    $('#report tfoot input').val('');

                    $('#report tfoot select').prop('selectedIndex', 0);

                    $('.cvss-filter-footer').val('');
                    $('.epss-filter-footer').val('');

                    table.search('').columns().search('').draw();
                });
                
                $('.cvss-filter-footer, .epss-filter-footer').on('change', function () {
                    table.draw();
                });
            }
        });

    });

    $('#themeToggle').on('click', function() {
        $('body').toggleClass('dark');

        let isDark = $('body').hasClass('dark');
        $(this).html(isDark ? '☀️' : '🌙');

        localStorage.setItem('theme', isDark ? 'dark' : 'light');
    });

    if (localStorage.getItem('theme') === 'dark') {
        $('body').addClass('dark');
        $('#themeToggle').html('☀️');
    } else {
        $('#themeToggle').html('🌙');
    }

    function getCvssClass(score) {
        if (score === "N/A" || score === "") return "cvss-na";
        score = parseFloat(score);
        if (score >= 9.0) return "cvss-critical";
        if (score >= 7.0) return "cvss-high";
        if (score >= 4.0) return "cvss-medium";
        return "cvss-low";
    }
    </script>
    </body>
    </html>
    """

    for cve, cve_data in data.items():
        if cve_data["PoCs"]["GitHub"] != "No":
            if "nomi-sec" in cve_data["PoCs"]["GitHub"][0]:
                gh_td = f"<td><span class='badge yes'><a href='https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve}' target='_blank'>Yes ({cve_data['PoCs']['GitHub'][-1]})</a></span></td>"
            # gh_td = f"<td><span class='badge yes'><a href='https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve}' target='_blank'>Yes</a></span></td>"
            # gh_td = f"<td><span class='badge yes'><a href='{cve_data['PoCs']['GitHub']}' target='_blank'>Yes</a></span></td>"
            else:
                gh_td = f"<td><span class='badge yes'><a href='https://github.com/trickest/cve/blob/main{cve_data['PoCs']['GitHub'][0].split('main')[-1]}' target='_blank'>Yes ({cve_data['PoCs']['GitHub'][-1]})</a></span></td>"
        else:
            gh_td = "<td><span class='badge no'>No</a></span></td>"
        if cve_data["PoCs"]["ExploitDB"] != "No":
            exploit_db_td = f"<td><span class='badge yes'><a href='{cve_data['PoCs']['ExploitDB']}' target='_blank'>Yes</a></span></td>"
        else:
            exploit_db_td = "<td><span class='badge no'>No</a></span></td>"
        if cve_data["PoCs"]["Metasploit"] != "No":
            msf_td = f"<td><span class='badge yes'><a href='{cve_data['PoCs']['Metasploit']}' target='_blank'>Yes</a></span></td>"
        else:
            msf_td = "<td><span class='badge no'>No</a></span></td>"
        if cve_data["PoCs"]["Nuclei"] != "No":
            nuclei_td = f"<td><span class='badge yes'><a href='{cve_data['PoCs']['Nuclei']}' target='_blank'>Yes</a></span></td>"
        else:
            nuclei_td = "<td><span class='badge no'>No</a></span></td>"

        # <td><a href='https://www.cve.org/CVERecord?id={cve}' target='_blank'>{cve}</a></td>
        if len(cve_data["CWE"].split(",")) > 1:
            cwes = cve_data["CWE"].split(",")
            cwe_td = "<td>"
            for cwe in cwes:
                if cwe == cwes[-1]:
                    cwe_td += f"<a href='https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html' target='_blank'>{cwe}</a>"
                else:
                    cwe_td += f"<a href='https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html' target='_blank'>{cwe}, </a>"
            cwe_td += "</td>"
        elif cve_data["CWE"] != "N/A":
            cwe_td = f"<td><a href='https://cwe.mitre.org/data/definitions/{cve_data['CWE'].split('-')[-1]}.html' target='_blank'>{cve_data['CWE']}</a></td>"
        else:
            cwe_td = "<td>N/A</td>"

        # <td>{cve_data['CWE']}</td>

        head_and_body += f"""
        <tr>
            <td><a href='https://nvd.nist.gov/vuln/detail/{cve}' target='_blank'>{cve}</a></td>
            <td>{cve_data["Base Score"]}</td>
            <td>{cve_data["EPSS"]}</td>
            <td>{cve_data["KEV"]}</td>
            {cwe_td}
            <td class="vector-string">{cve_data["Vector String"]}</td>
            {gh_td}
            {exploit_db_td}
            {msf_td}
            {nuclei_td}
        </tr>
        """
    # <td data-search=f"{cve_data['PoCs']['GitHub'].split('(')[-1].replace(')','')}"><span class="{'badge yes' if cve_data['PoCs']['GitHub'] != 'No' else 'badge no'}">{cve_data['PoCs']['GitHub']}</span></td>
    html_report = head_and_body + footer

    with open(
        f"{output_dir_path}/cve2poc_report_{str(datetime.now().date()).replace('-', '_')}_{datetime.now().strftime('%H:%M:%S').replace(':', '_')}.html",
        "w",
        encoding="utf-8",
    ) as f:
        f.write(html_report)
        return True
    return False

def get_cve_record_and_exploits(cve_id, headers, kevs, epss_data, exploits_db):
    """
    This function retrieves cve_record and exploits related to a CVE ID

    :param headers: HTTP headers used to send requests to GitHub API and Cve.org
    :param kevs: A dictionary containing KEVs
    :param epss_data: A list containing EPSS scores
    :param exploits_db: This stores Nuclei templates, Metasploit and Exploit-DB exploits databases
    :param cve_id: The CVE ID
    """
    github_headers = headers[0]
    # Checking whether the submitted CVE is valid or not
    if not check_cve_id_format(cve_id):
        return None, f"Skipping {cve_id}: Incorrect CVE ID"

    cve_record = retrieve_cve_info_from_cve_org(cve_id, headers)
    if cve_record is None:
        return None, f"No record found for {cve_id}!"

    # Checking if CVE is a KEV
    kev_status, _ = is_kev(kevs, cve_id)
    if kev_status == "Yes":
        cve_record["kev"] = "Yes"
    else:
        cve_record["kev"] = "No"

    # Retrieving EPSS score
    cve_record["epss"] = get_epss(cve_id, epss_data)
    # Pass msf_modules_db_json, exploit_db_csv, nuclei_db_json as function arguments or try to import them
    # exploits_db is a tuple
    msf_modules_db_json, exploit_db_csv, nuclei_db_json = exploits_db
    pocs_from_other_sources = search_exploits_from_other_sources(
        cve_id, msf_modules_db_json, exploit_db_csv, nuclei_db_json
    )
    gh_pocs, poc_url = search_github_exploits(cve_id, github_headers)

    return {
        "cve_id": cve_id,
        "cve_record": cve_record,
        "pocs_from_other_sources": pocs_from_other_sources,
        "github_pocs": (gh_pocs, poc_url),
    }, None
