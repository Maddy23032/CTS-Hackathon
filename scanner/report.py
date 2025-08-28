def generate_html_report(base_url, vulnerabilities, filename="report.html"):
    from collections import Counter
    import json

    type_counts = Counter(v["vulnerability_type"] for v in vulnerabilities if v.get("vulnerable"))
    labels = list(type_counts.keys())
    data = list(type_counts.values())

    labels_json = json.dumps(labels)
    data_json = json.dumps(data)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Scan Report for {base_url}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .vulnerable {{ color: red; font-weight: bold; }}
        .remediation {{ font-style: italic; background-color: #f9f9f9; padding: 6px; }}
    </style>
</head>
<body>
    <h1>Scan Report for {base_url}</h1>

    <h2>Vulnerability Summary</h2>
    <canvas id="vulnChart" width="600" height="400"></canvas>

    <script>
    const ctx = document.getElementById('vulnChart').getContext('2d');
    const vulnChart = new Chart(ctx, {{
        type: 'pie',
        data: {{
            labels: {labels_json},
            datasets: [{{
                data: {data_json},
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(153, 102, 255, 0.7)',
                    'rgba(255, 159, 64, 0.7)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)',
                    'rgba(255, 159, 64, 1)'
                ],
                borderWidth: 1
            }}]
        }},
        options: {{
            responsive: false,
            plugins: {{
                legend: {{
                    position: 'right',
                    labels: {{
                        boxWidth: 20,
                        padding: 15
                    }}
                }}
            }}
        }}
    }});
    </script>

    <h2>Detailed Vulnerabilities</h2>
    <table>
        <thead>
            <tr>
                <th>URL</th>
                <th>Form #</th>
                <th>Vulnerability Type</th>
                <th>Status</th>
                <th>Details</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
    """

    for vuln in vulnerabilities:
        url = vuln.get("url", "N/A")
        form_num = vuln.get("form_number", "N/A")
        vul_type = vuln.get("vulnerability_type", "N/A")
        status_class = "vulnerable" if vuln.get("vulnerable") else ""
        status_text = "Yes" if vuln.get("vulnerable") else "No"
        message = vuln.get("message", "")
        remediation = vuln.get("remediation", "")

        html += f"""
            <tr>
                <td>{url}</td>
                <td>{form_num}</td>
                <td>{vul_type}</td>
                <td class="{status_class}">{status_text}</td>
                <td>{message}</td>
                <td class="remediation">{remediation}</td>
            </tr>
        """

    html += """
        </tbody>
    </table>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\nReport generated: {filename}")
