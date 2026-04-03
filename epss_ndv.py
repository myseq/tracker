import requests
import time

epss_percentage = 0.50
epss_percentile = 0.99
top = 25

def get_cvss_score(cve_id):
    """Fetch the CVSS score from the NVD API."""
    """https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218"""

    #nvd_url = f"https://nist.gov{cve_id}"
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    print(f"Fetching from: {nvd_url}\n")

    try:
        # Note: NVD requests a delay between calls if you don't have an API key
        time.sleep(0.6) 
        response = requests.get(nvd_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                metrics = vulnerabilities[0].get('cve', {}).get('metrics', {})
                # Try to get CVSS v3.1 or v3.0, fallback to v2.0
                v3 = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
                if v3:
                    return v3[0]['cvssData']['baseScore']
                v2 = metrics.get('cvssMetricV2')
                if v2:
                    return v2[0]['cvssData']['baseScore']
        return "N/A"
    except Exception:
        return "Error"

def fetch_and_format_epss():
    url = f"https://api.first.org/data/v1/epss?epss-gt={epss_percentage}&percentile-gt={epss_percentile}&order=!epss&limit={top}"
    
    print(f"Fetching from: {url}\n")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get('data', [])
        total_found = data.get('total', 0)

        markdown_output = f"### EPSS Priority Report (Top {len(vulnerabilities)} of {total_found} Total CVEs)\n\n"
        markdown_output += "| CVE | Percentage (Probability) | Percentile | CVSS Score |\n"
        markdown_output += "| :--- | :--- | :--- | :--- |\n"

        for v in vulnerabilities:
            cve_id = v['cve']
            prob_percent = f"{float(v['epss']) * 100:.2f}%"
            percentile = f"{float(v['percentile']) * 100:.2f}th"
            
            # Call NVD for CVSS score
            print(f"Enriching {cve_id}...")
            cvss_score = get_cvss_score(cve_id)

            markdown_output += f"| {cve_id} | {prob_percent} | {percentile} | {cvss_score} |\n"

        print("\n" + markdown_output)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching EPSS data: {e}")

if __name__ == "__main__":
    print(f'## Top-{top} CVE')
    print(f'')
    print(f'This show the top-{top} vulnerabilities that have more than {epss_percentage *100:.2f}% chance of being exploit in the next 30 days and are randked in the top {100-(epss_percentile*100):.2f}% of all risks, sorted from highest to lowest risk.')
    print(f'')
    fetch_and_format_epss()

