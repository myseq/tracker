import asyncio
import aiohttp
import time

epss_percentage = 0.50
epss_percentile = 0.99
top = 5

# NVD is strict. This limits us to 2 concurrent requests at a time.
# If you have an API key, you can increase this number.
MAX_CONCURRENT_REQUESTS = 2 

async def get_cvss_score(session, cve_id, semaphore):
    """Fetch the CVSS score from the NVD API asynchronously."""
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    async with semaphore:
        try:
            # Respectful delay for NVD (adjust if using an API key)
            await asyncio.sleep(0.6) 
            async with session.get(nvd_url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    if vulnerabilities:
                        cve_data = vulnerabilities[0].get('cve', {})
                        metrics = cve_data.get('metrics', {})
                        cvename = cve_data.get('cisaVulnerabilityName', 'n/a')
                        
                        # Try to get CVSS v3.1, v3.0, or v2.0
                        v3 = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
                        if v3:
                            return v3[0]['cvssData']['baseScore'], cvename
                        
                        v2 = metrics.get('cvssMetricV2')
                        if v2:
                            return v2[0]['cvssData']['baseScore'], cvename
                            
                return "N/A", 'n/a'
        except Exception:
            return "Error", 'n/a'

async def fetch_and_format_epss():
    url = f"https://api.first.org/data/v1/epss?epss-gt={epss_percentage}&percentile-gt={epss_percentile}&order=!epss&limit={top}"

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()

            vulnerabilities = data.get('data', [])
            total_found = data.get('total', 0)

            # Create a list of tasks for the NVD enrichment
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
            tasks = []
            for v in vulnerabilities:
                tasks.append(get_cvss_score(session, v['cve'], semaphore))

            # Run NVD calls concurrently
            enriched_results = await asyncio.gather(*tasks)

            # Build Markdown
            markdown_output = f"### EPSS Priority Report (Top {len(vulnerabilities)} of {total_found} Total CVEs)\n\n"
            markdown_output += "| CVE | Vulnerability | Percentage (Probability) | Percentile | CVSS Score |\n"
            markdown_output += "| :-- | :------------ | :----------------------: | ---------: | :--------: |\n"

            for i, v in enumerate(vulnerabilities):
                cve_id = v['cve']
                prob_percent = f"{float(v['epss']) * 100:.2f}%"
                percentile = f"{float(v['percentile']) * 100:.2f}th"
                cvss_score, cvename = enriched_results[i]

                markdown_output += f"| {cve_id} | {cvename} | {prob_percent} | {percentile} | {cvss_score} |\n"

            print("\n" + markdown_output)

        except Exception as e:
            print(f"Error fetching EPSS data: {e}")

if __name__ == "__main__":
    print(f'## Top-{top} CVE\n')
    print(f'This shows the top-{top} vulnerabilities that have more than {epss_percentage *100:.2f}% chance of being exploited in the next 30 days.')
    
    # Run the entry point
    asyncio.run(fetch_and_format_epss())

