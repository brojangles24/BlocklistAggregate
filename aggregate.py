import requests
import tldextract
from datetime import datetime

# Sources
BLOCKLIST_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt",
    "https://badmojr.github.io/1Hosts/Lite/domains.txt",
]
TLD_LIST_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

def get_list(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except:
        return []

def main():
    # Load Spam TLDs
    spam_tlds = {line.strip().lower() for line in get_list(TLD_LIST_URL) if line.strip() and not line.startswith('#')}
    
    unique_domains = set()
    excluded_count = 0

    # Aggregate and Filter
    for url in BLOCKLIST_URLS:
        for line in get_list(url):
            domain = line.strip().lower()
            if not domain or domain.startswith(('#', '!', '[')):
                continue
            
            clean = domain.replace('*.', '').replace('||', '').replace('^', '')
            if tldextract.extract(clean).suffix in spam_tlds:
                excluded_count += 1
                continue
            
            unique_domains.add(clean)

    sorted_list = sorted(list(unique_domains))
    total_after = len(sorted_list)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Output File
    with open("output.txt", "w") as f:
        f.write(f"# Total Unique Domains (After Exclusions): {total_after}\n")
        f.write(f"# Total Domains Excluded: {excluded_count}\n")
        f.write(f"# Last Updated: {timestamp}\n")
        f.write("# Optimized via Aggregator Script\n\n")
        f.write("\n".join(sorted_list))
    
    # Console Output for GitHub Actions Logs
    print(f"Aggregation Complete.")
    print(f"Domains Excluded: {excluded_count}")
    print(f"Total Domains in List: {total_after}")

if __name__ == "__main__":
    main()
