import requests
import tldextract
from datetime import datetime

# Updated Sources
BLOCKLIST_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
]
TLD_LIST_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

def get_list(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def main():
    # 1. Load Spam TLDs
    spam_tlds = {line.strip().lower() for line in get_list(TLD_LIST_URL) if line.strip() and not line.startswith('#')}
    
    raw_filtered_domains = set()
    excluded_tld_count = 0

    # 2. First Pass: Aggregate and Filter by TLD
    for url in BLOCKLIST_URLS:
        print(f"Processing: {url}")
        for line in get_list(url):
            domain = line.strip().lower()
            if not domain or domain.startswith(('#', '!', '[')):
                continue
            
            clean = domain.replace('*.', '').replace('||', '').replace('^', '')
            ext = tldextract.extract(clean)
            
            if ext.suffix in spam_tlds:
                excluded_tld_count += 1
                continue
            
            raw_filtered_domains.add(clean)

    # 3. Second Pass: Deep Deduplication (Subdomain Stripping)
    # Sort by length so shorter (root) domains are prioritized
    sorted_raw = sorted(list(raw_filtered_domains), key=len)
    final_domains = set()

    for d in sorted_raw:
        ext = tldextract.extract(d)
        root = f"{ext.domain}.{ext.suffix}"
        
        # If the root domain is already present, this subdomain is redundant
        if root in final_domains:
            continue
        final_domains.add(d)

    sorted_list = sorted(list(final_domains))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # 4. Generate Output with required header
    with open("output.txt", "w") as f:
        f.write(f"# Total Unique Domains: {len(sorted_list)}\n")
        f.write(f"# Domains Excluded (Spam TLDs): {excluded_tld_count}\n")
        f.write(f"# Redundant Subdomains Removed: {len(raw_filtered_domains) - len(final_domains)}\n")
        f.write(f"# Last Updated: {timestamp}\n")
        f.write("# Optimized via Aggregator Script\n\n")
        f.write("\n".join(sorted_list))

    print(f"\n--- Process Complete ---")
    print(f"Final Count: {len(sorted_list)}")

if __name__ == "__main__":
    main()
