import requests
import tldextract
from datetime import datetime

# Target Sources (Raw Domain Format)
BLOCKLIST_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt"
]

# Exclusion Source (Raw TLD Format)
TLD_LIST_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

def get_list(url):
    """Fetches and cleans a remote text file into a list of lines."""
    try:
        print(f"Fetching: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def main():
    # 1. Load Spam TLDs into a hash set for O(1) lookups
    spam_tlds_raw = get_list(TLD_LIST_URL)
    spam_tlds = {line.strip().lower() for line in spam_tlds_raw if line.strip() and not line.startswith('#')}
    print(f"Loaded {len(spam_tlds)} spam TLDs.")

    unique_domains = set()
    excluded_domains = set()

    # 2. Process all blocklists
    for url in BLOCKLIST_URLS:
        lines = get_list(url)
        for line in lines:
            # Basic sanitization
            domain = line.strip().lower()
            if not domain or domain.startswith(('#', '!', '[')):
                continue
            
            # Clean common syntax if present (||domain.com^)
            clean_domain = domain.replace('*.', '').replace('||', '').replace('^', '')
            
            # 3. Precise TLD check using tldextract
            ext = tldextract.extract(clean_domain)
            if ext.suffix in spam_tlds:
                excluded_domains.add(clean_domain)
            else:
                unique_domains.add(clean_domain)

    # 4. Sort results
    sorted_kept = sorted(list(unique_domains))
    sorted_excluded = sorted(list(excluded_domains))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # 5. Write the final aggregated list with header
    with open("output.txt", "w") as f:
        f.write(f"# Total Unique Domains: {len(sorted_kept)}\n")
        f.write(f"# Domains Excluded (Spam TLDs): {len(sorted_excluded)}\n")
        f.write(f"# Last Updated: {timestamp}\n")
        f.write("# Optimized via Aggregator Script\n\n")
        f.write("\n".join(sorted_kept))
    
    # 6. Write the exclusion audit log
    with open("excluded.txt", "w") as f:
        f.write(f"# Total Domains Removed: {len(sorted_excluded)}\n")
        f.write(f"# Timestamp: {timestamp}\n\n")
        f.write("\n".join(sorted_excluded))

    print(f"\n--- SUCCESS ---")
    print(f"Aggregated: {len(sorted_kept)} domains")
    print(f"Excluded:   {len(sorted_excluded)} domains")

if __name__ == "__main__":
    main()
