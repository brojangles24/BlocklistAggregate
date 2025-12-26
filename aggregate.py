import requests
import tldextract

# Target Sources
BLOCKLIST_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt"
]
# Exclusion Source
TLD_LIST_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

def get_list(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Error: {e}")
        return []

def main():
    print("Loading Spam TLDs...")
    spam_tlds = {line.strip().lower() for line in get_list(TLD_LIST_URL) if line.strip()}
    
    unique_domains = set()
    excluded_domains = set()

    for url in BLOCKLIST_URLS:
        print(f"Fetching: {url}")
        for line in get_list(url):
            domain = line.strip().lower()
            if not domain or domain.startswith(('#', '!', '[')):
                continue
            
            clean_domain = domain.replace('*.', '').replace('||', '').replace('^', '')
            ext = tldextract.extract(clean_domain)
            
            if ext.suffix in spam_tlds:
                excluded_domains.add(clean_domain)
            else:
                unique_domains.add(clean_domain)

    # Save output
    with open("output.txt", "w") as f:
        f.write("\n".join(sorted(list(unique_domains))))
    
    # Save excluded audit trail
    with open("excluded.txt", "w") as f:
        f.write("\n".join(sorted(list(excluded_domains))))
    
    print("\n--- Summary ---")
    print(f"Total Unique Domains Kept: {len(unique_domains)}")
    print(f"Total Domains Excluded:    {len(excluded_domains)}")

if __name__ == "__main__":
    main()
