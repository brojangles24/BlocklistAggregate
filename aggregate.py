import requests
import tldextract

# Target Sources
BLOCKLIST_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
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

    for url in BLOCKLIST_URLS:
        print(f"Fetching: {url}")
        for line in get_list(url):
            domain = line.strip().lower()
            if not domain or domain.startswith(('#', '!', '[')):
                continue
            
            # Handle potential "wildcard" notation if present
            clean_domain = domain.replace('*.', '').replace('||', '').replace('^', '')
            
            ext = tldextract.extract(clean_domain)
            if ext.suffix not in spam_tlds:
                unique_domains.add(clean_domain)

    sorted_domains = sorted(list(unique_domains))
    with open("output.txt", "w") as f:
        f.write("\n".join(sorted_domains))
    
    print(f"\nTotal Unique Domains: {len(sorted_domains)}")

if __name__ == "__main__":
    main()
