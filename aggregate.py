import requests
import tldextract

# Sources
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts"
]
# Your new raw TLD source
TLD_LIST_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

def get_list(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def main():
    print("Fetching HaGeZi Raw Spam TLDs...")
    # This list is raw domains/TLDs, so we just strip whitespace
    spam_tlds = {line.strip().lower() for line in get_list(TLD_LIST_URL) if line.strip()}
    print(f"Loaded {len(spam_tlds)} spam TLDs.")

    unique_domains = set()

    for url in BLOCKLIST_URLS:
        print(f"Processing source: {url}")
        lines = get_list(url)
        for line in lines:
            clean_line = line.strip().lower()
            if not clean_line or clean_line.startswith(('#', '!', '[')):
                continue

            # Extract domain from hosts format or plain list
            parts = clean_line.split()
            domain = parts[-1] if len(parts) > 1 else parts[0]
            
            # Use tldextract to isolate the suffix
            ext = tldextract.extract(domain)
            
            # Check if the TLD/suffix matches the spam list
            if ext.suffix not in spam_tlds:
                unique_domains.add(domain)

    # Sort for consistency and output
    sorted_domains = sorted(list(unique_domains))
    with open("output.txt", "w") as f:
        # Exporting in standard domain format
        f.write("\n".join(sorted_domains))
    
    print(f"\n--- Process Complete ---")
    print(f"Total Unique Domains: {len(sorted_domains)}")

if __name__ == "__main__":
    main()
