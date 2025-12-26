import requests
import re

# Sources: Replace with your actual blocklist URLs
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts"
]
# HaGeZi's Most Abused TLDs (Raw)
TLD_LIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds.txt"

def get_list(url):
    response = requests.get(url)
    return response.text.splitlines()

def extract_tlds(tld_raw):
    # Extracts TLDs from HaGeZi's adblock format (e.g., ||*.zip^)
    tlds = set()
    for line in tld_raw:
        match = re.search(r'\|\|\*\.([a-z0-9-]+)\^', line)
        if match:
            tlds.add(match.group(1))
    return tlds

def main():
    print("Fetching TLD blocklist...")
    spam_tlds = extract_tlds(get_list(TLD_LIST_URL))
    
    unique_domains = set()
    
    print("Fetching and filtering blocklists...")
    for url in BLOCKLIST_URLS:
        lines = get_list(url)
        for line in lines:
            # Clean comments and ignore empty lines/headers
            clean_line = line.strip()
            if not clean_line or clean_line.startswith(('#', '!', '[', '127.0.0.1', '0.0.0.0')):
                # Simple regex to grab the domain if it's a hosts file format
                match = re.search(r'(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)', clean_line)
                if match:
                    domain = match.group(1).lower()
                else:
                    continue
            else:
                domain = clean_line.lower()

            # Filter by TLD
            tld = domain.split('.')[-1]
            if tld not in spam_tlds:
                unique_domains.add(domain)

    # Output results
    sorted_domains = sorted(list(unique_domains))
    with open("output.txt", "w") as f:
        f.write("\n".join(sorted_domains))
    
    print(f"--- Process Complete ---")
    print(f"Total Unique Domains: {len(sorted_domains)}")

if __name__ == "__main__":
    main()
