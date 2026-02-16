import requests
import concurrent.futures
from datetime import datetime

# --- CONFIGURATION ---
# Format: URL
SOURCES = [
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif-onlydomains.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
    "https://github.com/sjhgvr/oisd/blob/main/domainswild_nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
]

DOMAIN_LIMIT = 2000000
OUTPUT_FILE = "blocklist.txt"

def fetch_url(url):
    """Fetch text content with a reasonable timeout."""
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def parse_domains(lines):
    """Optimized parsing of domain lines."""
    parsed = set()
    for line in lines:
        line = line.strip().lower()
        
        # Skip comments and empty lines early
        if not line or line.startswith(('#', '!', ';')):
            continue
        
        # Remove inline comments and clean up
        line = line.split('#')[0].split(';')[0].strip()
        
        # Clean wildcards
        if line.startswith("*."):
            line = line[2:]
            
        # Handle hosts file format (0.0.0.0 domain.com)
        parts = line.split()
        if len(parts) >= 2:
            # Check if first part is an IP redirect
            if parts[0] in ("0.0.0.0", "127.0.0.1", "::1"):
                parsed.add(parts[1])
            else:
                # Sometimes it's just 'domain.com # comment'
                parsed.add(parts[0])
        elif len(parts) == 1:
            parsed.add(parts[0])
            
    return parsed

def main():
    all_domains = set()
    start_time = datetime.now()

    # 1. Parallel Fetching & Parsing
    print(f"Starting fetch of {len(SOURCES)} sources...")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            lines = future.result()
            domains = parse_domains(lines)
            all_domains.update(domains)
            print(f"  + Added {len(domains)} domains from {url[:50]}...")

    # 2. Smart Deduplication (Remove www. version if root exists)
    print("Performing deduplication...")
    # We iterate over a copy of the set to avoid modification errors
    for domain in list(all_domains):
        if domain.startswith("www."):
            root = domain[4:]
            if root in all_domains:
                all_domains.discard(domain)

    # 3. Alphabetical Sorting
    print("Sorting list alphabetically...")
    final_list = sorted(list(all_domains))
    
    # Apply limit if necessary
    if len(final_list) > DOMAIN_LIMIT:
        final_list = final_list[:DOMAIN_LIMIT]

    # 4. Write to File with Header
    print(f"Saving to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write(f"# Optimized Blocklist\n")
        f.write(f"# Date Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total Domains: {len(final_list)}\n")
        f.write(f"# Sources: {len(SOURCES)}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_list))

    print(f"Done! Processed in {datetime.now() - start_time}")

if __name__ == "__main__":
    main()
