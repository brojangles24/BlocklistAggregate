import requests
import concurrent.futures
from collections import Counter

# --- CONFIGURATION ---
# Format: (URL, Weight, Category)
SOURCES = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", 15, "Malware"), 
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards", 10, "Tracking"),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt", 8, "Aggressive"),
    ("https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt", 6, "Mobile Ads"),
    ("https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt", 5, "General Ads"),
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/domains.wildcards", 2, "Gap Filler")
]

# High priority spam TLD domains (Weight 20 to ensure inclusion)
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

DOMAIN_LIMIT = 300000

def fetch_url(url):
    """Helper to fetch text content safely."""
    print(f"Fetching: {url}")
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        return []

def parse_domains(lines):
    """Parses raw lines into a set of domains."""
    domains = set()
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith(('!', '#')):
            continue
        
        # Strip inline comments
        line = line.split('#')[0].strip()
        
        # Clean wildcard asterisks if present (e.g., *.example.com -> example.com)
        if line.startswith("*."):
            line = line[2:]
            
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domains.add(parts[1])
        elif len(parts) == 1:
            domains.add(parts[0])
            
    return domains

def main():
    domain_scores = Counter()
    
    # 1. Parallel Fetching
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Map futures to (weight, category)
        future_map = {}
        
        # Add Standard Sources
        for url, weight, cat in SOURCES:
            future = executor.submit(fetch_url, url)
            future_map[future] = (weight, cat)
            
        # Add Spam TLD Source (Treat as Critical/Malware level)
        spam_future = executor.submit(fetch_url, SPAM_TLD_URL)
        future_map[spam_future] = (20, "Spam TLDs")
        
        # Process Blocklists
        for future in concurrent.futures.as_completed(future_map):
            weight, cat = future_map[future]
            lines = future.result()
            domains = parse_domains(lines)
            print(f" -> {cat}: Found {len(domains)} domains. Adding {weight} points.")
            for d in domains:
                domain_scores[d] += weight

    # 2. Smart Deduplication (www.x vs x)
    print("Running Smart Deduplication...")
    for domain in list(domain_scores):
        if domain.startswith("www."):
            root = domain[4:]
            if root in domain_scores:
                del domain_scores[domain]

    # 3. Sort & Cut
    print("Sorting by risk score...")
    ranked = sorted(domain_scores.items(), key=lambda x: (-x[1], x[0]))
    final_list = [d[0] for d in ranked[:DOMAIN_LIMIT]]

    # 4. Output
    print(f"Writing {len(final_list)} unique domains to blocklist.txt...")
    with open("blocklist.txt", "w") as f:
        f.write(f"# Isaac's Optimized Blocklist\n# Total: {len(final_list)}\n\n")
        f.write("\n".join(final_list))

if __name__ == "__main__":
    main()
