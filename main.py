import requests
import concurrent.futures
from datetime import datetime

# --- CONFIGURATION ---
VERSION = datetime.now().strftime("%Y.%m.%d.01")  # Revision format: Year.Month.Day.Rev
SOURCES = [
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif-onlydomains.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/pro.plus-onlydomains.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
    "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
]

OUTPUT_FILE = "blocklist.txt"

def fetch_url(url):
    """Fetches list content with a timeout and basic error handling."""
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def parse_domains(lines):
    """Cleans raw lines into normalized domains, handling various host-file formats."""
    parsed = set()
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith(('#', '!', ';')): 
            continue
        
        # Remove inline comments
        line = line.split('#')[0].split(';')[0].strip()
        
        # Strip wildcard markers if present
        if line.startswith("*."): 
            line = line[2:]
        
        parts = line.split()
        if len(parts) >= 2:
            # Handle hosts format: 0.0.0.0 example.com
            if parts[0] in ("0.0.0.0", "127.0.0.1", "::1"): 
                parsed.add(parts[1])
            else: 
                parsed.add(parts[0])
        elif len(parts) == 1:
            parsed.add(parts[0])
    return parsed

def prune_domains(domain_set):
    """
    Performs tree-based pruning. 
    If 'example.com' exists, 'ads.example.com' is redundant and removed.
    """
    print(f"Pruning redundant subdomains from {len(domain_set):,} entries...")
    
    # Reverse domains: 'ads.google.com' -> 'com.google.ads' for sequential sorting
    reversed_domains = sorted(['.'.join(d.split('.')[::-1]) for d in domain_set])
    
    pruned_list = []
    last_added = ""
    
    for rd in reversed_domains:
        # Check if current reversed domain is a branch of the last added root
        if last_added and rd.startswith(last_added + "."):
            continue
        
        pruned_list.append(rd)
        last_added = rd

    # Reverse back to original format
    return ['.'.join(d.split('.')[::-1]) for d in pruned_list]

def main():
    all_domains = set()
    start_time = datetime.now()

    # 1. Concurrent Download & Parse
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            domains = parse_domains(future.result())
            all_domains.update(domains)
            print(f"  + Added {len(domains):,} from {url[:50]}...")

    raw_count = len(all_domains)

    # 2. Tree-based Pruning (The "Optimizer")
    final_list = prune_domains(all_domains)
    final_list.sort() # Final alphabetical sort for usability

    pruned_count = raw_count - len(final_list)

    # 3. Output with Detailed Metadata
    print(f"Saving to {OUTPUT_FILE} (Optimized {pruned_count:,} redundant entries)")
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S MASTER BLOCKLIST (TREE-PRUNED)\n")
        f.write(f"# Revision: {VERSION}\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("#\n")
        f.write("# SCOPE OF PROTECTION:\n")
        f.write("# - Malware, Phishing, & Ransomware C2\n")
        f.write("# - Aggressive Tracking & Telemetry\n")
        f.write("# - Mobile & Desktop Advertisements\n")
        f.write("# - Fake News & Anti-Piracy Domains\n")
        f.write("# - NSFW & Adult Content\n")
        f.write("#\n")
        f.write(f"# STATISTICS:\n")
        f.write(f"# - Total Unique Domains: {len(final_list):,}\n")
        f.write(f"# - Redundant Branches Pruned: {pruned_count:,}\n")
        f.write(f"# - Source Feeds Integrated: {len(SOURCES)}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_list))

    print(f"Process completed in {datetime.now() - start_time}")

if __name__ == "__main__":
    main()
