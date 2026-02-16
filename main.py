import requests
import concurrent.futures
from datetime import datetime

# --- CONFIGURATION ---
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
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def parse_domains(lines):
    parsed = set()
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith(('#', '!', ';')): continue
        line = line.split('#')[0].split(';')[0].strip()
        if line.startswith("*."): line = line[2:]
        parts = line.split()
        if len(parts) >= 2:
            if parts[0] in ("0.0.0.0", "127.0.0.1", "::1"): parsed.add(parts[1])
            else: parsed.add(parts[0])
        elif len(parts) == 1:
            parsed.add(parts[0])
    return parsed

def prune_domains(domain_set):
    """
    Performs tree-based pruning. If 'example.com' is in the list, 
    'sub.example.com' is redundant and will be removed.
    """
    print(f"Pruning redundant subdomains from {len(domain_set):,} entries...")
    
    # 1. Reverse the domains: 'ads.google.com' -> 'com.google.ads'
    # This groups subdomains directly after their parent domains when sorted.
    reversed_domains = sorted(['.'.join(d.split('.')[::-1]) for d in domain_set])
    
    pruned_list = []
    last_added = ""
    
    for rd in reversed_domains:
        # If the current reversed domain starts with the previous one + '.', 
        # it is a subdomain of something we already blocked.
        if last_added and rd.startswith(last_added + "."):
            continue
        
        pruned_list.append(rd)
        last_added = rd

    # 2. Reverse back to original format
    final_domains = ['.'.join(d.split('.')[::-1]) for d in pruned_list]
    return final_domains

def main():
    all_domains = set()
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            domains = parse_domains(future.result())
            all_domains.update(domains)
            print(f"  + Added {len(domains):,} from {url[:50]}...")

    # Initial count before pruning
    raw_count = len(all_domains)

    # Tree-based Pruning
    final_list = prune_domains(all_domains)
    final_list.sort() # Final alphabetical sort

    print(f"Saving to {OUTPUT_FILE} (Removed {raw_count - len(final_list):,} redundant subdomains)")
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write(f"# Isaac's Master Blocklist (Tree-Pruned)\n")
        f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total Unique Domains: {len(final_list):,}\n")
        f.write(f"# Redundant Subdomains Pruned: {raw_count - len(final_list):,}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_list))

    print(f"Finished in {datetime.now() - start_time}")

if __name__ == "__main__":
    main()
