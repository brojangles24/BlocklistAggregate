import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = datetime.now().strftime("%Y.%m.%d.01")
SOURCES = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt",
    "https://big.oisd.nl",
    "https://nsfw.oisd.nl",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://filters.adtidy.org/extension/chromium/filters/3.txt"    # DNS-Optimized Tracking
]

# Keywords to Nuke (Applied to building AND injected into the list)
NSFW_KEYWORDS = r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)"
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"
NSFW_REGEX_COMP = re.compile(f"(?i){NSFW_KEYWORDS}")

# YouTube Safety Rule
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

OUTPUT_FILE = "blocklist.txt"

def fetch_url(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def main():
    blocked_tlds = set()
    advanced_rules = set()
    simple_domains = set()
    allow_rules = set()
    
    start_time = datetime.now()

    # 1. First Pass: Download and Identify Nuclear TLDs
    print(f"Fetching {len(SOURCES)} sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    # 2. Categorize and Filter
    print("Categorizing rules and applying TLD Firewall...")
    for line in all_lines:
        # Strip comments and whitespace
        line = line.strip().lower()
        line = line.split('#')[0].split('!')[0].split(';')[0].strip()
        
        if not line or "adblock plus" in line: continue
        
        # Nuclear NSFW Scrub
        if NSFW_REGEX_COMP.search(line): continue
        
        # Identify TLDs to nuke (||*.tld^ or ||tld^)
        if line.startswith("||*.") and "^" in line and "$" not in line:
            tld = line.replace("||*.", "").replace("^", "")
            if "." not in tld: blocked_tlds.add(tld)
            advanced_rules.add(line)
            continue

        # Handle Allows (Exceptions)
        if line.startswith("@@"):
            allow_rules.add(line)
            continue
        
        # Handle Advanced Modifiers ($)
        if "$" in line:
            advanced_rules.add(line)
            continue

        # Process standard domains for tree-pruning
        domain = line.replace("||", "").replace("^", "").strip()
        parts = domain.split()
        # Handle hosts format (0.0.0.0 domain.com)
        domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1")) else parts[0]
        
        if "." in domain and not domain.startswith("."):
            tld = domain.split('.')[-1]
            # TLD Firewall: Nuke it if it belongs to a blocked TLD
            if tld in blocked_tlds:
                continue
            simple_domains.add(domain)

    # 3. Exception-Aware Tree Pruning
    print(f"Pruning {len(simple_domains):,} domains...")
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in simple_domains])
    pruned_rev = []
    last_added = ""
    for rd in rev_domains:
        if last_added and rd.startswith(last_added + "."): continue
        pruned_rev.append(rd)
        last_added = rd
    
    # 4. Final Construction
    final_output = list(advanced_rules)
    for rd in pruned_rev:
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    final_output.extend(list(allow_rules))
    
    # Final cleanup and enforcement injection
    final_output.sort()
    final_output.append(NSFW_REGEX_RAW)
    final_output.append(YOUTUBE_RULE)

    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S PROACTIVE MASTER (NUCLEAR EDITION)\n")
        f.write(f"# Revision: {VERSION}\n")
        f.write(f"# Rules: {len(final_output):,} | TLDs: {len(blocked_tlds)}\n")
        f.write("# Cleanup: Tree-Pruned, NSFW-Scrubbed, TLD-Nuked\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_output))

    print(f"Completed in {datetime.now() - start_time}.")
    print(f"Final Rule Count: {len(final_output):,}")

if __name__ == "__main__":
    main()
