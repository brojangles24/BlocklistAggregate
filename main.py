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
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
]

NSFW_REGEX = re.compile(r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)")

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
    raw_rules = set()
    blocked_tlds = set()
    advanced_rules = set()
    simple_domains = set()
    allow_rules = set()
    
    start_time = datetime.now()

    # 1. Download and Categorize
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            lines = future.result()
            for line in lines:
                line = line.strip().lower()
                if not line or line.startswith(('#', '!', ';')): continue
                if NSFW_REGEX.search(line): continue
                
                # A. Handle Allows
                if line.startswith("@@"):
                    allow_rules.add(line)
                    continue
                
                # B. Handle Advanced Rules ($)
                if "$" in line:
                    advanced_rules.add(line)
                    continue

                # C. Handle Nuclear TLD blocks (||*.tld^)
                if line.startswith("||*."):
                    tld = line.replace("||*.", "").replace("^", "")
                    blocked_tlds.add(tld)
                    advanced_rules.add(line) # Keep TLD rules in the "protected" set
                    continue
                
                # D. Extract naked domain for pruning logic
                domain = line.replace("||", "").replace("^", "").strip()
                parts = domain.split()
                domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1")) else parts[0]
                
                if "." in domain and not domain.startswith("."):
                    # Check if TLD is already nuked
                    tld = domain.split('.')[-1]
                    if tld not in blocked_tlds:
                        simple_domains.add(domain)

    print(f"Pruning {len(simple_domains):,} domains against {len(blocked_tlds)} Nuclear TLDs...")

    # 2. Tree-Based Pruning for Simple Domains
    # Reverse domains for efficient sorting/pruning
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in simple_domains])
    pruned_rev = []
    last_added = ""
    
    for rd in rev_domains:
        if last_added and rd.startswith(last_added + "."):
            continue
        pruned_rev.append(rd)
        last_added = rd
    
    # 3. Final Construction
    final_output = []
    
    # Add Advanced rules ($denyallow, ||*.tld^)
    final_output.extend(list(advanced_rules))
    
    # Add Pruned Simple rules (converted back to AdGuard syntax)
    for rd in pruned_rev:
        original = '.'.join(rd.split('.')[::-1])
        final_output.append(f"||{original}^")
        
    # Add Allow rules (@@)
    final_output.extend(list(allow_rules))
    
    # Add YouTube Rule
    final_output.sort()
    final_output.append(YOUTUBE_RULE)

    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# ISAAC'S PROACTIVE MASTER (TREE-PRUNED & NUCLEAR)\n")
        f.write(f"# Revision: {VERSION}\n")
        f.write(f"# Pruned Simple Rules: {len(pruned_rev):,}\n")
        f.write(f"# Protected TLD/Advanced Rules: {len(advanced_rules):,}\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_output))

    print(f"Process completed in {datetime.now() - start_time}.")

if __name__ == "__main__":
    main()
