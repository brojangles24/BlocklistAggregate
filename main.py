import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = datetime.now().strftime("%Y.%m.%d.01")

# 11 Core sources for optimization
CORE_SOURCES = [
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
    "https://filters.adtidy.org/extension/chromium/filters/3.txt"
]

# The "Unedited" Source
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

# Keywords & Enforcement
NSFW_KEYWORDS = r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)"
NSFW_REGEX_COMP = re.compile(f"(?i){NSFW_KEYWORDS}")
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"
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
    advanced_rules = set()
    simple_domains = set()
    allow_rules = set()
    start_time = datetime.now()

    # 1. Fetch Everything
    print(f"Fetching {len(CORE_SOURCES)} core sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    print("Fetching RAW Spam TLD list...")
    spam_tlds = fetch_url(SPAM_TLD_URL)
    # Filter comments from the raw list for clean merging
    spam_tlds = [line.strip() for line in spam_tlds if line.strip() and not line.startswith(('#', '!', ';'))]

    # 2. Process Core Sources (Pruning & Scrubbing)
    print("Executing deduplication and keyword scrubbing...")
    for line in all_lines:
        line = line.strip().lower()
        line = line.split('#')[0].split('!')[0].split(';')[0].strip()
        
        if not line or "adblock plus" in line: continue
        if NSFW_REGEX_COMP.search(line): continue
        
        if line.startswith("@@") or "||~" in line:
            allow_rules.add(line)
        elif "$" in line:
            advanced_rules.add(line)
        else:
            domain = line.replace("||", "").replace("^", "").strip()
            parts = domain.split()
            domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1")) else parts[0]
            if "." in domain and not domain.startswith("."):
                simple_domains.add(domain)

    # 3. Tree-Pruning
    print(f"Pruning {len(simple_domains):,} domains...")
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in simple_domains])
    pruned_rev = []
    last_added = ""
    for rd in rev_domains:
        if last_added and rd.startswith(last_added + "."): continue
        pruned_rev.append(rd)
        last_added = rd
    
    # 4. Final Construction
    print("Merging and sorting master file...")
    final_output = list(advanced_rules)
    for rd in pruned_rev:
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    final_output.extend(list(allow_rules))
    
    # Merge the RAW Spam TLDs here
    all_final_rules = final_output + spam_tlds
    all_final_rules.sort()
    
    # 5. Writing the file
    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write(f"# ISAAC'S PROACTIVE MASTER - REVISION: {VERSION}\n")
        f.write(f"# Status: Tree-Pruned, NSFW-Scrubbed, RAW-TLD Appended\n")
        f.write("############################################################\n\n")
        
        f.write("\n".join(all_final_rules))
        f.write(f"\n{NSFW_REGEX_RAW}")
        f.write(f"\n{YOUTUBE_RULE}")

    print(f"Completed in {datetime.now() - start_time}.")
    print(f"Final Rule Count: {len(all_final_rules):,}")

if __name__ == "__main__":
    main()
