import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = "2026.02.16.ULTRA"
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
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

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
    blocked_tlds = set()
    advanced_rules = set()
    simple_domains = set()
    allow_rules = set()
    start_time = datetime.now()

    # 1. Fetch Everything
    print("Fetching sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    spam_tlds_raw = fetch_url(SPAM_TLD_URL)

    # 2. Extract TLD strings for the Firewall
    print("Extracting TLDs for the cross-reference firewall...")
    for line in spam_tlds_raw:
        clean = line.strip().lower()
        # Extracts 'xyz' from '||*.xyz^' or '||xyz^'
        tld_match = re.search(r"(\*\.|\^|\|\|)([a-z0-9\-]+)\^", clean)
        if tld_match:
            tld = tld_match.group(2)
            if tld and len(tld) > 1:
                blocked_tlds.add(tld)

    # 3. Process Core Sources with "Deep Scan" TLD and Keyword Scrubbing
    tld_nuke_count = 0
    keyword_nuke_count = 0
    
    for line in all_lines:
        line_clean = line.strip().lower()
        # Split comments
        line_clean = line_clean.split('#')[0].split('!')[0].split(';')[0].strip()
        
        if not line_clean or "adblock plus" in line_clean: continue
        
        # Keyword Nuke
        if NSFW_REGEX_COMP.search(line_clean):
            keyword_nuke_count += 1
            continue
        
        # --- THE AGGRESSIVE TLD SCRUB ---
        # Check if the line contains any blocked TLD pattern
        is_redundant = False
        for tld in blocked_tlds:
            if f".{tld}" in line_clean:
                is_redundant = True
                break
        
        if is_redundant:
            tld_nuke_count += 1
            continue
        # -------------------------------

        if line_clean.startswith("@@") or "||~" in line_clean:
            allow_rules.add(line_clean)
        elif "$" in line_clean:
            advanced_rules.add(line_clean)
        else:
            domain = line_clean.replace("||", "").replace("^", "").strip()
            parts = domain.split()
            domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1")) else parts[0]
            if "." in domain and not domain.startswith("."):
                simple_domains.add(domain)

    # 4. Tree-Pruning
    print(f"Pruning {len(simple_domains):,} core domains...")
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in simple_domains])
    pruned_rev = []
    last_added = ""
    for rd in rev_domains:
        if last_added and rd.startswith(last_added + "."): continue
        pruned_rev.append(rd)
        last_added = rd
    
    # 5. Assemble and Final Write
    final_output = list(advanced_rules)
    for rd in pruned_rev:
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    final_output.extend(list(allow_rules))
    final_output.sort()
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# PART 1: HAGEZI SPAM TLD LIST (UNEDITED RAW)\n")
        f.write("############################################################\n")
        f.write("\n".join(spam_tlds_raw))
        f.write("\n\n")

        f.write("############################################################\n")
        f.write(f"# PART 2: OPTIMIZED CORE - {VERSION}\n")
        f.write(f"# Removed: {keyword_nuke_count} Keywords | {tld_nuke_count} TLD Redundancies\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_output))
        f.write(f"\n{NSFW_REGEX_RAW}\n{YOUTUBE_RULE}\n")

    print(f"Success. Nuked {tld_nuke_count} rules matching Hagezi TLDs.")
    print(f"Nuked {keyword_nuke_count} rules matching NSFW Keywords.")

if __name__ == "__main__":
    main()
