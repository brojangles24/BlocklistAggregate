import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = "2026.02.16.FINAL_FIX"
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

    # 2. Extract TLDs for the Firewall (The Fix)
    print("Extracting TLDs from Hagezi list to build the firewall...")
    for line in spam_tlds_raw:
        clean = line.strip().lower()
        # Look for wildcards: ||*.xyz^ or *.xyz^
        if "*." in clean:
            match = re.search(r"\*\.([a-z0-9\-]+)\^", clean)
            if match:
                blocked_tlds.add(match.group(1))
        # Look for simple TLD blocks: ||xyz^
        elif clean.startswith("||") and clean.count(".") == 0 and clean.endswith("^"):
            tld = clean.replace("||", "").replace("^", "")
            blocked_tlds.add(tld)

    print(f"Firewall active for {len(blocked_tlds)} TLDs (including .xyz, .top, etc.)")

    # 3. Process Core Sources with TLD and Keyword Scrubbing
    tld_nuke_count = 0
    keyword_nuke_count = 0
    
    for line in all_lines:
        line = line.strip().lower()
        line = line.split('#')[0].split('!')[0].split(';')[0].strip()
        
        if not line or "adblock plus" in line: continue
        
        # Keyword Nuke
        if NSFW_REGEX_COMP.search(line):
            keyword_nuke_count += 1
            continue
        
        if line.startswith("@@") or "||~" in line:
            allow_rules.add(line)
        elif "$" in line:
            advanced_rules.add(line)
        else:
            domain = line.replace("||", "").replace("^", "").strip()
            parts = domain.split()
            domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1")) else parts[0]
            
            if "." in domain and not domain.startswith("."):
                tld = domain.split('.')[-1]
                # THE TLD FIREWALL: Check if the domain's TLD is in our blocked set
                if tld in blocked_tlds:
                    tld_nuke_count += 1
                    continue
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
    
    # 5. Assemble
    final_output = list(advanced_rules)
    for rd in pruned_rev:
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    final_output.extend(list(allow_rules))
    final_output.sort()
    
    # 6. Final Write
    with open(OUTPUT_FILE, "w") as f:
        f.write("############################################################\n")
        f.write("# PART 1: HAGEZI SPAM TLD LIST (UNEDITED RAW)\n")
        f.write("############################################################\n")
        f.write("\n".join(spam_tlds_raw))
        f.write("\n\n")

        f.write("############################################################\n")
        f.write(f"# PART 2: OPTIMIZED CORE - {VERSION}\n")
        f.write(f"# Scrubbed: {keyword_nuke_count} Keywords | {tld_nuke_count} TLD Redundancies\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_output))
        f.write(f"\n{NSFW_REGEX_RAW}")
        f.write(f"\n{YOUTUBE_RULE}\n")

    print(f"Completed. Nuked {tld_nuke_count} domains for matching TLDs.")
    print(f"Nuked {keyword_nuke_count} rules for matching Keywords.")

if __name__ == "__main__":
    main()
