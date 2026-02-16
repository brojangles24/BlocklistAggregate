import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = "2026.02.16.FINAL_BOSS"
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
    blocked_tlds = set()
    advanced_rules = set()
    simple_domains = set()
    allow_rules = set()
    start_time = datetime.now()

    print("Fetching sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    spam_tlds_raw = fetch_url(SPAM_TLD_URL)

    # 1. Extract TLD Firewall (Memorizes .xyz, .top, etc.)
    print("Building TLD Firewall...")
    for line in spam_tlds_raw:
        clean = line.strip().lower()
        tld_match = re.search(r"(\*\.|\^|\|\|)([a-z0-9\-]+)\^", clean)
        if tld_match:
            tld = tld_match.group(2)
            if tld and len(tld) > 1:
                blocked_tlds.add(tld)

    # 2. Surgical Scrub (TLD Redundancies, NSFW Keywords, and Incompatible Syntax)
    print("Surgically scrubbing core lists...")
    tld_nuke = 0
    keyword_nuke = 0
    syntax_nuke = 0

    for line in all_lines:
        line_clean = line.strip().lower()
        line_clean = line_clean.split('#')[0].split('!')[0].split(';')[0].strip()
        
        if not line_clean or "adblock plus" in line_clean: continue
        
        # A. SCRUB INCOMPATIBLE SYNTAX (Cookies, Paths, Browser-only Regex)
        if line_clean.startswith("/") and any(x in line_clean for x in [".js", ".php", ".png", ".jpg", "/api/", "/v1/"]):
            syntax_nuke += 1
            continue
        if any(x in line_clean for x in ["$cookie", "$script", "$image", "$stylesheet", "$popup", "$subdocument"]):
            syntax_nuke += 1
            continue

        # B. KEYWORD SCRUB
        if NSFW_REGEX_COMP.search(line_clean):
            keyword_nuke += 1
            continue
        
        # C. TLD REDUNDANCY SCRUB
        is_redundant = False
        for tld in blocked_tlds:
            if f".{tld}" in line_clean:
                is_redundant = True
                break
        if is_redundant:
            tld_nuke += 1
            continue

        # D. CATEGORIZE VALID RULES
        if line_clean.startswith("@@") or "||~" in line_clean:
            allow_rules.add(line_clean)
        elif "$" in line_clean:
            # Keep only DNS-compatible modifiers
            if any(x in line_clean for x in ["$dnsrewrite", "$important", "$client", "$network"]):
                advanced_rules.add(line_clean)
        else:
            domain = line_clean.replace("||", "").replace("^", "").strip()
            parts = domain.split()
            domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1")) else parts[0]
            if "." in domain and not domain.startswith("."):
                simple_domains.add(domain)

    # 3. Tree-Pruning
    print(f"Pruning {len(simple_domains):,} core domains...")
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
    final_output.sort()
    
    # 5. Write to File
    with open(OUTPUT_FILE, "w") as f:
        # Title Branding
        f.write("! Title: Isaac's Extended Blocklist\n")
        f.write(f"! Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"! Revision: {VERSION}\n\n")

        # Part 1: RAW Hagezi TLDs
        f.write("############################################################\n")
        f.write("# PART 1: HAGEZI SPAM TLD LIST (UNEDITED RAW)\n")
        f.write("############################################################\n")
        f.write("\n".join(spam_tlds_raw) + "\n\n")

        # Part 2: Optimized Core
        f.write("############################################################\n")
        f.write(f"# PART 2: OPTIMIZED CORE (TLD/NSFW/SYNTAX SCRUBBED)\n")
        f.write(f"# Removed: {syntax_nuke} Ghost Rules | {keyword_nuke} NSFW | {tld_nuke} Redundant\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_output) + "\n")
        
        # Enforcements
        f.write(f"\n{NSFW_REGEX_RAW}\n{YOUTUBE_RULE}\n")

    print(f"Done. Deleted {syntax_nuke} ghost rules and {tld_nuke} TLD redundancies.")

if __name__ == "__main__":
    main()
