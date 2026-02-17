import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = "2026.02.16.SCORCHED_EARTH_FINAL"
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
]
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

# --- AGGRESSIVE REGEX (NO SAFETY) ---
# No \b boundaries. No exceptions.
# Matches "sex" inside "sussex", "porn" inside "foodporn", etc.
NSFW_KEYWORDS = r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)"
NSFW_REGEX_COMP = re.compile(f"(?i){NSFW_KEYWORDS}")
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"
FORCE_SAFE = """
||edgeservices.bing.com^$dnsrewrite=NOERROR;CNAME;strict.bing.com
||www.bing.com^$dnsrewrite=NOERROR;CNAME;strict.bing.com
||search.brave.com^$dnsrewrite=NOERROR;CNAME;safesearch.brave.com
||duckduckgo.com^$dnsrewrite=NOERROR;CNAME;safe.duckduckgo.com
||start.duckduckgo.com^$dnsrewrite=NOERROR;CNAME;safe.duckduckgo.com
||www.duckduckgo.com^$dnsrewrite=NOERROR;CNAME;safe.duckduckgo.com
||www.ecosia.org^$dnsrewrite=NOERROR;CNAME;strict-safe-search.ecosia.org
||pixabay.com^$dnsrewrite=NOERROR;CNAME;safesearch.pixabay.com
||api.qwant.com^$dnsrewrite=NOERROR;CNAME;safeapi.qwant.com
||www.startpage.com^$dnsrewrite=NOERROR;CNAME;safe.startpage.com
||startpage.com^$dnsrewrite=NOERROR;CNAME;safe.startpage.com
||google.*^$dnsrewrite=NOERROR;CNAME;forcesafesearch.google.com
||www.google.*^$dnsrewrite=NOERROR;CNAME;forcesafesearch.google.com
||yandex.com^$dnsrewrite=NOERROR;A;213.180.193.56
||yandex.ru^$dnsrewrite=NOERROR;A;213.180.193.56
||ya.ru^$dnsrewrite=NOERROR;A;213.180.193.56
"""

YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"
OUTPUT_FILE = "blocklist.txt"

DNS_VALID_MODIFIERS = ["$dnsrewrite", "$important", "$client", "$network", "$ctag", "$badfilter", "$denyallow"]

def fetch_url(url):
    try:
        print(f"  -> Downloading: {url}")
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"  !! Error fetching {url}: {e}")
        return []

def main():
    blocked_tlds = set()
    advanced_rules = set()
    simple_domains = set()
    
    # Stats
    tld_nuke = 0
    keyword_nuke = 0
    cosmetic_nuke = 0
    syntax_nuke = 0
    
    start_time = datetime.now()
    print(f"--- STARTING SCORCHED EARTH SCRUB ({start_time.strftime('%H:%M:%S')}) ---")

    # 1. Build TLD Firewall
    print("Building TLD Firewall...")
    spam_tlds_raw = fetch_url(SPAM_TLD_URL)
    for line in spam_tlds_raw:
        clean = line.strip().lower()
        tld_match = re.search(r"(\*\.|\^|\|\|)([a-z0-9\-]+)\^", clean)
        if tld_match:
            tld = tld_match.group(2)
            if tld and len(tld) > 1:
                blocked_tlds.add(tld)
    
    blocked_tlds_tuple = tuple(f".{t}" for t in blocked_tlds)
    print(f"  -> Memorized {len(blocked_tlds)} spam TLDs.")

    # 2. Fetch Sources
    print("Fetching sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    # 3. Processing Loop
    print("Executing Aggressive Scrub...")
    for line in all_lines:
        line_clean = line.strip().lower()
        line_clean = line_clean.split('!')[0].split(' #')[0].strip()
        
        if not line_clean or "adblock plus" in line_clean: continue
        
        # --- PHASE 1: KEYWORD NUKE (THE PRIORITY KILLER) ---
        # We check this FIRST so it steals the stats from TLD/Syntax nukes.
        # We strip modifiers to check just the domain text.
        domain_check = line_clean.replace("||", "").replace("^", "").split('$')[0]
        
        if NSFW_REGEX_COMP.search(domain_check):
            keyword_nuke += 1
            continue

        # --- PHASE 2: COSMETIC & SYNTAX PURGE ---
        if any(x in line_clean for x in ["##", "#@#", "#?#", "#%#", "#$#"]):
            cosmetic_nuke += 1
            continue

        if line_clean.startswith("@@"): continue

        if line_clean.startswith("|"):
             line_clean = re.sub(r"^\|{2,}", "||", line_clean)

        if "$" in line_clean:
            is_valid_dns = any(mod in line_clean for mod in DNS_VALID_MODIFIERS)
            if not is_valid_dns:
                syntax_nuke += 1
                continue
            else:
                advanced_rules.add(line_clean)
                continue

        if "/" in line_clean:
            if line_clean.startswith("/") and line_clean.endswith("/"):
                advanced_rules.add(line_clean)
                continue
            if line_clean.startswith("||") and "/" in line_clean.replace("||", ""):
                 syntax_nuke += 1
                 continue
                 
        # --- PHASE 3: TLD & DOMAIN VALIDATION ---
        domain_part = line_clean.replace("||", "").replace("^", "").strip().rstrip('.')

        if domain_part.endswith(blocked_tlds_tuple):
            tld_nuke += 1
            continue

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_part):
            syntax_nuke += 1
            continue
            
        if "." not in domain_part:
            if domain_part.endswith("*"):
                 advanced_rules.add(line_clean)
            else:
                syntax_nuke += 1
                continue
        else:
            simple_domains.add(domain_part)

    # 4. Tree-Pruning
    print(f"Tree-Pruning {len(simple_domains):,} core domains...")
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in simple_domains])
    pruned_rev = []
    last_added = ""
    
    for rd in rev_domains:
        if last_added and rd.startswith(last_added + "."): 
            continue
        pruned_rev.append(rd)
        last_added = rd
    
    # 5. Final Construction
    final_output = list(advanced_rules)
    for rd in pruned_rev:
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    
    final_output.sort()
    
    # 6. Write to File
    print(f"Writing {len(final_output):,} rules to file...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Isaac's Scorched Earth List\n")
        f.write(f"! Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"! Revision: {VERSION}\n")
        f.write("! Description: Aggressive keyword filtering enabled. False positives expected.\n\n")

        f.write("! --- SPAM TLDs ---\n")
        f.write("\n".join(spam_tlds_raw) + "\n\n")

        f.write("! --- OPTIMIZED DNS CORE ---\n")
        f.write("\n".join(final_output) + "\n")
        
        f.write("\n! --- NUCLEAR REGEX ENFORCEMENT ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(f"{FORCE_SAFE}\n")

    # --- FINAL STATS PRINT ---
    elapsed = datetime.now() - start_time
    print(f"\n--- SCRUB COMPLETE in {elapsed.total_seconds():.2f}s ---")
    print(f"Deleted {keyword_nuke:,} domains via Aggressive Regex.")
    print(f"Deleted {tld_nuke:,} TLD redundancies.")
    print(f"Deleted {cosmetic_nuke:,} cosmetic rules.")
    print(f"Final blocklist saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
