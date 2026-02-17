import requests
import concurrent.futures
import re
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import Counter

# --- CONFIGURATION ---
VERSION = "2026.02.16.FINAL_BOSS_V11"
AZ_TZ = ZoneInfo("America/Phoenix") 

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

# --- AGGRESSIVE REGEX (NO SAFETY) ---
NSFW_KEYWORDS = r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)"
NSFW_REGEX_COMP = re.compile(f"(?i){NSFW_KEYWORDS}")
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"

YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

FORCE_SAFE = """
! --- SEARCH ENGINE SAFESEARCH REWRITES ---
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

! --- GOOGLE SAFESEARCH (GLOBAL) ---
||google.*^$dnsrewrite=NOERROR;CNAME;forcesafesearch.google.com
||www.google.*^$dnsrewrite=NOERROR;CNAME;forcesafesearch.google.com

! --- YANDEX FAMILY SEARCH ---
||yandex.com^$dnsrewrite=NOERROR;A;213.180.193.56
||yandex.ru^$dnsrewrite=NOERROR;A;213.180.193.56
||ya.ru^$dnsrewrite=NOERROR;A;213.180.193.56
"""

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
    
    start_time = datetime.now(AZ_TZ)
    print(f"DEBUG: Script initialized at {start_time.strftime('%Y-%m-%d %I:%M %p')} AZ Time")

    # 1. Build TLD Firewall
    spam_tlds_raw = fetch_url(SPAM_TLD_URL)
    for line in spam_tlds_raw:
        clean = line.strip().lower()
        tld_match = re.search(r"(\*\.|\^|\|\|)([a-z0-9\-]+)\^", clean)
        if tld_match:
            tld = tld_match.group(2)
            if tld and len(tld) > 1:
                blocked_tlds.add(tld)
    
    blocked_tlds_tuple = tuple(f".{t}" for t in blocked_tlds)

    # 2. Fetch Sources
    print("Fetching core sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    # 3. Processing Loop
    print("Executing Aggressive Scrub & Pattern Detection...")
    for line in all_lines:
        line_clean = line.strip().lower()
        line_clean = line_clean.split('!')[0].split(' #')[0].strip()
        
        if not line_clean or "adblock plus" in line_clean: continue
        
        # Keyword Nuke
        domain_check = line_clean.replace("||", "").replace("^", "").split('$')[0]
        if NSFW_REGEX_COMP.search(domain_check): continue

        # Cosmetic Purge
        if any(x in line_clean for x in ["##", "#@#", "#?#", "#%#", "#$#"]): continue
        if line_clean.startswith("@@"): continue

        # DNS Rule Handling
        if "$" in line_clean:
            if any(mod in line_clean for mod in DNS_VALID_MODIFIERS):
                advanced_rules.add(line_clean)
            continue
                 
        domain_part = line_clean.replace("||", "").replace("^", "").strip().rstrip('.')
        if domain_part.endswith(blocked_tlds_tuple): continue

        if "." in domain_part:
            simple_domains.add(domain_part)

    # 4. INTELLIGENT TLD COLLAPSING
    # We find domains that appear with 5+ different TLDs and collapse them
    print("Collapsing redundant regional TLDs...")
    domain_base_counts = Counter()
    for d in simple_domains:
        parts = d.split('.')
        if len(parts) >= 2:
            # Join all parts except the last one (the TLD)
            base = '.'.join(parts[:-1]) 
            domain_base_counts[base] += 1

    collapsed_wildcards = set()
    for base, count in domain_base_counts.items():
        if count > 5: # If a domain appears in 5+ regions, nuke it globally
            collapsed_wildcards.add(f"||{base}.*^")

    # 5. Tree-Pruning & Final Construction
    print(f"Tree-Pruning {len(simple_domains):,} core domains...")
    # Remove domains already covered by our new wildcards
    filtered_domains = {d for d in simple_domains if not any(d.startswith(w.replace('||','').replace('.*^','')) for w in collapsed_wildcards)}
    
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in filtered_domains])
    pruned_rev = []
    last_added = ""
    for rd in rev_domains:
        if last_added and rd.startswith(last_added + "."): continue
        pruned_rev.append(rd)
        last_added = rd
    
    final_output = list(advanced_rules) + list(collapsed_wildcards)
    for rd in pruned_rev:
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    final_output.sort()
    
    # 6. Write to File
    now_az = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')
    print(f"Writing {len(final_output):,} rules to file...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Isaac's Scorched Earth Ultimate List\n")
        f.write("! Homepage: https://github.com/brojangles24/BlocklistAggregate\n")
        f.write(f"! Last Updated: {now_az} (Arizona Time)\n")
        f.write(f"! Revision: {VERSION}\n")
        f.write("! Description: Aggressive keyword filtering + Intelligent TLD Collapsing.\n\n")

        f.write("! --- OPTIMIZED DNS CORE ---\n")
        f.write("\n".join(final_output) + "\n\n")
        
        f.write("! --- ENFORCEMENT RULES ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(f"{FORCE_SAFE}\n")

    elapsed = datetime.now(AZ_TZ) - start_time
    print(f"\n--- SCRUB COMPLETE in {elapsed.total_seconds():.2f}s ---")
    print(f"Final blocklist saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
