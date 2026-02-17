import requests
import concurrent.futures
import re
from datetime import datetime
from zoneinfo import ZoneInfo

# --- CONFIGURATION ---
VERSION = "2026.02.16.TLD_SHIELD_V3"
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
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
]
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

# --- SCRUBBING CRITERIA ---
NSFW_KEYWORDS = r"(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)"
NSFW_REGEX_COMP = re.compile(f"(?i){NSFW_KEYWORDS}")

# --- ENFORCEMENT ---
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"
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

OUTPUT_FILE = "blocklist.txt"

def fetch_url(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"  !! Error fetching {url}: {e}")
        return []

def main():
    unique_rules = set()
    spam_tld_extensions = set()
    
    # Tracking
    kw_nukes = 0
    tld_nukes = 0
    allow_nukes = 0
    
    start_time = datetime.now(AZ_TZ)
    print(f"DEBUG: Process started at {start_time.strftime('%Y-%m-%d %I:%M %p')}\n")

    # 1. Fetch Spam TLDs first
    print("--- STEP 1: Building TLD Firewall & Preserving TLD Rules ---")
    tld_lines = fetch_url(SPAM_TLD_URL)
    for line in tld_lines:
        clean = line.split(' !')[0].split(' #')[0].strip()
        if not clean or clean.startswith(("!", "#", "[Adblock")):
            continue
        
        # Preserve EVERYTHING from this specific file (including @@ rules)
        unique_rules.add(clean)
        
        # Identify the TLD extension for scrubbing core sources
        # Look for the pattern ||tld^ specifically
        match = re.search(r"\|\|([a-z0-9\-]+)\^", clean.lower())
        if match:
            # We skip @@ lines when building the 'nuke' list to be safe
            if not clean.startswith("@@"):
                spam_tld_extensions.add(match.group(1))

    print(f"  -> Protected TLD rules added.")
    print(f"  -> {len(spam_tld_extensions)} TLD extensions identified for scrubbing.\n")

    # 2. Process Core Sources
    print("--- STEP 2: Scrubbing Core Sources ---")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            lines = future.result()
            print(f"  -> Processing: {url}")
            
            for line in lines:
                clean = line.split(' !')[0].split(' #')[0].strip()
                
                if not clean or clean.startswith(("!", "#", "[Adblock")):
                    continue
                
                # Rule 1: Remove all @@ rules from CORE sources
                if clean.startswith("@@"):
                    allow_nukes += 1
                    continue
                
                check_val = clean.lower()
                
                # Rule 2: Keyword Scrub
                if NSFW_REGEX_COMP.search(check_val):
                    kw_nukes += 1
                    continue
                
                # Rule 3: Improved TLD Scrub
                # Extract domain by removing common markers
                domain_bits = check_val.replace("||", "").replace("@@", "").split("^")[0].split("$")[0].split("/")[0]
                
                is_spam = False
                if "." in domain_bits:
                    # Get the extension (last part after the dot)
                    ext = domain_bits.split(".")[-1]
                    if ext in spam_tld_extensions:
                        is_spam = True
                
                if is_spam:
                    tld_nukes += 1
                    continue

                unique_rules.add(clean)

    # 3. Output
    final_list = sorted(list(unique_rules))
    now_az = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"! Last Updated: {now_az} (Arizona Time)\n")
        f.write(f"! Keyword Nukes: {kw_nukes:,} | TLD Nukes: {tld_nukes:,} | Core @@ Nukes: {allow_nukes:,}\n")
        f.write(f"! Rules: {len(final_list):,}\n\n")
        f.write("\n".join(final_list) + "\n\n")
        f.write("! --- ENFORCEMENT ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(f"{FORCE_SAFE.strip()}\n")

    print(f"\n--- RESULTS ---")
    print(f"Keywords Scrubbed: {kw_nukes:,}")
    print(f"Spam TLDs Scrubbed: {tld_nukes:,}")
    print(f"Core @@ Removed:   {allow_nukes:,}")
    print(f"Final Count:       {len(final_list):,}")

if __name__ == "__main__":
    main()
