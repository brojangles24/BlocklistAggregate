import requests
import concurrent.futures
import re
from datetime import datetime
from zoneinfo import ZoneInfo

# --- CONFIGURATION ---
VERSION = "2026.02.16.SCRUB_TRACKER_V1"
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

# --- STATIC ENFORCEMENT RULES ---
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
    blocked_tlds = set()
    
    # Counters
    keyword_nuke_count = 0
    tld_nuke_count = 0
    exception_nuke_count = 0
    
    start_time = datetime.now(AZ_TZ)
    print(f"DEBUG: Script initialized at {start_time.strftime('%Y-%m-%d %I:%M %p')} AZ Time\n")

    # 1. Process Hagezi Spam TLDs (Special Case: Keep @@)
    print("--- STEP 1: Processing Spam TLD Firewall ---")
    tld_raw = fetch_url(SPAM_TLD_URL)
    for line in tld_raw:
        clean = line.split(' !')[0].split(' #')[0].strip()
        if not clean or clean.startswith(("!", "#", "[Adblock Plus")):
            continue
        
        unique_rules.add(clean)
        
        tld_match = re.search(r"\|\|([a-z0-9\-]+)\^", clean.lower())
        if tld_match:
            blocked_tlds.add(f".{tld_match.group(1)}")
    
    blocked_tlds_tuple = tuple(blocked_tlds)
    print(f"Loaded {len(blocked_tlds)} Spam TLDs.\n")

    # 2. Fetch Core Sources
    print("--- STEP 2: Fetching and Scrubbing Core Sources ---")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            lines = future.result()
            print(f"  -> Scrubbing: {url}")
            
            for line in lines:
                clean = line.split(' !')[0].split(' #')[0].strip()
                
                if not clean or clean.startswith(("!", "#", "[Adblock Plus")):
                    continue
                
                # A. Remove exceptions (@@)
                if clean.startswith("@@"):
                    exception_nuke_count += 1
                    continue
                
                check_val = clean.lower()
                
                # B. Keyword Scrub
                if NSFW_REGEX_COMP.search(check_val):
                    keyword_nuke_count += 1
                    continue
                
                # C. TLD Scrub
                domain_part = check_val.replace("||", "").split("^")[0].split("$")[0]
                if domain_part.endswith(blocked_tlds_tuple):
                    tld_nuke_count += 1
                    continue

                unique_rules.add(clean)

    # 3. Final Construction
    final_output = sorted(list(unique_rules))
    
    # 4. Write to File
    now_az = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"! Last Updated: {now_az} (Arizona Time)\n")
        f.write(f"! Total Rules: {len(final_output):,}\n")
        f.write(f"! Keyword Matches Removed: {keyword_nuke_count:,}\n")
        f.write(f"! Spam TLD Matches Removed: {tld_nuke_count:,}\n")
        f.write(f"! Non-Spam TLD Exceptions Removed: {exception_nuke_count:,}\n\n")

        f.write("\n".join(final_output) + "\n\n")
        
        f.write("! --- ENFORCEMENT ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(f"{FORCE_SAFE.strip()}\n")

    # Console Summary
    elapsed = datetime.now(AZ_TZ) - start_time
    print(f"\n--- SCRUB COMPLETE ---")
    print(f"Total Keyword Nukes:   {keyword_nuke_count:,}")
    print(f"Total Spam TLD Nukes:  {tld_nuke_count:,}")
    print(f"Total @@ Rules Nuked:  {exception_nuke_count:,}")
    print(f"Final Rule Count:      {len(final_output):,}")
    print(f"Execution Time:        {elapsed.total_seconds():.2f}s")
    print(f"Saved to:              {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
