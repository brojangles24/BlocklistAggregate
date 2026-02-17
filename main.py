import requests
import concurrent.futures
from datetime import datetime
from zoneinfo import ZoneInfo

# --- CONFIGURATION ---
VERSION = "2026.02.16.DEDUPE_ONLY_V1"
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

# --- STATIC ENFORCEMENT RULES ---
NSFW_REGEX_RAW = "/(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)/"
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
    unique_rules = set()
    start_time = datetime.now(AZ_TZ)
    print(f"DEBUG: Script initialized at {start_time.strftime('%Y-%m-%d %I:%M %p')} AZ Time")

    # 1. Fetch Core Sources
    print("Fetching core sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Include the Spam TLD URL in the general fetch now since we aren't parsing it specifically
        all_urls = CORE_SOURCES + [SPAM_TLD_URL]
        future_to_url = {executor.submit(fetch_url, url): url for url in all_urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            lines = future.result()
            for line in lines:
                clean = line.strip()
                # Only ignore comments and empty lines to keep the final file clean
                if clean and not clean.startswith(("!", "#", "[Adblock Plus")):
                    unique_rules.add(clean)

    # 2. Final Construction
    # We convert set to list and sort for a consistent output file
    final_output = sorted(list(unique_rules))
    
    # 3. Write to File
    now_az = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')
    print(f"Writing {len(final_output):,} unique rules to file...")
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Isaac's Deduplicated Ultimate List\n")
        f.write("! Homepage: https://github.com/brojangles24/BlocklistAggregate\n")
        f.write(f"! Last Updated: {now_az} (Arizona Time)\n")
        f.write(f"! Revision: {VERSION}\n")
        f.write("! Description: Combined list with exact-match deduplication only.\n\n")

        f.write("! --- DEDUPLICATED CORE RULES ---\n")
        f.write("\n".join(final_output) + "\n\n")
        
        f.write("! --- ENFORCEMENT RULES ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(f"{FORCE_SAFE}\n")

    elapsed = datetime.now(AZ_TZ) - start_time
    print(f"\n--- PROCESS COMPLETE in {elapsed.total_seconds():.2f}s ---")
    print(f"Final blocklist saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
