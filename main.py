import requests
import concurrent.futures
from datetime import datetime
from zoneinfo import ZoneInfo

# --- CONFIGURATION ---
VERSION = "2026.02.16.CORE_CLEAN_TLD_RAW"
AZ_TZ = ZoneInfo("America/Phoenix") 

# Core Sources to be cleaned (Dedupe + Remove all @@)
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

# Source to be kept RAW (No filtering)
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

# --- CUSTOM ENFORCEMENT RULES ---
NSFW_REGEX_RAW = "/(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)/"
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
    core_rules = set()
    start_time = datetime.now(AZ_TZ)
    
    print(f"DEBUG: Process started at {start_time.strftime('%I:%M %p')}\n")

    # 1. Fetch Core Sources (Scrub all @@ and Dedupe)
    print("--- STEP 1: Fetching & Cleaning Core Sources ---")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        
        for future in concurrent.futures.as_completed(future_to_url):
            lines = future.result()
            for line in lines:
                # Strip comments
                clean = line.split(' !')[0].split(' #')[0].strip()
                
                # Rule: No empty lines, no comment lines, and strictly NO allow rules (@@)
                if clean and not clean.startswith(("!", "#", "[Adblock", "@@")):
                    core_rules.add(clean)

    # 2. Fetch Hagezi Spam TLDs (Keep RAW)
    print("--- STEP 2: Fetching Hagezi Spam TLDs (Preserving Raw) ---")
    raw_tld_lines = fetch_url(SPAM_TLD_URL)

    # 3. Final Construction
    sorted_core = sorted(list(core_rules))
    now_str = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        # Header
        f.write(f"! Title: Isaac's Clean Blocklist\n")
        f.write(f"! Last Updated: {now_str} (AZ Time)\n")
        f.write(f"! Core Rules: {len(sorted_core):,}\n\n")

        # Part 1: Cleaned Core
        f.write("! --- CLEANED CORE BLOCK RULES ---\n")
        f.write("\n".join(sorted_core) + "\n\n")
        
        # Part 2: Raw Hagezi TLDs
        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(raw_tld_lines) + "\n\n")
        
        # Part 3: Custom Enforcement
        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(f"{FORCE_SAFE.strip()}\n")

    print(f"\n--- SUCCESS ---")
    print(f"Core Blocks (No @@): {len(sorted_core):,}")
    print(f"Hagezi TLD Rules:    {len(raw_tld_lines):,}")
    print(f"Final file saved:    {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
