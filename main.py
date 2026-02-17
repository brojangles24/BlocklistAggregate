import requests
import concurrent.futures
import re
from datetime import datetime
from zoneinfo import ZoneInfo

# --- CONFIGURATION ---
VERSION = "2026.02.16.SCRUB_DEDUPE_V1"
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
        print(f"  -> Downloading: {url}")
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"  !! Error fetching {url}: {e}")
        return []

def main():
    unique_rules = set()
    blocked_tlds = set()
    start_time = datetime.now(AZ_TZ)
    
    print(f"DEBUG: Script initialized at {start_time.strftime('%Y-%m-%d %I:%M %p')} AZ Time")

    # 1. Build the TLD Blacklist
    print("Building Spam TLD Firewall...")
    tld_raw = fetch_url(SPAM_TLD_URL)
    for line in tld_raw:
        clean = line.strip().lower()
        # Extract TLD from Hagezi format: ||tld^
        tld_match = re.search(r"\|\|([a-z0-9\-]+)\^", clean)
        if tld_match:
            blocked_tlds.add(f".{tld_match.group(1)}")
    
    blocked_tlds_tuple = tuple(blocked_tlds)
    print(f"  -> Loaded {len(blocked_tlds)} Spam TLDs.")

    # 2. Fetch Core Sources
    print("Fetching core sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        
        for future in concurrent.futures.as_completed(future_to_url):
            lines = future.result()
            for line in lines:
                # Basic cleaning
                clean = line.split(' !')[0].split(' #')[0].strip()
                
                # Filter out pure comments/empty lines
                if not clean or clean.startswith(("!", "#", "[Adblock Plus")):
                    continue
                
                # --- THE SCRUB ---
                # Lowercase for checking purposes
                check_val = clean.lower()
                
                # 1. Keyword Check
                if NSFW_REGEX_COMP.search(check_val):
                    continue
                
                # 2. TLD Check
                # Extracts the domain part (removes || and ^) to check the ending
                domain_part = check_val.replace("||", "").split("^")[0].split("$")[0]
                if domain_part.endswith(blocked_tlds_tuple):
                    continue

                # If it passed both, add to set
                unique_rules.add(clean)

    # 3. Final Construction
    final_output = sorted(list(unique_rules))
    
    # 4. Write to File
    now_az = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')
    print(f"Writing {len(final_output):,} unique rules to file...")
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"! Last Updated: {now_az} (Arizona Time)\n")
        f.write(f"! Total Rules After Scrub & Dedupe: {len(final_output):,}\n")
        f.write(f"! Version: {VERSION}\n\n")

        f.write("\n".join(final_output) + "\n\n")
        
        f.write("! --- ENFORCEMENT ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(f"{FORCE_SAFE.strip()}\n")

    elapsed = datetime.now(AZ_TZ) - start_time
    print(f"\n--- PROCESS COMPLETE in {elapsed.total_seconds():.2f}s ---")
    print(f"Final blocklist saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
