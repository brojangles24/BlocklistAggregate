import requests
from datetime import datetime, timezone
import re
import textwrap

# --- CONFIGURATION ---
VERSION = "2026.02.16.CORE_CLEAN_TLD_RAW"
# Use UTC to avoid threading/tzdata issues
AZ_TZ = timezone.utc

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

NSFW_REGEX_RAW = "(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)"
YOUTUBE_RULE = "||youtube.com^$dnsrewrite=restrictmoderate.youtube.com"
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

# --- FUNCTIONS ---

def fetch_url(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        r.encoding = 'utf-8'
        return r.text.splitlines()
    except Exception as e:
        print(f"  !! Error fetching {url}: {e}")
        return []


def clean_rule(line):
    line = line.partition('!')[0].partition('#')[0].strip()
    if not line or '@@' in line:
        return None
    line = re.sub(r'\$.*$', '', line).strip()
    if not line:
        return None
    m = re.match(r'\|\|([\w\-\.]+)\..{2,3}$', line)
    if m:
        return f'||{m.group(1)}^'
    if line.startswith('||') and not line.endswith('^'):
        line += '^'
    return line


def main():
    core_rules = set()
    start_time = datetime.now(AZ_TZ)
    print(f"DEBUG: Process started at {start_time.strftime('%I:%M %p')}\n")

    # Fetch Core Sources sequentially to avoid thread limits
    print("--- STEP 1: Fetching & Cleaning Core Sources ---")
    for url in CORE_SOURCES:
        lines = fetch_url(url)
        for line in lines:
            clean = clean_rule(line)
            if clean:
                core_rules.add(clean)

    # Fetch Hagezi Spam TLDs (RAW)
    print("--- STEP 2: Fetching Hagezi Spam TLDs (Preserving Raw) ---")
    raw_tld_lines = fetch_url(SPAM_TLD_URL)

    # Final Construction
    sorted_core = sorted(core_rules)
    now_str = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! Title: Isaac's Clean Blocklist\n")
        f.write(f"! Last Updated: {now_str} (AZ Time)\n")
        f.write(f"! Core Rules: {len(sorted_core):,}\n\n")

        f.write("! --- CLEANED CORE BLOCK RULES ---\n")
        f.write('\n'.join(sorted_core) + '\n\n')

        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write('\n'.join(raw_tld_lines) + '\n\n')

        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(textwrap.dedent(FORCE_SAFE).strip() + '\n')

    print(f"\n--- SUCCESS ---")
    print(f"Core Blocks (No @@ / DNS-only): {len(sorted_core):,}")
    print(f"Hagezi TLD Rules:    {len(raw_tld_lines):,}")
    print(f"Final file saved:    {OUTPUT_FILE}")


if __name__ == '__main__':
    main()
