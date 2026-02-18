import requests
from datetime import datetime, timezone, timedelta
import re

# Arizona is MST (UTC-7) year-round
AZ_TZ = timezone(timedelta(hours=-7))

VERSION = "2026.02.17.CORE_CLEAN_ULTIMATE"
CORE_SOURCES = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/ultimate.txt",
    "https://big.oisd.nl",
    "https://nsfw.oisd.nl",
    "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adguard/dns-rebind-protection.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
]
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

NSFW_REGEX = re.compile(r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)")

OUTPUT_FILE = "blocklist.txt"
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

def fetch(url):
    try:
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except:
        return []

def parse_tld_patterns(lines):
    patterns = set()
    for line in lines:
        # Strip comments and AdBlock syntax ||...^
        clean = line.split('!')[0].split('#')[0].strip().lower()
        if not clean: continue
        clean = clean.replace('||', '').replace('^', '').lstrip('.')
        if clean:
            patterns.add(clean)
    # Sort by length descending to catch multi-part TLDs (like co.uk) first
    return sorted(list(patterns), key=len, reverse=True)

def is_spam_tld(host, patterns):
    for p in patterns:
        # Match if host is exactly the TLD or ends with .TLD
        if host == p or host.endswith('.' + p):
            return True
    return False

def main():
    print("[*] Fetching Hagezi Spam TLDs...")
    spam_tld_raw = fetch(SPAM_TLD_URL)
    spam_patterns = parse_tld_patterns(spam_tld_raw)
    
    final_rules = set()
    
    print(f"[*] Processing {len(CORE_SOURCES)} sources (including Ultimate)...")
    for url in CORE_SOURCES:
        for line in fetch(url):
            clean = line.split('!')[0].split('#')[0].strip()
            # DNS rules only: start with || and no modifiers ($)
            if not clean.startswith('||') or '$' in clean:
                continue
            
            if '^' not in clean: clean += '^'
            
            # Extract host for filtering
            host = clean.replace('||', '').split('^')[0].lower().strip('.')
            
            # 1. Keyword check
            if NSFW_REGEX.search(host):
                continue
                
            # 2. TLD check (drops redundant domains already blocked by TLD list)
            if is_spam_tld(host, spam_patterns):
                continue
            
            final_rules.add(clean)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! Clean DNS Blocklist\n! Generated: {datetime.now(AZ_TZ).strftime('%Y-%m-%d %H:%M:%S MST')}\n! Rules: {len(final_rules)}\n\n")
        
        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write("\n".join(sorted(final_rules)) + "\n\n")
        
        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(spam_tld_raw) + "\n\n")
        
        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(YOUTUBE_RULE + "\n\n")
        
        f.write(f"! NSFW Regex Pattern: {NSFW_REGEX.pattern}\n")

    print(f"SUCCESS: Generated {OUTPUT_FILE} with {len(final_rules)} filtered rules.")

if __name__ == '__main__':
    main()
