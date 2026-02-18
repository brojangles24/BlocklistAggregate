import requests
from datetime import datetime, timezone, timedelta
import re

# Arizona is MST (UTC-7) year-round
AZ_TZ = timezone(timedelta(hours=-7))

VERSION = "2026.02.17.CORE_CLEAN_FULL_DUMP"
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
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
]
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

# Aggressive keyword filter
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
    patterns = []
    for line in lines:
        # Strip markers to get clean suffix for comparison
        clean = line.split('!')[0].split('#')[0].strip().lower().replace('||', '').replace('^', '').lstrip('.')
        if clean:
            patterns.append(tuple(clean.split('.')))
    return patterns

def is_spam_tld(host, patterns):
    host_labels = tuple(host.split('.'))
    for pat in patterns:
        if len(pat) <= len(host_labels) and host_labels[-len(pat):] == pat:
            return True
    return False

def main():
    # 1. GET TLDs FIRST FOR FILTERING
    print("[*] Loading Spam TLDs...")
    spam_tld_raw = fetch(SPAM_TLD_URL)
    spam_patterns = parse_tld_patterns(spam_tld_raw)
    
    final_rules = set()
    
    # 2. PROCESS CORE SOURCES
    print(f"[*] Processing {len(CORE_SOURCES)} sources...")
    for url in CORE_SOURCES:
        for line in fetch(url):
            clean = line.split('!')[0].split('#')[0].strip()
            if not clean.startswith('||') or '$' in clean:
                continue
            
            if '^' not in clean:
                clean += '^'
            
            # Extract host for filtering logic
            host = clean.replace('||', '').split('^')[0].lower().strip('.')
            
            # Drop if Keyword match
            if NSFW_REGEX.search(host):
                continue
                
            # Drop if TLD match (prevents redundant rules if TLD is already blocked)
            if is_spam_tld(host, spam_patterns):
                continue
            
            final_rules.add(clean)

    # 3. WRITE FINAL FILE
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # Header
        f.write(f"! Clean DNS Blocklist\n")
        f.write(f"! Generated: {datetime.now(AZ_TZ).strftime('%Y-%m-%d %H:%M:%S MST')}\n")
        f.write(f"! Rules: {len(final_rules)}\n\n")
        
        # Filtered Domains
        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write("\n".join(sorted(final_rules)) + "\n\n")
        
        # RAW Hagezi TLD Dump
        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(spam_tld_raw) + "\n\n")
        
        # Custom Rules
        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(YOUTUBE_RULE + "\n\n")
        
        # Regex Reference
        f.write(f"! NSFW Regex Pattern: {NSFW_REGEX.pattern}\n")

    print(f"SUCCESS: {len(final_rules)} rules + raw TLD dump written.")

if __name__ == '__main__':
    main()
