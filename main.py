import requests
from datetime import datetime, timezone, timedelta
import re

# Arizona is MST (UTC-7) year-round
AZ_TZ = timezone(timedelta(hours=-7))

VERSION = "2026.02.17.CORE_CLEAN_TLD_FIXED"
CORE_SOURCES = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.plus.txt",
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
    except: return []

def parse_tld_patterns(lines):
    patterns = []
    for line in lines:
        # Strip || and ^ from TLD list so they actually match against extracted hostnames
        clean = line.split('!')[0].split('#')[0].strip().lower().replace('||', '').replace('^', '').lstrip('.')
        if clean: patterns.append(tuple(clean.split('.')))
    return patterns

def is_spam_tld(host, patterns):
    labels = tuple(host.split('.'))
    for pat in patterns:
        if len(pat) <= len(labels) and labels[-len(pat):] == pat:
            return True
    return False

def main():
    spam_patterns = parse_tld_patterns(fetch(SPAM_TLD_URL))
    final_rules = set()
    
    for url in CORE_SOURCES:
        for line in fetch(url):
            line = line.split('!')[0].split('#')[0].strip()
            # Strict DNS check: must start with ||, no cosmetic modifiers ($)
            if not line.startswith('||') or '$' in line: continue
            if '^' not in line: line += '^'
            
            host = line.replace('||', '').split('^')[0].lower().strip('.')
            
            # Scorched earth filtering
            if NSFW_REGEX.search(host): continue
            if is_spam_tld(host, spam_patterns): continue
            
            final_rules.add(line)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! Clean DNS Blocklist\n! Generated: {datetime.now(AZ_TZ).strftime('%Y-%m-%d %H:%M:%S MST')}\n! Rules: {len(final_rules)}\n\n")
        f.write("\n".join(sorted(final_rules)) + "\n\n")
        f.write("! --- CUSTOM ---\n" + YOUTUBE_RULE + "\n\n")
        f.write(f"! NSFW Regex Pattern: {NSFW_REGEX.pattern}\n")

    print(f"SUCCESS: {len(final_rules)} rules.")

if __name__ == '__main__':
    main()
