import requests
from datetime import datetime, timezone, timedelta
import re
import textwrap
from collections import defaultdict
import sys

# Try to import tldextract, handle missing dependency gracefully
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False
    print("!! WARNING: 'tldextract' not found. Install it with `pip install tldextract` for accurate TLD parsing.")
    print("!! Falling back to basic string splitting (less accurate).\n")

# --- CONFIGURATION ---
VERSION = "2026.02.17.CORE_CLEAN_TLD_AWARE"
# Fixed: Arizona is UTC-7 (MST) and does not observe DST
AZ_TZ = timezone(timedelta(hours=-7))

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

# Compiled regex for efficiency
NSFW_REGEX = re.compile(r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)")

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
MIN_TLD_COUNT = 3  # Lowered to 3 since tldextract is accurate

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

def clean_line(line):
    line = line.partition('!')[0].partition('#')[0].strip()
    if not line or '@@' in line:
        return None
    
    # Standardize domain lines
    if not line.startswith('||') and not line.startswith('/'):
         if '.' in line and ' ' not in line:
             line = f"||{line}^"

    if line.startswith('||') and not line.endswith('^'):
        line += '^'
        
    return line

def is_dns_compatible(rule):
    if not rule: return False
    if '##' in rule or '#@#' in rule: return False
    if '/' in rule and not rule.startswith('/') and not rule.startswith('||'): return False
    if '$' in rule: return False
    return True

def extract_tld_raw(domain_part):
    """Fallback if tldextract is missing."""
    if '.' not in domain_part:
        return None
    return domain_part.split('.')[-1]

def consolidate_domains(rules, min_tld_count=MIN_TLD_COUNT):
    """
    Groups domains by their SLD+Subdomain (e.g. 'google' or 'ads.google') 
    and consolidates TLDs (e.g. .com, .fr, .de) into a wildcard.
    """
    grouped = defaultdict(list)
    others = set()

    print("DEBUG: Consolidating domains...")
    
    for rule in rules:
        # Pass through regex or non-standard rules
        if not rule.startswith('||'):
            others.add(rule)
            continue

        # Strip syntax: ||example.com^ -> example.com
        clean_domain = rule[2:].rstrip('^')
        
        if HAS_TLDEXTRACT:
            ext = tldextract.extract(clean_domain)
            if not ext.domain:
                others.add(rule)
                continue
            
            # Key = "subdomain.domain" (e.g. "ads.google" or just "google")
            key = f'{ext.subdomain}.{ext.domain}' if ext.subdomain else ext.domain
        else:
            # Fallback (less accurate)
            parts = clean_domain.split('.')
            if len(parts) < 2:
                others.add(rule)
                continue
            key = parts[0] # Very rough approximation

        grouped[key].append(rule)

    consolidated = set(others)
    
    for key, variants in grouped.items():
        if len(variants) >= min_tld_count:
            # IMPORTANT: Use '.*^' to match any TLD safely.
            # "||google.*^" matches google.com, google.co.uk
            # "||google*^" would match googleplex.com (BAD)
            consolidated.add(f'||{key}.*^')
        else:
            consolidated.update(variants)

    return consolidated

def filter_rules(rules, spam_rules_raw, nsfw_regex):
    filtered = set()
    
    # 1. Parse Spam TLDs correctly
    blocked_tlds = set()
    for r in spam_rules_raw:
        clean_r = r.strip()
        # Parse "||zip^" -> "zip"
        if clean_r.startswith('||') and clean_r.endswith('^'):
            tld = clean_r[2:-1] 
            blocked_tlds.add(tld)
        else:
            blocked_tlds.add(clean_r)

    print(f"DEBUG: Parsed {len(blocked_tlds)} blocked TLDs.")

    for rule in rules:
        # 2. Check NSFW keywords
        if nsfw_regex.search(rule):
            continue
            
        # 3. Check against Spam TLDs
        # Extract the TLD from the rule to check against blocked list
        clean_r = rule.replace('||', '').replace('^', '')
        
        # Fast suffix check
        # matches .zip or .zip^
        is_spam_tld = False
        for tld in blocked_tlds:
             if clean_r.endswith(f".{tld}"):
                 is_spam_tld = True
                 break
        
        if is_spam_tld:
            continue
            
        filtered.add(rule)
        
    return filtered, blocked_tlds

def main():
    print('DEBUG: Starting process...')

    raw_rules = set()
    for url in CORE_SOURCES:
        print(f"Fetching: {url}")
        for line in fetch_url(url):
            clean = clean_line(line)
            if clean and is_dns_compatible(clean):
                raw_rules.add(clean)

    spam_lines = fetch_url(SPAM_TLD_URL)
    spam_rules_cleaned = [clean_line(l) for l in spam_lines if clean_line(l)]

    # Filter
    filtered_rules, parsed_spam_tlds = filter_rules(raw_rules, spam_rules_cleaned, NSFW_REGEX)
    
    # Consolidate
    final_rules = consolidate_domains(filtered_rules)

    now_str = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! Title: Isaac's Clean DNS Blocklist\n")
        f.write(f"! Last Updated: {now_str} (Arizona Time)\n")
        f.write(f"! Version: {VERSION}\n")
        f.write(f"! Core Rules: {len(final_rules):,}\n")
        f.write(f"! Spam TLDs: {len(parsed_spam_tlds):,}\n\n")

        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(textwrap.dedent(FORCE_SAFE).strip() + '\n\n')

        f.write("! --- HAGEZI SPAM TLDs ---\n")
        f.write('\n'.join(sorted(spam_rules_cleaned)) + '\n\n')

        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write('\n'.join(sorted(final_rules)) + '\n')

    print(f"SUCCESS: Blocklist generated at {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
