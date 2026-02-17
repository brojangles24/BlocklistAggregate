import requests
from datetime import datetime, timezone, timedelta
import re
import textwrap
from collections import defaultdict

# --- CONFIGURATION ---
VERSION = "2026.02.17.CORE_CLEAN"
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
MIN_TLD_COUNT = 4  # Minimum variations to trigger wildcard consolidation

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
    # Remove comments and whitespace
    line = line.partition('!')[0].partition('#')[0].strip()
    
    # Filter invalid or whitelist lines
    if not line or '@@' in line:
        return None
    
    # Ensure Adblock syntax for domains
    if not line.startswith('||') and not line.startswith('/'):
         # Simple heuristic: if it looks like a domain, wrap it
         if '.' in line and ' ' not in line:
             line = f"||{line}^"

    # Ensure trailing caret for exact domain matches
    if line.startswith('||') and not line.endswith('^'):
        line += '^'
        
    return line

def is_dns_compatible(rule):
    if not rule: 
        return False
    # Filter cosmetic rules
    if '##' in rule or '#@#' in rule:
        return False
    # Filter rules with paths (unless regex)
    if '/' in rule and not rule.startswith('/') and not rule.startswith('||'):
        return False
    # Filter rules with unsupported modifiers (keeping simple domain blocks)
    # Note: If targeting AdGuard Home, some $ modifiers are okay, but for a raw list, stripping them is safer.
    if '$' in rule:
        return False
    return True

def extract_tld_from_rule(rule):
    """Extracts 'zip' from '||example.zip^'"""
    # Remove syntax wrappers
    clean = rule.replace('||', '').replace('^', '')
    if '.' in clean:
        return clean.split('.')[-1]
    return None

def filter_rules(rules, spam_rules_raw, nsfw_regex):
    filtered = set()
    
    # 1. Parse Spam TLDs correctly
    blocked_tlds = set()
    for r in spam_rules_raw:
        clean_r = r.strip()
        if clean_r.startswith('||') and clean_r.endswith('^'):
            tld = clean_r[2:-1] # Remove || and ^
            blocked_tlds.add(tld)
        else:
            blocked_tlds.add(clean_r)

    print(f"DEBUG: Parsed {len(blocked_tlds)} blocked TLDs (e.g., {list(blocked_tlds)[:3]})")

    for rule in rules:
        # 2. Check NSFW keywords
        if nsfw_regex.search(rule):
            continue
            
        # 3. Check against Spam TLDs
        rule_tld = extract_tld_from_rule(rule)
        if rule_tld and rule_tld in blocked_tlds:
            continue
            
        filtered.add(rule)
        
    return filtered, blocked_tlds

def prune_and_consolidate(rules):
    """
    1. Consolidate: specific variants -> wildcard (e.g., google.fr, google.de -> google.*)
    2. Prune: remove subdomains if parent is blocked (e.g., ad.test.com -> test.com)
    """
    # --- Step 1: Wildcard Consolidation ---
    # Group by the main label (e.g., 'google' from '||google.com^')
    groups = defaultdict(list)
    
    # Regex to grab the first segment after ||
    # Matches ||(segment).rest^
    pattern = re.compile(r'^\|\|([a-z0-9-]+)\..+\^$')
    
    # We split rules into those we can group and those we can't (regexes, IPs, etc)
    ungroupable = set()
    
    for rule in rules:
        m = pattern.match(rule)
        if m:
            base = m.group(1)
            # Safety: Don't wildcard short bases (avoids ||com.*^ if 'com.ua' exists)
            if len(base) > 3:
                groups[base].append(rule)
            else:
                ungroupable.add(rule)
        else:
            ungroupable.add(rule)
            
    final_rules = list(ungroupable)
    
    for base, variants in groups.items():
        if len(variants) >= MIN_TLD_COUNT:
            # Create wildcard rule
            final_rules.append(f'||{base}.*^')
        else:
            # Keep original variants
            final_rules.extend(variants)
            
    # --- Step 2: Subdomain Pruning ---
    # Convert to set for O(1) lookups, but we need to iterate carefully
    # Optimization: If ||example.com^ is present, we don't need ||ads.example.com^
    
    # Sort by length (shortest first) so we see '||example.com^' before '||ads.example.com^'
    sorted_rules = sorted(final_rules, key=len)
    optimized_set = set()
    
    for rule in sorted_rules:
        # Check if this rule is redundant
        is_redundant = False
        
        # Strip syntax to get raw domain "ads.example.com"
        clean = rule.replace('||', '').replace('^', '')
        
        # Logic: iteratively strip subdomains and check if parent exists in optimized_set
        # e.g., check "example.com", then "com" (though "com" won't be there usually)
        parts = clean.split('.')
        
        # We check from root up. 
        # If we have ||example.*^ (wildcard), we need to catch that too.
        
        # 1. Check against wildcards
        # If 'example' is in our wildcard set (implied), we skip.
        # Implementation: Check if `||{parts[0]}.*^` is in optimized_set
        wildcard_check = f"||{parts[0]}.*^"
        if wildcard_check in optimized_set:
            continue # Redundant because of wildcard
            
        # 2. Check against parent domains
        # For "a.b.c", check if "||b.c^" or "||c^" is in optimized_set
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            parent_rule = f"||{parent_domain}^"
            if parent_rule in optimized_set:
                is_redundant = True
                break
        
        if not is_redundant:
            optimized_set.add(rule)
            
    return optimized_set

def main():
    print('DEBUG: Starting process...')

    # 1. Fetch and Clean Core Rules
    raw_rules = set()
    for url in CORE_SOURCES:
        print(f"Fetching: {url}")
        for line in fetch_url(url):
            clean = clean_line(line)
            if clean and is_dns_compatible(clean):
                raw_rules.add(clean)

    # 2. Fetch Spam TLDs (Keep raw for now)
    spam_lines = fetch_url(SPAM_TLD_URL)
    spam_rules_cleaned = [clean_line(l) for l in spam_lines if clean_line(l)]

    # 3. Filter Core Rules (Remove NSFW + Redundant Spam TLDs)
    filtered_rules, parsed_spam_tlds = filter_rules(raw_rules, spam_rules_cleaned, NSFW_REGEX)
    
    # 4. Prune and Wildcard Consolidation
    final_rules = prune_and_consolidate(filtered_rules)

    # 5. Generate File
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
