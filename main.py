import requests
from datetime import datetime, timezone
import re
import textwrap
from collections import defaultdict
import tldextract

# --- CONFIGURATION ---
VERSION = "2026.02.16.CORE_CLEAN_TLD_RAW"
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
MIN_TLD_COUNT = 3

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
    if line.startswith('||') and not line.endswith('^'):
        line += '^'
    return line


def is_dns_compatible(rule):
    if not rule:
        return False
    if rule.startswith('@@') or '##' in rule or '#@#' in rule:
        return False
    if '/' in rule and not rule.startswith('/') and not rule.startswith('||'):
        return False
    if '$' in rule:
        return False
    return True


def consolidate_domains_tldaware(rules, min_tld_count=MIN_TLD_COUNT):
    grouped = defaultdict(list)
    others = set()

    for rule in rules:
        if not rule.startswith('||'):
            others.add(rule)
            continue
        domain = rule[2:].rstrip('^')
        ext = tldextract.extract(domain)
        if not ext.domain:
            others.add(rule)
            continue
        key = f'{ext.subdomain}.{ext.domain}' if ext.subdomain else ext.domain
        grouped[key].append(rule)

    consolidated = set(others)
    for key, variants in grouped.items():
        if len(variants) >= min_tld_count:
            consolidated.add(f'||{key}*^')
        else:
            consolidated.update(variants)

    return consolidated


def filter_keywords_and_tlds(rules, spam_tlds, nsfw_pattern):
    filtered = set()
    tlds = [tld.strip() for tld in spam_tlds if tld.strip()]
    tld_pattern = re.compile(r'(?:\.|\*\.)(' + '|'.join(re.escape(t) for t in tlds) + r')\^?$')

    for rule in rules:
        if re.search(nsfw_pattern, rule):
            continue
        if tld_pattern.search(rule):
            continue
        filtered.add(rule)
    return filtered


def main():
    print('DEBUG: Starting process')

    raw_rules = set()
    for url in CORE_SOURCES:
        for line in fetch_url(url):
            clean = clean_line(line)
            if clean:
                raw_rules.add(clean)

    spam_tlds = fetch_url(SPAM_TLD_URL)

    dns_rules = set(r for r in raw_rules if is_dns_compatible(r))
    dns_rules = filter_keywords_and_tlds(dns_rules, spam_tlds, NSFW_REGEX_RAW)

    consolidated = consolidate_domains_tldaware(dns_rules)

    now_str = datetime.now(AZ_TZ).strftime('%Y-%m-%d %I:%M:%S %p')

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! Title: Isaac's Clean DNS Blocklist\n")
        f.write(f"! Last Updated: {now_str} (UTC)\n")
        f.write(f"! Version: {VERSION}\n")
        f.write(f"! Core Rules: {len(consolidated):,}\n")
        f.write(f"! Spam TLDs: {len(spam_tlds):,}\n\n")

        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write('\n'.join(sorted(consolidated)) + '\n\n')

        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write('\n'.join(spam_tlds) + '\n\n')

        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")
        f.write(textwrap.dedent(FORCE_SAFE).strip() + '\n')

    print(f"SUCCESS: Blocklist generated at {OUTPUT_FILE}")


if __name__ == '__main__':
    main()
