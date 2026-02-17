from datetime import datetime, timezone
import re
import textwrap
from collections import defaultdict
from urllib import request
from urllib.error import URLError, HTTPError

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
        req = request.Request(url, headers={"User-Agent": "BlocklistAggregate/1.0"})
        with request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode('utf-8', errors='replace')
        return body.splitlines()
    except (HTTPError, URLError, TimeoutError) as e:
        print(f"  !! Error fetching {url}: {e}")
        return []
    except Exception as e:
        print(f"  !! Error fetching {url}: {e}")
        return []


def domain_key_from_rule(rule):
    domain = rule[2:].rstrip('^').lower().rstrip('.')
    domain = domain.replace('*.', '')

    if not domain or any(c in domain for c in ('/', ':')):
        return None

    labels = [part for part in domain.split('.') if part]
    if len(labels) < 2:
        return None

    # Treat common country-code second-level domains (e.g., co.uk) as suffixes.
    common_cc_slds = {
        'ac', 'co', 'com', 'edu', 'gov', 'mil', 'net', 'org', 'sch'
    }
    suffix_labels = 1
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in common_cc_slds:
        suffix_labels = 2

    key_labels = labels[:-suffix_labels]
    return '.'.join(key_labels) if key_labels else None


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
        key = domain_key_from_rule(rule)
        if not key:
            others.add(rule)
            continue
        grouped[key].append(rule)

    consolidated = set(others)
    for key, variants in grouped.items():
        if len(variants) >= min_tld_count:
            consolidated.add(f'||{key}*^')
        else:
            consolidated.update(variants)

    return consolidated


def parse_spam_tld_patterns(spam_tlds):
    patterns = []
    for raw in spam_tlds:
        line = raw.partition('!')[0].partition('#')[0].strip().lower().lstrip('.')
        if not line:
            continue
        labels = tuple(part for part in line.split('.') if part)
        if labels:
            patterns.append(labels)
    return patterns


def rule_host(rule):
    if not rule.startswith('||'):
        return None
    host = rule[2:].rstrip('^').lower().rstrip('.')
    if not host:
        return None
    return host


def host_matches_spam_tld(host, spam_tld_patterns):
    labels = tuple(part for part in host.split('.') if part)
    if not labels:
        return False

    for pattern in spam_tld_patterns:
        if len(pattern) > len(labels):
            continue

        suffix = labels[-len(pattern):]
        if all(p == '*' or h == '*' or p == h for p, h in zip(pattern, suffix)):
            return True

    return False


def prune_redundant_rules(rules):
    wildcard_prefixes = [
        rule[2:-2]
        for rule in rules
        if rule.startswith('||') and rule.endswith('*^')
    ]

    if not wildcard_prefixes:
        return rules

    pruned = set()
    for rule in rules:
        if not rule.startswith('||'):
            pruned.add(rule)
            continue

        if rule.endswith('*^'):
            host = rule[2:-2]
            covered = any(host.startswith(prefix) and host != prefix for prefix in wildcard_prefixes)
            if not covered:
                pruned.add(rule)
            continue

        host = rule_host(rule)
        if not host:
            pruned.add(rule)
            continue

        covered = any(host.startswith(prefix) and host != prefix for prefix in wildcard_prefixes)
        if not covered:
            pruned.add(rule)

    return pruned


def filter_keywords_and_tlds(rules, spam_tlds, nsfw_pattern):
    filtered = set()
    spam_tld_patterns = parse_spam_tld_patterns(spam_tlds)

    for rule in rules:
        if re.search(nsfw_pattern, rule):
            continue

        host = rule_host(rule)
        if host and host_matches_spam_tld(host, spam_tld_patterns):
            continue

        filtered.add(rule)

    return prune_redundant_rules(filtered)


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

    consolidated = prune_redundant_rules(consolidate_domains_tldaware(dns_rules))

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
