import requests
from datetime import datetime, timezone
import re
import textwrap
from collections import defaultdict

# --- CONFIGURATION ---
VERSION = "2026.02.17.CORE_CLEAN_TLD_FIXED"
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
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
]

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

NSFW_REGEX = re.compile(r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo|camgirl|nude|naked)")

OUTPUT_FILE = "blocklist.txt"

YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

MIN_TLD_COUNT = 3

# --- HELPERS ---

def fetch_url(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        r.encoding = 'utf-8'
        return r.text.splitlines()
    except Exception as e:
        print(f"!! Error fetching {url}: {e}")
        return []


def clean_line(line):
    line = line.partition('!')[0].partition('#')[0].strip()
    if not line or line.startswith('@@'):
        return None
    if line.startswith('||') and '^' not in line:
        line += '^'
    return line


def is_dns_compatible(rule):
    if not rule:
        return False
    if rule.startswith('@@') or '##' in rule or '#@#' in rule:
        return False
    if '$' in rule:
        return False
    return rule.startswith('||')


def parse_spam_tld_patterns(lines):
    patterns = []
    for line in lines:
        line = line.partition('!')[0].partition('#')[0].strip().lower()
        if not line:
            continue
        line = line.lstrip('.')
        parts = tuple(p for p in line.split('.') if p and p != '*')
        if parts:
            patterns.append(parts)
    return patterns


def host_from_rule(rule):
    host = rule[2:].split('^', 1)[0].lower().rstrip('.')
    host = host.replace('*.', '')
    return host


def matches_spam_tld(host, patterns):
    labels = tuple(host.split('.'))
    for pat in patterns:
        if len(pat) > len(labels):
            continue
        if labels[-len(pat):] == pat:
            return True
    return False


def filter_rules(rules, spam_patterns):
    kept = []
    for r in rules:
        host = host_from_rule(r)
        if NSFW_REGEX.search(host):
            continue
        if matches_spam_tld(host, spam_patterns):
            continue
        kept.append(r)
    return kept


# NOTE: no consolidation or pruning beyond exact dedupe
# DNS-only requirement: only remove spam-TLD matches and keyword matches

def consolidate_domains(rules):
    return set(rules)



# --- MAIN ---

def main():
    raw = set()
    for url in CORE_SOURCES:
        for line in fetch_url(url):
            cl = clean_line(line)
            if cl:
                raw.add(cl)

    spam_tld_lines = fetch_url(SPAM_TLD_URL)
    spam_patterns = parse_spam_tld_patterns(spam_tld_lines)

    dns_rules = [r for r in raw if is_dns_compatible(r)]
    filtered = filter_rules(dns_rules, spam_patterns)
    consolidated = set(filtered)

    now = datetime.now(AZ_TZ).strftime('%Y-%m-%d %H:%M:%S UTC')

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"! Clean DNS Blocklist\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Version: {VERSION}\n")
        f.write(f"! Rules: {len(consolidated)}\n\n")
        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write("\n".join(sorted(consolidated)) + "\n\n")

        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(spam_tld_lines))
        f.write("\n\n")

        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(YOUTUBE_RULE + "\n")
        f.write(textwrap.dedent(FORCE_SAFE).strip() + "\n")

    print(f"SUCCESS: wrote {len(consolidated)} rules")


if __name__ == '__main__':
    main()
