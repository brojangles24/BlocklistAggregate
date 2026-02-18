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

NSFW_REGEX = re.compile(
    r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|"
    r"hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|"
    r"horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|"
    r"xnxx|xvideo|xxvideo|camgirl|nude|naked)"
)

OUTPUT_FILE = "blocklist.txt"
YOUTUBE_RULE = (
    "/^(www\\.|m\\.|youtubei\\.|youtube\\.)?(youtube(-nocookie)?\\.com|"
    "googleapis\\.com)$/$dnsrewrite=restrictmoderate.youtube.com"
)


def fetch(url):
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return []


def parse_tld_patterns(lines):
    """
    Parse Hagezi spam TLD list into plain TLD strings.
    Input lines look like: ||*.xyz^  or  ||*.co.uk^
    After stripping AdBlock syntax and the wildcard prefix we get: xyz / co.uk
    """
    patterns = set()
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip().lower()
        if not clean:
            continue
        # Remove AdBlock wrapper
        clean = clean.replace("||", "").replace("^", "")
        # Strip leading wildcard and dots (*.xyz -> xyz, .xyz -> xyz)
        if clean.startswith("*."):
            clean = clean[2:]
        clean = clean.lstrip(".")
        if clean:
            patterns.add(clean)
    # Sort longest-first so multi-part TLDs (e.g. co.uk) are checked before single-part
    return sorted(patterns, key=len, reverse=True)


def is_spam_tld(host, patterns):
    """Return True if the host's TLD (or TLD+1) matches a spam TLD pattern."""
    for p in patterns:
        if host == p or host.endswith("." + p):
            return True
    return False


def main():
    print(f"[*] DNS Blocklist Generator {VERSION}")

    print("[*] Fetching Hagezi Spam TLDs...")
    spam_tld_raw = fetch(SPAM_TLD_URL)
    spam_patterns = parse_tld_patterns(spam_tld_raw)
    print(f"    -> {len(spam_patterns)} TLD patterns loaded")

    final_rules = set()

    print(f"[*] Processing {len(CORE_SOURCES)} sources...")
    for url in CORE_SOURCES:
        before = len(final_rules)
        lines = fetch(url)
        for line in lines:
            clean = line.split("!")[0].split("#")[0].strip()

            # Only DNS-compatible rules: must start with || and have no modifiers
            if not clean.startswith("||") or "$" in clean:
                continue

            # Ensure closing anchor
            if "^" not in clean:
                clean += "^"

            # Extract bare hostname for filtering
            host = clean.replace("||", "").split("^")[0].lower().strip(".")

            # 1. Drop NSFW keyword matches
            if NSFW_REGEX.search(host):
                continue

            # 2. Drop domains whose TLD is already blocked by the spam TLD list
            #    (they're redundant — the TLD wildcard covers them)
            if is_spam_tld(host, spam_patterns):
                continue

            final_rules.add(clean)

        added = len(final_rules) - before
        print(f"    -> {url.split('/')[-1]}: +{added} rules  (total: {len(final_rules)})")

    print(f"[*] Writing {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %H:%M:%S MST")
        f.write(
            f"! Clean DNS Blocklist\n"
            f"! Version: {VERSION}\n"
            f"! Generated: {now}\n"
            f"! Rules: {len(final_rules)}\n\n"
        )

        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write("\n".join(sorted(final_rules)))
        f.write("\n\n")

        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(spam_tld_raw))
        f.write("\n\n")

        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(YOUTUBE_RULE + "\n\n")

        f.write(f"! NSFW Regex Pattern: {NSFW_REGEX.pattern}\n")

    print(f"\n[+] SUCCESS: {OUTPUT_FILE} — {len(final_rules):,} filtered rules.")


if __name__ == "__main__":
    main()
