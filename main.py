import requests
import re
import time
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Arizona is MST (UTC-7) year-round
AZ_TZ = timezone(timedelta(hours=-7))

VERSION = "2026.02.17.CORE_CLEAN_ULTIMATE"

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

# Domains matching these keywords are counted and optionally dropped.
# APPLY_NSFW_FILTER=False means count only — useful since we include NSFW
# sources deliberately and don't want to silently remove what we want blocked.
NSFW_REGEX = re.compile(
    r"(?i)(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|"
    r"hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|"
    r"horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|"
    r"xnxx|xvideo|xxvideo|camgirl|nude|naked)"
)
APPLY_NSFW_FILTER = True

OUTPUT_FILE = "blocklist.txt"
YOUTUBE_RULE = (
    "/^(www\\.|m\\.|youtubei\\.|youtube\\.)?(youtube(-nocookie)?\\.com|"
    "googleapis\\.com)$/$dnsrewrite=restrictmoderate.youtube.com"
)

MAX_RETRIES = 3
RETRY_DELAY = 3


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------

def fetch(url, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=(5, 30),
            )
            r.raise_for_status()
            return r.text.splitlines()
        except Exception as e:
            if attempt < retries:
                print(f"  [!] Attempt {attempt}/{retries} failed for {url}: {e} — retrying in {RETRY_DELAY}s")
                time.sleep(RETRY_DELAY)
            else:
                print(f"  [!] All {retries} attempts failed for {url}: {e}")
                return []


def fetch_all_parallel(urls, max_workers=6):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            results[url] = future.result()
    return results


# ---------------------------------------------------------------------------
# TLD helpers
# ---------------------------------------------------------------------------

def parse_tld_patterns(lines):
    """
    Parse Hagezi spam TLD list into:
      - tld_patterns: sorted list of bare TLD strings e.g. ['accountant', 'xyz', ...]
      - denyallow_map: dict of {tld: set_of_whitelisted_hosts}

    Hagezi format examples:
      ||*.xyz^
      ||*.wiki^$denyallow=minecraft.wiki|runescape.wiki|...
      *.accountant   (no || prefix on some entries)

    The $denyallow= value lists domains that are EXCEPTIONS and must NOT be blocked.
    """
    tld_patterns = []
    denyallow_map = {}
    seen = set()

    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip().lower()
        if not clean:
            continue

        # Split off modifiers ($denyallow=...) before stripping AdBlock syntax
        denyallow_hosts = set()
        if "$" in clean:
            rule_part, _, modifiers = clean.partition("$")
            for mod in modifiers.split(","):
                if mod.startswith("denyallow="):
                    denyallow_hosts = set(mod[len("denyallow="):].split("|"))
        else:
            rule_part = clean

        # Strip AdBlock syntax to get bare TLD
        rule_part = rule_part.replace("||", "").replace("^", "")
        if rule_part.startswith("*."):
            rule_part = rule_part[2:]
        rule_part = rule_part.lstrip(".")

        if not rule_part or rule_part in seen:
            continue
        seen.add(rule_part)

        tld_patterns.append(rule_part)
        if denyallow_hosts:
            denyallow_map[rule_part] = denyallow_hosts

    # Sort longest-first so multi-part TLDs (co.uk) match before single-part (uk)
    tld_patterns.sort(key=len, reverse=True)
    return tld_patterns, denyallow_map


def get_matching_tld(host, patterns_sorted, denyallow_map):
    """
    Return the matching spam TLD if host ends with one AND is not whitelisted.
    Returns the matched TLD string, or None if no match / whitelisted.
    """
    for p in patterns_sorted:
        if host == p or host.endswith("." + p):
            # Check if this specific host is whitelisted via denyallow
            if p in denyallow_map and host in denyallow_map[p]:
                return None  # whitelisted exception — do not block
            return p
    return None


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def parse_rules(lines):
    """
    Extract valid rules from raw list lines. Returns:
      - domain_rules: list of (rule, host) tuples for ||domain^ style rules
      - regex_rules:  list of raw /regex/ AdGuard rules passed through as-is
    """
    domain_rules = []
    regex_rules = []
    for line in lines:
        clean = line.split("!")[0].split("#")[0].strip()
        if not clean:
            continue

        # AdGuard regex rules — pass through as-is (e.g. DNS rebind protection)
        if clean.startswith("/") and clean.endswith("/"):
            regex_rules.append(clean)
            continue

        # Standard DNS domain rules
        if not clean.startswith("||") or "$" in clean:
            continue
        if "^" not in clean:
            clean += "^"
        host = clean.replace("||", "").split("^")[0].lower().strip(".")
        if host:
            domain_rules.append((clean, host))

    return domain_rules, regex_rules


# ---------------------------------------------------------------------------
# Subdomain deduplication
# ---------------------------------------------------------------------------

def prune_subdomains(rules_set):
    """
    Remove rules whose host is a subdomain of another blocked host.
    e.g. if ||example.com^ is blocked, ||sub.example.com^ is redundant.
    Returns (pruned_set, removed_count).
    """
    host_to_rule = {}
    for rule in rules_set:
        host = rule.replace("||", "").split("^")[0].lower().strip(".")
        host_to_rule[host] = rule

    all_hosts = set(host_to_rule.keys())
    pruned = set()
    removed = 0

    for host, rule in host_to_rule.items():
        parts = host.split(".")
        is_redundant = any(
            ".".join(parts[i:]) in all_hosts
            for i in range(1, len(parts))
        )
        if is_redundant:
            removed += 1
        else:
            pruned.add(rule)

    return pruned, removed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    start_time = time.time()
    print(f"[*] DNS Blocklist Generator {VERSION}")
    print(f"    NSFW keyword filter: {'ACTIVE (dropping matches)' if APPLY_NSFW_FILTER else 'OBSERVE ONLY (counting, not dropping)'}")

    # Spam TLD list
    print("\n[*] Fetching Hagezi Spam TLDs...")
    spam_tld_raw = fetch(SPAM_TLD_URL)
    spam_patterns, denyallow_map = parse_tld_patterns(spam_tld_raw)
    print(f"    -> {len(spam_patterns)} TLD patterns loaded")
    print(f"    -> {len(denyallow_map)} TLDs have denyallow whitelists")
    print(f"    -> Sample TLDs: {spam_patterns[:12]}")
    if denyallow_map:
        sample_tld = next(iter(denyallow_map))
        sample_exceptions = list(denyallow_map[sample_tld])[:5]
        print(f"    -> Sample denyallow ({sample_tld}): {sample_exceptions}")

    # Fetch all sources in parallel
    print(f"\n[*] Fetching {len(CORE_SOURCES)} sources in parallel...")
    fetched = fetch_all_parallel(CORE_SOURCES)

    # Process rules
    print("\n[*] Processing rules...\n")
    header = f"    {'Source':<42} {'Lines':>8}  {'Added':>8}  {'Drop(TLD)':>10}  {'Drop(KW)':>10}"
    print(header)
    print("    " + "-" * (len(header) - 4))

    raw_rules = set()
    all_regex_rules = set()
    total_dropped_tld = 0
    total_dropped_kw = 0

    for url in CORE_SOURCES:
        lines = fetched.get(url, [])
        source_name = url.split("/")[-1] or url.split("/")[-2]
        before = len(raw_rules)
        dropped_tld = 0
        dropped_kw = 0

        domain_rules, regex_rules = parse_rules(lines)

        # Regex rules pass through unfiltered
        all_regex_rules.update(regex_rules)

        for rule, host in domain_rules:
            # Filter: spam TLD (respects denyallow whitelist)
            if get_matching_tld(host, spam_patterns, denyallow_map):
                dropped_tld += 1
                continue

            # Filter: NSFW keyword
            if NSFW_REGEX.search(host):
                dropped_kw += 1
                if APPLY_NSFW_FILTER:
                    continue

            raw_rules.add(rule)

        added = len(raw_rules) - before
        total_dropped_tld += dropped_tld
        total_dropped_kw += dropped_kw
        print(
            f"    {source_name:<42} {len(lines):>8,}  {added:>8,}  {dropped_tld:>10,}  {dropped_kw:>10,}"
        )

    print(f"\n    {'TOTAL':<42} {'':>8}  {len(raw_rules):>8,}  {total_dropped_tld:>10,}  {total_dropped_kw:>10,}")
    print(f"    Regex rules collected: {len(all_regex_rules)}")
    print(f"\n[*] Raw rules after filters: {len(raw_rules):,}")

    # Subdomain deduplication
    print("\n[*] Pruning redundant subdomain rules...")
    final_rules, removed_subdomains = prune_subdomains(raw_rules)
    print(f"    -> Removed {removed_subdomains:,} redundant subdomain rules")
    print(f"    -> Final rule count: {len(final_rules):,}")

    # Write output
    elapsed = time.time() - start_time
    now = datetime.now(AZ_TZ).strftime("%Y-%m-%d %H:%M:%S MST")
    nsfw_note = (
        f"! NSFW keyword filter: ACTIVE — {total_dropped_kw:,} domains dropped\n"
        if APPLY_NSFW_FILTER
        else f"! NSFW keyword filter: OBSERVE ONLY — {total_dropped_kw:,} keyword-matched domains kept\n"
    )

    print(f"\n[*] Writing {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(
            f"! Clean DNS Blocklist\n"
            f"! Version: {VERSION}\n"
            f"! Generated: {now}\n"
            f"! Build time: {elapsed:.1f}s\n"
            f"! Rules: {len(final_rules):,}\n"
            f"! Regex rules: {len(all_regex_rules)}\n"
            f"! Dropped (spam TLD filter): {total_dropped_tld:,}\n"
            f"! Dropped (subdomain dedup): {removed_subdomains:,}\n"
            + nsfw_note + "\n"
        )
        f.write(f"! --- REGEX RULES (DNS REBIND PROTECTION + OTHER) ---\n")
        f.write("\n".join(sorted(all_regex_rules)))
        f.write("\n\n")
        f.write("! --- DNS-COMPATIBLE CORE BLOCK RULES ---\n")
        f.write("\n".join(sorted(final_rules)))
        f.write("\n\n")
        f.write("! --- HAGEZI SPAM TLDs (RAW) ---\n")
        f.write("\n".join(spam_tld_raw))
        f.write("\n\n")
        f.write("! --- CUSTOM ENFORCEMENT & SAFESEARCH ---\n")
        f.write(YOUTUBE_RULE + "\n\n")
        f.write(f"! --- NSFW REGEX RULE ---\n")
        f.write(f"/{NSFW_REGEX.pattern}/\n")

    print(f"\n[+] SUCCESS — {len(final_rules):,} domain rules + {len(all_regex_rules)} regex rules written to {OUTPUT_FILE}")
    print(f"    Spam TLD filter dropped:    {total_dropped_tld:,}")
    print(f"    Keyword matches (NSFW):     {total_dropped_kw:,}  ({'dropped' if APPLY_NSFW_FILTER else 'observed only'})")
    print(f"    Subdomain dedup dropped:    {removed_subdomains:,}")
    print(f"    Build time:                 {elapsed:.1f}s")


if __name__ == "__main__":
    main()
