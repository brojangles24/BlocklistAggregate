import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = "2026.02.16.DESKTOP_ULTIMATE_V1"
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
    "https://filters.adtidy.org/extension/chromium/filters/3.txt"
]
SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

# Keywords (Safety Optimized with \b)
NSFW_KEYWORDS = r"\b(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)\b"
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

OUTPUT_FILE = "desktop_blocklist.txt"

def fetch_url(url):
    try:
        print(f"  -> Downloading: {url}")
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"  !! Error fetching {url}: {e}")
        return []

def main():
    blocked_tlds = set()
    final_rules = set()
    start_time = datetime.now()

    print(f"--- STARTING DESKTOP OPTIMIZER V1 ({start_time.strftime('%H:%M:%S')}) ---")

    # 1. Build TLD Firewall
    print("Building TLD Firewall...")
    spam_tlds_raw = fetch_url(SPAM_TLD_URL)
    for line in spam_tlds_raw:
        clean = line.strip().lower()
        tld_match = re.search(r"(\*\.|\^|\|\|)([a-z0-9\-]+)\^", clean)
        if tld_match:
            tld = tld_match.group(2)
            if tld and len(tld) > 1:
                blocked_tlds.add(tld)
    
    # 2. Fetch Sources
    print("Fetching core sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    # 3. Surgical Scrub (Desktop Mode: LESS DESTRUCTIVE)
    print("Executing Scrub (Repairing Syntax & Typos)...")
    
    triple_pipe_fixes = 0
    duplicates = 0
    bad_syntax = 0

    blocked_tlds_tuple = tuple(f".{t}" for t in blocked_tlds)

    for line in all_lines:
        line_clean = line.strip() # Case sensitive for cosmetic rules!
        
        # Strip comments but keep ! for rules if they are AdGuard modifiers (rare)
        if line_clean.startswith("!") or line_clean.startswith("# "): continue
        if not line_clean: continue

        # A. TRIPLE-PIPE REPAIR (Crucial Fix)
        # Fixes |||example.com -> ||example.com
        if line_clean.startswith("|"):
             if "|||" in line_clean:
                 line_clean = re.sub(r"^\|{2,}", "||", line_clean)
                 triple_pipe_fixes += 1

        # B. TRAILING DOT FIX (Crucial Fix)
        # Only applies to Network rules (starting with ||), not Cosmetic rules (##)
        if line_clean.startswith("||"):
            # Split domain from modifiers ($)
            parts = line_clean.split('$')
            domain_part = parts[0].replace("^", "")
            
            if domain_part.endswith("."):
                # Reconstruct the rule without the trailing dot
                clean_domain = domain_part.rstrip('.')
                line_clean = f"{clean_domain}^{'$' + parts[1] if len(parts) > 1 else ''}"
                bad_syntax += 1

        # C. TLD REDUNDANCY (Optimization)
        # If we block .top, we don't need ||spam.top^
        # But we MUST keep cosmetic rules for .top sites (e.g. google.top##.ad)
        if line_clean.startswith("||"):
            check_domain = line_clean.replace("||", "").replace("^", "").split('$')[0].lower()
            if check_domain.endswith(blocked_tlds_tuple):
                duplicates += 1
                continue

        final_rules.add(line_clean)

    # 4. Write to File
    final_output = sorted(list(final_rules))
    
    print(f"Writing {len(final_output):,} rules to file...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Isaac's Desktop Ultimate List\n")
        f.write(f"! Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"! Revision: {VERSION}\n")
        f.write("! Description: Optimized for AdGuard Desktop (Windows/Mac). Includes cosmetic filtering.\n\n")

        # Part 1: RAW TLD Firewall
        f.write("! --- SPAM TLDs ---\n")
        f.write("\n".join(spam_tlds_raw) + "\n\n")

        # Part 2: Scrubbed Core
        f.write("! --- CORE RULES ---\n")
        f.write("\n".join(final_output) + "\n")
        
        # Global Regex & YouTube
        f.write("\n! --- NUCLEAR REGEX ENFORCEMENT ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")

    # --- FINAL STATS PRINT ---
    elapsed = datetime.now() - start_time
    print(f"\n--- DESKTOP SCRUB COMPLETE in {elapsed.total_seconds():.2f}s ---")
    print(f"Repaired {triple_pipe_fixes:,} '|||' syntax errors.")
    print(f"Fixed {bad_syntax:,} trailing dot errors.")
    print(f"Removed {duplicates:,} redundant TLD rules.")
    print(f"Final blocklist saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
