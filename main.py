import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = "2026.02.16.NUCLEAR_FINAL_BOSS_V5"
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

# Keywords & Enforcements (Optimized for Safety)
# Added \b (word boundaries) to prevent blocking words like 'Sussex', 'Analysis', 'Button', etc.
NSFW_KEYWORDS = r"\b(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)\b"
NSFW_REGEX_COMP = re.compile(f"(?i){NSFW_KEYWORDS}")
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

OUTPUT_FILE = "blocklist.txt"

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
    advanced_rules = set()
    simple_domains = set()
    start_time = datetime.now()

    print(f"--- STARTING NUCLEAR SCRUB V5 ({start_time.strftime('%H:%M:%S')}) ---")

    # 1. Build TLD Firewall (Memorizes .xyz, .top, etc.)
    print("Building TLD Firewall...")
    spam_tlds_raw = fetch_url(SPAM_TLD_URL)
    for line in spam_tlds_raw:
        clean = line.strip().lower()
        tld_match = re.search(r"(\*\.|\^|\|\|)([a-z0-9\-]+)\^", clean)
        if tld_match:
            tld = tld_match.group(2)
            if tld and len(tld) > 1:
                blocked_tlds.add(tld)
    print(f"  -> Memorized {len(blocked_tlds)} spam TLDs.")

    # 2. Fetch Sources
    print("Fetching core sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    # 3. Surgical Scrub
    print("Executing Nuclear Scrub (Nuking Exceptions & Repairing Triple-Pipes)...")
    tld_nuke = 0
    keyword_nuke = 0
    syntax_nuke = 0
    exception_nuke = 0
    
    # Convert TLD set to tuple for faster 'endswith' checking
    blocked_tlds_tuple = tuple(f".{t}" for t in blocked_tlds)

    for line in all_lines:
        line_clean = line.strip().lower()
        # Strip comments/whitespace
        line_clean = line_clean.split('#')[0].split('!')[0].split(';')[0].strip()
        
        if not line_clean or "adblock plus" in line_clean: continue
        
        # A. EXCEPTION PURGE (Remove all @@ rules)
        if line_clean.startswith("@@"):
            exception_nuke += 1
            continue

        # B. TRIPLE-PIPE REPAIR (Convert ||| to || globally)
        if "|||" in line_clean:
            line_clean = line_clean.replace("|||", "||")

        # C. PATH & BROWSER SYNTAX SCRUB (DNS Blindspots)
        if line_clean.startswith("/") and any(x in line_clean for x in [".js", ".php", ".png", ".jpg", "/api/"]):
            syntax_nuke += 1
            continue
        if any(x in line_clean for x in ["$cookie", "$script", "$image", "$stylesheet", "$popup", "$object", "$xmlhttprequest"]):
            syntax_nuke += 1
            continue

        # D. KEYWORD SCRUB
        if NSFW_REGEX_COMP.search(line_clean):
            keyword_nuke += 1
            continue
        
        # E. TLD REDUNDANCY SCRUB (Optimized)
        # Check if domain part ends with a blocked TLD
        domain_part = line_clean.replace("||", "").replace("^", "").split('$')[0].strip()
        if domain_part.endswith(blocked_tlds_tuple):
            tld_nuke += 1
            continue

        # F. CATEGORIZE & FILTER (The "AdGuard-Native" Logic)
        if "$" in line_clean:
            # Keep only DNS-compatible enforcements
            if any(x in line_clean for x in ["$dnsrewrite", "$important", "$client", "$network", "$ctag"]):
                advanced_rules.add(line_clean)
            else:
                syntax_nuke += 1 # Discard browser-specific modifiers
        else:
            # Domain and IP Validation
            domain_only = line_clean.replace("||", "").replace("^", "").strip()
            
            # Nuke raw IP blocks (DNS filters usually don't handle IP lists well mixed with domains)
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_only):
                syntax_nuke += 1
                continue
            
            # Nuke incomplete wildcards (e.g. ||piwik.^) if they lack a TLD or dot
            if "." not in domain_only and not domain_only.endswith("*"):
                # If it's a known AdGuard wildcard like ||piwik.^ we keep it as 'Advanced'
                if "^" in line_clean:
                    advanced_rules.add(line_clean)
                else:
                    syntax_nuke += 1
                    continue
            else:
                # Standard domain - add to simple list for tree-pruning
                simple_domains.add(domain_only)

    # 4. Tree-Pruning
    print(f"Pruning {len(simple_domains):,} core domains...")
    # Reverse the domains (com.google.ads) to sort and find subdomains easily
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in simple_domains])
    pruned_rev = []
    last_added = ""
    
    for rd in rev_domains:
        # If current domain starts with the last added domain + dot, it's a subdomain (Redundant)
        if last_added and rd.startswith(last_added + "."): 
            continue
        pruned_rev.append(rd)
        last_added = rd
    
    # 5. Final Construction
    final_output = list(advanced_rules)
    for rd in pruned_rev:
        # Re-reverse to standard format (ads.google.com)
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    
    final_output.sort()
    
    # 6. Write to File
    print(f"Writing {len(final_output):,} rules to file...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Isaac's Zero-Exception Nuclear List\n")
        f.write(f"! Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"! Revision: {VERSION}\n")
        f.write(f"! Total Rules: {len(final_output) + len(spam_tlds_raw)}\n\n")

        # Part 1: RAW TLD Firewall
        f.write("############################################################\n")
        f.write("# PART 1: HAGEZI SPAM TLD LIST (UNEDITED RAW)\n")
        f.write("############################################################\n")
        f.write("\n".join(spam_tlds_raw) + "\n\n")

        # Part 2: Scrubbed Core
        f.write("############################################################\n")
        f.write(f"# PART 2: OPTIMIZED CORE (NO EXCEPTIONS | NO GHOSTS)\n")
        f.write("############################################################\n\n")
        f.write("\n".join(final_output) + "\n")
        
        # Global Regex & YouTube
        f.write("\n! --- NUCLEAR REGEX ENFORCEMENT ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")

    # --- FINAL STATS PRINT ---
    elapsed = datetime.now() - start_time
    print(f"\n--- NUCLEAR SCRUB COMPLETE in {elapsed.total_seconds():.2f}s ---")
    print(f"Deleted {syntax_nuke:,} ghost rules (paths, IPs, bad syntax).")
    print(f"Deleted {tld_nuke:,} TLD redundancies (covered by Part 1).")
    print(f"Deleted {keyword_nuke:,} NSFW keyword matches.")
    print(f"Deleted {exception_nuke:,} 'Allow' rules (@@ exceptions purged).")
    print(f"Final blocklist saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
