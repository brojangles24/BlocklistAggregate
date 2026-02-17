import requests
import concurrent.futures
import re
from datetime import datetime

# --- CONFIGURATION ---
VERSION = "2026.02.16.ADGUARD_DESKTOP_DNS_FINAL"
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

# Keywords & Enforcements
# Added \b to prevent blocking safe words like "Sussex"
NSFW_KEYWORDS = r"\b(xxx|porn|sex|sexy|fuck|tits|titties|titty|boobs|boobies|booty|pussy|hentai|milf|blowjob|threesome|bondage|bdsm|gangbang|handjob|deepthroat|horny|bukkake|titfuck|brazzers|redtube|pornhub|shemale|erotic|omegle|xnxx|xvideo|xxvideo)\b"
NSFW_REGEX_COMP = re.compile(f"(?i){NSFW_KEYWORDS}")
NSFW_REGEX_RAW = f"/(?i){NSFW_KEYWORDS}/"
YOUTUBE_RULE = "/^(www\.|m\.|youtubei\.|youtube\.)?(youtube(-nocookie)?\.com|googleapis\.com)$/$dnsrewrite=restrictmoderate.youtube.com"

OUTPUT_FILE = "adguard_dns_filter.txt"

# Modifiers supported by AdGuard DNS engine
DNS_VALID_MODIFIERS = ["$dnsrewrite", "$important", "$client", "$network", "$ctag", "$badfilter", "$denyallow"]

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
    advanced_rules = set() # Rules with $dnsrewrite, etc.
    simple_domains = set() # Standard ||domain^ rules
    
    # Stats
    tld_nuke = 0
    keyword_nuke = 0
    cosmetic_nuke = 0
    syntax_nuke = 0
    
    start_time = datetime.now()
    print(f"--- STARTING ADGUARD DESKTOP DNS SCRUB ({start_time.strftime('%H:%M:%S')}) ---")

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
    
    blocked_tlds_tuple = tuple(f".{t}" for t in blocked_tlds)
    print(f"  -> Memorized {len(blocked_tlds)} spam TLDs.")

    # 2. Fetch Sources
    print("Fetching sources...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in CORE_SOURCES}
        all_lines = []
        for future in concurrent.futures.as_completed(future_to_url):
            all_lines.extend(future.result())

    # 3. Surgical Scrub (DNS-ONLY MODE)
    print("Executing DNS Scrub (Removing Cosmetic & Browser Rules)...")
    for line in all_lines:
        line_clean = line.strip().lower()
        # Strip comments
        line_clean = line_clean.split('!')[0].split(' #')[0].strip()
        
        if not line_clean or "adblock plus" in line_clean: continue
        
        # A. COSMETIC / SCRIPTLET PURGE (##, #@#, #%#, #$#)
        # DNS filters cannot use these. Delete them.
        if any(x in line_clean for x in ["##", "#@#", "#?#", "#%#", "#$#"]):
            cosmetic_nuke += 1
            continue

        # B. EXCEPTION PURGE (@@)
        # We usually remove exceptions to keep the list "Nuclear"
        if line_clean.startswith("@@"):
            continue

        # C. TRIPLE-PIPE REPAIR (Crucial Fix for AdGuard)
        # Fixes |||example.com -> ||example.com
        if line_clean.startswith("|"):
             line_clean = re.sub(r"^\|{2,}", "||", line_clean)

        # D. BROWSER MODIFIER PURGE
        # If it has $, check if it's a DNS modifier. If not (e.g. $image), delete it.
        if "$" in line_clean:
            is_valid_dns = any(mod in line_clean for mod in DNS_VALID_MODIFIERS)
            if not is_valid_dns:
                syntax_nuke += 1
                continue
            else:
                advanced_rules.add(line_clean)
                continue

        # E. PATH & FILE PURGE
        # DNS cannot block paths.
        if "/" in line_clean:
            # Keep valid Regex rules (start/end with /)
            if line_clean.startswith("/") and line_clean.endswith("/"):
                advanced_rules.add(line_clean)
                continue
            # Kill path blocks (||example.com/banner.php)
            if line_clean.startswith("||") and "/" in line_clean.replace("||", ""):
                 syntax_nuke += 1
                 continue
                 
        # F. KEYWORD SCRUB (SAFE FOR DNS)
        # Since we deleted cosmetic rules, we can safely delete domains matching "sex"
        # because the global Regex will catch them.
        if NSFW_REGEX_COMP.search(line_clean):
            keyword_nuke += 1
            continue
        
        # --- PREPARE DOMAIN PART FOR VALIDATION ---
        # 1. Remove Anchors
        domain_part = line_clean.replace("||", "").replace("^", "").strip()
        
        # 2. STRIP TRAILING DOTS (Fixes ||load.gtm.^ -> ||load.gtm^)
        domain_part = domain_part.rstrip('.')

        # G. TLD REDUNDANCY SCRUB
        if domain_part.endswith(blocked_tlds_tuple):
            tld_nuke += 1
            continue

        # H. FINAL VALIDATION
        # Nuke raw IP blocks (AdGuard DNS prefers domain blocks)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_part):
            syntax_nuke += 1
            continue
            
        # Nuke incomplete wildcards / Bad Domains
        if "." not in domain_part:
            if domain_part.endswith("*"): # Valid wildcard
                 advanced_rules.add(line_clean)
            else:
                syntax_nuke += 1
                continue
        else:
            # Valid Domain (e.g. load.gtm)
            simple_domains.add(domain_part)

    # 4. Tree-Pruning
    print(f"Tree-Pruning {len(simple_domains):,} core domains...")
    rev_domains = sorted(['.'.join(d.split('.')[::-1]) for d in simple_domains])
    pruned_rev = []
    last_added = ""
    
    for rd in rev_domains:
        if last_added and rd.startswith(last_added + "."): 
            continue
        pruned_rev.append(rd)
        last_added = rd
    
    # 5. Final Construction
    final_output = list(advanced_rules)
    for rd in pruned_rev:
        final_output.append(f"||{'.'.join(rd.split('.')[::-1])}^")
    
    final_output.sort()
    
    # 6. Write to File
    print(f"Writing {len(final_output):,} rules to file...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Isaac's DNS-Only Nuclear List\n")
        f.write(f"! Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"! Revision: {VERSION}\n")
        f.write("! Description: DNS-Only. No cosmetic rules. Optimized for AdGuard DNS Filter.\n\n")

        # Part 1: RAW TLD Firewall
        f.write("! --- SPAM TLDs ---\n")
        f.write("\n".join(spam_tlds_raw) + "\n\n")

        # Part 2: Scrubbed Core
        f.write("! --- OPTIMIZED DNS CORE ---\n")
        f.write("\n".join(final_output) + "\n")
        
        # Global Regex & YouTube
        f.write("\n! --- NUCLEAR REGEX ENFORCEMENT ---\n")
        f.write(f"{NSFW_REGEX_RAW}\n")
        f.write(f"{YOUTUBE_RULE}\n")

    # --- FINAL STATS PRINT ---
    elapsed = datetime.now() - start_time
    print(f"\n--- DNS SCRUB COMPLETE in {elapsed.total_seconds():.2f}s ---")
    print(f"Deleted {cosmetic_nuke:,} cosmetic rules (##, #%#).")
    print(f"Deleted {syntax_nuke:,} browser-only rules ($image, paths, IPs).")
    print(f"Deleted {tld_nuke:,} TLD redundancies.")
    print(f"Deleted {keyword_nuke:,} NSFW keyword matches (Covered by Regex).")
    print(f"Final blocklist saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
