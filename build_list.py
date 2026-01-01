import requests
import json
import os
import datetime
from collections import Counter, defaultdict
import pandas as pd
import plotly.express as px
import tldextract

# --- CONFIGURATION ---
# Format: (URL, Weight, Tag)
SOURCES = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", 15, "Malware"), 
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards", 10, "Tracking"),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt", 8, "Aggressive"),
    ("https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt", 6, "Mobile Ads"),
    ("https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt", 5, "General Ads"),
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/domains.wildcards", 2, "Gap Filler")
]

DOMAIN_LIMIT = 300000
HISTORY_FILE = "history.json"

def fetch_domains(url):
    print(f"Fetching: {url}")
    domains = set()
    try:
        r = requests.get(url, timeout=60)
        for line in r.text.splitlines():
            line = line.strip().lower()
            
            # Clean comments and empty lines
            if '#' in line: line = line.split('#')[0].strip()
            if not line or line.startswith('!'): continue

            # Clean wildcards (e.g. *.example.com -> example.com)
            line = line.lstrip('*.')

            parts = line.split()
            # Handle hosts file format (0.0.0.0 example.com)
            if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1"]:
                domains.add(parts[1])
            # Handle raw domains format (example.com)
            elif len(parts) == 1:
                domains.add(parts[0])
                
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return domains

def save_history(stats_data):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except:
            pass
    history.append(stats_data)
    return history[-365:] 

def generate_dashboard(final_domains, domain_tags, history):
    print("Generating Dashboard...")
    
    # 1. Kingpin Tracker (Root Domain Grouping)
    print("Extracting Root Domains...")
    ext = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=None)
    
    root_domains = []
    for d in final_domains:
        res = ext(d)
        if res.domain and res.suffix:
            root_domains.append(f"{res.domain}.{res.suffix}")
    
    top_roots = Counter(root_domains).most_common(20)
    df_roots = pd.DataFrame(top_roots, columns=['Root Domain', 'Subdomains Blocked'])

    # 2. Category Breakdown
    final_categories = []
    for d in final_domains:
        tags = domain_tags.get(d, ["Unknown"])
        # Priority mapping
        if "Malware" in tags: cat = "Malware"
        elif "Tracking" in tags: cat = "Tracking"
        elif "Aggressive" in tags: cat = "Aggressive"
        elif "Mobile Ads" in tags: cat = "Mobile Ads"
        else: cat = tags[0]
        final_categories.append(cat)
    
    df_cat = pd.DataFrame(Counter(final_categories).items(), columns=['Category', 'Count'])

    # 3. History
    df_hist = pd.DataFrame(history)

    # --- VISUALIZATION ---
    # Chart A: The Kingpins
    fig_roots = px.bar(df_roots, x='Subdomains Blocked', y='Root Domain', orientation='h', 
                 title="👑 The Kingpins: Top Blocked Organizations", template="plotly_dark",
                 color='Subdomains Blocked', color_continuous_scale='Redor')
    fig_roots.update_layout(yaxis=dict(autorange="reversed")) 

    # Chart B: Categories
    fig_cat = px.sunburst(df_cat, path=['Category'], values='Count', 
                       title="🛡️ Threat Landscape by Category", template="plotly_dark",
                       color_discrete_sequence=px.colors.qualitative.Pastel)

    # Chart C: Growth
    fig_hist = None
    if not df_hist.empty and 'date' in df_hist.columns:
        fig_hist = px.line(df_hist, x='date', y='total_count', title="List Growth Over Time", template="plotly_dark")

    # Generate HTML
    with open("stats.html", "w", encoding="utf-8") as f:
        f.write("<html><head><title>Isaac's DNS Intel</title></head><body style='background-color:#111; color:white; font-family:sans-serif'>")
        f.write("<div style='max-width: 1200px; margin: 0 auto; padding: 20px;'>")
        f.write("<h1>🛡️ DNS Defense Report</h1>")
        f.write(f"<h3>Total Domains: {len(final_domains)} | Limit: {DOMAIN_LIMIT}</h3>")
        f.write(f"<p>Sources: {', '.join([s[2] for s in SOURCES])}</p>")
        
        f.write(fig_roots.to_html(full_html=False, include_plotlyjs='cdn'))
        f.write(fig_cat.to_html(full_html=False, include_plotlyjs='cdn'))
        
        if fig_hist:
            f.write(fig_hist.to_html(full_html=False, include_plotlyjs='cdn'))
            
        f.write("</div></body></html>")

def main():
    domain_scores = Counter()
    domain_tags = defaultdict(list)

    # 1. Fetch & Score
    for url, weight, tag in SOURCES:
        domains = fetch_domains(url)
        print(f"[{tag}] Found {len(domains)} domains")
        for d in domains:
            domain_scores[d] += weight
            domain_tags[d].append(tag)

    # 2. Smart Deduplication
    print("Running Smart Deduplication (www vs root)...")
    all_keys = list(domain_scores.keys())
    existing = set(all_keys)
    removed_count = 0
    
    for d in all_keys:
        if d.startswith("www."):
            root = d[4:]
            # If root exists, remove the www variant
            if root in existing:
                del domain_scores[d]
                removed_count += 1
    print(f"  -> Removed {removed_count} redundant subdomains.")

    # 3. Sort & Cut
    print(f"Sorting by Risk Score (Limit: {DOMAIN_LIMIT})...")
    # Sort by Score (Desc), then Alphabetical
    ranked = sorted(domain_scores.items(), key=lambda x: (-x[1], x[0]))
    final_list = [d[0] for d in ranked[:DOMAIN_LIMIT]]

    # 4. Stats & Output
    stats = {
        "date": datetime.date.today().isoformat(),
        "total_count": len(final_list)
    }
    history = save_history(stats)
    
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)

    generate_dashboard(final_list, domain_tags, history)

    print(f"Writing {len(final_list)} domains to blocklist.txt...")
    with open("blocklist.txt", "w") as f:
        f.write(f"# Isaac's High-Weighted Blocklist\n")
        f.write(f"# Total Domains: {len(final_list)}\n")
        f.write(f"# Updated: {datetime.datetime.now()}\n")
        for domain in final_list:
            f.write(f"{domain}\n")

if __name__ == "__main__":
    main()
