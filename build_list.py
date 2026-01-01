import requests
import json
import os
import datetime
import math
from collections import Counter, defaultdict
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import tldextract

# --- CONFIGURATION ---
SOURCES = [
    ("https://urlhaus.abuse.ch/downloads/hostfile/", 15, "Malware"), 
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards", 10, "Tracking"),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt", 8, "Aggressive"),
    ("https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt", 6, "Mobile Ads"),
    ("https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt", 5, "General Ads"),
    ("https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/domains.wildcards", 2, "Gap Filler")
]

# Hagezi Spam TLDs (Extensions to purge from list because you should block them globally)
SPAM_TLD_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/tlds/spam.txt"

DOMAIN_LIMIT = 300000
HISTORY_FILE = "history.json"
PREVIOUS_LIST_FILE = "blocklist.txt"
PHISHING_TARGETS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'bank', 'login', 'verify', 'secure', 'account', 'update', 'crypto', 'wallet']

# --- APPLE DESIGN SYSTEM COLORS ---
APPLE_COLORS = ['#0A84FF', '#30D158', '#BF5AF2', '#FF9F0A', '#FF453A', '#64D2FF', '#FF375F', '#5E5CE6']
BG_COLOR = "#000000"
CARD_COLOR = "#1C1C1E"
TEXT_COLOR = "#F5F5F7"

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def fetch_spam_tlds():
    print("Fetching Spam TLDs...")
    tlds = set()
    try:
        r = requests.get(SPAM_TLD_URL, timeout=30)
        for line in r.text.splitlines():
            line = line.strip().lower()
            if line and not line.startswith('#'):
                # Store as ".tld" for easy suffix checking
                tlds.add("." + line)
    except Exception as e:
        print(f"Error fetching Spam TLDs: {e}")
    return tuple(tlds) # Return as tuple for .endswith()

def fetch_domains(url):
    print(f"Fetching: {url}")
    domains = set()
    try:
        r = requests.get(url, timeout=60)
        for line in r.text.splitlines():
            line = line.strip().lower()
            if '#' in line: line = line.split('#')[0].strip()
            if not line or line.startswith('!'): continue
            line = line.lstrip('*.')
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1"]:
                domains.add(parts[1])
            elif len(parts) == 1:
                domains.add(parts[0])
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return domains

def load_previous_domains():
    if not os.path.exists(PREVIOUS_LIST_FILE): return set()
    prev = set()
    try:
        with open(PREVIOUS_LIST_FILE, "r") as f:
            for line in f:
                if line.startswith("0.0.0.0"): prev.add(line.split()[1].strip())
    except: pass
    return prev

def save_history(stats_data):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f: history = json.load(f)
        except: pass
    history.append(stats_data)
    return history[-365:] 

def generate_dashboard(final_domains, domain_scores, history, churn_stats, target_stats, removed_tld_count):
    print("Generating Dashboard...")
    
    tlds = [d.split('.')[-1] for d in final_domains]
    df_tld = pd.DataFrame(Counter(tlds).most_common(8), columns=['TLD', 'Count']) 
    entropies = [calculate_entropy(d) for d in final_domains]
    depths = [d.count('.') for d in final_domains]
    df_depth = pd.DataFrame(Counter(depths).items(), columns=['Depth', 'Count']).sort_values('Depth')
    df_targets = pd.DataFrame(target_stats.items(), columns=['Target', 'Count']).sort_values('Count', ascending=True).tail(10)
    df_hist = pd.DataFrame(history)

    common_layout = dict(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif', color=TEXT_COLOR),
        margin=dict(l=20, r=20, t=40, b=20)
    )

    fig_targets = px.bar(df_targets, x='Count', y='Target', orientation='h', color_discrete_sequence=[APPLE_COLORS[6]])
    fig_targets.update_layout(**common_layout, xaxis_title="", yaxis_title="")

    fig_depth = px.bar(df_depth, x='Depth', y='Count', color_discrete_sequence=[APPLE_COLORS[5]])
    fig_depth.update_layout(**common_layout, xaxis_title="Depth Level", yaxis_title="")

    fig_entropy = go.Figure(data=[go.Histogram(x=entropies, nbinsx=40, marker_color=APPLE_COLORS[1])])
    fig_entropy.update_layout(**common_layout, title_text="", showlegend=False)

    fig_tld = px.pie(df_tld, values='Count', names='TLD', hole=0.6, color_discrete_sequence=APPLE_COLORS)
    fig_tld.update_layout(**common_layout)
    fig_tld.update_traces(textposition='inside', textinfo='percent+label')

    fig_hist = px.line(df_hist, x='date', y='total_count', markers=True, color_discrete_sequence=[APPLE_COLORS[0]])
    fig_hist.update_layout(**common_layout)
    fig_hist.update_xaxes(showgrid=False)
    fig_hist.update_yaxes(gridcolor='#333')

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DNS Intel</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            :root {{ --bg: {BG_COLOR}; --card: {CARD_COLOR}; --text: {TEXT_COLOR}; --danger: #FF453A; --success: #30D158; }}
            body {{ background-color: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", Roboto, sans-serif; margin: 0; padding: 40px 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            header {{ margin-bottom: 40px; }}
            h1 {{ font-size: 40px; font-weight: 700; margin: 0; }}
            .subtitle {{ color: #8E8E93; font-size: 17px; margin-top: 8px; }}
            .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }}
            .kpi-card {{ background: var(--card); border-radius: 18px; padding: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
            .kpi-label {{ color: #8E8E93; font-size: 13px; font-weight: 600; text-transform: uppercase; }}
            .kpi-value {{ font-size: 34px; font-weight: 600; margin-top: 8px; }}
            .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 24px; }}
            .chart-card {{ background: var(--card); border-radius: 18px; padding: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); overflow: hidden; }}
            h2 {{ font-size: 22px; margin: 0 0 20px 0; font-weight: 600; }}
            .table-container {{ margin-top: 40px; background: var(--card); border-radius: 18px; padding: 24px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ text-align: left; color: #8E8E93; font-size: 13px; padding: 12px; border-bottom: 1px solid #38383A; }}
            td {{ padding: 16px 12px; border-bottom: 1px solid #2C2C2E; font-size: 15px; }}
            tr:last-child td {{ border-bottom: none; }}
            .badge {{ background: rgba(10, 132, 255, 0.15); color: #0A84FF; padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
            @media (max-width: 700px) {{ .charts-grid {{ grid-template-columns: 1fr; }} h1 {{ font-size: 32px; }} }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Security Dashboard</h1>
                <div class="subtitle">Updated {datetime.date.today().strftime('%B %d, %Y')} • {len(final_domains):,} Active Threats</div>
            </header>
            
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Active Threats</div>
                    <div class="kpi-value">{len(final_domains):,}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">TLD Optimization</div>
                    <div class="kpi-value" style="color: #FF9F0A">-{removed_tld_count}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">New Today</div>
                    <div class="kpi-value" style="color: var(--danger)">+{churn_stats['added']}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Removed</div>
                    <div class="kpi-value" style="color: var(--success)">-{churn_stats['removed']}</div>
                </div>
            </div>

            <div class="charts-grid">
                <div class="chart-card"><h2>Impersonation Targets</h2>{fig_targets.to_html(full_html=False, include_plotlyjs=False)}</div>
                <div class="chart-card"><h2>Threat Landscape (TLDs)</h2>{fig_tld.to_html(full_html=False, include_plotlyjs=False)}</div>
                <div class="chart-card"><h2>Network Churn History</h2>{fig_hist.to_html(full_html=False, include_plotlyjs=False)}</div>
                <div class="chart-card"><h2>Botnet Detection (Entropy)</h2>{fig_entropy.to_html(full_html=False, include_plotlyjs=False)}</div>
            </div>
            
            <div class="table-container">
                <h2>Top Phishing Targets</h2>
                <table>
                    <thead><tr><th>TARGET BRAND</th><th>DOMAINS DETECTED</th><th>STATUS</th></tr></thead>
                    <tbody>{"".join(f"<tr><td>{t}</td><td>{c}</td><td><span class='badge'>BLOCKED</span></td></tr>" for t, c in list(target_stats.items())[:8])}</tbody>
                </table>
            </div>
            <footer style="margin-top: 60px; text-align: center; color: #8E8E93; font-size: 13px;">Generated via GitHub Actions</footer>
        </div>
    </body>
    </html>
    """
    
    with open("stats.html", "w", encoding="utf-8") as f: f.write(html)

def main():
    prev_domains = load_previous_domains()
    domain_scores = Counter()
    
    # 0. Fetch Spam TLDs
    spam_tlds = fetch_spam_tlds()
    print(f"Loaded {len(spam_tlds)} Spam TLDs to purge.")

    # 1. Fetch & Score Domains
    for url, weight, tag in SOURCES:
        domains = fetch_domains(url)
        print(f"[{tag}] Found {len(domains)}")
        for d in domains:
            domain_scores[d] += weight

    # 2. Spam TLD Purge
    print("Purging domains from Spam TLDs...")
    all_keys = list(domain_scores.keys())
    removed_tld_count = 0
    for d in all_keys:
        if d.endswith(spam_tlds):
            del domain_scores[d]
            removed_tld_count += 1
    print(f"  -> Purged {removed_tld_count} domains from list (Optimization).")

    # 3. Dedupe (www vs root)
    print("Deduplicating...")
    all_keys = list(domain_scores.keys())
    existing = set(all_keys)
    for d in all_keys:
        if d.startswith("www.") and d[4:] in existing: del domain_scores[d]

    # 4. Sort & Cut
    ranked = sorted(domain_scores.items(), key=lambda x: (-x[1], x[0]))
    final_list = [d[0] for d in ranked[:DOMAIN_LIMIT]]
    final_set = set(final_list)

    # 5. Stats
    churn_stats = {"added": len(final_set - prev_domains), "removed": len(prev_domains - final_set)}
    target_counts = Counter()
    for d in final_list:
        for target in PHISHING_TARGETS:
            if target in d: target_counts[target] += 1
    target_counts = dict(sorted(target_counts.items(), key=lambda item: item[1], reverse=True))

    stats = {"date": datetime.date.today().isoformat(), "total_count": len(final_list)}
    history = save_history(stats)
    with open(HISTORY_FILE, "w") as f: json.dump(history, f)

    generate_dashboard(final_list, domain_scores, history, churn_stats, target_counts, removed_tld_count)

    with open("blocklist.txt", "w") as f:
        f.write(f"# Isaac's Blocklist\n")
        for domain in final_list: f.write(f"0.0.0.0 {domain}\n")
    with open("adblock.txt", "w") as f:
        f.write(f"! Isaac's Blocklist\n")
        for domain in final_list: f.write(f"||{domain}^\n")

if __name__ == "__main__":
    main()
