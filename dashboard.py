import json
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# --- CYBER COMMAND THEME ---
COLORS = {
    'bg': '#000000',
    'card': 'rgba(20, 20, 25, 0.85)',
    'border': 'rgba(0, 243, 255, 0.2)',
    'text': '#E0E0E0',
    'accent': '#00F3FF',   # Cyan
    'danger': '#FF003C',   # Red
    'success': '#00FF9D',  # Green
    'grid': 'rgba(0, 243, 255, 0.05)'
}

def generate_dashboard(df_main, history, churn_stats, removed_tld_count, source_overlap_matrix, top_bigrams, final_list, collateral_hits):
    print("Generating Command Center Dashboard...")

    # --- DATA PREP ---
    df_tld = df_main['tld'].value_counts().head(6).reset_index()
    df_tld.columns = ['TLD', 'Count']
    typos = df_main[df_main['typosquat'].notnull()]['typosquat'].value_counts().head(8).reset_index()
    typos.columns = ['Target', 'Count']
    df_bigrams = pd.DataFrame(top_bigrams, columns=['Phrase', 'Count']).head(8)
    
    # Radar Data
    avg_entropy = df_main['entropy'].mean()
    avg_len = df_main['length'].mean()
    typo_ratio = len(df_main[df_main['typosquat'].notnull()]) / len(df_main) * 1000 
    radar_vals = [min(avg_entropy / 4.5, 1), min(avg_len / 20, 1), min(typo_ratio / 5, 1), min(removed_tld_count / 500, 1)]
    radar_cats = ['Entropy', 'Length', 'Impersonation', 'Optimization']

    # --- PLOTLY CONFIG ---
    layout_style = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='JetBrains Mono, monospace', color=COLORS['text']),
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(showgrid=True, gridcolor=COLORS['grid'], zeroline=False),
        yaxis=dict(showgrid=True, gridcolor=COLORS['grid'], zeroline=False)
    )

    # 1. Globe
    df_geo = df_main[df_main['tld'].str.len() == 2]['tld'].value_counts().reset_index()
    df_geo.columns = ['iso_alpha', 'count']
    df_geo['iso_alpha'] = df_geo['iso_alpha'].str.upper()
    fig_globe = px.scatter_geo(df_geo, locations="iso_alpha", size="count", projection="orthographic", color="count", color_continuous_scale='Redor')
    fig_globe.update_layout(geo=dict(bgcolor='rgba(0,0,0,0)', showland=True, landcolor='#111', showocean=True, oceancolor='#000', showcountries=True, countrycolor='#333'), height=350, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor='rgba(0,0,0,0)', showlegend=False)

    # 2. Radar
    fig_radar = go.Figure(data=go.Scatterpolar(r=radar_vals, theta=radar_cats, fill='toself', line=dict(color=COLORS['danger'], width=2), fillcolor='rgba(255, 0, 60, 0.2)'))
    fig_radar.update_layout(polar=dict(bgcolor='rgba(0,0,0,0)', radialaxis=dict(visible=True, range=[0, 1], gridcolor=COLORS['grid']), angularaxis=dict(gridcolor=COLORS['grid'])), showlegend=False, height=300, **layout_style)

    # 3. Gauge
    risk_score = min(churn_stats['added'] / 500 * 100, 100)
    fig_gauge = go.Figure(go.Indicator(mode = "gauge+number", value = risk_score, title = {'text': "THREAT FLUX"},
        gauge = {'axis': {'range': [None, 100], 'tickcolor': COLORS['text']}, 'bar': {'color': COLORS['accent']}, 'bgcolor': "rgba(0,0,0,0)", 'borderwidth': 2, 'bordercolor': COLORS['border'],
            'steps': [{'range': [0, 33], 'color': 'rgba(0, 255, 157, 0.1)'}, {'range': [33, 66], 'color': 'rgba(252, 238, 9, 0.1)'}, {'range': [66, 100], 'color': 'rgba(255, 0, 60, 0.1)'}]}))
    fig_gauge.update_layout(height=250, **layout_style)

    # Charts
    fig_tld = px.pie(df_tld, values='Count', names='TLD', hole=0.7, color_discrete_sequence=px.colors.sequential.Plasma)
    fig_tld.update_layout(**layout_style, height=300, showlegend=False)
    fig_tld.update_traces(textposition='outside', textinfo='label+percent')

    fig_hist = px.area(pd.DataFrame(history), x='date', y='total_count', line_shape='spline', markers=True)
    fig_hist.update_layout(**layout_style, height=250)
    fig_hist.update_traces(line_color=COLORS['success'], fillcolor='rgba(0, 255, 157, 0.1)')

    sources = sorted(list(set([k[0] for k in source_overlap_matrix.keys()])))
    matrix_data = [[source_overlap_matrix.get((r, c), 0) for c in sources] for r in sources]
    fig_matrix = go.Figure(data=go.Heatmap(z=matrix_data, x=sources, y=sources, colorscale='Magma', showscale=False, text=matrix_data, texttemplate="%{text:.0%}"))
    fig_matrix.update_layout(**layout_style, height=350)

    # --- HTML GENERATION ---
    search_list = final_list[:25000]
    collateral_html = ""
    if collateral_hits:
        for domain, rank in collateral_hits:
            collateral_html += f'<div class="collateral-row"><span class="col-rank">#{rank}</span><span class="col-domain">{domain}</span><span class="col-warn">BLOCKED</span></div>'
    else:
        collateral_html = '<div style="color:var(--success); padding:10px;">No Top 5,000 Sites Detected. Network Safe.</div>'

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SOC // OVERWATCH</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{ --bg: {COLORS['bg']}; --card: {COLORS['card']}; --border: {COLORS['border']}; --text: {COLORS['text']}; --accent: {COLORS['accent']}; --danger: {COLORS['danger']}; --success: {COLORS['success']}; }}
            body {{ background-color: var(--bg); background-image: linear-gradient(rgba(0, 243, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 243, 255, 0.03) 1px, transparent 1px); background-size: 30px 30px; color: var(--text); font-family: 'Rajdhani', sans-serif; margin: 0; overflow-x: hidden; }}
            .hud-header {{ border-bottom: 2px solid var(--border); background: rgba(0,0,0,0.8); backdrop-filter: blur(10px); padding: 15px 40px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 1000; box-shadow: 0 5px 20px rgba(0, 243, 255, 0.1); }}
            .brand {{ font-family: 'JetBrains Mono'; font-weight: 800; font-size: 24px; letter-spacing: -1px; }}
            .brand span {{ color: var(--accent); }}
            .status {{ font-size: 14px; color: var(--success); font-weight: 600; display: flex; align-items: center; gap: 8px; }}
            .blink {{ width: 8px; height: 8px; background: var(--success); border-radius: 50%; animation: pulse 2s infinite; }}
            .grid-container {{ display: grid; grid-template-columns: 280px 1fr 350px; gap: 20px; padding: 20px; max-width: 1900px; margin: 0 auto; }}
            .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 20px; position: relative; backdrop-filter: blur(5px); transition: 0.3s; }}
            .card:hover {{ border-color: var(--accent); }}
            .card::before {{ content: ''; position: absolute; top: -1px; left: -1px; width: 10px; height: 10px; border-top: 2px solid var(--accent); border-left: 2px solid var(--accent); }}
            .card::after {{ content: ''; position: absolute; bottom: -1px; right: -1px; width: 10px; height: 10px; border-bottom: 2px solid var(--accent); border-right: 2px solid var(--accent); }}
            
            /* HEADERS & INFO */
            .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
            h3 {{ margin: 0; font-family: 'JetBrains Mono'; font-size: 14px; text-transform: uppercase; color: var(--accent); letter-spacing: 1px; }}
            .info-toggle {{ color: #555; cursor: pointer; font-size: 14px; padding: 2px 8px; border: 1px solid #333; border-radius: 4px; transition: 0.2s; }}
            .info-toggle:hover {{ color: var(--accent); border-color: var(--accent); background: rgba(0, 243, 255, 0.1); }}
            .info-panel {{ display: none; background: rgba(0,0,0,0.8); border-left: 3px solid var(--accent); padding: 15px; margin-bottom: 15px; font-size: 13px; color: #ccc; line-height: 1.5; }}
            
            .stat-box {{ margin-bottom: 25px; }}
            .stat-label {{ color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }}
            .stat-value {{ font-family: 'JetBrains Mono'; font-size: 32px; font-weight: 700; }}
            .pos {{ color: var(--danger); }} .neg {{ color: var(--success); }}
            
            /* TERMINAL */
            .terminal {{ background: #050505; border: 1px solid #333; padding: 15px; font-family: 'JetBrains Mono'; height: 100%; display: flex; flex-direction: column; }}
            .term-input {{ background: transparent; border: none; border-bottom: 1px solid #333; color: var(--accent); font-family: inherit; font-size: 16px; padding: 10px; width: 100%; outline: none; }}
            .term-output {{ flex-grow: 1; overflow-y: auto; margin-top: 10px; font-size: 13px; color: #aaa; scroll-behavior: smooth; }}
            .term-match {{ color: var(--danger); display: block; margin: 4px 0; }}
            .btn-group {{ display: flex; gap: 10px; }}
            .cyber-btn {{ background: rgba(0, 243, 255, 0.1); border: 1px solid var(--accent); color: var(--accent); padding: 8px 16px; text-decoration: none; font-family: 'JetBrains Mono'; font-size: 12px; font-weight: 700; text-transform: uppercase; transition: 0.3s; cursor: pointer; }}
            .cyber-btn:hover {{ background: var(--accent); color: #000; box-shadow: 0 0 15px var(--accent); }}
            
            /* TABS & COLLATERAL */
            .tabs {{ display: flex; gap: 2px; margin-bottom: 20px; }}
            .tab-btn {{ background: #111; border: 1px solid var(--border); color: #888; padding: 10px 20px; cursor: pointer; font-family: 'JetBrains Mono'; flex-grow: 1; transition: 0.3s; }}
            .tab-btn.active {{ background: var(--accent); color: #000; font-weight: bold; }}
            .section {{ display: none; }}
            .section.active {{ display: block; }}
            .collateral-box {{ background: rgba(255, 0, 60, 0.1); border: 1px solid var(--danger); padding: 10px; border-radius: 4px; margin-bottom: 20px; }}
            .collateral-row {{ display: flex; justify-content: space-between; font-family: 'JetBrains Mono'; font-size: 12px; padding: 5px 0; border-bottom: 1px solid rgba(255,0,0,0.2); }}
            .col-warn {{ color: var(--danger); font-weight: bold; }}

            /* BENCHMARK & NETWORK CHECK */
            .bench-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 20px; }}
            .bench-col {{ background: rgba(0,0,0,0.3); padding: 15px; border: 1px solid #333; }}
            .bench-title {{ font-family: 'JetBrains Mono'; font-size: 12px; color: #888; border-bottom: 1px solid #333; padding-bottom: 5px; margin-bottom: 10px; }}
            .bench-item {{ font-size: 11px; display: flex; justify-content: space-between; margin: 4px 0; font-family: 'JetBrains Mono'; }}
            .status-ok {{ color: var(--success); }} .status-bad {{ color: var(--danger); }}
            
            .net-identity {{ display: flex; gap: 20px; margin-top: 20px; }}
            .net-card {{ flex: 1; background: rgba(0, 243, 255, 0.05); border: 1px solid var(--accent); padding: 20px; text-align: center; }}
            .net-val {{ font-size: 20px; font-weight: 700; color: #fff; display: block; margin-top: 10px; font-family: 'JetBrains Mono'; }}
            .net-lbl {{ font-size: 11px; color: var(--accent); text-transform: uppercase; letter-spacing: 1px; }}

            @media (max-width: 1400px) {{ .grid-container {{ grid-template-columns: 1fr 1fr; }} }}
            @media (max-width: 900px) {{ .grid-container {{ grid-template-columns: 1fr; }} }}
        </style>
    </head>
    <body>

        <nav class="hud-header">
            <div class="brand">SOC <span>//</span> OVERWATCH</div>
            <div class="btn-group">
                <a href="blocklist.txt" class="cyber-btn">DOWNLOAD RAW</a>
                <a href="adblock.txt" class="cyber-btn">ADBLOCK FORMAT</a>
            </div>
            <div class="status"><div class="blink"></div> SYSTEM ONLINE</div>
        </nav>

        <div class="grid-container">
            
            <div style="display: flex; flex-direction: column; gap: 20px;">
                <div class="card">
                    <div class="card-header"><h3>Global Threat Map</h3><span class="info-toggle" onclick="toggleInfo('info-globe')">?</span></div>
                    <div id="info-globe" class="info-panel">Real-time origin analysis of blocked domains based on Country Code TLDs. Visualizes the geopolitical source of threats.</div>
                    {fig_globe.to_html(full_html=False, include_plotlyjs=False)}
                </div>
                <div class="card">
                    <div class="card-header"><h3>Collateral Damage</h3><span class="info-toggle" onclick="toggleInfo('info-col')">?</span></div>
                    <div id="info-col" class="info-panel">Cross-references your blocklist against the Tranco Top 5,000 popular sites. If a domain appears here, you are breaking a major website.</div>
                    <div class="collateral-box">{collateral_html}</div>
                </div>
                <div class="card">
                    <div class="card-header"><h3>Threat Level</h3><span class="info-toggle" onclick="toggleInfo('info-gauge')">?</span></div>
                    <div id="info-gauge" class="info-panel">Volatility score based on list churn (added/removed domains). High flux indicates active botnet campaigns.</div>
                    {fig_gauge.to_html(full_html=False, include_plotlyjs=False)}
                </div>
            </div>

            <div style="display: flex; flex-direction: column;">
                <div class="tabs">
                    <button class="tab-btn active" onclick="openTab('intel')">INTEL</button>
                    <button class="tab-btn" onclick="openTab('benchmark')">BENCHMARK</button>
                    <button class="tab-btn" onclick="openTab('syscheck')">DIAGNOSTICS</button>
                </div>

                <div id="intel" class="section active" style="display: flex; flex-direction: column; gap: 20px;">
                    <div class="card">
                        <div class="card-header"><h3>Network Growth</h3><span class="info-toggle" onclick="toggleInfo('info-hist')">?</span></div>
                        <div id="info-hist" class="info-panel">Historical size of your blocklist. Sudden drops indicate cleanup of dead domains; spikes indicate new threat feeds.</div>
                        {fig_hist.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                    <div class="card">
                        <div class="card-header"><h3>Source Matrix</h3><span class="info-toggle" onclick="toggleInfo('info-matrix')">?</span></div>
                        <div id="info-matrix" class="info-panel">Redundancy Heatmap. Shows how much your blocklists overlap. If two lists are 95% similar, you might only need one.</div>
                        {fig_matrix.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                    <div class="card">
                        <div class="card-header"><h3>Threat Fingerprint</h3><span class="info-toggle" onclick="toggleInfo('info-radar')">?</span></div>
                        <div id="info-radar" class="info-panel">Multi-vector analysis of the list's composition.<br><b>Entropy:</b> Randomness (Botnets).<br><b>Length:</b> Phishing attempts often use long URLs.<br><b>Optimization:</b> Efficiency of TLD blocks.</div>
                        {fig_radar.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                </div>

                <div id="benchmark" class="section">
                    <div class="card">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
                            <h3>ADBLOCK STRESS TEST</h3>
                            <button class="cyber-btn" id="runBench" onclick="runBenchmark()">INITIATE SEQUENCE</button>
                        </div>
                        <div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 4px; margin-bottom: 15px; font-size: 13px; border-left: 2px solid var(--accent);">
                            Attempts connection to known trackers. <span style="color:var(--success)">Green = Blocked</span>. <span style="color:var(--danger)">Red = Vulnerable</span>.
                        </div>
                        <div class="bench-grid" id="benchResults">
                            <div class="bench-col"><div class="bench-title">ADVERTISING</div><div id="col-ads">Waiting...</div></div>
                            <div class="bench-col"><div class="bench-title">ANALYTICS</div><div id="col-ana">Waiting...</div></div>
                            <div class="bench-col"><div class="bench-title">TRACKERS</div><div id="col-trk">Waiting...</div></div>
                        </div>
                    </div>
                </div>

                <div id="syscheck" class="section">
                    <div class="card">
                        <div class="card-header">
                            <h3>NETWORK IDENTITY</h3>
                            <span class="info-toggle" onclick="toggleInfo('info-net')">?</span>
                        </div>
                        <div id="info-net" class="info-panel">Checks your public IP. If this matches your ISP (Comcast/Verizon) instead of Control D, you are unprotected.</div>
                        <div class="net-identity">
                            <div class="net-card"><span class="net-lbl">VISIBLE IP ADDRESS</span><span class="net-val" id="net-ip">SCANNING...</span></div>
                            <div class="net-card"><span class="net-lbl">DETECTED ISP / ORG</span><span class="net-val" id="net-isp">SCANNING...</span></div>
                        </div>
                    </div>

                    <div class="card" style="margin-top:20px;">
                        <div class="card-header">
                            <h3>UPLINKS LATENCY (SPEED)</h3>
                            <button class="cyber-btn" onclick="runLatency()">PING</button>
                        </div>
                        <div class="net-identity">
                            <div class="net-card"><span class="net-lbl">CLOUDFLARE (1.1.1.1)</span><span class="net-val" id="ping-cf">-- ms</span></div>
                            <div class="net-card"><span class="net-lbl">GOOGLE (8.8.8.8)</span><span class="net-val" id="ping-goo">-- ms</span></div>
                        </div>
                    </div>

                    <div class="card" style="margin-top:20px;">
                        <h3>EXTERNAL DIAGNOSTICS</h3>
                        <div class="diag-row">
                            <a href="https://dnsleaktest.com" target="_blank" class="diag-card"><span class="diag-title">DNS LEAK TEST ↗</span><span class="diag-desc">Verify DNS path.</span></a>
                            <a href="https://rebind.network" target="_blank" class="diag-card"><span class="diag-title">REBINDING CHECK ↗</span><span class="diag-desc">Test router vulnerability.</span></a>
                        </div>
                    </div>
                </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 20px;">
                <div class="card" style="flex-grow: 1; min-height: 400px; padding: 0; overflow: hidden;">
                    <div class="terminal">
                        <div style="margin-bottom: 10px; color: var(--accent);">>_ DOMAIN_SEARCH.EXE</div>
                        <input type="text" id="termInput" class="term-input" placeholder="Enter query..." onkeyup="runSearch()" autofocus>
                        <div id="termOutput" class="term-output">
                            <div style="color: #666;">// Database loaded.</div>
                            <div style="color: #666;">// {len(final_list)} records indexed.</div>
                            <div style="color: #666;">// Awaiting input...</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h3>High Value Targets</h3>
                    <table style="width: 100%; font-size: 13px; color: #aaa;">
                         { "".join([f"<tr><td style='padding:4px 0;'>{t}</td><td style='text-align:right; color:var(--danger)'>{c}</td></tr>" for t, c in list(zip(typos['Target'], typos['Count']))]) }
                    </table>
                </div>
            </div>

        </div>

        <script>
            // --- INFO TOGGLE ---
            function toggleInfo(id) {{
                const el = document.getElementById(id);
                el.style.display = (el.style.display === 'block') ? 'none' : 'block';
            }}

            // --- SEARCH LOGIC ---
            const db = {json.dumps(search_list)};
            function runSearch() {{
                const q = document.getElementById('termInput').value.toLowerCase();
                const out = document.getElementById('termOutput');
                if (q.length < 3) {{ out.innerHTML = '<div style="color: #666;">// Awaiting input...</div>'; return; }}
                let matches = [];
                for (let i = 0; i < db.length; i++) {{ if (db[i].includes(q)) {{ matches.push(db[i]); if (matches.length > 15) break; }} }}
                if (matches.length > 0) {{ out.innerHTML = matches.map(m => `<span class="term-match">>> BLOCKED: ${{m}}</span>`).join(''); }} 
                else {{ out.innerHTML = '<span style="color: #666;">>> NO MATCH FOUND IN RISK TIER</span>'; }}
            }}

            // --- TAB LOGIC ---
            function openTab(id) {{
                document.querySelectorAll('.section').forEach(el => el.style.display = 'none');
                document.getElementById(id).style.display = 'block';
                document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
                event.target.classList.add('active');
                
                if(id === 'syscheck') {{ checkIdentity(); }}
            }}
            document.getElementById('benchmark').style.display = 'none';
            document.getElementById('syscheck').style.display = 'none';

            // --- BENCHMARK LOGIC ---
            const benchTargets = {{
                "Ads": ["doubleclick.net", "adservice.google.com", "pagead2.googlesyndication.com", "adnxs.com", "ads.yahoo.com"],
                "Analytics": ["google-analytics.com", "hotjar.com", "crazyegg.com", "segment.io", "mixpanel.com"],
                "Trackers": ["pixel.facebook.com", "analytics.twitter.com", "metric.gstatic.com", "newrelic.com", "branch.io"]
            }};
            
            async function runBenchmark() {{
                const btn = document.getElementById('runBench');
                btn.disabled = true; btn.innerText = "TESTING...";
                ['col-ads', 'col-ana', 'col-trk'].forEach(id => document.getElementById(id).innerHTML = '');

                const checkDomain = (domain, colId) => {{
                    return new Promise(resolve => {{
                        const img = new Image();
                        const row = document.createElement('div');
                        row.className = 'bench-item';
                        img.src = 'https://' + domain + '/favicon.ico?t=' + Date.now();
                        const timeout = setTimeout(() => {{ row.innerHTML = `<span>${{domain}}</span> <span class="status-bad">TIMEOUT</span>`; document.getElementById(colId).appendChild(row); resolve(); }}, 2000);
                        img.onerror = () => {{ clearTimeout(timeout); row.innerHTML = `<span>${{domain}}</span> <span class="status-ok">BLOCKED</span>`; document.getElementById(colId).appendChild(row); resolve(); }};
                        img.onload = () => {{ clearTimeout(timeout); row.innerHTML = `<span>${{domain}}</span> <span class="status-bad">ALLOWED</span>`; document.getElementById(colId).appendChild(row); resolve(); }};
                    }});
                }};

                for (const d of benchTargets.Ads) await checkDomain(d, 'col-ads');
                for (const d of benchTargets.Analytics) await checkDomain(d, 'col-ana');
                for (const d of benchTargets.Trackers) await checkDomain(d, 'col-trk');
                btn.disabled = false; btn.innerText = "RE-TEST";
            }}

            // --- NETWORK CHECKS ---
            async function checkIdentity() {{
                try {{
                    const req = await fetch('https://ipapi.co/json/');
                    const data = await req.json();
                    document.getElementById('net-ip').innerText = data.ip || 'UNKNOWN';
                    document.getElementById('net-isp').innerText = (data.org || data.asn).toUpperCase();
                }} catch(e) {{
                    document.getElementById('net-isp').innerText = "BLOCK DETECTED";
                }}
            }}

            async function runLatency() {{
                const ping = async (url) => {{
                    const start = Date.now();
                    try {{ await fetch(url, {{ mode: 'no-cors' }}); }} catch(e) {{}}
                    return Date.now() - start;
                }};
                
                document.getElementById('ping-cf').innerText = "PINGING...";
                document.getElementById('ping-goo').innerText = "PINGING...";
                
                const cf = await ping('https://1.1.1.1/cdn-cgi/trace?t=' + Date.now());
                document.getElementById('ping-cf').innerText = cf + " ms";
                
                const goo = await ping('https://www.google.com/generate_204?t=' + Date.now());
                document.getElementById('ping-goo').innerText = goo + " ms";
            }}
        </script>
    </body>
    </html>
    """
    
    with open("stats.html", "w", encoding="utf-8") as f:
        f.write(html)
