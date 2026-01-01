import json
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# --- CYBER COMMAND THEME ---
COLORS = {
    'bg': '#000000',
    'card': 'rgba(20, 20, 25, 0.7)',
    'border': 'rgba(0, 243, 255, 0.2)',
    'text': '#E0E0E0',
    'accent': '#00F3FF',   # Cyan
    'danger': '#FF003C',   # Red
    'success': '#00FF9D',  # Green
    'warning': '#FCEE09',  # Yellow
    'grid': 'rgba(0, 243, 255, 0.05)'
}

def generate_dashboard(df_main, history, churn_stats, removed_tld_count, source_overlap_matrix, top_bigrams, final_list):
    print("Generating Command Center Dashboard...")

    # --- DATA PREP ---
    df_tld = df_main['tld'].value_counts().head(6).reset_index()
    df_tld.columns = ['TLD', 'Count']
    typos = df_main[df_main['typosquat'].notnull()]['typosquat'].value_counts().head(8).reset_index()
    typos.columns = ['Target', 'Count']
    df_bigrams = pd.DataFrame(top_bigrams, columns=['Phrase', 'Count']).head(8)
    df_sample = df_main.sample(min(2000, len(df_main)))

    # Threat Radar
    avg_entropy = df_main['entropy'].mean()
    avg_len = df_main['length'].mean()
    avg_depth = df_main['depth'].mean()
    typo_ratio = len(df_main[df_main['typosquat'].notnull()]) / len(df_main) * 1000 
    
    radar_vals = [min(avg_entropy / 4.5, 1), min(avg_len / 20, 1), min(avg_depth / 3, 1), min(typo_ratio / 5, 1), min(removed_tld_count / 500, 1)]
    radar_cats = ['Entropy', 'Length', 'Depth', 'Impersonation', 'Optimization']

    # --- PLOTLY CONFIG ---
    layout_style = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='JetBrains Mono, monospace', color=COLORS['text']),
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(showgrid=True, gridcolor=COLORS['grid'], zeroline=False),
        yaxis=dict(showgrid=True, gridcolor=COLORS['grid'], zeroline=False)
    )

    # 1. Radar
    fig_radar = go.Figure(data=go.Scatterpolar(r=radar_vals, theta=radar_cats, fill='toself', line=dict(color=COLORS['danger'], width=2), fillcolor='rgba(255, 0, 60, 0.2)'))
    fig_radar.update_layout(polar=dict(bgcolor='rgba(0,0,0,0)', radialaxis=dict(visible=True, range=[0, 1], gridcolor=COLORS['grid']), angularaxis=dict(gridcolor=COLORS['grid'])), showlegend=False, height=350, **layout_style)

    # 2. Gauge
    risk_score = min(churn_stats['added'] / 500 * 100, 100)
    fig_gauge = go.Figure(go.Indicator(mode = "gauge+number", value = risk_score, title = {'text': "THREAT FLUX"},
        gauge = {'axis': {'range': [None, 100], 'tickcolor': COLORS['text']}, 'bar': {'color': COLORS['accent']}, 'bgcolor': "rgba(0,0,0,0)", 'borderwidth': 2, 'bordercolor': COLORS['border'],
            'steps': [{'range': [0, 33], 'color': 'rgba(0, 255, 157, 0.1)'}, {'range': [33, 66], 'color': 'rgba(252, 238, 9, 0.1)'}, {'range': [66, 100], 'color': 'rgba(255, 0, 60, 0.1)'}]}))
    fig_gauge.update_layout(height=250, **layout_style)

    # 3. Charts
    fig_tld = px.pie(df_tld, values='Count', names='TLD', hole=0.7, color_discrete_sequence=px.colors.sequential.Plasma)
    fig_tld.update_layout(**layout_style, height=300, showlegend=False)
    fig_tld.update_traces(textposition='outside', textinfo='label+percent')

    fig_words = px.bar(df_bigrams, x='Count', y='Phrase', orientation='h', color='Count', color_continuous_scale='Viridis')
    fig_words.update_layout(**layout_style, height=300, coloraxis_showscale=False)
    fig_words.update_yaxes(autorange="reversed")

    fig_hist = px.area(pd.DataFrame(history), x='date', y='total_count', line_shape='spline', markers=True)
    fig_hist.update_layout(**layout_style, height=250)
    fig_hist.update_traces(line_color=COLORS['success'], fillcolor='rgba(0, 255, 157, 0.1)')

    sources = sorted(list(set([k[0] for k in source_overlap_matrix.keys()])))
    matrix_data = [[source_overlap_matrix.get((r, c), 0) for c in sources] for r in sources]
    fig_matrix = go.Figure(data=go.Heatmap(z=matrix_data, x=sources, y=sources, colorscale='Magma', showscale=False, text=matrix_data, texttemplate="%{text:.0%}"))
    fig_matrix.update_layout(**layout_style, height=350)

    # --- HTML GENERATION ---
    search_list = final_list[:25000] # Top 25k for search
    test_list = final_list[:50]      # Top 50 for Live Fire Test

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
            .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: 20px; position: relative; backdrop-filter: blur(5px); }}
            .card::before {{ content: ''; position: absolute; top: -1px; left: -1px; width: 10px; height: 10px; border-top: 2px solid var(--accent); border-left: 2px solid var(--accent); }}
            .card::after {{ content: ''; position: absolute; bottom: -1px; right: -1px; width: 10px; height: 10px; border-bottom: 2px solid var(--accent); border-right: 2px solid var(--accent); }}
            h3 {{ margin: 0 0 15px 0; font-family: 'JetBrains Mono'; font-size: 14px; text-transform: uppercase; color: var(--accent); letter-spacing: 1px; }}
            .stat-box {{ margin-bottom: 25px; }}
            .stat-label {{ color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }}
            .stat-value {{ font-family: 'JetBrains Mono'; font-size: 32px; font-weight: 700; }}
            .stat-sub {{ font-size: 14px; margin-left: 10px; }}
            .pos {{ color: var(--danger); }} .neg {{ color: var(--success); }}
            .terminal {{ background: #050505; border: 1px solid #333; padding: 15px; font-family: 'JetBrains Mono'; height: 100%; display: flex; flex-direction: column; }}
            .term-input {{ background: transparent; border: none; border-bottom: 1px solid #333; color: var(--accent); font-family: inherit; font-size: 16px; padding: 10px; width: 100%; outline: none; }}
            .term-output {{ flex-grow: 1; overflow-y: auto; margin-top: 10px; font-size: 13px; color: #aaa; }}
            .term-match {{ color: var(--danger); display: block; margin: 4px 0; }}
            .btn-group {{ display: flex; gap: 10px; }}
            .cyber-btn {{ background: rgba(0, 243, 255, 0.1); border: 1px solid var(--accent); color: var(--accent); padding: 8px 16px; text-decoration: none; font-family: 'JetBrains Mono'; font-size: 12px; font-weight: 700; text-transform: uppercase; transition: 0.3s; cursor: pointer; }}
            .cyber-btn:hover {{ background: var(--accent); color: #000; box-shadow: 0 0 15px var(--accent); }}
            
            /* TABS */
            .tabs {{ display: flex; gap: 2px; margin-bottom: 20px; }}
            .tab-btn {{ background: #111; border: 1px solid var(--border); color: #888; padding: 10px 20px; cursor: pointer; font-family: 'JetBrains Mono'; flex-grow: 1; transition: 0.3s; }}
            .tab-btn.active {{ background: var(--accent); color: #000; font-weight: bold; }}
            .section {{ display: none; }}
            .section.active {{ display: block; }}

            /* LIVE FIRE TEST GRID */
            .test-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; margin-top: 20px; }}
            .test-item {{ background: rgba(0,0,0,0.5); border: 1px solid #333; padding: 10px; font-size: 11px; font-family: 'JetBrains Mono'; display: flex; justify-content: space-between; align-items: center; }}
            .status-dot {{ width: 8px; height: 8px; border-radius: 50%; background: #555; }}
            .blocked .status-dot {{ background: var(--success); box-shadow: 0 0 5px var(--success); }}
            .leaking .status-dot {{ background: var(--danger); box-shadow: 0 0 5px var(--danger); }}
            
            /* DIAGNOSTICS LINKS */
            .diag-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }}
            .diag-card {{ border: 1px solid #333; padding: 20px; text-decoration: none; color: #fff; transition: 0.3s; display: block; background: rgba(255,255,255,0.02); }}
            .diag-card:hover {{ border-color: var(--accent); background: rgba(0, 243, 255, 0.05); }}
            .diag-title {{ font-family: 'JetBrains Mono'; color: var(--accent); font-size: 16px; margin-bottom: 5px; display: block; }}
            .diag-desc {{ font-size: 13px; color: #888; }}

            @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} 100% {{ opacity: 1; }} }}
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
                    <h3>Threat Level</h3>
                    {fig_gauge.to_html(full_html=False, include_plotlyjs=False)}
                </div>
                <div class="card">
                    <div class="stat-box">
                        <div class="stat-label">Active Threats</div>
                        <div class="stat-value">{len(final_list):,}</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">New Intecepts</div>
                        <div class="stat-value pos">+{churn_stats['added']}</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">Optimization</div>
                        <div class="stat-value neg">-{removed_tld_count}</div>
                    </div>
                </div>
                <div class="card">
                    <h3>Threat Fingerprint</h3>
                    {fig_radar.to_html(full_html=False, include_plotlyjs=False)}
                </div>
            </div>

            <div style="display: flex; flex-direction: column;">
                <div class="tabs">
                    <button class="tab-btn active" onclick="openTab('intel')">INTEL</button>
                    <button class="tab-btn" onclick="openTab('syscheck')">SYSTEMS CHECK</button>
                </div>

                <div id="intel" class="section active" style="display: flex; flex-direction: column; gap: 20px;">
                    <div class="card">
                        <h3>Network Growth History</h3>
                        {fig_hist.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                    <div class="card">
                        <h3>Source Correlation Matrix</h3>
                        {fig_matrix.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div class="card">
                            <h3>TLD Distribution</h3>
                            {fig_tld.to_html(full_html=False, include_plotlyjs=False)}
                        </div>
                        <div class="card">
                            <h3>Attack Phrases</h3>
                            {fig_words.to_html(full_html=False, include_plotlyjs=False)}
                        </div>
                    </div>
                </div>

                <div id="syscheck" class="section">
                    <div class="card">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <h3>LIVE BLOCK TEST (TOP 50 RISK DOMAINS)</h3>
                            <button class="cyber-btn" onclick="runFireTest()">INITIATE TEST</button>
                        </div>
                        <div id="test-results" class="test-grid">
                            <div style="grid-column: 1/-1; color: #666; padding: 20px; text-align: center;">Waiting for initialization...</div>
                        </div>
                    </div>

                    <div class="diag-row">
                        <a href="https://dnsleaktest.com" target="_blank" class="diag-card">
                            <span class="diag-title">DNS LEAK TEST ↗</span>
                            <span class="diag-desc">Verify your queries aren't bypassing the blocklist.</span>
                        </a>
                        <a href="https://rebind.network" target="_blank" class="diag-card">
                            <span class="diag-title">REBINDING CHECK ↗</span>
                            <span class="diag-desc">Test router vulnerability to DNS rebinding attacks.</span>
                        </a>
                        <a href="https://d3ward.github.io/toolz/adblock.html" target="_blank" class="diag-card">
                            <span class="diag-title">ADBLOCK BENCHMARK ↗</span>
                            <span class="diag-desc">Comprehensive 3rd party adblock stress test.</span>
                        </a>
                        <a href="https://dnscheck.tools" target="_blank" class="diag-card">
                            <span class="diag-title">DNSSEC & SPEED ↗</span>
                            <span class="diag-desc">Detailed resolver diagnostics and record validation.</span>
                        </a>
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
            // SEARCH LOGIC
            const db = {json.dumps(search_list)};
            function runSearch() {{
                const q = document.getElementById('termInput').value.toLowerCase();
                const out = document.getElementById('termOutput');
                if (q.length < 3) {{ out.innerHTML = '<div style="color: #666;">// Awaiting input...</div>'; return; }}
                let matches = [];
                for (let i = 0; i < db.length; i++) {{
                    if (db[i].includes(q)) {{ matches.push(db[i]); if (matches.length > 15) break; }}
                }}
                if (matches.length > 0) {{
                    out.innerHTML = matches.map(m => `<span class="term-match">>> BLOCKED: ${{m}}</span>`).join('');
                }} else {{
                    out.innerHTML = '<span style="color: #666;">>> NO MATCH FOUND IN RISK TIER</span>';
                }}
            }}

            // TABS LOGIC
            function openTab(id) {{
                document.querySelectorAll('.section').forEach(el => el.style.display = 'none');
                document.getElementById(id).style.display = 'flex';
                if(id === 'syscheck') document.getElementById(id).style.display = 'block'; // Block for this specific tab layout
                document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
                event.target.classList.add('active');
            }}
            document.getElementById('syscheck').style.display = 'none'; // Init state

            // LIVE FIRE TEST LOGIC
            const testDomains = {json.dumps(test_list)};
            async function runFireTest() {{
                const container = document.getElementById('test-results');
                container.innerHTML = '';
                
                testDomains.forEach(domain => {{
                    const el = document.createElement('div');
                    el.className = 'test-item';
                    el.innerHTML = `<span>${{domain}}</span><span class="status-dot"></span>`;
                    container.appendChild(el);
                    
                    // The test: Try to fetch. 
                    // If it FAILS (Network Error), it means the blocklist works (Success).
                    // If it SUCCEEDS (or returns 404/200), the domain is reachable (Failure).
                    const img = new Image();
                    img.onerror = () => {{ el.classList.add('blocked'); }}; // Blocked = Good
                    img.onload = () => {{ el.classList.add('leaking'); }};  // Loaded = Bad
                    img.src = 'https://' + domain + '/favicon.ico?t=' + new Date().getTime();
                }});
            }}
        </script>
    </body>
    </html>
    """
    
    with open("stats.html", "w", encoding="utf-8") as f:
        f.write(html)
