#!/usr/bin/env python3
"""
Nessus HTML Report Generator
------------------------------
Generates two professional HTML reports from a .nessus XML file:
  1. By Host   — each host with its vulnerabilities grouped by severity
  2. By Plugin — each vulnerability with the affected hosts/ports

Usage:
  python3 nessus_html_report.py nessus_GETS_PRD_168_vulnerabilities.nessus
  python3 nessus_html_report.py <file.nessus> --outdir ~/reports --label GETS_PRD_168
"""

import argparse, os, re, sys, xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SEV_MAP   = {"0":"Info","1":"Low","2":"Medium","3":"High","4":"Critical"}
SEV_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
SEV_HEX   = {"Critical":"#c0392b","High":"#e67e22","Medium":"#f1c40f",
             "Low":"#27ae60","Info":"#2980b9"}
SEV_BG    = {"Critical":"#fdecea","High":"#fef3e6","Medium":"#fefce6",
             "Low":"#eafaf1","Info":"#eaf4fb"}

def esc(s): return str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def sev_badge(sev):
    c = SEV_HEX.get(sev,"#95a5a6")
    return f'<span class="badge" style="background:{c}">{esc(sev)}</span>'

# ── Parser ─────────────────────────────────────────────────────────────────────
def parse_nessus(path):
    tree = ET.parse(path)
    root = tree.getroot()
    hosts = []
    for rh in root.iter("ReportHost"):
        props = {t.get("name"):t.text for t in rh.findall("HostProperties/tag")}
        items = []
        for item in rh.findall("ReportItem"):
            sev = SEV_MAP.get(item.get("severity","0"),"Info")
            cve = [c.text for c in item.findall("cve") if c.text]
            items.append({
                "plugin_id":    item.get("pluginID",""),
                "plugin_name":  item.get("pluginName",""),
                "family":       item.get("pluginFamily",""),
                "severity":     sev,
                "severity_num": int(item.get("severity","0")),
                "port":         item.get("port","0"),
                "protocol":     item.get("protocol",""),
                "svc_name":     item.get("svc_name",""),
                "cvss":         (item.findtext("cvss_base_score") or
                                 item.findtext("cvss3_base_score") or ""),
                "cve":          cve,
                "synopsis":     (item.findtext("synopsis") or "").strip(),
                "description":  (item.findtext("description") or "").strip(),
                "solution":     (item.findtext("solution") or "").strip(),
                "plugin_output":(item.findtext("plugin_output") or "").strip(),
                "see_also":     (item.findtext("see_also") or "").strip(),
                "patch_date":   (item.findtext("patch_publication_date") or ""),
            })
        items.sort(key=lambda x: (SEV_ORDER.get(x["severity"],9), x["plugin_name"]))
        hosts.append({"name": rh.get("name",""), "props": props, "items": items})
    return hosts

# ── Shared CSS ─────────────────────────────────────────────────────────────────
CSS = """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         font-size: 13px; color: #2c3e50; background: #f5f6fa; }
  a { color: #2980b9; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Header */
  .page-header { background: linear-gradient(135deg,#1a2a4a,#2c3e50);
    color:#fff; padding:24px 32px; }
  .page-header h1 { font-size:22px; font-weight:600; margin-bottom:4px; }
  .page-header p  { font-size:12px; opacity:.75; }

  /* Nav */
  .top-nav { background:#2c3e50; padding:0 32px; display:flex; gap:4px; }
  .top-nav a { color:#bdc3cb; padding:10px 16px; font-size:12px; display:block;
               border-bottom:3px solid transparent; }
  .top-nav a:hover, .top-nav a.active { color:#fff;
               border-bottom-color:#3498db; text-decoration:none; }

  /* Layout */
  .container { max-width:1400px; margin:24px auto; padding:0 24px; }

  /* Summary cards */
  .summary-grid { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }
  .summary-card { flex:1; min-width:120px; background:#fff; border-radius:8px;
    padding:16px 20px; box-shadow:0 1px 4px rgba(0,0,0,.08);
    border-top:4px solid var(--c); text-align:center; }
  .summary-card .num  { font-size:32px; font-weight:700; color:var(--c); }
  .summary-card .lbl  { font-size:11px; color:#7f8c8d; margin-top:2px; text-transform:uppercase; }

  /* Badges */
  .badge { display:inline-block; padding:2px 9px; border-radius:12px;
           color:#fff; font-size:11px; font-weight:600; }

  /* Host / Plugin card */
  .card { background:#fff; border-radius:8px; margin-bottom:16px;
          box-shadow:0 1px 4px rgba(0,0,0,.08); overflow:hidden; }
  .card-header { padding:14px 20px; cursor:pointer;
                 display:flex; align-items:center; justify-content:space-between;
                 border-left:5px solid #3498db; }
  .card-header:hover { background:#f8f9fa; }
  .card-header h2 { font-size:14px; font-weight:600; }
  .card-header .meta { font-size:11px; color:#7f8c8d; margin-top:3px; }
  .card-body { padding:16px 20px; display:none; border-top:1px solid #eee; }
  .card-body.open { display:block; }

  /* Vuln table */
  .vuln-table { width:100%; border-collapse:collapse; font-size:12px; }
  .vuln-table th { background:#f4f6f8; padding:8px 10px; text-align:left;
                   border-bottom:2px solid #dee2e6; white-space:nowrap; }
  .vuln-table td { padding:7px 10px; border-bottom:1px solid #f0f0f0;
                   vertical-align:top; }
  .vuln-table tr:hover td { background:#fafbfc; }
  .vuln-table tr.sev-Critical td { border-left:3px solid #c0392b; }
  .vuln-table tr.sev-High     td { border-left:3px solid #e67e22; }
  .vuln-table tr.sev-Medium   td { border-left:3px solid #f1c40f; }
  .vuln-table tr.sev-Low      td { border-left:3px solid #27ae60; }
  .vuln-table tr.sev-Info     td { border-left:3px solid #2980b9; }

  /* Detail panel */
  .detail-toggle { font-size:11px; color:#3498db; cursor:pointer;
                   white-space:nowrap; }
  .detail-panel { display:none; background:#f8f9fa; border-radius:6px;
                  padding:12px 14px; margin-top:8px; font-size:12px;
                  line-height:1.6; }
  .detail-panel.open { display:block; }
  .detail-panel h4 { color:#2c3e50; margin:8px 0 4px; font-size:12px; }
  .detail-panel p  { color:#444; white-space:pre-wrap; word-break:break-word; }
  .cve-tag { display:inline-block; background:#eaf4fb; color:#2980b9;
             border:1px solid #bee3f8; border-radius:4px; padding:1px 6px;
             font-size:11px; margin:1px; }

  /* TOC sidebar */
  .layout { display:flex; gap:20px; }
  .toc    { width:240px; flex-shrink:0; }
  .toc-sticky { position:sticky; top:16px; background:#fff; border-radius:8px;
                box-shadow:0 1px 4px rgba(0,0,0,.08); padding:16px;
                max-height:90vh; overflow-y:auto; }
  .toc-sticky h3 { font-size:12px; text-transform:uppercase; color:#7f8c8d;
                   letter-spacing:.5px; margin-bottom:10px; }
  .toc-sticky a  { display:block; padding:4px 6px; font-size:12px;
                   color:#2c3e50; border-radius:4px; }
  .toc-sticky a:hover { background:#f0f4f8; text-decoration:none; }
  .main-content { flex:1; min-width:0; }

  /* Severity section headers */
  .sev-section h3 { font-size:13px; font-weight:700; padding:6px 12px;
                    border-radius:6px; margin:12px 0 8px;
                    display:inline-flex; align-items:center; gap:8px; }

  /* Print */
  @media print {
    .top-nav, .toc, .detail-toggle { display:none !important; }
    .card-body { display:block !important; }
    body { background:#fff; }
  }
"""

JS = """
  function toggle(id) {
    var el = document.getElementById(id);
    el.classList.toggle('open');
  }
  function expandAll() {
    document.querySelectorAll('.card-body,.detail-panel').forEach(function(e){
      e.classList.add('open');
    });
  }
  function collapseAll() {
    document.querySelectorAll('.card-body,.detail-panel').forEach(function(e){
      e.classList.remove('open');
    });
  }
"""

# ── Report helpers ─────────────────────────────────────────────────────────────
def severity_counts(items):
    from collections import Counter
    return Counter(i["severity"] for i in items)

def summary_cards(counts, total_label="Vulnerabilities"):
    cards = ""
    colors = {"Critical":"#c0392b","High":"#e67e22","Medium":"#f1c40f",
              "Low":"#27ae60","Info":"#2980b9","Total":"#8e44ad"}
    total = sum(counts.values())
    for sev in ["Critical","High","Medium","Low","Info"]:
        c = colors[sev]
        n = counts.get(sev,0)
        cards += f'<div class="summary-card" style="--c:{c}">'
        cards += f'<div class="num">{n}</div><div class="lbl">{sev}</div></div>'
    cards += f'<div class="summary-card" style="--c:#8e44ad">'
    cards += f'<div class="num">{total}</div><div class="lbl">Total</div></div>'
    return f'<div class="summary-grid">{cards}</div>'

def detail_panel(item, panel_id):
    desc   = esc(item["description"][:2000] + ("…" if len(item["description"])>2000 else ""))
    sol    = esc(item["solution"])
    out    = esc(item["plugin_output"][:3000] + ("…" if len(item["plugin_output"])>3000 else ""))
    cves   = "".join(f'<a class="cve-tag" href="https://www.cve.org/CVERecord?id={esc(c)}" target="_blank">{esc(c)}</a>'
                     for c in item["cve"])
    see    = esc(item["see_also"])
    cvss   = esc(item["cvss"])
    patch  = esc(item["patch_date"])

    html  = f'<div class="detail-panel" id="{panel_id}">'
    if cves:   html += f'<h4>CVE</h4><p>{cves}</p>'
    if cvss:   html += f'<h4>CVSS Score</h4><p>{cvss}</p>'
    if patch:  html += f'<h4>Patch Date</h4><p>{patch}</p>'
    if item["synopsis"]:
               html += f'<h4>Synopsis</h4><p>{esc(item["synopsis"])}</p>'
    if desc:   html += f'<h4>Description</h4><p>{desc}</p>'
    if sol:    html += f'<h4>Solution</h4><p>{sol}</p>'
    if out:    html += f'<h4>Plugin Output</h4><p style="font-family:monospace;font-size:11px">{out}</p>'
    if see:    html += f'<h4>See Also</h4><p>{see}</p>'
    html += '</div>'
    return html

# ── Report 1: By Host ──────────────────────────────────────────────────────────
def build_by_host(hosts, label, nessus_file):
    from collections import Counter
    all_items = [i for h in hosts for i in h["items"]]
    total_counts = Counter(i["severity"] for i in all_items)
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # TOC
    toc_links = ""
    for h in hosts:
        ip = h["props"].get("host-ip", h["name"])
        cnt = len(h["items"])
        toc_links += f'<a href="#host-{esc(ip)}">{esc(ip)} <small>({cnt})</small></a>'

    # Host sections
    host_sections = ""
    for hi, h in enumerate(hosts):
        ip   = h["props"].get("host-ip", h["name"])
        fqdn = h["props"].get("host-fqdn", ip)
        os_  = h["props"].get("operating-system", h["props"].get("os","N/A"))
        mac  = h["props"].get("mac-address","N/A")
        hcnt = severity_counts(h["items"])
        card_id = f"host-body-{hi}"

        badges = "".join(f'<span class="badge" style="background:{SEV_HEX.get(s,"#95a5a6")};margin-right:3px">{hcnt.get(s,0)} {s}</span>'
                         for s in ["Critical","High","Medium","Low","Info"] if hcnt.get(s,0))

        host_sections += f'<div class="card" id="host-{esc(ip)}">'
        host_sections += f'<div class="card-header" onclick="toggle(\'{card_id}\')">'
        host_sections += f'<div><h2>🖥 {esc(ip)}</h2>'
        host_sections += f'<div class="meta">{esc(fqdn)} &nbsp;|&nbsp; {esc(os_)} &nbsp;|&nbsp; MAC: {esc(mac)}</div>'
        host_sections += f'<div style="margin-top:6px">{badges}</div></div>'
        host_sections += f'<span style="font-size:18px;color:#bdc3cb">⌄</span>'
        host_sections += f'</div>'
        host_sections += f'<div class="card-body open" id="{card_id}">'

        # Group items by severity
        for sev in ["Critical","High","Medium","Low","Info"]:
            sev_items = [i for i in h["items"] if i["severity"]==sev]
            if not sev_items: continue
            c = SEV_HEX[sev]
            host_sections += f'<div class="sev-section"><h3 style="color:{c};background:{SEV_BG[sev]}">'
            host_sections += f'{sev_badge(sev)} &nbsp;{len(sev_items)} finding{"s" if len(sev_items)!=1 else ""}</h3>'
            host_sections += '<table class="vuln-table">'
            host_sections += '<tr><th>#</th><th>Plugin ID</th><th>Vulnerability</th><th>Family</th><th>Port</th><th>CVSS</th><th>Details</th></tr>'

            for idx, item in enumerate(sev_items):
                row_n = f"h{hi}s{sev}r{idx}"
                panel_id = f"dp-{row_n}"
                port_str = f'{item["port"]}/{item["protocol"]}' if item["port"] != "0" else "—"
                host_sections += f'<tr class="sev-{esc(sev)}">'
                host_sections += f'<td>{idx+1}</td>'
                host_sections += f'<td><small>{esc(item["plugin_id"])}</small></td>'
                host_sections += f'<td><strong>{esc(item["plugin_name"])}</strong>'
                if item["cve"]:
                    host_sections += f'<br><small style="color:#7f8c8d">{esc(", ".join(item["cve"][:3]))}</small>'
                host_sections += '</td>'
                host_sections += f'<td>{esc(item["family"])}</td>'
                host_sections += f'<td style="white-space:nowrap">{esc(port_str)}</td>'
                host_sections += f'<td>{esc(item["cvss"] or "—")}</td>'
                host_sections += f'<td><span class="detail-toggle" onclick="toggle(\'{panel_id}\')">▶ Show</span>'
                host_sections += detail_panel(item, panel_id) + '</td>'
                host_sections += '</tr>'

            host_sections += '</table></div>'
        host_sections += '</div></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nessus Report — {esc(label)} — By Host</title>
<style>{CSS}</style>
</head>
<body>
<div class="page-header">
  <h1>🔍 Nessus Vulnerability Report — By Host</h1>
  <p>{esc(label)} &nbsp;·&nbsp; Generated: {gen_time} &nbsp;·&nbsp; Source: {esc(Path(nessus_file).name)}</p>
</div>
<div class="top-nav">
  <a href="#" class="active">By Host</a>
  <a href="{esc(label)}_by_plugin.html">By Plugin</a>
  <span style="flex:1"></span>
  <a href="#" onclick="expandAll();return false">Expand All</a>
  <a href="#" onclick="collapseAll();return false">Collapse All</a>
  <a href="#" onclick="window.print();return false">🖨 Print</a>
</div>
<div class="container">
  {summary_cards(total_counts)}
  <div class="layout">
    <div class="toc">
      <div class="toc-sticky">
        <h3>Hosts ({len(hosts)})</h3>
        {toc_links}
      </div>
    </div>
    <div class="main-content">
      {host_sections}
    </div>
  </div>
</div>
<script>{JS}</script>
</body>
</html>"""
    return html

# ── Report 2: By Plugin ────────────────────────────────────────────────────────
def build_by_plugin(hosts, label, nessus_file):
    from collections import Counter
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Group all findings by plugin_id
    by_plugin = defaultdict(list)
    for h in hosts:
        ip = h["props"].get("host-ip", h["name"])
        for item in h["items"]:
            by_plugin[item["plugin_id"]].append({**item, "host_ip": ip})

    # Build plugin list sorted by severity then name
    plugins = []
    for pid, findings in by_plugin.items():
        max_sev = min(findings, key=lambda x: SEV_ORDER.get(x["severity"],9))
        plugins.append({
            "plugin_id":   pid,
            "plugin_name": findings[0]["plugin_name"],
            "family":      findings[0]["family"],
            "severity":    max_sev["severity"],
            "severity_num":max_sev["severity_num"],
            "cvss":        findings[0]["cvss"],
            "cve":         findings[0]["cve"],
            "synopsis":    findings[0]["synopsis"],
            "description": findings[0]["description"],
            "solution":    findings[0]["solution"],
            "see_also":    findings[0]["see_also"],
            "patch_date":  findings[0]["patch_date"],
            "plugin_output": findings[0]["plugin_output"],
            "findings":    findings,
        })
    plugins.sort(key=lambda x: (SEV_ORDER.get(x["severity"],9), x["plugin_name"]))

    total_counts = Counter(p["severity"] for p in plugins)

    # TOC by severity
    toc_links = ""
    for sev in ["Critical","High","Medium","Low","Info"]:
        sev_plugins = [p for p in plugins if p["severity"]==sev]
        if not sev_plugins: continue
        c = SEV_HEX[sev]
        toc_links += f'<a href="#sev-{sev}" style="color:{c};font-weight:600">{sev} ({len(sev_plugins)})</a>'
        for p in sev_plugins:
            toc_links += f'<a href="#plugin-{esc(p["plugin_id"])}" style="padding-left:14px;font-size:11px">{esc(p["plugin_name"][:40])}</a>'

    # Plugin sections
    plugin_sections = ""
    for sev in ["Critical","High","Medium","Low","Info"]:
        sev_plugins = [p for p in plugins if p["severity"]==sev]
        if not sev_plugins: continue
        c  = SEV_HEX[sev]
        bg = SEV_BG[sev]
        plugin_sections += f'<h2 id="sev-{sev}" style="color:{c};background:{bg};padding:10px 16px;border-radius:8px;margin:20px 0 10px">'
        plugin_sections += f'{sev_badge(sev)} &nbsp;{len(sev_plugins)} Vulnerabilit{"y" if len(sev_plugins)==1 else "ies"}</h2>'

        for pi, p in enumerate(sev_plugins):
            pid     = p["plugin_id"]
            card_id = f"plugin-body-{pid}"

            # Affected hosts summary
            hosts_aff = list({f["host_ip"] for f in p["findings"]})
            hosts_str = ", ".join(hosts_aff[:5]) + (f" +{len(hosts_aff)-5} more" if len(hosts_aff)>5 else "")

            plugin_sections += f'<div class="card" id="plugin-{esc(pid)}">'
            plugin_sections += f'<div class="card-header" onclick="toggle(\'{card_id}\')" style="border-left-color:{c}">'
            plugin_sections += f'<div><h2>{esc(p["plugin_name"])}</h2>'
            plugin_sections += f'<div class="meta">Plugin {esc(pid)} &nbsp;|&nbsp; {esc(p["family"])} &nbsp;|&nbsp; '
            plugin_sections += f'CVSS: {esc(p["cvss"] or "N/A")} &nbsp;|&nbsp; {len(p["findings"])} finding{"s" if len(p["findings"])!=1 else ""} on: {esc(hosts_str)}</div>'
            if p["cve"]:
                cve_tags = "".join(
                    f'<a class="cve-tag" href="https://www.cve.org/CVERecord?id={esc(cv)}" target="_blank">{esc(cv)}</a>'
                    for cv in p["cve"][:8])
                plugin_sections += f'<div style="margin-top:4px">{cve_tags}</div>'
            plugin_sections += '</div>'
            plugin_sections += f'<span style="font-size:18px;color:#bdc3cb">⌄</span></div>'
            plugin_sections += f'<div class="card-body open" id="{card_id}">'

            # Description / Solution / etc.
            if p["synopsis"]:
                plugin_sections += f'<p style="margin-bottom:10px;color:#555">{esc(p["synopsis"])}</p>'

            info_cols = ""
            if p["cvss"]:      info_cols += f'<td><strong>CVSS:</strong> {esc(p["cvss"])}</td>'
            if p["patch_date"]:info_cols += f'<td><strong>Patch Date:</strong> {esc(p["patch_date"])}</td>'
            if p["family"]:    info_cols += f'<td><strong>Family:</strong> {esc(p["family"])}</td>'
            if info_cols:
                plugin_sections += f'<table style="width:100%;margin-bottom:12px"><tr>{info_cols}</tr></table>'

            if p["description"]:
                desc_short = p["description"][:600] + ("…" if len(p["description"])>600 else "")
                plugin_sections += f'<h4 style="margin-bottom:4px">Description</h4>'
                plugin_sections += f'<p style="color:#444;white-space:pre-wrap;margin-bottom:12px">{esc(desc_short)}</p>'

            if p["solution"]:
                plugin_sections += f'<div style="background:#eafaf1;border-left:4px solid #27ae60;padding:10px 14px;border-radius:4px;margin-bottom:12px">'
                plugin_sections += f'<strong>✅ Solution:</strong><br><p style="color:#333;white-space:pre-wrap">{esc(p["solution"])}</p></div>'

            if p["see_also"]:
                links = p["see_also"].strip().splitlines()
                plugin_sections += '<h4 style="margin-bottom:4px">References</h4><ul style="margin-left:16px;margin-bottom:12px">'
                for lnk in links[:10]:
                    lnk = lnk.strip()
                    if lnk:
                        plugin_sections += f'<li><a href="{esc(lnk)}" target="_blank">{esc(lnk)}</a></li>'
                plugin_sections += '</ul>'

            # Affected hosts table
            plugin_sections += f'<h4 style="margin-bottom:6px">Affected Hosts ({len(p["findings"])} finding{"s" if len(p["findings"])!=1 else ""})</h4>'
            plugin_sections += '<table class="vuln-table"><tr><th>#</th><th>Host IP</th><th>Port</th><th>Protocol</th><th>Service</th><th>Plugin Output</th></tr>'
            for fi, f in enumerate(p["findings"]):
                port_str = f['port'] if f['port'] != '0' else '—'
                out_short = esc(f["plugin_output"][:300] + ("…" if len(f["plugin_output"])>300 else ""))
                plugin_sections += f'<tr class="sev-{esc(sev)}">'
                plugin_sections += f'<td>{fi+1}</td><td>{esc(f["host_ip"])}</td>'
                plugin_sections += f'<td>{esc(port_str)}</td><td>{esc(f["protocol"])}</td>'
                plugin_sections += f'<td>{esc(f["svc_name"])}</td>'
                plugin_sections += f'<td style="font-family:monospace;font-size:11px">{out_short}</td>'
                plugin_sections += '</tr>'
            plugin_sections += '</table>'
            plugin_sections += '</div></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nessus Report — {esc(label)} — By Plugin</title>
<style>{CSS}</style>
</head>
<body>
<div class="page-header">
  <h1>🔍 Nessus Vulnerability Report — By Plugin</h1>
  <p>{esc(label)} &nbsp;·&nbsp; Generated: {gen_time} &nbsp;·&nbsp; Source: {esc(Path(nessus_file).name)}</p>
</div>
<div class="top-nav">
  <a href="{esc(label)}_by_host.html">By Host</a>
  <a href="#" class="active">By Plugin</a>
  <span style="flex:1"></span>
  <a href="#" onclick="expandAll();return false">Expand All</a>
  <a href="#" onclick="collapseAll();return false">Collapse All</a>
  <a href="#" onclick="window.print();return false">🖨 Print</a>
</div>
<div class="container">
  {summary_cards(total_counts, "Unique Vulnerabilities")}
  <div class="layout">
    <div class="toc">
      <div class="toc-sticky">
        <h3>Plugins ({len(plugins)})</h3>
        {toc_links}
      </div>
    </div>
    <div class="main-content">
      {plugin_sections}
    </div>
  </div>
</div>
<script>{JS}</script>
</body>
</html>"""
    return html

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nessus_file", help=".nessus XML file to process")
    parser.add_argument("--label",  default="",    help="Report label (defaults to filename stem)")
    parser.add_argument("--outdir", default="",    help="Output directory (defaults to same as input file)")
    args = parser.parse_args()

    nessus_path = Path(args.nessus_file).expanduser().resolve()
    if not nessus_path.exists():
        print(f"[✗] File not found: {nessus_path}"); sys.exit(1)

    label  = args.label or re.sub(r"_vulnerabilities$","", nessus_path.stem)
    label  = re.sub(r"^nessus_","", label)
    outdir = Path(args.outdir).expanduser() if args.outdir else nessus_path.parent

    out_host   = outdir / f"{label}_by_host.html"
    out_plugin = outdir / f"{label}_by_plugin.html"

    print(f"[*] Parsing {nessus_path.name}…")
    hosts = parse_nessus(str(nessus_path))
    total = sum(len(h["items"]) for h in hosts)
    print(f"[+] {len(hosts)} host(s), {total} findings")

    print("[*] Building By Host report…")
    out_host.write_text(build_by_host(hosts, label, str(nessus_path)), encoding="utf-8")
    print(f"[+] Saved → {out_host}")

    print("[*] Building By Plugin report…")
    out_plugin.write_text(build_by_plugin(hosts, label, str(nessus_path)), encoding="utf-8")
    print(f"[+] Saved → {out_plugin}")

    from collections import Counter
    cnt = Counter(i["severity"] for h in hosts for i in h["items"])
    print(f"\n{'═'*45}")
    print(f"  {label}")
    print(f"{'═'*45}")
    for sev in ["Critical","High","Medium","Low","Info"]:
        if cnt.get(sev): print(f"  {sev:<12}: {cnt[sev]}")
    print(f"  {'Total':<12}: {total}")
    print(f"{'═'*45}")
    print(f"\n[✓] By Host   → {out_host}")
    print(f"[✓] By Plugin → {out_plugin}")
    print(f"\n    open '{out_host}'")
    print(f"    open '{out_plugin}'")

if __name__ == "__main__":
    main()
