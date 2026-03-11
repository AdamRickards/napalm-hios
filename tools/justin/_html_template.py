"""HTML report template for JUSTIN.

Self-contained HTML with inline CSS and JS. Report data and certs are
embedded as JSON in <script> tags. The browser renders everything —
no external dependencies.

Usage:
    from _html_template import HTML_TEMPLATE
    html = HTML_TEMPLATE.format(
        json_data=json.dumps(report),
        certs_data=json.dumps(certs),
        timestamp='2026-03-10 14:30',
    )
"""

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JUSTIN — IEC 62443-4-2 Security Audit Report</title>
<style>
  :root {{
    --bg: #1a1a2e;
    --bg2: #16213e;
    --fg: #e0e0e0;
    --fg-dim: #888;
    --accent: #c77dff;
    --green: #4caf50;
    --yellow: #ffc107;
    --red: #f44336;
    --cyan: #00bcd4;
    --border: #333;
    --card: #1e2a4a;
  }}
  @media print {{
    :root {{
      --bg: #fff; --bg2: #f5f5f5; --fg: #222; --fg-dim: #666;
      --accent: #6a1b9a; --green: #2e7d32; --yellow: #f57f17;
      --red: #c62828; --cyan: #00838f; --border: #ccc; --card: #fafafa;
    }}
    body {{ font-size: 11pt; }}
    .no-print {{ display: none !important; }}
    details {{ break-inside: avoid; }}
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--fg);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1000px;
    margin: 0 auto;
  }}
  h1 {{
    color: var(--accent);
    font-size: 1.8rem;
    margin-bottom: 0.2rem;
  }}
  h1 span {{ font-weight: 300; color: var(--fg-dim); font-size: 0.9rem; }}
  .subtitle {{ color: var(--fg-dim); margin-bottom: 1.5rem; }}
  .meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.5rem 2rem;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.5rem;
    margin-bottom: 1.5rem;
  }}
  .meta-item {{ display: flex; gap: 0.5rem; }}
  .meta-label {{ color: var(--fg-dim); min-width: 5rem; }}
  .meta-value {{ font-weight: 600; }}
  .cert {{ color: var(--cyan); }}
  .score-section {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    text-align: center;
  }}
  .score-bar {{
    width: 100%;
    height: 24px;
    background: #333;
    border-radius: 12px;
    overflow: hidden;
    margin: 0.75rem 0;
  }}
  .score-fill {{
    height: 100%;
    border-radius: 12px;
    transition: width 0.5s;
  }}
  .score-text {{
    font-size: 1.4rem;
    font-weight: 700;
  }}
  .score-detail {{ color: var(--fg-dim); font-size: 0.9rem; }}
  .checks-table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1.5rem;
  }}
  .checks-table th {{
    text-align: left;
    padding: 0.6rem 0.8rem;
    border-bottom: 2px solid var(--border);
    color: var(--fg-dim);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .checks-table td {{
    padding: 0.5rem 0.8rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
  }}
  .checks-table tr:hover {{ background: rgba(199, 125, 255, 0.05); }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}
  .badge-pass {{ background: rgba(76,175,80,0.15); color: var(--green); }}
  .badge-crit {{ background: rgba(244,67,54,0.15); color: var(--red); }}
  .badge-warn {{ background: rgba(255,193,7,0.15); color: var(--yellow); }}
  .badge-info {{ background: rgba(0,188,212,0.15); color: var(--cyan); }}
  .badge-stub {{ background: rgba(136,136,136,0.15); color: var(--fg-dim); }}
  .section-title {{
    color: var(--accent);
    font-size: 1.1rem;
    margin: 1.5rem 0 0.75rem;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid var(--border);
  }}
  .remediation {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.75rem;
  }}
  .remediation .check-id {{ color: var(--accent); font-weight: 600; }}
  .remediation .desc {{ color: var(--fg-dim); font-size: 0.85rem; }}
  .fix-label {{
    color: var(--cyan);
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    margin-top: 0.4rem;
  }}
  .fix-cmd {{
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 0.85rem;
    background: var(--bg);
    padding: 0.3rem 0.6rem;
    border-radius: 4px;
    display: inline-block;
    margin-top: 0.2rem;
  }}
  .footer {{
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--fg-dim);
    font-size: 0.8rem;
    text-align: center;
  }}
  .source-tag {{
    display: inline-block;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
  }}
  .source-iec {{ background: rgba(0,188,212,0.12); color: var(--cyan); }}
  .source-vendor {{ background: rgba(199,125,255,0.12); color: var(--accent); }}
  .ev-link {{
    color: var(--cyan);
    text-decoration: none;
    font-size: 0.75rem;
    opacity: 0.7;
    vertical-align: super;
  }}
  .ev-link:hover {{ opacity: 1; text-decoration: underline; }}
  .evidence-block {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 0.75rem;
  }}
  .evidence-block summary {{
    padding: 0.6rem 1rem;
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--cyan);
  }}
  .evidence-block summary:hover {{ background: rgba(0,188,212,0.05); }}
  .evidence-block .ev-meta {{
    padding: 0.2rem 1rem 0.4rem;
    font-size: 0.75rem;
    color: var(--fg-dim);
  }}
  .evidence-block pre {{
    padding: 0.6rem 1rem;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 0.8rem;
    overflow-x: auto;
    max-height: 400px;
    overflow-y: auto;
    background: var(--bg);
    border-top: 1px solid var(--border);
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
  }}
  .ev-checks {{
    padding: 0.2rem 1rem 0.4rem;
    font-size: 0.8rem;
    color: var(--fg-dim);
  }}
  .ev-checks span {{ color: var(--accent); }}
</style>
</head>
<body>
<h1>JUSTIN <span>Justified Unified Security Testing for Industrial Networks</span></h1>
<p class="subtitle">IEC 62443-4-2 Security Audit Report</p>

<div class="meta" id="meta"></div>
<div class="score-section" id="score"></div>
<h2 class="section-title">Checks</h2>
<table class="checks-table" id="checks-table">
  <thead>
    <tr>
      <th>Result</th>
      <th>Source</th>
      <th>Clause</th>
      <th>Check</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody id="checks-body"></tbody>
</table>
<div id="remediation-section"></div>
<div id="evidence-section"></div>
<div class="footer" id="footer"></div>

<script>
const REPORT = {json_data};
const CERTS = {certs_data};

(function() {{
  const d = REPORT.device || {{}};
  const meta = document.getElementById('meta');
  const items = [
    ['Device', (d.ip || '?') + (d.model ? ' (' + d.model + ', ' + (d.os_version || '?') + ')' : '')],
    ['Hostname', d.hostname || d.ip || '?'],
    ['Level', REPORT.level || 'SL1'],
    ['Date', '{timestamp}'],
  ];

  // Cert lookup
  const model = (d.model || '').toUpperCase();
  let certInfo = null;
  if (CERTS.families) {{
    const fams = Object.keys(CERTS.families).sort((a,b) => b.length - a.length);
    for (const fam of fams) {{
      // Wildcard: lowercase 'x' in key matches any char
      const pat = new RegExp('^' + fam.split('').map(c =>
        c === 'x' ? '.' : c.replace(/[.*+?^${{}}()|[\]\\]/g, '\\$&')
      ).join('').toUpperCase());
      if (pat.test(model)) {{
        certInfo = CERTS.families[fam];
        break;
      }}
    }}
  }}
  if (certInfo && certInfo.cert) {{
    const valid = certInfo.valid_until ? ', valid to ' + certInfo.valid_until : '';
    items.push(['Cert', certInfo.cert + ' (SL-C ' + certInfo.sl_c + valid + ')']);
  }} else if (certInfo && certInfo.note) {{
    items.push(['Cert', certInfo.note]);
  }}

  meta.innerHTML = items.map(function(i) {{
    const cls = i[0] === 'Cert' ? ' cert' : '';
    return '<div class="meta-item"><span class="meta-label">' + i[0] +
           ':</span><span class="meta-value' + cls + '">' + i[1] + '</span></div>';
  }}).join('');

  // Score
  const findings = REPORT.findings || [];
  const total = findings.length;
  const passed = findings.filter(f => f.passed).length;
  const failed = total - passed;
  const notImpl = findings.filter(f => (f.desc || '').indexOf('Not yet implemented') !== -1).length;
  const assessed = total - notImpl;
  const pct = assessed > 0 ? Math.round(passed / assessed * 100) : 0;
  const hasCrit = findings.some(f => !f.passed && f.severity === 'critical');
  const barColor = hasCrit ? 'var(--red)' : (failed > 0 ? 'var(--yellow)' : 'var(--green)');

  const score = document.getElementById('score');
  score.innerHTML =
    '<div class="score-text" style="color:' + barColor + '">' + passed + '/' + assessed + ' passed (' + pct + '%)</div>' +
    '<div class="score-bar"><div class="score-fill" style="width:' + pct + '%;background:' + barColor + '"></div></div>' +
    '<div class="score-detail">' + assessed + ' assessed, ' + passed + ' passed, ' + (assessed - passed) + ' failed' +
    (notImpl > 0 ? ', ' + notImpl + ' not yet implemented' : '') + '</div>';

  // Evidence index: which checks use which getter
  const evidence = REPORT.evidence || {{}};
  const evChecks = {{}};
  findings.forEach(function(f) {{
    if (f.evidence_key) {{
      if (!evChecks[f.evidence_key]) evChecks[f.evidence_key] = [];
      evChecks[f.evidence_key].push(f.check_id);
    }}
  }});

  // Checks table
  const tbody = document.getElementById('checks-body');
  const sorted = findings.slice().sort(function(a, b) {{
    if (a.passed !== b.passed) return a.passed ? 1 : -1;
    const sev = {{critical: 0, warning: 1, info: 2}};
    return (sev[a.severity] || 9) - (sev[b.severity] || 9);
  }});

  sorted.forEach(function(f) {{
    const tr = document.createElement('tr');
    let badge, bcls;
    if (f.passed) {{
      badge = 'PASS'; bcls = 'badge-pass';
    }} else if ((f.desc || '').indexOf('Not yet implemented') !== -1) {{
      badge = 'STUB'; bcls = 'badge-stub';
    }} else {{
      const labels = {{critical: 'CRIT', warning: 'WARN', info: 'INFO'}};
      const classes = {{critical: 'badge-crit', warning: 'badge-warn', info: 'badge-info'}};
      badge = labels[f.severity] || '?';
      bcls = classes[f.severity] || '';
    }}
    const source = f.source || 'iec';
    const srcCls = source === 'vendor' ? 'source-vendor' : 'source-iec';
    const srcLabel = source === 'vendor' ? 'VENDOR' : 'IEC';
    // Evidence link
    const evLink = (f.evidence_key && evidence[f.evidence_key])
      ? ' <a class="ev-link" href="#ev-' + f.evidence_key + '" title="View evidence: ' + f.evidence_key + '()">[evidence]</a>'
      : '';
    tr.innerHTML =
      '<td><span class="badge ' + bcls + '">' + badge + '</span></td>' +
      '<td><span class="source-tag ' + srcCls + '">' + srcLabel + '</span></td>' +
      '<td>' + (f.clause || '') + '</td>' +
      '<td>' + (f.check_id || '') + '</td>' +
      '<td>' + (f.desc || '') + evLink +
      (f.detail ? '<br><span style="color:var(--fg-dim);font-size:0.8rem">' + f.detail + '</span>' : '') + '</td>';
    tbody.appendChild(tr);
  }});

  // Remediation section
  const failures = sorted.filter(f => !f.passed && (f.desc || '').indexOf('Not yet implemented') === -1);
  if (failures.length > 0) {{
    const sec = document.getElementById('remediation-section');
    let html = '<h2 class="section-title">Remediation</h2>';
    failures.forEach(function(f) {{
      html += '<div class="remediation">';
      html += '<div><span class="check-id">' + f.check_id + '</span> &mdash; ' + (f.clause || '') + ' ' + (f.clause_title || '') + '</div>';
      html += '<div class="desc">' + (f.desc || '') + '</div>';
      if (f.fix) {{
        html += '<div class="fix-label">JUSTIN Auto-Fix</div>';
        html += '<div class="fix-cmd">' + f.fix + '</div>';
      }}
      if (f.fix_cli) {{
        html += '<div class="fix-label">CLI</div>';
        const cmds = typeof f.fix_cli === 'object' && f.fix_cli.commands
          ? f.fix_cli.commands : [String(f.fix_cli)];
        cmds.forEach(function(c) {{
          html += '<div class="fix-cmd">' + c + '</div> ';
        }});
      }}
      if (f.fix_tool) {{
        html += '<div class="fix-label">Tool</div>';
        html += '<div class="fix-cmd">' + f.fix_tool + '</div>';
      }}
      html += '</div>';
    }});
    sec.innerHTML = html;
  }}

  // Evidence Trail section
  const evKeys = Object.keys(evidence).sort();
  if (evKeys.length > 0) {{
    const sec = document.getElementById('evidence-section');
    let html = '<h2 class="section-title">Evidence Trail</h2>';
    html += '<p style="color:var(--fg-dim);font-size:0.85rem;margin-bottom:1rem">' +
            'Raw getter data gathered from the device. Each check result above links to the evidence it was based on.</p>';
    evKeys.forEach(function(key) {{
      const ev = evidence[key];
      const ts = ev.gathered_at || '?';
      const checks = evChecks[key] || [];
      const hasError = !!ev.error;
      html += '<details class="evidence-block" id="ev-' + key + '">';
      html += '<summary>' + key + '()' +
              (hasError ? ' <span style="color:var(--red)">[error]</span>' : '') +
              '</summary>';
      html += '<div class="ev-meta">Gathered at: ' + ts + '</div>';
      if (checks.length > 0) {{
        html += '<div class="ev-checks">Used by: ' +
                checks.map(c => '<span>' + c + '</span>').join(', ') + '</div>';
      }}
      if (hasError) {{
        html += '<pre style="color:var(--red)">Error: ' + ev.error + '</pre>';
      }} else {{
        html += '<pre>' + JSON.stringify(ev.data, null, 2) + '</pre>';
      }}
      html += '</details>';
    }});
    sec.innerHTML = html;
  }}

  // Auto-expand evidence on click — works even for repeat clicks
  // to the same getter (multiple checks share evidence)
  document.addEventListener('click', function(e) {{
    const link = e.target.closest('a.ev-link');
    if (!link) return;
    e.preventDefault();
    const id = link.getAttribute('href').slice(1);
    const el = document.getElementById(id);
    if (el && el.tagName === 'DETAILS') {{
      el.open = true;
      el.style.outline = '2px solid var(--cyan)';
      el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
      setTimeout(function() {{ el.style.outline = ''; }}, 2000);
    }}
  }});

  // Footer
  document.getElementById('footer').innerHTML =
    'Generated by JUSTIN v0.2 (napalm-hios) &mdash; {timestamp}';
}})();
</script>
</body>
</html>"""
