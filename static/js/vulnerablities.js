function refreshIcons(root = document) {
  if (!window.lucide || !lucide.createIcons) return;
  const target = root && typeof root.querySelectorAll === 'function' ? root : document;
  lucide.createIcons({ root: target, attrs: { 'stroke-width': 1.9 } });
}
document.addEventListener('DOMContentLoaded', refreshIcons);

function tickClock() {
  const ist = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }));
  const p = n => String(n).padStart(2, '0');
  document.getElementById('live-time').textContent =
    `${p(ist.getHours())}:${p(ist.getMinutes())}:${p(ist.getSeconds())} IST`;
}
tickClock(); setInterval(tickClock, 1000);

// ── State ─────────────────────────────────────────────
let SEV_FILTER = '';
let DEBOUNCE = null;

function setSeverity(sev) {
  SEV_FILTER = (SEV_FILTER === sev) ? '' : sev;
  document.getElementById('f-sev').value = SEV_FILTER;
  document.querySelectorAll('.vuln-kpi').forEach(el => {
    el.classList.toggle('active', el.dataset.sev === SEV_FILTER);
  });
  loadVulns();
}

function debouncedLoad() {
  clearTimeout(DEBOUNCE);
  DEBOUNCE = setTimeout(loadVulns, 300);
}

// ── Loaders ──────────────────────────────────────────
async function loadSummary() {
  try {
    const agent = document.getElementById('f-agent').value;
    const qs = agent ? '?summary=true&agent=' + encodeURIComponent(agent) : '?summary=true';
    const r = await fetch('/api/v1/vulnerabilities' + qs, { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    const d = body.data;
    document.getElementById('kpi-critical').textContent = d.bySeverity.Critical || 0;
    document.getElementById('kpi-high').textContent     = d.bySeverity.High || 0;
    document.getElementById('kpi-medium').textContent   = d.bySeverity.Medium || 0;
    document.getElementById('kpi-low').textContent      = d.bySeverity.Low || 0;
    document.getElementById('sum-total').textContent    = (d.totalHits || 0).toLocaleString();
    document.getElementById('sum-cves').textContent     = (d.uniqueCVEs || 0).toLocaleString();
    document.getElementById('sum-pkgs').textContent     = (d.uniquePackages || 0).toLocaleString();
    document.getElementById('sum-idx').textContent      = d.indexPattern || '—';
  } catch (err) {
    showError('Could not load vulnerability summary: ' + err.message);
  }
}

async function loadAgentFilter() {
  try {
    const r = await fetch('/api/v1/vulnerabilities/agents', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') return;
    const sel = document.getElementById('f-agent');
    const cur = sel.value;
    const agents = body.data || [];
    sel.innerHTML = '<option value="">All agents</option>' +
      agents.map(a => `<option value="${escapeHtml(a.agent)}">${escapeHtml(a.agent)} (${a.count})</option>`).join('');
    if (cur) sel.value = cur;
  } catch (_) { /* non-fatal */ }
}

async function loadVulns() {
  const tbody = document.getElementById('vuln-tbody');
  const count = document.getElementById('vuln-count');
  const errBanner = document.getElementById('error-banner');
  errBanner.style.display = 'none';

  const agent = document.getElementById('f-agent').value;
  const sev   = document.getElementById('f-sev').value;
  const q     = document.getElementById('f-search').value.trim();

  const p = new URLSearchParams();
  if (agent) p.set('agent', agent);
  if (sev)   p.set('severity', sev);
  if (q)     p.set('q', q);
  p.set('limit', '200');

  tbody.innerHTML = '<tr><td colspan="7" class="vuln-empty"><span class="spin"></span>Loading…</td></tr>';

  try {
    const r = await fetch('/api/v1/vulnerabilities?' + p.toString(), { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') {
      throw new Error(body.error + (body.hint ? ' — ' + body.hint : ''));
    }
    const rows = body.data || [];
    count.textContent = `${rows.length} of ${body.total || rows.length} findings`;

    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="vuln-empty">
        <i data-lucide="circle-check" class="ui-icon" style="width:28px;height:28px;color:var(--c-low)"></i>
        <div style="margin-top:8px;font-weight:600;color:var(--text-2)">No findings match your filters</div>
        <div style="font-size:12.5px">If you expected findings, see docs/vulnerabilities.md.</div>
      </td></tr>`;
      refreshIcons(tbody);
      return;
    }

    tbody.innerHTML = rows.map(v => {
      const sevLower = (v.severity || 'low').toLowerCase();
      const ref = v.reference
        ? `<a href="${escapeHtml(v.reference)}" target="_blank" rel="noopener" class="vuln-ref">
             <i data-lucide="external-link" class="ui-icon"></i>
           </a>`
        : '—';
      const pkg = v.package
        ? `<span class="vuln-pkg">${escapeHtml(v.package)}</span>${v.version ? ` <span class="vuln-pkg-v">${escapeHtml(v.version)}</span>` : ''}`
        : '—';
      const detected = v.detected_at ? fmtDate(v.detected_at) : '—';
      const cvss = (v.cvss != null) ? Number(v.cvss).toFixed(1) : '—';
      return `
        <tr>
          <td><span class="vuln-cve">${escapeHtml(v.cve || '—')}</span></td>
          <td><span class="vuln-sev ${sevLower}">${escapeHtml(v.severity)}</span></td>
          <td><span class="vuln-cvss">${cvss}</span></td>
          <td><span class="vuln-agent">${escapeHtml(v.agent)}</span></td>
          <td>${pkg}</td>
          <td><span class="vuln-date">${escapeHtml(detected)}</span></td>
          <td>${ref}</td>
        </tr>`;
    }).join('');
    refreshIcons(tbody);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="vuln-empty vuln-err">
      <strong>Could not load vulnerabilities</strong>
      <div style="font-size:12.5px;margin-top:6px">${escapeHtml(err.message)}</div>
      <div style="font-size:12px;margin-top:10px;color:var(--text-3)">
        See <code>docs/vulnerabilities.md</code> for troubleshooting.
      </div>
    </td></tr>`;
    count.textContent = '—';
    showError(err.message);
  }
}

function showError(msg) {
  const el = document.getElementById('error-banner');
  el.textContent = msg;
  el.style.display = 'block';
}

function loadAll() {
  loadAgentFilter();
  loadSummary();
  loadVulns();
}

// ── Helpers ──────────────────────────────────────────
function fmtDate(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    }) + ' IST';
  } catch (e) { return iso; }
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Boot ─────────────────────────────────────────────
loadAll();
setInterval(() => {
  if (document.visibilityState === 'visible' &&
      document.activeElement !== document.getElementById('f-search')) {
    loadSummary();
    loadVulns();
  }
}, 60000);