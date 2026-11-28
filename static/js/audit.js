
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

// ── Audit loader ─────────────────────────────────────
let DEBOUNCE = null;
let CACHED_AUDIT = [];

function debouncedLoad() {
  clearTimeout(DEBOUNCE);
  DEBOUNCE = setTimeout(loadAudit, 300);
}

async function loadAudit() {
  const el = document.getElementById('audit-list');
  const q = document.getElementById('audit-search').value.trim();
  const actor = document.getElementById('audit-filter-actor').value;

  const p = new URLSearchParams();
  if (q)     p.set('q', q);
  if (actor) p.set('actor', actor);
  p.set('limit', '500');

  try {
    const r = await fetch('/api/v1/audit?' + p.toString(), { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    CACHED_AUDIT = body.data || [];
    renderAudit(CACHED_AUDIT);
  } catch (err) {
    el.innerHTML = `<div style="padding:32px;text-align:center;color:var(--c-critical)">
      <i data-lucide="circle-x" class="ui-icon" style="width:32px;height:32px"></i>
      <div style="margin-top:10px;font-weight:700;font-size:15px">Could not load audit log</div>
      <div style="font-size:13px;color:var(--text-3);margin-top:6px">${escapeHtml(err.message)}</div>
    </div>`;
    refreshIcons(el);
  }
}

function renderAudit(rows) {
  const el = document.getElementById('audit-list');
  document.getElementById('audit-count').textContent =
    rows.length ? `${rows.length} entr${rows.length === 1 ? 'y' : 'ies'}` : '';

  if (!rows.length) {
    el.innerHTML = `<div class="empty-state">
      <i data-lucide="scroll-text" class="ui-icon"></i>
      <div class="empty-state-title">No audit entries${hasFilter() ? ' match your filter' : ' yet'}</div>
      <div class="empty-state-sub">${hasFilter() ? 'Try clearing the filter above.' : 'Actions on cases, evidence, and reports appear here.'}</div>
    </div>`;
    refreshIcons(el);
    return;
  }

  el.innerHTML = rows.map(r => {
    const actorCls = (r.actor || '').toLowerCase() === 'system' ? 'system'
                    : (r.actor || '').toLowerCase() === 'wazuh' ? 'wazuh' : '';
    const refHtml = r.ref ? `<strong>${escapeHtml(r.ref)}</strong>` : '';
    const detailHtml = r.detail ? ` — ${escapeHtml(r.detail)}` : '';
    return `<div class="audit-row">
      <span class="audit-time">${escapeHtml(r.createdAtIst)}</span>
      <span class="audit-action">${escapeHtml(r.action)}</span>
      <span class="audit-detail">${refHtml}${detailHtml}</span>
      <span class="audit-actor ${actorCls}">${escapeHtml(r.actor || 'System')}</span>
    </div>`;
  }).join('');
  refreshIcons(el);
}

function hasFilter() {
  return document.getElementById('audit-search').value.trim()
      || document.getElementById('audit-filter-actor').value;
}

// ── CSV export ────────────────────────────────────────
function exportAuditCsv() {
  if (!CACHED_AUDIT.length) {
    alert('No audit entries to export.');
    return;
  }
  const header = ['Timestamp', 'Action', 'Reference', 'Detail', 'Actor'];
  const rows = CACHED_AUDIT.map(r => [
    r.createdAtIst,
    r.action,
    r.ref || '',
    r.detail || '',
    r.actor || 'System',
  ]);
  const csv = [header, ...rows]
    .map(row => row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(','))
    .join('\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ZeroRespond-audit-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Report history (reuses /api/v1/reports) ──────────
async function loadReportHistory() {
  const el = document.getElementById('report-history-list');
  try {
    const r = await fetch('/api/v1/reports', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    const rows = body.data || [];

    if (!rows.length) {
      el.innerHTML = `<div class="empty-state">
        <i data-lucide="file-text" class="ui-icon"></i>
        <div class="empty-state-title">No reports generated yet</div>
        <div class="empty-state-sub">Complete a playbook and generate a report to see it here.</div>
      </div>`;
    } else {
      el.innerHTML = rows.map(row => `
        <div class="report-history-row">
          <strong>${escapeHtml(row.reportRef)}</strong>
          <span style="font-family:var(--font-code);color:var(--text-2)">${escapeHtml(row.caseRef)}</span>
          <span>${escapeHtml(row.threatType)}</span>
          <span style="color:var(--text-3)">${escapeHtml(row.generatedAtIst)}</span>
          <span class="status-chip status-resolved" style="justify-self:start">
            <i data-lucide="circle-check" class="ui-icon"></i> Generated
          </span>
        </div>`).join('');
    }
    refreshIcons(el);
  } catch (err) {
    el.innerHTML = `<div style="padding:24px;text-align:center;color:var(--c-critical)">
      <strong>Could not load report history</strong><br>
      <span style="font-size:13px;color:var(--text-3)">${escapeHtml(err.message)}</span>
    </div>`;
  }
}

// ── Escaping ──────────────────────────────────────────
function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Boot ─────────────────────────────────────────────
loadAudit();
loadReportHistory();
setInterval(() => {
  const focused = document.activeElement === document.getElementById('audit-search');
  if (!focused) loadAudit();
}, 30000);
