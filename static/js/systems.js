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

// ── Data ──────────────────────────────────────────────
let SYSTEMS = [];

function levelToClass(lvl) {
  if (lvl > 15) return 'has-critical';
  if (lvl >= 14) return 'has-high';
  if (lvl >= 12)  return 'has-medium';
  return '';
}
function levelToLabel(lvl) {
  if (lvl > 15) return 'critical';
  if (lvl >= 14) return 'high';
  if (lvl >= 12)  return 'medium';
  return 'low';
}

function formatAge(sec) {
  if (sec == null) return '—';
  if (sec < 60)   return sec + 's ago';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
  return Math.floor(sec / 86400) + 'd ago';
}
function ageClass(sec) {
  if (sec == null) return '';
  if (sec < 300)   return '';
  if (sec < 3600)  return 'stale';
  return 'dead';
}

function statusPill(st) {
  const LBL = { online: 'Online', warning: 'Warning', offline: 'Offline' };
  return `<span class="sys-status-pill ${st}"><span class="sys-pulse ${st}"></span>${LBL[st] || st}</span>`;
}

async function loadSystems() {
  const tbody = document.getElementById('systems-tbody');
  tbody.innerHTML = `<tr><td colspan="8" style="padding:40px;text-align:center;color:var(--text-3)">
    <span class="spin"></span>Loading systems from Wazuh…</td></tr>`;

  try {
    const r = await fetch('/api/v1/systems', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed to load');

    SYSTEMS = body.data || [];
    document.getElementById('stat-online').textContent  = body.online  ?? '—';
    document.getElementById('stat-offline').textContent = body.offline ?? '—';
    document.getElementById('stat-alerts').textContent  = body.alertsToday ?? '—';

    const bar    = document.getElementById('wazuh-bar');
    const barT   = document.getElementById('wazuh-bar-title');
    const barSub = document.getElementById('wazuh-bar-sub');
    bar.className = 'wazuh-status-bar';
    barT.textContent = `Connected to Wazuh — ${body.count} agents registered`;
    barSub.textContent = `${body.online} online · ${body.warning || 0} warning · ${body.offline} offline`;
    document.getElementById('last-sync').textContent =
      'Last sync: ' + new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST';

    applySysFilters();
  } catch (err) {
    SYSTEMS = [];
    const bar = document.getElementById('wazuh-bar');
    bar.className = 'wazuh-status-bar error';
    document.getElementById('wazuh-bar-title').textContent = 'Could not reach Wazuh';
    document.getElementById('wazuh-bar-sub').textContent = err.message;
    document.getElementById('last-sync').textContent = '—';
    tbody.innerHTML = `<tr><td colspan="8" style="padding:40px;text-align:center;color:var(--c-critical)">
      <strong>${escapeHtml(err.message)}</strong><br>
      <span style="font-size:13px;color:var(--text-3)">Check that the Wazuh manager is running and the API credentials are correct.</span>
    </td></tr>`;
  }
}

function applySysFilters() {
  const q      = (document.getElementById('sys-search').value || '').toLowerCase().trim();
  const status = document.getElementById('sys-filter-status').value;
  const type   = document.getElementById('sys-filter-type').value;

  let rows = SYSTEMS;
  if (q)      rows = rows.filter(s =>
                (s.host||'').toLowerCase().includes(q) ||
                (s.os||'').toLowerCase().includes(q) ||
                (s.dept||'').toLowerCase().includes(q) ||
                (s.ip||'').toLowerCase().includes(q));
  if (status) rows = rows.filter(s => s.status === status);
  if (type)   rows = rows.filter(s => s.type   === type);

  document.getElementById('sys-count').textContent =
    `${rows.length} of ${SYSTEMS.length} systems`;

  const tbody = document.getElementById('systems-tbody');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="padding:40px;text-align:center;color:var(--text-3)">
      No systems match your filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(s => {
    const alertCls = s.alertsToday === 0
      ? 'clean'
      : levelToClass(s.alertMaxLvl);
    const alertTxt = s.alertsToday === 0
      ? '<i data-lucide="check" class="ui-icon"></i> None'
      : `${s.alertsToday} (${levelToLabel(s.alertMaxLvl)})`;
    const age = formatAge(s.lastLogSec);
    const ageCls = ageClass(s.lastLogSec);

    return `<tr>
      <td>
        <strong style="font-family:var(--font-brand);font-size:13.5px">${escapeHtml(s.host)}</strong>
        ${s.ip ? `<div style="font-size:11.5px;color:var(--text-3);font-family:var(--font-code)">${escapeHtml(s.ip)}</div>` : ''}
      </td>
      <td><span class="sys-type-badge ${s.type}">${escapeHtml(s.typeLbl)}</span></td>
      <td style="font-size:13px;color:var(--text-2)">${escapeHtml(s.os)}</td>
      <td style="font-size:12.5px;color:var(--text-3)">${escapeHtml(s.dept)}</td>
      <td>${statusPill(s.status)}</td>
      <td><span class="last-log-time ${ageCls}">${age}</span></td>
      <td><span class="alerts-today-cell ${alertCls}">${alertTxt}</span></td>
      <td style="white-space:nowrap">
        <button class="btn btn-ghost btn-sm" onclick="viewLogs('${escapeJs(s.host)}')">
          <i data-lucide="clipboard-list" class="ui-icon"></i> Logs
        </button>
      </td>
    </tr>`;
  }).join('');
  refreshIcons(tbody);
}

function viewLogs(host) {
  window.location = `/alerts?q=${encodeURIComponent(host)}`;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function escapeJs(s) {
  return String(s ?? '').replace(/\\/g,'\\\\').replace(/'/g,"\\'");
}

// Initial load + auto refresh
loadSystems();
setInterval(loadSystems, 30000);