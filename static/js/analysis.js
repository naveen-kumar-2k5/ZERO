
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

// ── Constants ─────────────────────────────────────────
const CAT_ICON = {
  bf:  'key-round',
  pe:  'arrow-up',
  fim: 'folder',
  ra:  'lock',
};
const CAT_LABEL = {
  bf:  'Brute Force',
  pe:  'Privilege Escalation',
  fim: 'File Integrity',
  ra:  'Ransomware',
};
const CAT_COLOR = {
  bf:  '#c81e2b',
  pe:  '#d97706',
  fim: '#16a34a',
  ra:  '#7c3aed',
};
const SEV_PILL = {
  critical: { bg: 'var(--c-critical-bg)', fg: 'var(--c-critical)' },
  high:     { bg: 'var(--c-high-bg)',     fg: 'var(--c-high)'     },
  medium:   { bg: 'var(--c-medium-bg)',   fg: 'var(--c-medium)'   },
  low:      { bg: 'var(--c-low-bg)',      fg: 'var(--c-low)'      },
};

let CUR_TYPE = 'bf';
let CHARTS = {};

// ── Loader ────────────────────────────────────────────
async function loadAnalysis() {
  const errBanner = document.getElementById('error-banner');
  errBanner.style.display = 'none';

  const days = document.getElementById('win-select').value || '14';

  setEmpty('empty-trend', true, 'Loading…');
  setEmpty('empty-targets', true, 'Loading…');

  try {
    const r = await fetch(`/api/v1/analysis?days=${days}&type=${CUR_TYPE}`, { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');

    renderCards(body.cards || []);
    renderTrend(body.trend || []);
    renderTargets(body.targets || []);
    renderDetail(body.detail || [], body.detailType, body.detailCount);
  } catch (err) {
    errBanner.textContent = 'Could not load analysis: ' + err.message;
    errBanner.style.display = 'block';
    setEmpty('empty-trend', true, 'Unavailable');
    setEmpty('empty-targets', true, 'Unavailable');
    document.getElementById('attack-detail-list').innerHTML = `
      <div style="padding:32px;text-align:center;color:var(--text-3)">
        Unavailable
      </div>`;
  }
}

// ── Cards ─────────────────────────────────────────────
function renderCards(cards) {
  const el = document.getElementById('attack-cards');
  const max = Math.max(1, ...cards.map(c => c.count));

  el.innerHTML = cards.map(c => {
    const icon = CAT_ICON[c.key] || 'triangle-alert';
    const barPct = Math.round((c.count / max) * 100);
    return `
      <div class="aa-card ${c.key}" data-type="${c.key}" style="cursor:pointer"
           onclick="setDetailType('${c.key}', document.querySelector('.at-tab.${c.key}'))">
        <div class="aa-card-icon"><i data-lucide="${icon}" class="ui-icon"></i></div>
        <div class="aa-card-name">${escapeHtml(c.label)}</div>
        <div class="aa-card-count">${c.count}</div>
        <div class="aa-card-sub">
          detection${c.count === 1 ? '' : 's'} · ${c.pct}% of total
        </div>
        <div class="aa-card-bar">
          <div class="aa-card-bar-fill" style="width:${barPct}%"></div>
        </div>
      </div>`;
  }).join('');
  refreshIcons(el);
}

// ── Trend chart ───────────────────────────────────────
function renderTrend(trend) {
  if (CHARTS.trend) { CHARTS.trend.destroy(); delete CHARTS.trend; }
  const ctx = document.getElementById('chart-trend').getContext('2d');
  const anyData = trend.some(p => p.bf + p.pe + p.fim + p.ra > 0);
  if (!trend.length || !anyData) {
    setEmpty('empty-trend', true, 'No alerts in this window');
    return;
  }
  setEmpty('empty-trend', false);

  CHARTS.trend = new Chart(ctx, {
    type: 'line',
    data: {
      labels: trend.map(p => shortDate(p.date)),
      datasets: [
        ds('Brute Force',      trend.map(p => p.bf),  CAT_COLOR.bf),
        ds('Privilege Esc.',   trend.map(p => p.pe),  CAT_COLOR.pe),
        ds('File Integrity',   trend.map(p => p.fim), CAT_COLOR.fim),
        ds('Ransomware',       trend.map(p => p.ra),  CAT_COLOR.ra),
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } },
        tooltip: { padding: 10 },
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } } },
      },
    },
  });
}

function ds(label, data, color) {
  return {
    label, data,
    borderColor: color,
    backgroundColor: color + '20',
    tension: .35, pointRadius: 3, pointHoverRadius: 5, borderWidth: 2, fill: false,
  };
}

// ── Targets chart ─────────────────────────────────────
function renderTargets(targets) {
  if (CHARTS.targets) { CHARTS.targets.destroy(); delete CHARTS.targets; }
  const ctx = document.getElementById('chart-targets').getContext('2d');
  if (!targets.length) {
    setEmpty('empty-targets', true, 'No agents with alerts');
    return;
  }
  setEmpty('empty-targets', false);

  // Build stacked-by-category bars per agent
  const bf  = targets.map(t => t.breakdown.bf  || 0);
  const pe  = targets.map(t => t.breakdown.pe  || 0);
  const fim = targets.map(t => t.breakdown.fim || 0);
  const ra  = targets.map(t => t.breakdown.ra  || 0);

  CHARTS.targets = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: targets.map(t => t.agent),
      datasets: [
        { label: 'Brute Force',   data: bf,  backgroundColor: CAT_COLOR.bf,  borderRadius: 3, maxBarThickness: 20 },
        { label: 'Priv. Esc.',    data: pe,  backgroundColor: CAT_COLOR.pe,  borderRadius: 3, maxBarThickness: 20 },
        { label: 'File Integrity',data: fim, backgroundColor: CAT_COLOR.fim, borderRadius: 3, maxBarThickness: 20 },
        { label: 'Ransomware',    data: ra,  backgroundColor: CAT_COLOR.ra,  borderRadius: 3, maxBarThickness: 20 },
      ],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 }, padding: 10 } },
      },
      scales: {
        x: { stacked: true, beginAtZero: true, ticks: { precision: 0, font: { size: 11 } } },
        y: { stacked: true, grid: { display: false }, ticks: { font: { size: 11 } } },
      },
    },
  });
}

// ── Detail list ───────────────────────────────────────
function setDetailType(type, tabEl) {
  CUR_TYPE = type;
  document.querySelectorAll('#attack-detail-card .at-tab').forEach(t => t.classList.remove('active'));
  if (tabEl) tabEl.classList.add('active');
  else document.querySelector(`#attack-detail-card .at-tab[data-tab="${type}"]`)?.classList.add('active');

  // update heading
  const icon = CAT_ICON[type] || 'triangle-alert';
  document.getElementById('attack-detail-title').innerHTML =
    `<i data-lucide="${icon}" class="ui-icon"></i> ${CAT_LABEL[type]} — Recent Detections`;
  refreshIcons(document.getElementById('attack-detail-title'));

  loadAnalysis();
}

function renderDetail(rows, type, totalCount) {
  const el = document.getElementById('attack-detail-list');
  if (!rows.length) {
    el.innerHTML = `<div class="empty-state">
      <i data-lucide="${CAT_ICON[type] || 'circle-check'}" class="ui-icon"></i>
      <div class="empty-state-title">No ${CAT_LABEL[type]} detections recorded</div>
      <div class="empty-state-sub">This attack type has produced no alerts yet.</div>
    </div>`;
    refreshIcons(el);
    return;
  }

  el.innerHTML = rows.map((r, i) => {
    const sev = SEV_PILL[r.sev] || SEV_PILL.low;
    return `
      <div class="attack-detail-row">
        <span class="adr-num">${i + 1}</span>
        <div class="adr-body">
          <div class="adr-name">${escapeHtml(r.name)}</div>
          <div class="adr-desc">${escapeHtml(r.desc)}</div>
          <div style="margin-top:4px;font-size:12px;color:var(--text-3)">
            <i data-lucide="laptop" class="ui-icon"></i> ${escapeHtml(r.computer)}
            &nbsp;·&nbsp;
            <i data-lucide="clock-3" class="ui-icon"></i> ${escapeHtml(r.time)}
            &nbsp;·&nbsp;
            Rule ${escapeHtml(r.ruleId)}
          </div>
        </div>
        <span class="adr-badge" style="background:${sev.bg};color:${sev.fg}">
          ${r.sev.charAt(0).toUpperCase() + r.sev.slice(1)}
        </span>
      </div>`;
  }).join('') + (
    totalCount > rows.length
      ? `<div style="padding:12px 20px;text-align:center;font-size:12.5px;color:var(--text-3);border-top:1px solid var(--border)">
          Showing ${rows.length} of ${totalCount} — open the Detection Feed for the full list.
        </div>`
      : ''
  );
  refreshIcons(el);
}

// ── Helpers ───────────────────────────────────────────
function setEmpty(id, show, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  if (show) { el.style.display = 'flex'; el.textContent = msg || 'No data'; }
  else      { el.style.display = 'none'; }
}

function shortDate(iso) {
  try {
    const d = new Date(iso + 'T00:00:00Z');
    return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' });
  } catch (e) { return iso; }
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Boot ─────────────────────────────────────────────
loadAnalysis();
setInterval(() => {
  if (document.visibilityState === 'visible') loadAnalysis();
}, 60000);
