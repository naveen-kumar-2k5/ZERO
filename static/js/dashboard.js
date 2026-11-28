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

// ── Palette + labels ──────────────────────────────────
const SEV_COLORS = {
  critical: '#dc2626',
  high:     '#d97706',
  medium:   '#b45309',
  low:      '#16a34a',
};
const CAT_COLORS = {
  bf:  '#c81e2b',
  pe:  '#7c3aed',
  fim: '#16a34a',
  ra:  '#dc2626',
};
const CAT_LABEL = {
  bf:  'Brute Force',
  pe:  'Privilege Escalation',
  fim: 'File Integrity',
  ra:  'Ransomware',
};

// ── Chart instances (reused across refreshes) ─────────
const charts = {};

function destroyChart(key) {
  if (charts[key]) { charts[key].destroy(); delete charts[key]; }
}

function setEmpty(id, show, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  if (show) { el.style.display = 'flex'; el.textContent = msg || 'No data'; }
  else      { el.style.display = 'none'; }
}

// ── Fetch + render ────────────────────────────────────
async function loadDashboard() {
  const days = document.getElementById('window-sel').value || '7';
  const errBanner = document.getElementById('error-banner');
  errBanner.style.display = 'none';

  ['trend','severity','category','agents','ips'].forEach(k =>
    setEmpty(`empty-${k}`, true, 'Loading…'));
  document.getElementById('recent-list').innerHTML =
    '<div style="padding:20px;text-align:center;color:var(--text-3);font-size:13px">' +
    '<span class="spin"></span>Loading…</div>';

  try {
    const res  = await fetch(`/api/v1/dashboard?days=${days}`, { cache: 'no-store' });
    const body = await res.json();
    if (!res.ok || body.status !== 'success') {
      throw new Error(body.error || 'Failed to load dashboard');
    }
    renderStats(body.stats || {});
    renderTrend(body.trend || []);
    renderSeverity(body.severity || []);
    renderCategory(body.categories || []);
    renderAgents(body.top_agents || []);
    renderIps(body.top_ips || []);
    renderRecent(body.recent || []);
  } catch (err) {
    errBanner.textContent = 'Could not load dashboard: ' + err.message;
    errBanner.style.display = 'block';
    ['trend','severity','category','agents','ips'].forEach(k =>
      setEmpty(`empty-${k}`, true, 'Unavailable'));
    document.getElementById('recent-list').innerHTML =
      '<div style="padding:20px;text-align:center;color:var(--text-3);font-size:13px">' +
      'Unavailable</div>';
  }
}

// ── Stat cards ────────────────────────────────────────
function renderStats(s) {
  const total = s.total || 0;
  document.getElementById('kpi-total').textContent = total.toLocaleString();
  document.getElementById('kpi-total-sub').textContent =
    `across ${s.high + s.medium + s.low + s.critical > 0 ? 'all levels' : 'no data yet'}`;
  document.getElementById('kpi-critical').textContent = (s.critical || 0).toLocaleString();
  document.getElementById('kpi-critical-sub').textContent =
    total ? `${Math.round((s.critical / total) * 100)}% of all alerts` : '—';
  document.getElementById('kpi-high').textContent = (s.high || 0).toLocaleString();
  document.getElementById('kpi-high-sub').textContent =
    total ? `${Math.round((s.high / total) * 100)}% of all alerts` : '—';
  document.getElementById('kpi-last24').textContent = (s.last24h || 0).toLocaleString();
  document.getElementById('kpi-last24-sub').textContent =
    s.last24h === 0 ? 'no new alerts — check /health' : 'new detections today';
}

// ── Trend line ────────────────────────────────────────
function renderTrend(trend) {
  destroyChart('trend');
  const canvas = document.getElementById('chart-trend');
  const ctx = canvas.getContext('2d');

  if (!trend.length || trend.every(p => p.total === 0)) {
    setEmpty('empty-trend', true, 'No alerts in this window');
    return;
  }
  setEmpty('empty-trend', false);

  charts.trend = new Chart(ctx, {
    type: 'line',
    data: {
      labels: trend.map(p => shortDate(p.date)),
      datasets: [
        {
          label: 'All alerts',
          data: trend.map(p => p.total),
          borderColor: '#c81e2b',
          backgroundColor: 'rgba(200,30,43,.10)',
          tension: .35,
          pointRadius: 3,
          pointHoverRadius: 5,
          borderWidth: 2,
          fill: true,
        },
        {
          label: 'Critical',
          data: trend.map(p => p.critical),
          borderColor: '#dc2626',
          backgroundColor: 'rgba(220,38,38,.10)',
          tension: .35,
          pointRadius: 2,
          pointHoverRadius: 4,
          borderWidth: 2,
          borderDash: [4, 3],
          fill: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } },
        tooltip: { padding: 10 },
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } },
             grid: { color: 'rgba(0,0,0,.05)' } },
      },
    },
  });
}

// ── Severity doughnut ─────────────────────────────────
function renderSeverity(sev) {
  destroyChart('severity');
  const ctx = document.getElementById('chart-severity').getContext('2d');
  const nonZero = sev.filter(s => s.count > 0);

  if (!nonZero.length) {
    setEmpty('empty-severity', true, 'No data');
    return;
  }
  setEmpty('empty-severity', false);

  charts.severity = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: sev.map(s => s.key.charAt(0).toUpperCase() + s.key.slice(1)),
      datasets: [{
        data: sev.map(s => s.count),
        backgroundColor: sev.map(s => SEV_COLORS[s.key] || '#94a3b8'),
        borderColor: '#fff',
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '58%',
      plugins: {
        legend: { position: 'bottom',
                  labels: { boxWidth: 10, font: { size: 11 }, padding: 12 } },
        tooltip: {
          callbacks: {
            label(ctx) {
              const total = ctx.dataset.data.reduce((a,b)=>a+b,0);
              const pct = total ? Math.round((ctx.parsed/total)*100) : 0;
              return `${ctx.label}: ${ctx.parsed} (${pct}%)`;
            },
          },
        },
      },
    },
  });
}

// ── Category bar ──────────────────────────────────────
function renderCategory(cats) {
  destroyChart('category');
  const ctx = document.getElementById('chart-category').getContext('2d');
  if (!cats.length || cats.every(c => c.count === 0)) {
    setEmpty('empty-category', true, 'No data');
    return;
  }
  setEmpty('empty-category', false);

  charts.category = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: cats.map(c => CAT_LABEL[c.key] || c.key),
      datasets: [{
        label: 'Alerts',
        data: cats.map(c => c.count),
        backgroundColor: cats.map(c => CAT_COLORS[c.key] || '#c81e2b'),
        borderRadius: 6,
        maxBarThickness: 48,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } },
             grid: { color: 'rgba(0,0,0,.05)' } },
      },
    },
  });
}

// ── Top agents horizontal bar ─────────────────────────
function renderAgents(agents) {
  destroyChart('agents');
  const ctx = document.getElementById('chart-agents').getContext('2d');
  if (!agents.length) {
    setEmpty('empty-agents', true, 'No agents yet');
    return;
  }
  setEmpty('empty-agents', false);

  charts.agents = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: agents.map(a => a.agent),
      datasets: [{
        label: 'Alerts',
        data: agents.map(a => a.count),
        backgroundColor: '#c81e2b',
        borderRadius: 5,
        maxBarThickness: 22,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } },
             grid: { color: 'rgba(0,0,0,.05)' } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } },
      },
    },
  });
}

// ── Top source IPs horizontal bar ─────────────────────
function renderIps(ips) {
  destroyChart('ips');
  const ctx = document.getElementById('chart-ips').getContext('2d');
  if (!ips.length) {
    setEmpty('empty-ips', true, 'No source IPs recorded');
    return;
  }
  setEmpty('empty-ips', false);

  charts.ips = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ips.map(i => i.ip),
      datasets: [{
        label: 'Alerts',
        data: ips.map(i => i.count),
        backgroundColor: '#7c3aed',
        borderRadius: 5,
        maxBarThickness: 22,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } },
             grid: { color: 'rgba(0,0,0,.05)' } },
        y: { grid: { display: false },
             ticks: { font: { size: 11, family: 'Fira Code' } } },
      },
    },
  });
}

// ── Recent alerts ─────────────────────────────────────
function renderRecent(rows) {
  const el = document.getElementById('recent-list');
  if (!rows.length) {
    el.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-3);font-size:13px">' +
                   'No alerts recorded yet.</div>';
    return;
  }
  el.innerHTML = rows.map(r => `
    <div class="recent-row">
      <span class="recent-sev ${r.sev}">${r.sev}</span>
      <div class="recent-main">
        <div class="recent-title">${escapeHtml(r.name)}</div>
        <div class="recent-meta">Rule ${escapeHtml(r.ruleId)} · ${escapeHtml(r.computer)}</div>
      </div>
      <div class="recent-host">${escapeHtml(r.source_ip || '—')}</div>
      <div class="recent-time">${escapeHtml(r.time)}</div>
    </div>
  `).join('');
  refreshIcons(el);
}

// ── Helpers ───────────────────────────────────────────
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

// ── Initial load + auto-refresh ───────────────────────
loadDashboard();
setInterval(loadDashboard, 60000);
