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
const CAT_COLOR = { bf: '#c81e2b', pe: '#d97706', fim: '#16a34a', ra: '#7c3aed' };
const CAT_LABEL = { bf: 'Brute Force', pe: 'Privilege Escalation', fim: 'File Integrity', ra: 'Ransomware' };

let CHARTS = {};

function destroyChart(k) { if (CHARTS[k]) { CHARTS[k].destroy(); delete CHARTS[k]; } }

// ── Loader ────────────────────────────────────────────
async function loadMetrics() {
  const errBanner = document.getElementById('error-banner');
  errBanner.style.display = 'none';

  try {
    const r = await fetch('/api/v1/metrics', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');

    renderReal(body.real || {});
    renderDemoMetrics(body.demo || {});
    renderTrend(body.demo?.trend30 || []);
    renderMonthly(body.demo?.monthly || []);
    renderTypes(body.real?.perCategory7d || []);
    renderFpr(body.demo?.fpr30 || []);
    renderProvenance(body.real || {}, body.disclaimer);
  } catch (err) {
    errBanner.textContent = 'Could not load metrics: ' + err.message;
    errBanner.style.display = 'block';
  }
}

// ── Real numbers ──────────────────────────────────────
function renderReal(real) {
  document.getElementById('w-total').textContent   = (real.totalAlerts      || 0).toLocaleString();
  document.getElementById('w-24h').textContent     = (real.alertsLast24h    || 0).toLocaleString();
  document.getElementById('w-open').textContent    = (real.openCases        || 0).toLocaleString();
  document.getElementById('w-reports').textContent = (real.reportsGenerated || 0).toLocaleString();
}

// ── Demo metric cards ─────────────────────────────────
function renderDemoMetrics(demo) {
  document.getElementById('m-mttd').textContent = `${demo.mttdMinutes?.toFixed(1) ?? '—'} min`;
  document.getElementById('m-mttr').textContent = `${demo.mttrMinutes?.toFixed(1) ?? '—'} min`;
  document.getElementById('m-fpr').textContent  = `${demo.falsePositivePct?.toFixed(0) ?? '—'}%`;
  document.getElementById('m-mttd-trend').innerHTML =
    '<i data-lucide="arrow-down" class="ui-icon"></i> Improving this month';
  document.getElementById('m-mttr-trend').innerHTML =
    '<i data-lucide="arrow-down" class="ui-icon"></i> Faster than manual handling';
  document.getElementById('m-fpr-trend').innerHTML =
    '<i data-lucide="arrow-down" class="ui-icon"></i> Down from default settings';
  refreshIcons(document.querySelector('.metrics-grid'));
}

// ── 30-day trend ──────────────────────────────────────
function renderTrend(trend) {
  destroyChart('trend');
  const el = document.getElementById('empty-trend');
  if (!trend.length) { el.textContent = 'No data'; el.style.display = 'flex'; return; }
  el.style.display = 'none';

  const labels = trend.map(p => shortDate(p.date));
  CHARTS.trend = new Chart(document.getElementById('ch-trend'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Time to detect (min)',
          data: trend.map(p => p.mttdMinutes),
          borderColor: '#c81e2b',
          backgroundColor: 'rgba(200,30,43,.08)',
          tension: .35, pointRadius: 2, borderWidth: 2, fill: true,
        },
        {
          label: 'Time to stop (min)',
          data: trend.map(p => p.mttrMinutes),
          borderColor: '#d97706',
          backgroundColor: 'rgba(217,119,6,.08)',
          tension: .35, pointRadius: 2, borderWidth: 2, fill: false,
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } },
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { beginAtZero: true, title: { display: true, text: 'Minutes', font: { size: 11 } } },
      },
    },
  });
}

// ── Monthly bar ───────────────────────────────────────
function renderMonthly(monthly) {
  destroyChart('monthly');
  CHARTS.monthly = new Chart(document.getElementById('ch-monthly'), {
    type: 'bar',
    data: {
      labels: monthly.map(m => m.month),
      datasets: [{
        label: 'Incidents',
        data: monthly.map(m => m.total),
        backgroundColor: 'rgba(200,30,43,.75)',
        borderRadius: 6,
        maxBarThickness: 34,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { beginAtZero: true, ticks: { precision: 0, font: { size: 11 } } },
      },
    },
  });
}

// ── Type doughnut (real 7-day) ────────────────────────
function renderTypes(perCategory) {
  destroyChart('types');
  const el = document.getElementById('empty-types');
  const nonZero = perCategory.filter(p => p.count > 0);
  if (!nonZero.length) { el.textContent = 'No alerts in last 7 days'; el.style.display = 'flex'; return; }
  el.style.display = 'none';

  CHARTS.types = new Chart(document.getElementById('ch-types'), {
    type: 'doughnut',
    data: {
      labels: perCategory.map(p => CAT_LABEL[p.key] || p.key),
      datasets: [{
        data: perCategory.map(p => p.count),
        backgroundColor: perCategory.map(p => CAT_COLOR[p.key] || '#94a3b8'),
        borderColor: '#fff',
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '58%',
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 }, padding: 10 } },
        tooltip: {
          callbacks: {
            label(ctx) {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct = total ? Math.round((ctx.parsed / total) * 100) : 0;
              return `${ctx.label}: ${ctx.parsed} (${pct}%)`;
            },
          },
        },
      },
    },
  });
}

// ── False-positive line ───────────────────────────────
function renderFpr(fpr) {
  destroyChart('fpr');
  if (!fpr.length) return;

  const labels = fpr.map(p => shortDate(p.date));
  const data   = fpr.map(p => p.pct);
  const target = Array(fpr.length).fill(15);

  CHARTS.fpr = new Chart(document.getElementById('ch-fpr'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'False Alarm Rate (%)',
          data,
          borderColor: '#d97706',
          backgroundColor: 'rgba(217,119,6,.08)',
          tension: .35, pointRadius: 2, borderWidth: 2.5, fill: true,
        },
        {
          label: 'Target — 15%',
          data: target,
          borderColor: '#16a34a',
          borderDash: [5, 5],
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false,
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } },
      },
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { min: 0, max: 35, ticks: { font: { size: 11 } } },
      },
    },
  });
}

// ── Data provenance card ──────────────────────────────
function renderProvenance(real, disclaimer) {
  const el = document.getElementById('provenance');
  el.innerHTML = `
    <p style="margin-bottom:8px">
      <strong>Live from PostgreSQL:</strong>
      ${real.totalAlerts || 0} alerts,
      ${real.totalCases || 0} cases (${real.openCases || 0} open),
      ${real.reportsGenerated || 0} reports generated.
      The "Breakdown by Attack Type" chart shows real alerts from the last 7 days.
    </p>
    <p style="color:var(--text-3);font-size:12.5px">
      ${escapeHtml(disclaimer || '')}
    </p>`;
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

// ── Boot ─────────────────────────────────────────────
loadMetrics();
setInterval(() => {
  if (document.visibilityState === 'visible') loadMetrics();
}, 60000);