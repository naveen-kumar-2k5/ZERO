function refreshIcons(root = document) {
  if (!window.lucide || !lucide.createIcons) return;
  const target = root && typeof root.querySelectorAll === 'function' ? root : document;
  lucide.createIcons({ root: target, attrs: { 'stroke-width': 1.9 } });
}
document.addEventListener('DOMContentLoaded', refreshIcons);

// ── Clock ─────────────────────────────────────────────
function tickClock() {
  const ist = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }));
  const p = n => String(n).padStart(2, '0');
  document.getElementById('live-time').textContent =
    `${p(ist.getHours())}:${p(ist.getMinutes())}:${p(ist.getSeconds())} IST`;
}
tickClock(); setInterval(tickClock, 1000);

// ── Icons per service name ────────────────────────────
const ICONS = {
  'Webhook API':     'webhook',
  'UI / Flask app':  'monitor',
  'PostgreSQL':      'database',
  'Wazuh poller':    'radar',
};
const STATUS_LABEL = { ok: 'Healthy', degraded: 'Degraded', down: 'Down' };

let _autoTimer = null;
const _history = [];        // last 5 checks — {t, status, downCount, degradedCount}

// ── Load ──────────────────────────────────────────────
async function loadHealth() {
  const hero  = document.getElementById('health-hero');
  const heroT = document.getElementById('hero-title');
  const heroS = document.getElementById('hero-sub');
  const heroI = document.getElementById('hero-icon');
  const note  = document.getElementById('refresh-note');

  note.innerHTML = '<span class="spinner"></span>Checking…';

  try {
    const r    = await fetch('/api/v1/health', { cache: 'no-store' });
    const body = await r.json();
    const overall = body.status || 'down';
    const checkedAt = new Date(body.checked_at || Date.now());

    // Hero
    hero.className = 'health-hero ' + overall;
    const titles = { ok: 'All systems operational',
                     degraded: 'Some services degraded',
                     down: 'One or more services down' };
    const icons  = { ok: 'circle-check', degraded: 'triangle-alert', down: 'circle-x' };
    heroT.textContent = titles[overall] || 'Unknown state';
    heroS.textContent = `Last checked ${checkedAt.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' })} IST`;
    heroI.className   = 'health-hero-icon ' + overall;
    heroI.innerHTML   = `<i data-lucide="${icons[overall] || 'circle-help'}" class="ui-icon"></i>`;
    refreshIcons(heroI);

    // Cards
    const grid = document.getElementById('health-grid');
    const checks = body.checks || [];
    grid.innerHTML = checks.map(c => {
      const st = c.status || 'down';
      const metaItems = [];

      // Latency (HTTP checks)
      if (c.latency_ms != null) {
        metaItems.push(`
          <div class="meta-item">
            <i data-lucide="timer" class="ui-icon"></i>
            latency <strong>${c.latency_ms} ms</strong>
          </div>`);
      }

      // Rows (DB + poller checks)
      if (c.rows != null) {
        metaItems.push(`
          <div class="meta-item">
            <i data-lucide="rows-3" class="ui-icon"></i>
            rows <strong>${c.rows}</strong>
          </div>`);
      }

      // Last write age (poller)
      if (c.stale_sec != null) {
        const age = c.stale_sec < 60
          ? `${c.stale_sec}s`
          : c.stale_sec < 3600
            ? `${Math.floor(c.stale_sec/60)}m ${c.stale_sec%60}s`
            : `${Math.floor(c.stale_sec/3600)}h ${Math.floor((c.stale_sec%3600)/60)}m`;
        metaItems.push(`
          <div class="meta-item">
            <i data-lucide="clock-3" class="ui-icon"></i>
            last write <strong>${age} ago</strong>
          </div>`);
      }

      // Last seen ISO timestamp (poller)
      if (c.last_seen) {
        const local = new Date(c.last_seen)
          .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
        metaItems.push(`
          <div class="meta-item">
            <i data-lucide="calendar" class="ui-icon"></i>
            seen <strong>${escapeHtml(local)}</strong>
          </div>`);
      }

      // Oldest row (DB)
      if (c.oldest) {
        const local = new Date(c.oldest)
          .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
        metaItems.push(`
          <div class="meta-item">
            <i data-lucide="history" class="ui-icon"></i>
            oldest <strong>${escapeHtml(local)}</strong>
          </div>`);
      }

      return `
        <div class="health-card ${st}">
          <div class="health-card-top">
            <div class="health-card-name">
              <i data-lucide="${ICONS[c.name] || 'activity'}" class="ui-icon"></i>
              ${escapeHtml(c.name)}
            </div>
            <span class="health-card-status ${st}">${STATUS_LABEL[st] || st}</span>
          </div>
          <div class="health-card-detail">${escapeHtml(c.detail || '')}</div>
          ${metaItems.length ? `<div class="health-card-meta">${metaItems.join('')}</div>` : ''}
        </div>`;
    }).join('');
    refreshIcons(grid);

    // History strip
    const downCount     = checks.filter(c => c.status === 'down').length;
    const degradedCount = checks.filter(c => c.status === 'degraded').length;
    _history.unshift({
      t: checkedAt.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' }),
      status: overall,
      downCount,
      degradedCount,
    });
    if (_history.length > 5) _history.length = 5;
    renderHistory();

    note.textContent = `Updated ${new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' })} IST`;
  } catch (err) {
    hero.className = 'health-hero down';
    heroT.textContent = 'Could not reach /api/v1/health';
    heroS.textContent = err.message;
    heroI.className = 'health-hero-icon down';
    heroI.innerHTML = '<i data-lucide="circle-x" class="ui-icon"></i>';
    refreshIcons(heroI);
    note.textContent = 'Fetch failed — check that the Flask app is running.';
    _history.unshift({
      t: new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata' }),
      status: 'down', downCount: '—', degradedCount: '—'
    });
    if (_history.length > 5) _history.length = 5;
    renderHistory();
  }
}

function renderHistory() {
  const el = document.getElementById('health-history');
  if (!el) return;
  el.innerHTML = _history.map(h => {
    const cls = h.status === 'ok' ? 'ok' : h.status === 'degraded' ? 'warn' : 'err';
    const extra = h.status === 'ok'
      ? ''
      : ` · ${h.downCount} down, ${h.degradedCount} degraded`;
    return `<span class="${cls}">${h.t} — ${h.status.toUpperCase()}${extra}</span>`;
  }).join('');
}

function toggleAutoRefresh() {
  const on = document.getElementById('auto-refresh').checked;
  if (_autoTimer) { clearInterval(_autoTimer); _autoTimer = null; }
  if (on) _autoTimer = setInterval(loadHealth, 15000);
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Initial
loadHealth();
toggleAutoRefresh();