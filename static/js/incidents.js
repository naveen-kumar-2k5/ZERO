
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

// ── State ─────────────────────────────────────────────
let CUR_TAB = 'all';
let DEBOUNCE = null;
let AGENT_CACHE = [];   // last loaded agents, so updateAgentHint can look up by name

const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const STATUS_LABEL = {
  'open': 'Open', 'investigating': 'Investigating', 'containing': 'Containing',
  'contained': 'Contained', 'resolved': 'Resolved', 'false-positive': 'False Positive',
};
const STATUS_CHIP = {
  'open': 'status-open', 'investigating': 'status-investigating',
  'containing': 'status-containing', 'contained': 'status-contained',
  'resolved': 'status-resolved', 'false-positive': 'status-false-positive',
};
const THREAT_ICON = {
  'Ransomware':          'lock',
  'Brute Force':         'key-round',
  'Privilege Escalation':'arrow-up',
  'File Integrity':      'folder',
};

// ── Loader (cases table) ──────────────────────────────
function debouncedLoad() {
  clearTimeout(DEBOUNCE);
  DEBOUNCE = setTimeout(loadCases, 300);
}

async function loadCases() {
  const tbody  = document.getElementById('inc-tbody');
  const q      = document.getElementById('inc-search').value.trim();
  const assign = document.getElementById('inc-filter-assignee').value;
  const type   = document.getElementById('inc-filter-type').value;

  const p = new URLSearchParams();
  p.set('tab', CUR_TAB);
  if (q)      p.set('q', q);
  if (assign) p.set('assignee', assign);
  if (type)   p.set('type', type);

  tbody.innerHTML = `<tr><td colspan="7" style="padding:40px;text-align:center;color:var(--text-3)">
    <span class="spin"></span>Loading cases…</td></tr>`;

  try {
    const r = await fetch('/api/v1/incidents?' + p.toString(), { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    renderTable(body.data || []);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="padding:40px;text-align:center;color:var(--c-critical)">
      <strong>Could not load cases</strong><br>
      <span style="font-size:13px;color:var(--text-3)">${escapeHtml(err.message)}</span>
    </td></tr>`;
  }
}

function renderTable(rows) {
  const tbody = document.getElementById('inc-tbody');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="padding:40px;text-align:center;color:var(--text-3)">
      No cases match your filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(c => {
    const pct = c.totalSteps ? Math.round((c.curStep / c.totalSteps) * 100) : 0;
    const icon = THREAT_ICON[c.threatType] || 'triangle-alert';
    const statusCls = STATUS_CHIP[c.status] || 'status-open';
    return `
      <tr onclick="openCase(${c.id})">
        <td><strong style="font-family:var(--font-brand)">${escapeHtml(c.caseRef)}</strong></td>
        <td><span class="badge ${c.severity}"><span class="bdot"></span>${SEV_LABEL[c.severity] || c.severity}</span></td>
        <td>
          <span style="display:inline-flex;align-items:center;gap:6px;font-weight:600">
            <i data-lucide="${icon}" class="ui-icon"></i> ${escapeHtml(c.threatType)}
          </span>
          <div style="font-size:11.5px;color:var(--text-3);margin-top:2px">${escapeHtml(c.title)}</div>
        </td>
        <td style="font-size:13px">${escapeHtml(c.assignedTo || 'Unassigned')}</td>
        <td style="font-size:12px;color:var(--text-3);font-family:var(--font-brand)">${escapeHtml(c.openedAtIst || '—')}</td>
        <td style="min-width:130px">
          <div class="progress-text">${c.curStep}/${c.totalSteps} steps done</div>
          <div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>
        </td>
        <td><span class="status-chip ${statusCls}">${STATUS_LABEL[c.status] || c.status}</span></td>
      </tr>`;
  }).join('');
  refreshIcons(tbody);
}

function setTab(tab, el) {
  CUR_TAB = tab;
  document.querySelectorAll('.inc-tab').forEach(t => t.classList.remove('active'));
  if (el) el.classList.add('active');
  loadCases();
}

function openCase(id) {
  window.location = '/incidents/' + id;
}

// ── Agent picker ──────────────────────────────────────
async function loadAgentsForModal() {
  const sel  = document.getElementById('ni-agent');
  const meta = document.getElementById('ni-agent-meta');
  meta.innerHTML = '<span class="spin" style="margin-right:4px"></span>Loading agents…';

  try {
    const r = await fetch('/api/v1/automation/agents', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    AGENT_CACHE = body.data || [];

    if (!AGENT_CACHE.length) {
      sel.innerHTML = '<option value="">No agents registered</option>';
      meta.innerHTML = '<span style="color:var(--c-high)">No agents in the inventory — click Sync to import from Wazuh.</span>';
      return;
    }

    sel.innerHTML = AGENT_CACHE.map(a => {
      const proto = a.wazuhStatus ? ` · wazuh:${a.wazuhStatus}` : '';
      const auto  = a.online ? ' · automation:online'
                  : a.lastSeen ? ' · automation:offline'
                  : ' · automation:never';
      return `<option value="${escapeHtml(a.name)}">
        ${escapeHtml(a.name)} — ${escapeHtml(a.os)} — ${escapeHtml(a.ip || '?')}${proto}${auto}
      </option>`;
    }).join('');

    // Prefer an online agent if one exists
    const firstOnline = AGENT_CACHE.find(a => a.online);
    if (firstOnline) sel.value = firstOnline.name;

    updateAgentHint();
  } catch (err) {
    sel.innerHTML = '<option value="">Could not load agents</option>';
    meta.innerHTML = `<span style="color:var(--c-critical)">${escapeHtml(err.message)}</span>`;
  }
}

function updateAgentHint() {
  const sel  = document.getElementById('ni-agent');
  const meta = document.getElementById('ni-agent-meta');
  const name = sel.value;
  const a = AGENT_CACHE.find(x => x.name === name);
  if (!a) { meta.innerHTML = ''; return; }

  let dotCls = 'unknown';
  let dotTxt = 'never seen by the automation agent';
  if (a.online) {
    dotCls = 'online';
    dotTxt = a.lastSeenAge != null ? `automation online · last seen ${a.lastSeenAge}s ago`
                                   : 'automation online';
  } else if (a.lastSeen) {
    dotCls = 'offline';
    const age = a.lastSeenAge != null
      ? (a.lastSeenAge < 60 ? `${a.lastSeenAge}s` : `${Math.floor(a.lastSeenAge/60)}m`)
      : '—';
    dotTxt = `automation offline · last seen ${age} ago`;
  }

  const wazuhPart = a.wazuhStatus ? ` · Wazuh: ${a.wazuhStatus}` : '';
  meta.innerHTML =
    `<span class="dot ${dotCls}"></span>` +
    `<span>${escapeHtml(dotTxt + wazuhPart)}</span>`;
}

async function syncAgents(btn) {
  const meta = document.getElementById('ni-agent-meta');
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.classList.add('spinning');
  btn.innerHTML = '<i data-lucide="refresh-cw" class="ui-icon"></i> Syncing…';
  refreshIcons(btn);
  meta.innerHTML = '<span class="spin" style="margin-right:4px"></span>Fetching agents from Wazuh…';

  try {
    const r = await fetch('/api/v1/automation/agents/sync', { method: 'POST' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Sync failed');

    const d = body.data || {};
    meta.innerHTML = `<span style="color:var(--c-low)">Synced · ${d.inserted ?? 0} new, ${d.updated ?? 0} updated.</span>`;
    await loadAgentsForModal();
    // Preserve the "Synced" note briefly, then restore the normal hint
    setTimeout(updateAgentHint, 2500);
  } catch (err) {
    meta.innerHTML = `<span style="color:var(--c-critical)">Sync failed: ${escapeHtml(err.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.classList.remove('spinning');
    btn.innerHTML = orig;
    refreshIcons(btn);
  }
}

// ── New Incident Modal ────────────────────────────────
function openNewIncidentModal() {
  document.getElementById('ni-type').value = 'Ransomware';
  document.getElementById('ni-desc').value = '';
  document.getElementById('ni-sev-m').checked = true;
  document.getElementById('ni-assign').value = 'IT Team';
  document.getElementById('new-incident-modal').style.display = 'flex';
  refreshIcons(document.getElementById('new-incident-modal'));
  loadAgentsForModal();
}

function closeNewIncidentModal() {
  document.getElementById('new-incident-modal').style.display = 'none';
}

async function createIncident() {
  const type   = document.getElementById('ni-type').value;
  const agent  = document.getElementById('ni-agent').value;
  const desc   = document.getElementById('ni-desc').value.trim();
  const sev    = document.querySelector('input[name="ni-sev"]:checked')?.value || 'medium';
  const assign = document.getElementById('ni-assign').value;

  if (!agent) { alert('Please select the affected agent.'); return; }
  if (!desc)  { alert('Please describe what you observed.'); return; }

  const body = {
    threatType:      type,
    agent:           agent,
    title:           desc.split('.')[0].slice(0, 120),
    description:     desc,
    severity:        sev,
    assignedTo:      assign,
    dataCategories:  'To be determined',
    personsAffected: 0,
  };

  try {
    const r = await fetch('/api/v1/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const resp = await r.json();
    if (!r.ok || resp.status !== 'success') {
      throw new Error(resp.error || 'Failed to create case');
    }
    closeNewIncidentModal();
    loadCases();
    if (resp.data && resp.data.id) {
      setTimeout(() => openCase(resp.data.id), 300);
    }
  } catch (err) {
    alert('Could not create case: ' + err.message);
  }
}

// ── Helpers ───────────────────────────────────────────
function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Initial load + auto-refresh ───────────────────────
loadCases();
setInterval(() => {
  const focused = document.activeElement === document.getElementById('inc-search');
  const modalOpen = document.getElementById('new-incident-modal').style.display !== 'none';
  if (!focused && !modalOpen) loadCases();
}, 30000);
