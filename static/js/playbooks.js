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

// ── Icon + label per playbook key ─────────────────────
const PB_ICON = {
  ransomware:    'lock',
  bruteforce:    'key-round',
  privilege:     'arrow-up',
  fileintegrity: 'folder',
};
const SEV_LABEL = { critical:'Critical', high:'High', medium:'Medium', low:'Low' };

// ── Loader ────────────────────────────────────────────
async function loadPlaybooks() {
  const libEl = document.getElementById('playbook-library');
  try {
    const r = await fetch('/api/v1/playbooks', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    renderLibrary(body.data || []);
  } catch (err) {
    libEl.innerHTML = `
      <div style="grid-column:1/-1;padding:48px;text-align:center;color:var(--c-critical)">
        <i data-lucide="circle-x" class="ui-icon" style="width:36px;height:36px"></i>
        <div style="margin-top:10px;font-weight:700;font-size:15px">Could not load playbooks</div>
        <div style="font-size:13px;color:var(--text-3);margin-top:6px">${escapeHtml(err.message)}</div>
        <div style="margin-top:14px">
          <a href="/health" class="btn btn-secondary btn-sm">
            <i data-lucide="activity" class="ui-icon"></i> Check API health
          </a>
        </div>
      </div>`;
    refreshIcons(libEl);
  }
}

function renderLibrary(items) {
  const libEl = document.getElementById('playbook-library');
  if (!items.length) {
    libEl.innerHTML = '<div style="grid-column:1/-1;padding:48px;text-align:center;color:var(--text-3)">No playbooks defined.</div>';
    return;
  }

  libEl.innerHTML = items.map(pb => {
    const icon = PB_ICON[pb.key] || 'list-checks';
    const hasCase = !!pb.currentCase;
    const clickAction = hasCase
      ? `window.location='/incidents/${pb.currentCase.id}'`
      : `openEmptyPlaybook('${pb.key}')`;

    const footerLeft = hasCase
      ? `Active case <strong>${escapeHtml(pb.currentCase.caseRef)}</strong>
         <span class="badge ${pb.currentCase.severity}"
               style="margin-left:6px;font-size:10px;padding:1px 6px">
           <span class="bdot"></span>${SEV_LABEL[pb.currentCase.severity] || pb.currentCase.severity}
         </span>`
      : `<span style="color:var(--text-3)">No active case</span>`;

    const footerRight = hasCase
      ? `<span style="color:var(--accent);font-weight:600">Open response <i data-lucide="arrow-right" class="ui-icon"></i></span>`
      : `<span style="color:var(--text-3)">View procedure <i data-lucide="arrow-right" class="ui-icon"></i></span>`;

    return `
      <div class="playbook-card" onclick="${clickAction}">
        <div class="playbook-card-top">
          <div class="playbook-card-icon"><i data-lucide="${icon}" class="ui-icon"></i></div>
          <div style="flex:1;min-width:0">
            <div class="playbook-card-title">${escapeHtml(pb.name)}</div>
            <div class="playbook-card-meta">
              ${pb.stepCount} response steps
              ${pb.totalCases > 0
                ? ` · <strong>${pb.totalCases}</strong> case${pb.totalCases === 1 ? '' : 's'} total`
                : ''}
            </div>
          </div>
        </div>
        <div class="playbook-card-desc">${escapeHtml(pb.description)}</div>
        <div class="playbook-card-footer">
          <span>${footerLeft}</span>
          ${footerRight}
        </div>
      </div>`;
  }).join('');

  refreshIcons(libEl);
}

function openEmptyPlaybook(key) {
  alert(
    'This playbook has no active case right now.\n\n' +
    'To use it: open Incident Cases, click "Report New Incident", choose the matching attack type, ' +
    'and the response steps will become available.'
  );
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Boot ─────────────────────────────────────────────
loadPlaybooks();
setInterval(loadPlaybooks, 30000);