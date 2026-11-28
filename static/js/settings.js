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

// ── Load settings from API ────────────────────────────
async function loadSettings() {
  try {
    const r = await fetch('/api/v1/settings', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    fillForm(body.data);
  } catch (err) {
    const eb = document.getElementById('error-banner');
    eb.textContent = 'Could not load settings: ' + err.message;
    eb.style.display = 'block';
  }
}

function fillForm(s) {
  document.getElementById('s-orgname').value  = s.orgName  || '';
  document.getElementById('s-orgtype').value  = s.orgType  || 'Educational Institution';
  document.getElementById('s-city').value     = s.city     || '';
  document.getElementById('s-state').value    = s.state    || '';
  document.getElementById('s-dponame').value  = s.dpoName  || '';
  document.getElementById('s-dpoemail').value = s.dpoEmail || '';
  document.getElementById('s-dpophone').value = s.dpoPhone || '';
  document.getElementById('s-dpdpid').value   = s.dpdpId   || '';
  document.getElementById('s-autoreport').value = s.autoreport || 'prompt';

  // Sync sidebar org name
  const sbOrg = document.getElementById('sb-org');
  if (sbOrg && s.orgName) {
    sbOrg.innerHTML = '<i data-lucide="landmark" class="ui-icon"></i> ' + escapeHtml(s.orgName);
    refreshIcons(sbOrg);
  }

  // Show last-saved timestamp
  if (s.updatedAt) {
    const t = new Date(s.updatedAt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
    document.getElementById('updated-at').textContent = 'Last saved: ' + t + ' IST';
  }
}

async function reloadSettings() {
  await loadSettings();
  const c = document.getElementById('save-confirm');
  c.style.display = 'none';
}

// ── Save ──────────────────────────────────────────────
async function saveSettings() {
  const body = {
    orgName:    document.getElementById('s-orgname').value.trim(),
    orgType:    document.getElementById('s-orgtype').value,
    city:       document.getElementById('s-city').value.trim(),
    state:      document.getElementById('s-state').value.trim(),
    dpoName:    document.getElementById('s-dponame').value.trim(),
    dpoEmail:   document.getElementById('s-dpoemail').value.trim(),
    dpoPhone:   document.getElementById('s-dpophone').value.trim(),
    dpdpId:     document.getElementById('s-dpdpid').value.trim(),
    autoreport: document.getElementById('s-autoreport').value,
  };

  if (!body.orgName || !body.city || !body.state || !body.dpoName || !body.dpoEmail) {
    alert('Please fill all required fields (marked with *).');
    return;
  }

  const btn = document.getElementById('save-btn');
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Saving…';

  try {
    const r = await fetch('/api/v1/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const resp = await r.json();
    if (!r.ok || resp.status !== 'success') throw new Error(resp.error || 'Failed');

    fillForm(resp.data);
    const c = document.getElementById('save-confirm');
    c.style.display = 'inline';
    refreshIcons(c);
    setTimeout(() => c.style.display = 'none', 3000);
  } catch (err) {
    alert('Could not save settings: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
    refreshIcons(btn);
  }
}

function notImplemented(name) {
  alert(
    name + ' — this page is reserved for a future release.\n\n' +
    'The Settings page persists the fields used by the report generator. ' +
    'Users and Integration configuration are out of scope for the current demo.'
  );
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Boot ─────────────────────────────────────────────
loadSettings();