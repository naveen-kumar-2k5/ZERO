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

const SEV_LABEL = { critical:'Critical', high:'High', medium:'Medium', low:'Low' };
let PREVIEW = null;      // current preview payload
let _certEmail = '';     // cached for copy button

// ── Populate case selector from completed cases ──────
async function loadEligibleCases() {
  const sel = document.getElementById('rpt-sel');
  try {
    const r = await fetch('/api/v1/incidents?tab=all', { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');

    const eligible = (body.data || []).filter(
      c => c.curStep >= c.totalSteps &&
           c.status !== 'false-positive'      // resolved is OK, false-positive is not
    );

    sel.innerHTML = '<option value="">Select an incident...</option>' +
      eligible.map(c =>
        `<option value="${c.id}">${escapeHtml(c.caseRef)} — ${escapeHtml(c.threatType)} — ${escapeHtml(c.openedAtIst.split(',')[0])} (${SEV_LABEL[c.severity]}, ${escapeHtml(c.status)})</option>`
      ).join('') +
      (eligible.length ? '' : '<option value="" disabled>(no cases are ready for report generation yet)</option>');

    // Honour ?case=<id> query string from the case-detail "Generate Report" button
    const params = new URLSearchParams(window.location.search);
    const cid = params.get('case');
    if (cid) {
      const opt = sel.querySelector(`option[value="${cid}"]`);
      if (opt) { sel.value = cid; onCaseChange(); }
    }
  } catch (err) {
    sel.innerHTML = '<option value="">Error loading cases</option>';
  }
}

// ── Case selected — fetch preview & show Step 2 ──────
async function onCaseChange() {
  const id = document.getElementById('rpt-sel').value;
  const s2 = document.getElementById('rpt-s2');
  const s3 = document.getElementById('rpt-s3');
  const prev = document.getElementById('rpt-preview-wrap');

  if (!id) {
    s2.style.display = 'none';
    s3.style.display = 'none';
    prev.style.display = 'none';
    PREVIEW = null;
    return;
  }

  s2.style.display = 'none';
  s3.style.display = 'none';
  prev.style.display = 'none';

  try {
    const r = await fetch(`/api/v1/reports/preview/${id}`, { cache: 'no-store' });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');
    PREVIEW = body.data;
    renderConfirm();
    s2.style.display = 'block';
    s3.style.display = 'block';
  } catch (err) {
    alert('Could not load case preview: ' + err.message);
    s2.innerHTML = `
      <div style="padding:14px;background:var(--c-critical-bg);border:1px solid var(--c-critical-border);border-radius:6px;font-size:13px;color:#991b1b">
        ${escapeHtml(err.message)}
      </div>`;
    s2.style.display = 'block';
  }
}

function renderConfirm() {
  const c = PREVIEW.case;
  document.getElementById('rpt-confirm').innerHTML = `
    <div class="confirm-item">
      <span class="confirm-icon"><i data-lucide="circle-check" class="ui-icon"></i></span>
      <div><div class="confirm-lbl">Type of attack</div><div class="confirm-val">${escapeHtml(c.threatType)}</div></div>
    </div>
    <div class="confirm-item">
      <span class="confirm-icon"><i data-lucide="circle-check" class="ui-icon"></i></span>
      <div><div class="confirm-lbl">Data at risk</div><div class="confirm-val">${escapeHtml(c.dataCategories || '—')}</div></div>
    </div>
    <div class="confirm-item">
      <span class="confirm-icon"><i data-lucide="circle-check" class="ui-icon"></i></span>
      <div><div class="confirm-lbl">People affected</div><div class="confirm-val">~${c.personsAffected || 0}</div></div>
    </div>
    <div class="confirm-item">
      <span class="confirm-icon"><i data-lucide="circle-check" class="ui-icon"></i></span>
      <div><div class="confirm-lbl">Discovered</div><div class="confirm-val">${escapeHtml(c.openedAtIst || '—')}</div></div>
    </div>
  `;
  refreshIcons(document.getElementById('rpt-confirm'));
}

// ── Generate ─────────────────────────────────────────
async function generateReport() {
  if (!PREVIEW) return;
  const btn = document.getElementById('rpt-gen-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Generating…';

  try {
    const r = await fetch('/api/v1/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caseId: PREVIEW.case.id, generatedBy: 'IT Team' }),
    });
    const body = await r.json();
    if (!r.ok || body.status !== 'success') throw new Error(body.error || 'Failed');

    PREVIEW.reportRef = body.data.reportRef;
    PREVIEW.generatedAt = body.data.createdAt;
    renderPreview();
    loadHistory();
  } catch (err) {
    alert('Could not generate report: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="file-text" class="ui-icon"></i> Generate Incident Report';
    refreshIcons(btn);
  }
}

// ── Preview renderer ─────────────────────────────────
function renderPreview() {
  const c = PREVIEW.case;
  const reportRef = PREVIEW.reportRef || `ZR-${c.caseRef}-${new Date().getFullYear()}`;
  const genTime = new Date(PREVIEW.generatedAt || Date.now())
    .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

  // Timeline → action rows
  const actHtml = PREVIEW.events
    .filter(e => ['opened','step_done','status_change','evidence','report'].includes(e.kind))
    .map(e => {
      const t = (e.createdAtIst || '').split(', ')[1] || '';
      return `<div class="rpt-action">
        <span class="rpt-action-time">${escapeHtml(t.split(' IST')[0] || '—')}</span>
        <span class="rpt-action-text">${escapeHtml(e.message)}</span>
      </div>`;
    }).join('');

  // Evidence list
  const evHtml = PREVIEW.evidence.length
    ? PREVIEW.evidence.map(e =>
        `<div class="rpt-action">
           <span class="rpt-action-time">${escapeHtml((e.kind || '').slice(0, 8))}</span>
           <span class="rpt-action-text"><strong>${escapeHtml(e.filename)}</strong>${e.notes ? ' — ' + escapeHtml(e.notes) : ''}</span>
         </div>`).join('')
    : '<div style="font-size:13px;color:var(--text-3)">No evidence attached.</div>';

  _certEmail = PREVIEW.certEmail || '';

  document.getElementById('rpt-preview').innerHTML = `
    <div class="rpt-prev-hd">
      <h2><i data-lucide="clipboard-list" class="ui-icon"></i> INCIDENT REPORT</h2>
      <p>Kumaraguru College of Technology, Coimbatore</p>
      <div class="rpt-badge">
        <i data-lucide="circle-check" class="ui-icon"></i> Regulatory reporting record
      </div>
    </div>
    <div class="rpt-body">
      <div class="rpt-section">
        <div class="rpt-sec-title">Report Information</div>
        <div class="rpt-field-grid">
          <div><div class="rpt-field-lbl">Report ID</div><div class="rpt-field-val">${escapeHtml(reportRef)}</div></div>
          <div><div class="rpt-field-lbl">Incident ID</div><div class="rpt-field-val">${escapeHtml(c.caseRef)}</div></div>
          <div><div class="rpt-field-lbl">Organisation</div><div class="rpt-field-val">Kumaraguru College of Technology</div></div>
          <div><div class="rpt-field-lbl">Data Officer</div><div class="rpt-field-val">KCT IT Department</div></div>
          <div><div class="rpt-field-lbl">Report Generated</div><div class="rpt-field-val">${escapeHtml(genTime)} IST</div></div>
          <div><div class="rpt-field-lbl">Platform</div><div class="rpt-field-val">ZeroRespond v1.0 — Team Zero, KCT</div></div>
        </div>
      </div>
      <div class="rpt-section">
        <div class="rpt-sec-title">Breach Details</div>
        <div class="rpt-field-grid">
          <div><div class="rpt-field-lbl">Type of Incident</div><div class="rpt-field-val">${escapeHtml(c.threatType)}</div></div>
          <div><div class="rpt-field-lbl">System Affected</div><div class="rpt-field-val">${escapeHtml(c.agent || '—')}</div></div>
          <div><div class="rpt-field-lbl">Data Categories</div><div class="rpt-field-val">${escapeHtml(c.dataCategories || '—')}</div></div>
          <div><div class="rpt-field-lbl">People Affected</div><div class="rpt-field-val">~${c.personsAffected || 0}</div></div>
          <div><div class="rpt-field-lbl">Date Discovered</div><div class="rpt-field-val">${escapeHtml(c.openedAtIst || '—')}</div></div>
          <div><div class="rpt-field-lbl">Severity</div><div class="rpt-field-val">${SEV_LABEL[c.severity] || c.severity}</div></div>
        </div>
      </div>
      <div class="rpt-section">
        <div class="rpt-sec-title">Response Actions Taken</div>
        <div class="rpt-action-list">${actHtml || '<div style="font-size:13px;color:var(--text-3)">No events recorded.</div>'}</div>
      </div>
      <div class="rpt-section">
        <div class="rpt-sec-title">Evidence Attached</div>
        <div class="rpt-action-list">${evHtml}</div>
      </div>
      <div class="rpt-section">
        <div class="rpt-sec-title">CERT-In Notification (6-Hour Legal Requirement)</div>
        <div class="cert-block">
          <div class="cert-note">
            <i data-lucide="clock-3" class="ui-icon"></i>
            This notification must be sent to CERT-In within <strong>6 hours</strong> of the incident being discovered — DPDP Act 2023, Section 8(6).
          </div>
          <div class="cert-email-preview">
            <div class="cert-field"><strong>To:</strong> incident@cert-in.org.in</div>
            <div class="cert-field"><strong>Subject:</strong> Data Breach Notification — KCT — ${escapeHtml(c.caseRef)}</div>
            <div class="cert-body">${escapeHtml(_certEmail.split('\n\n').slice(1).join('\n\n'))}</div>
          </div>
        </div>
      </div>
      <div style="padding-top:16px;border-top:1px solid var(--border);text-align:center;font-size:12px;color:var(--text-3)">
        ZeroRespond v1.0 &nbsp;·&nbsp; Team Zero &nbsp;·&nbsp; Kumaraguru College of Technology &nbsp;·&nbsp; Detect · Respond · Report · Repeat
      </div>
    </div>`;

  document.getElementById('rpt-preview-wrap').style.display = 'block';
  refreshIcons(document.getElementById('rpt-preview'));
  setTimeout(() => document.getElementById('rpt-preview-wrap').scrollIntoView({ behavior: 'smooth' }), 60);
}

function copyCert() {
  if (!_certEmail) return;
  navigator.clipboard.writeText(_certEmail).catch(() => {});
  const btn = document.getElementById('copy-cert-btn');
  const orig = btn.innerHTML;
  btn.innerHTML = '<i data-lucide="check" class="ui-icon"></i> Copied!';
  refreshIcons(btn);
  setTimeout(() => { btn.innerHTML = orig; refreshIcons(btn); }, 2200);
}

function resetBuilder() {
  document.getElementById('rpt-preview-wrap').style.display = 'none';
  document.getElementById('rpt-sel').value = '';
  document.getElementById('rpt-s2').style.display = 'none';
  document.getElementById('rpt-s3').style.display = 'none';
  PREVIEW = null;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Report history ────────────────────────────────────
async function loadHistory() {
  const el = document.getElementById('rpt-history');
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
          <span>${escapeHtml(row.caseRef)}</span>
          <span>${escapeHtml(row.threatType)}</span>
          <span>${escapeHtml(row.generatedAtIst)}</span>
          <span class="status-chip status-resolved" style="justify-self:start">
            <i data-lucide="circle-check" class="ui-icon"></i> Generated
          </span>
        </div>`).join('');
    }
    refreshIcons(el);
      } catch (err) {
    el.innerHTML = `<div style="padding:24px;text-align:center;color:var(--c-critical)">
      <strong>Could not load history</strong><br>
      <span style="font-size:13px;color:var(--text-3)">${escapeHtml(err.message)}</span>
    </div>`;
  }
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Boot ─────────────────────────────────────────────
loadEligibleCases();
loadHistory();