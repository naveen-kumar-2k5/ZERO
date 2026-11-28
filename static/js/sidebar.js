(async function syncSidebarOrg() {
  const sbOrg = document.getElementById('sb-org');
  if (!sbOrg) return;

  try {
    const res = await fetch('/api/v1/settings', { cache: 'no-store' });
    const body = await res.json();
    const orgName = body && body.status === 'success' && body.data && body.data.orgName;
    if (!orgName) return;

    const safeName = String(orgName)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

    sbOrg.innerHTML = `<i data-lucide="landmark" class="ui-icon"></i> ${safeName}`;

    if (typeof window.refreshIcons === 'function') {
      window.refreshIcons(sbOrg);
    } else if (window.lucide && typeof lucide.createIcons === 'function') {
      lucide.createIcons({ root: sbOrg, attrs: { 'stroke-width': 1.9 } });
    }
  } catch (_) {
    // Keep fallback organisation text if /api/v1/settings is unreachable
  }
})();