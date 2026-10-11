'use strict';

// ════════════════════════════════════════════════════════════════════
// Page script (REQ-002 P-02, D-17 / AC-P02-6). Served as /app.js so the
// page runs under `script-src 'self'` with no inline <script>. Loaded with
// `defer` after /vendor/lucide-1.48.0.min.js, so the DOM is parsed when it runs.
//
// Safe rendering (REQ-002 P-02). Data returned by the API reaches the DOM
// only as text nodes (textContent / createTextNode) or as attribute values
// set through setAttribute/dataset. No HTML string is ever built from API
// data, so no escaping helper is needed; inline on* handlers are not used.
// ════════════════════════════════════════════════════════════════════

/** True for same-origin absolute paths and http(s) URLs; anything else (javascript:, data:, mailto:, //host) is refused. */
function isAllowedHref(value) {
  const s = String(value);
  if (s.startsWith('/') && !s.startsWith('//') && !s.startsWith('/\\')) return true;
  return safeExternalHref(s) !== null;
}

/** Returns a normalised http/https URL or null. */
function safeExternalHref(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

/** Builds an /api path; every dynamic segment is URL-encoded. */
function apiPath(...segments) {
  return '/api/' + segments.map((s) => encodeURIComponent(String(s))).join('/');
}

/**
 * Element builder. `props.text` and string children become text nodes.
 * `style` must only receive literal style strings from this file, never API data.
 */
function el(tag, props, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'className') node.className = value;
      else if (key === 'style') node.style.cssText = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key === 'href') { if (isAllowedHref(value)) node.setAttribute('href', String(value)); }
      else node.setAttribute(key, value === true ? '' : String(value));
    }
  }
  return append(node, children);
}

function append(parent, children) {
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

function icon(name, style, className) {
  return el('i', { 'data-lucide': name, style, className });
}

function clear(node) {
  if (node) node.textContent = '';
  return node;
}

function byId(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const node = byId(id);
  if (node) node.textContent = String(text);
}

/** lucide is vendored (/vendor/lucide-1.48.0.min.js); the page must keep working if it is missing. */
function refreshIcons() {
  try {
    if (typeof lucide !== 'undefined' && lucide && typeof lucide.createIcons === 'function') lucide.createIcons();
  } catch {
    /* icons are decorative */
  }
}

function setButtonContent(button, iconName, label, spinning) {
  if (!button) return;
  clear(button);
  append(button, [icon(iconName, undefined, spinning ? 'spin' : undefined), ' ' + label]);
  refreshIcons();
}

function emptyState(iconName, title, hint, iconStyle) {
  return el('div', { className: 'empty-state' },
    icon(iconName, 'display:block; margin:0 auto 1rem;' + (iconStyle || '')),
    el('p', { text: title }),
    hint ? el('small', { text: hint }) : null);
}

function emptyRow(tbody, colspan, text) {
  tbody.appendChild(el('tr', null,
    el('td', { colspan, style: 'text-align:center; color:var(--text-muted);' }, text)));
}

function setPlaceholderOption(select, text) {
  clear(select);
  select.appendChild(el('option', { value: '' }, text));
}

// ════════════════════════════════════════════════════════════════════
// Error plumbing. Every async entry point (listener, timer, init) goes
// through fire() so no promise rejection is ever left unhandled.
// ════════════════════════════════════════════════════════════════════

function onUnexpectedError(err) {
  if (err && err.authRedirect) return;
  try {
    if (document && document.getElementById('toast-msg')) {
      showToast(err && err.message ? err.message : 'Unexpected error', 'error');
    }
  } catch {
    /* page is being torn down */
  }
}

function fire(fn) {
  return function (...args) {
    try {
      const result = fn.apply(this, args);
      if (result && typeof result.then === 'function') result.catch(onUnexpectedError);
    } catch (err) {
      onUnexpectedError(err);
    }
  };
}

function reportError(err, fallback) {
  if (err && err.authRedirect) return; // the auth form already explains what happened
  showToast(err && err.message ? err.message : fallback, 'error');
}

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
    this.authRedirect = false;
  }
}

/**
 * fetch wrapper. Session cookie is HttpOnly + SameSite=Strict: JS never
 * reads it, the browser sends it (credentials: 'same-origin').
 * Error bodies are {error, message, code}; we branch on `code`.
 * A 401 setup_required / unauthenticated switches to the matching form
 * unless `authRedirect: false` (login/setup/logout handle 401 themselves).
 */
async function api(path, options = {}) {
  const { method = 'GET', body, authRedirect = true } = options;
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  let payload = null;
  if (response.status !== 204) {
    try { payload = await response.json(); } catch { payload = null; }
  }
  if (!response.ok) {
    const code = payload && typeof payload.code === 'string' ? payload.code : '';
    let message = payload && typeof payload.message === 'string' && payload.message
      ? payload.message
      : `Request failed (HTTP ${response.status})`;
    if (response.status === 429) {
      const retryAfter = Number.parseInt(response.headers.get('Retry-After') || '', 10);
      if (Number.isFinite(retryAfter) && retryAfter > 0) message += ` Try again in ${retryAfter} seconds.`;
    }
    const err = new ApiError(response.status, code, message);
    if (response.status === 401 && authRedirect) {
      err.authRedirect = true;
      if (code === 'setup_required') showAuth('setup', '');
      else showAuth('login', currentUser ? 'Your session has ended. Please sign in again.' : '');
    }
    throw err;
  }
  return payload || {};
}

// ── Global states
const pollingScans = new Map(); // scanId -> interval id
let currentActiveView = 'dashboard';
let currentUser = null;
let authMode = null; // 'login' | 'setup' | null
let toastTimer = null;

// ── Toast notifier (message always rendered as text)
function showToast(msg, type = 'success') {
  const t = byId('toast');
  const msgEl = byId('toast-msg');
  if (!t || !msgEl) return;
  const kind = type === 'error' ? 'error' : 'success';
  msgEl.textContent = String(msg ?? '');
  t.className = `show ${kind}`;
  const toastIcon = byId('toast-icon');
  if (toastIcon) toastIcon.setAttribute('data-lucide', kind === 'success' ? 'check-circle' : 'alert-circle');
  refreshIcons();
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, 3500);
}

// ── Health checker
async function checkHealth() {
  const dot = byId('db-dot');
  try {
    const r = await fetch('/health', { credentials: 'same-origin' });
    const data = await r.json();
    if (data.status === 'healthy') {
      if (dot) {
        dot.style.background = 'var(--success)';
        dot.style.boxShadow = '0 0 6px var(--success)';
      }
      setText('db-status-text', 'Database connected');
    } else {
      if (dot) dot.style.background = 'var(--danger)';
      setText('db-status-text', 'DB error');
    }
  } catch {
    if (dot) dot.style.background = 'var(--danger)';
    setText('db-status-text', 'Backend offline');
  }
}

// ── Formatter helpers
function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(diff)) return '—';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!n || !Number.isFinite(n)) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), sizes.length - 1);
  return parseFloat((n / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(value) {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

/** Maps API severity / risk strings onto the fixed set of tag classes. */
function tagLevel(value) {
  const s = String(value || 'medium').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(s) ? s : 'low';
}

function securityLabel(row) {
  if (!row.total_vulnerabilities) return el('span', { style: 'color: var(--success);' }, '✓ Clean');
  const parts = [];
  if (row.critical_vulns) parts.push(el('span', { style: 'color: var(--danger);' }, `${row.critical_vulns} Critical`));
  if (row.high_vulns) parts.push(el('span', { style: 'color: var(--warning);' }, `${row.high_vulns} High`));
  if (!parts.length) parts.push(el('span', { style: 'color: var(--text-muted);' }, `${row.total_vulnerabilities} Med/Low`));
  const wrap = el('span');
  parts.forEach((p, i) => append(wrap, [i ? ' / ' : null, p]));
  return wrap;
}

function licenseLabel(row) {
  const n = Number(row.license_violations) || 0;
  if (n === 0) return el('span', { style: 'color: var(--success);' }, 'All Safe');
  return el('span', { style: 'color: var(--warning);' }, `${n} Alert${n > 1 ? 's' : ''}`);
}

const STATUS_BADGES = {
  completed: { cls: 'status-healthy', icon: 'check-circle', label: 'Completed' },
  running: { cls: 'status-scanning', icon: 'refresh-cw', label: 'Scanning...', spin: true },
  pending: { cls: 'status-pending', icon: 'clock', label: 'Pending' },
  queued: { cls: 'status-pending', icon: 'clock', label: 'Pending' },
  failed: { cls: 'status-critical', icon: 'x-circle', label: 'Failed' },
  cancelled: { cls: 'status-pending', icon: 'minus-circle', label: 'Cancelled' },
};

function statusBadge(status) {
  const def = Object.prototype.hasOwnProperty.call(STATUS_BADGES, status) ? STATUS_BADGES[status] : null;
  if (!def) return el('span', { className: 'status-badge status-pending' }, String(status ?? '—'));
  return el('span', { className: `status-badge ${def.cls}` },
    icon(def.icon, 'width:13px;height:13px;', def.spin ? 'spin' : undefined), def.label);
}

function isActiveStatus(status) {
  return ['pending', 'queued', 'running'].includes(status);
}

function scanActions(row) {
  if (isActiveStatus(row.status)) {
    return el('div', { className: 'progress-bar-container', style: 'width:80px;' },
      el('div', { className: 'progress-bar', style: `width: ${row.status === 'running' ? '65' : '15'}%;` }));
  }
  if (row.status === 'completed') {
    // One-click exports (REQ-007 AC-P24-8, contract section 8): plain same-origin
    // <a download> links, no fetch/Blob and no waiting screen. An empty `download`
    // value lets the browser use the server's Content-Disposition file name.
    // On 429 export_busy / 404 the browser reports the download as failed; the
    // README tells the user to retry after a few seconds (accepted limitation).
    const linkStyle = 'text-decoration:none; display:inline-flex; align-items:center; gap:0.25rem;';
    const downloadLink = (href, label, text) => el('a', {
      className: 'btn btn-sm',
      href,
      download: true,
      'aria-label': label,
      style: linkStyle,
    }, icon('download', 'width:12px;height:12px;'), ' ' + text);
    const pdfLink = downloadLink(apiPath('scans', row.id, 'exports', 'project-report.pdf'), 'Download project PDF report', 'PDF');
    const excelLink = downloadLink(apiPath('scans', row.id, 'exports', 'license-inventory.xlsx'), 'Download license inventory (Excel)', 'Excel');
    const csvLink = downloadLink(apiPath('scans', row.id, 'exports', 'license-inventory.csv'), 'Download license inventory (CSV)', 'CSV');
    const noticeLink = downloadLink(apiPath('scans', row.id, 'notice'), 'Download NOTICE file', 'NOTICE');
    const sbomLink = el('a', {
      className: 'btn btn-sm',
      href: apiPath('scans', row.id, 'sbom', 'download'),
      target: '_blank',
      rel: 'noopener',
      style: linkStyle,
    }, icon('download', 'width:12px;height:12px;'), ' SBOM');
    return el('div', { style: 'display:inline-flex; align-items:center; gap:0.375rem; flex-wrap:wrap;' },
      pdfLink, excelLink, csvLink, noticeLink, sbomLink);
  }
  return el('span', { style: 'color: var(--text-muted); font-size:0.8rem;' }, '—');
}

// ── Direct Download helper (failsafe)
function downloadDoc(docId) {
  window.location.href = apiPath('sbom', docId, 'download');
}

// ── Generate and download CycloneDX JSON (default fast download)
async function downloadCycloneDxSbom(scanId) {
  showToast('Generating CycloneDX JSON SBOM...', 'success');
  try {
    const { data } = await api(apiPath('scans', scanId, 'sbom'), { method: 'POST', body: { format: 'cyclonedx_json' } });
    downloadDoc(data.id);
    showToast('SBOM downloaded successfully!');
  } catch (e) {
    reportError(e, 'Failed to trigger SBOM download');
  }
}

// ── Scan rows (dashboard + history share one renderer)
function buildScanRow(row, idPrefix, withTrigger) {
  const tr = el('tr', { className: 'scan-row', id: `${idPrefix}-${row.id}` });
  return append(tr, [
    el('td', null,
      el('strong', null, row.project_name || '—'),
      el('br'),
      el('small', { style: 'color:var(--text-muted);' }, row.ref || 'main')),
    el('td', null, statusBadge(row.status)),
    el('td', null, row.total_dependencies ? Number(row.total_dependencies).toLocaleString() : '—'),
    el('td', null, licenseLabel(row)),
    el('td', null, securityLabel(row)),
    withTrigger
      ? el('td', { style: 'text-transform: capitalize;' }, el('span', { className: 'capsule' }, row.trigger || 'manual'))
      : null,
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, timeAgo(row.completed_at || row.started_at || row.queued_at)),
    el('td', null, scanActions(row)),
  ]);
}

function renderScanRow(row) {
  return buildScanRow(row, 'scan-row', false);
}

function renderHistoryRow(row) {
  return buildScanRow(row, 'history-row', true);
}

// ── Poll individual scan details until completed/failed
function stopPolling(scanId) {
  clearInterval(pollingScans.get(scanId));
  pollingScans.delete(scanId);
}

function stopAllPolling() {
  for (const id of Array.from(pollingScans.keys())) stopPolling(id);
}

function pollScanUntilDone(scanId) {
  if (pollingScans.has(scanId)) return;
  const interval = setInterval(fire(async () => {
    try {
      const { data } = await api(apiPath('scans', scanId));
      if (!data) throw new Error('Scan not found');

      const rowDashboard = byId(`scan-row-${scanId}`);
      if (rowDashboard) rowDashboard.replaceWith(renderScanRow(data));
      const rowHistory = byId(`history-row-${scanId}`);
      if (rowHistory) rowHistory.replaceWith(renderHistoryRow(data));
      refreshIcons();

      if (!isActiveStatus(data.status)) {
        stopPolling(scanId);
        if (data.status === 'completed') showToast(`Scan for "${data.project_name}" completed!`);
        else if (data.status === 'failed') showToast(`Scan for "${data.project_name}" failed!`, 'error');
        if (currentActiveView === 'dashboard') await updateStats();
      }
    } catch {
      stopPolling(scanId);
    }
  }), 2000);
  pollingScans.set(scanId, interval);
}

// ── Load Dashboard Scans (Recent)
async function loadScans() {
  const loading = byId('table-loading');
  const container = byId('table-container');
  const empty = byId('table-empty');
  const tbody = byId('scans-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';
  empty.style.display = 'none';

  try {
    const { data } = await api('/api/scans');

    loading.style.display = 'none';
    clear(tbody);

    if (!Array.isArray(data) || data.length === 0) {
      empty.style.display = 'block';
      return;
    }

    container.style.display = 'block';
    // Display top 10 recent scans on dashboard
    for (const scan of data.slice(0, 10)) {
      tbody.appendChild(renderScanRow(scan));
      if (isActiveStatus(scan.status)) pollScanUntilDone(scan.id);
    }
    refreshIcons();
    setText('last-updated', `Last updated: ${new Date().toLocaleTimeString()}`);
  } catch {
    loading.style.display = 'none';
    empty.style.display = 'block';
  }
}

// ── Update Dashboard statistics counters
async function updateStats() {
  try {
    const projData = await api('/api/projects');
    setText('stat-projects', Array.isArray(projData.data) ? projData.data.length : 0);

    const scanData = await api('/api/scans');
    const scans = (Array.isArray(scanData.data) ? scanData.data : []).filter((s) => s.status === 'completed');

    const totalPkgs = scans.reduce((acc, s) => acc + (Number(s.total_dependencies) || 0), 0);
    const totalLicAlerts = scans.reduce((acc, s) => acc + (Number(s.license_violations) || 0), 0);
    const totalCritical = scans.reduce((acc, s) => acc + (Number(s.critical_vulns) || 0), 0);

    animateNumber('stat-packages', totalPkgs);
    animateNumber('stat-license-alerts', totalLicAlerts);
    animateNumber('stat-critical-cves', totalCritical);
  } catch {
    ['stat-projects', 'stat-packages', 'stat-license-alerts', 'stat-critical-cves'].forEach((id) => setText(id, '—'));
  }
}

function animateNumber(id, target) {
  const node = byId(id);
  if (!node) return;
  const start = parseInt(node.textContent, 10) || 0;
  if (start === target) { node.textContent = target.toLocaleString(); return; }
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduceMotion || typeof requestAnimationFrame !== 'function') { node.textContent = target.toLocaleString(); return; }
  const duration = 600;
  const startTime = performance.now();
  function step(now) {
    const p = Math.min((now - startTime) / duration, 1);
    node.textContent = Math.round(start + (target - start) * p).toLocaleString();
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Dashboard "Vulnerability data" panel (REQ-005 contract section 6).
// Read-only: one GET, no write request. Every API value reaches the DOM
// as text only (el()/textContent); none goes into style/href/className.
const VULN_RUN_LABELS = {
  completed: 'Completed',
  partial: 'Partial',
  failed: 'Failed',
  interrupted: 'Interrupted',
  disabled: 'Skipped (lookup disabled)',
};

const VULN_PROJECT_STATUS_TEXT = {
  partial: 'vulnerability data partial',
  unavailable: 'vulnerability data unavailable',
  disabled: 'vulnerability lookup disabled',
};

// Guards against an older response overwriting a newer one (load + 30 s refresh can overlap).
let vulnDataRequestSeq = 0;

function hasOwn(obj, key) {
  return obj !== null && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key);
}

/** Locale time for an ISO timestamp; null/invalid -> `fallback`. */
function vulnTime(iso, fallback) {
  if (typeof iso !== 'string' || iso === '') return fallback;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? fallback : d.toLocaleString();
}

function vulnNumber(value) {
  return Number(value).toLocaleString();
}

function vulnMutedParagraph(text) {
  return el('p', { style: 'color: var(--text-muted);', text });
}

function setVulnDataBody(state, children) {
  const body = byId('vuln-data-body');
  if (!body) return;
  clear(body);
  body.dataset.state = state;
  append(body, children);
}

function vulnRecheckValue(settings) {
  if (settings.recheck_enabled === false) return 'Disabled (VULNERABILITY_RECHECK=off)';
  if (settings.lookup_enabled === false) return 'Disabled (VULNERABILITY_LOOKUP=off)';
  return `Every ${vulnNumber(settings.interval_hours)} h`;
}

function vulnLastRunValue(scheduler, lastRun) {
  if (scheduler.current_run) return `Running since ${vulnTime(scheduler.current_run.started_at, '—')}`;
  if (lastRun === null || lastRun === undefined) return 'Never run';
  const label = hasOwn(VULN_RUN_LABELS, lastRun.status) ? VULN_RUN_LABELS[lastRun.status] : String(lastRun.status ?? '—');
  return `${label} · ${vulnTime(lastRun.finished_at, '—')}`;
}

function vulnNextCheckValue(scheduler, generatedAt) {
  if (scheduler.paused === true) return 'Paused';
  const next = scheduler.next_check_earliest_at;
  if (next === null || next === undefined) return '—';
  const nextMs = new Date(next).getTime();
  const nowMs = new Date(generatedAt).getTime();
  if (Number.isNaN(nextMs)) return '—';
  if (!Number.isNaN(nowMs) && nextMs <= nowMs) return 'Due now';
  return vulnTime(next, '—');
}

function vulnDataRows(data) {
  const settings = data.settings || {};
  const scheduler = data.scheduler || {};
  const lastRun = data.last_run ?? null;
  const expiry = data.risk_acceptance_expiry || {};

  const rows = [
    ['Daily recheck', vulnRecheckValue(settings)],
    ['Last recheck', vulnLastRunValue(scheduler, lastRun)],
    ['New findings (last recheck)', lastRun === null ? '—' : vulnNumber(lastRun.findings_opened)],
  ];
  if (lastRun !== null && Number(lastRun.packages_unchecked) > 0) {
    rows.push(['Packages not checked (last recheck)', vulnNumber(lastRun.packages_unchecked)]);
  }
  rows.push(
    ['Next check', vulnNextCheckValue(scheduler, data.generated_at)],
    ['Risk acceptances reopened (last 7 days)', vulnNumber(expiry.reopened_last_7_days)],
    ['Last expiry check', vulnTime(expiry.last_evaluated_at, 'Not yet evaluated')],
  );

  return el('table', null,
    el('tbody', null, rows.map(([label, value]) => el('tr', null,
      el('th', { scope: 'row', style: 'width: 45%; padding: 0.75rem 1rem;', text: label }),
      el('td', { style: 'padding: 0.75rem 1rem;', text: value })))));
}

function vulnDataWarnings(data) {
  const projects = Array.isArray(data.projects) ? data.projects : [];
  const incomplete = projects.filter((p) => p && p.vulnerability_data_status !== 'complete');
  const counts = data.project_status_counts || {};
  let total = 0;
  for (const [key, value] of Object.entries(counts)) {
    if (key !== 'complete') total += Number(value) || 0;
  }

  const nodes = [];
  if (incomplete.length === 0 && total === 0) {
    nodes.push(el('p', { style: 'margin-top: 1rem;', text: 'All projects have complete vulnerability data.' }));
  } else {
    nodes.push(el('p', { style: 'margin-top: 1rem; font-weight: 600;', text: `Projects with incomplete vulnerability data (${vulnNumber(total)})` }));
    nodes.push(el('ul', { id: 'vuln-data-warnings', style: 'margin: 0.5rem 0 0 1.25rem;' },
      incomplete.map((p) => {
        const status = p.vulnerability_data_status;
        let description;
        if (status === null || status === undefined) description = 'not checked yet';
        else if (hasOwn(VULN_PROJECT_STATUS_TEXT, status)) description = VULN_PROJECT_STATUS_TEXT[status];
        else description = String(status);
        return el('li', { text: `${String(p.project_name ?? '')}: ${description}` });
      })));
  }
  if (data.projects_truncated === true) {
    nodes.push(vulnMutedParagraph('Showing the first 500 projects.'));
  }
  return nodes;
}

async function loadVulnerabilityDataStatus() {
  const body = byId('vuln-data-body');
  if (!body) return;
  const seq = ++vulnDataRequestSeq;
  // Loading text only until the first successful render; a refresh keeps the current panel.
  if (body.dataset.state !== 'ready') {
    setVulnDataBody('loading', [vulnMutedParagraph('Loading vulnerability data status...')]);
  }
  try {
    const { data } = await api('/api/vulnerability-data/status');
    if (seq !== vulnDataRequestSeq) return;
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('malformed body');
    const content = [vulnDataRows(data), ...vulnDataWarnings(data)];
    setVulnDataBody('ready', content);
  } catch (err) {
    if (seq !== vulnDataRequestSeq) return;
    if (err && err.authRedirect) return; // the auth form already explains what happened
    // Server message is intentionally not shown (contract 6.3); previous content is dropped.
    setVulnDataBody('error', [vulnMutedParagraph('Vulnerability data status could not be loaded.')]);
  }
}

// ── Load Scan History Tab
async function loadAllScansHistory() {
  const loading = byId('scans-list-loading');
  const container = byId('scans-list-container');
  const tbody = byId('scans-list-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';

  try {
    const { data } = await api('/api/scans');

    loading.style.display = 'none';
    clear(tbody);
    container.style.display = 'block';

    if (!Array.isArray(data) || data.length === 0) {
      emptyRow(tbody, 8, 'No scans registered');
      return;
    }

    for (const scan of data) {
      tbody.appendChild(renderHistoryRow(scan));
      if (isActiveStatus(scan.status)) pollScanUntilDone(scan.id);
    }
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, 'Failed to load scan history');
  }
}

// ── Load Projects Tab
const CRITICALITY_STYLES = {
  critical: 'color: var(--danger); background: rgba(239,68,68,0.1);',
  high: 'color: var(--danger); background: rgba(239,68,68,0.1);',
  medium: 'color: var(--warning); background: rgba(245,158,11,0.1);',
};

function renderProjectRow(p) {
  const critStyle = Object.prototype.hasOwnProperty.call(CRITICALITY_STYLES, p.criticality)
    ? CRITICALITY_STYLES[p.criticality]
    : 'color: var(--success); background: rgba(16,185,129,0.1);';

  // Only http/https URLs become links; local paths and anything else stay plain text.
  const repoHref = safeExternalHref(p.repo_url);
  const repoContent = repoHref
    ? el('a', { href: repoHref, target: '_blank', rel: 'noopener noreferrer', style: 'color: var(--primary); text-decoration: none;' }, p.repo_url)
    : (p.repo_url || '—');

  const ecosystems = (Array.isArray(p.ecosystems) ? p.ecosystems : [])
    .map((e) => el('span', { className: 'capsule', style: 'margin-right:0.25rem;' }, e));

  // Values travel in data-* attributes and are read back from dataset — never interpolated into code.
  const scanButton = el('button', {
    className: 'btn btn-sm',
    type: 'button',
    dataset: { action: 'scan-project', projectId: String(p.id ?? ''), projectName: String(p.name ?? '') },
  }, icon('play', 'width:12px;height:12px;'), ' Scan Now');

  return el('tr', null,
    el('td', null, el('strong', null, p.name ?? '—')),
    el('td', null, el('span', { className: 'status-badge', style: critStyle }, p.criticality ?? '—')),
    el('td', { style: 'font-family: monospace; font-size: 0.8rem; color: var(--text-muted);' }, repoContent),
    el('td', null, ecosystems.length ? ecosystems : el('span', { style: 'color:var(--text-muted)' }, '—')),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, timeAgo(p.created_at)),
    el('td', null, scanButton));
}

async function loadProjectsList() {
  const loading = byId('projects-loading');
  const container = byId('projects-container');
  const tbody = byId('projects-list-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';

  try {
    const { data } = await api('/api/projects');

    loading.style.display = 'none';
    clear(tbody);
    container.style.display = 'block';

    if (!Array.isArray(data) || data.length === 0) {
      emptyRow(tbody, 6, 'No projects registered');
      return;
    }

    for (const p of data) tbody.appendChild(renderProjectRow(p));
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, 'Failed to load projects');
  }
}

async function triggerManualScan(projectId, name) {
  showToast(`Scheduling scan for "${name}"...`, 'success');
  try {
    await api('/api/scans', { method: 'POST', body: { projectId, trigger: 'manual' } });
    showToast('Scan queued successfully!');
    // Return to main dashboard view to display scanning progress
    await switchView('dashboard');
  } catch (e) {
    reportError(e, 'Failed to trigger scan');
  }
}

// ── Dropdowns Populator for Scans (Vulnerabilities and SBOM)
async function populateScansDropdown(selectId, loader) {
  const select = byId(selectId);
  setPlaceholderOption(select, 'Loading completed scans...');

  try {
    const { data } = await api('/api/scans');
    const completed = (Array.isArray(data) ? data : []).filter((s) => s.status === 'completed');
    clear(select);

    if (completed.length === 0) {
      setPlaceholderOption(select, 'No completed scans found');
      return;
    }

    for (const scan of completed) {
      select.appendChild(el('option', { value: String(scan.id) },
        `${scan.project_name} - ${scan.ref} (${formatDate(scan.completed_at)})`));
    }
  } catch (e) {
    setPlaceholderOption(select, 'Failed to fetch scans');
    reportError(e, 'Failed to fetch scans');
    return;
  }
  // Load the view for the first (pre-selected) scan.
  await loader();
}

// ── Load Vulnerabilities Tab
function renderFinding(f) {
  const badges = el('div');
  let iconName;
  let iconColor;
  let iconBg;

  if (f.finding_type === 'security') {
    const sev = tagLevel(f.severity);
    append(badges, [
      el('span', { className: `tag tag-${sev}` }, f.severity ?? 'medium'),
      ' ',
      el('span', { className: `tag tag-${sev}` }, `CVSS ${f.cvss_score || '—'}`),
    ]);
    if (f.cve_id) append(badges, [' ', el('span', { className: 'capsule' }, f.cve_id)]);

    iconName = 'shield-alert';
    if (sev === 'critical' || sev === 'high') {
      iconColor = 'var(--danger)';
      iconBg = 'rgba(239,68,68,0.15)';
    } else if (sev === 'medium') {
      iconColor = 'var(--warning)';
      iconBg = 'rgba(245,158,11,0.15)';
    } else {
      iconColor = 'var(--text-muted)';
      iconBg = 'rgba(255,255,255,0.06)';
    }
  } else {
    iconName = 'scale';
    iconColor = 'var(--warning)';
    iconBg = 'rgba(245,158,11,0.15)';
    const riskText = String(f.risk_level || 'medium').toLowerCase();
    append(badges, [
      el('span', { className: 'tag tag-violation' }, 'License Alert'),
      ' ',
      el('span', { className: `tag tag-${tagLevel(riskText)}` }, `${riskText} risk`),
    ]);
    if (f.detected_license) append(badges, [' ', el('span', { className: 'capsule' }, f.detected_license)]);
  }

  const description = f.vuln_description
    || `Package "${f.package_name}" is using license "${f.detected_license}" which triggers risk constraints under active policy "${f.applied_policy || 'Default prohibited list'}".`;

  return el('div', { className: 'finding-item' },
    el('div', { className: 'finding-icon', style: `background: ${iconBg}; color: ${iconColor};` }, icon(iconName)),
    el('div', { className: 'finding-info' },
      el('div', { className: 'finding-title-row' },
        el('h4', { className: 'finding-title' }, f.vuln_title || f.normalized_license || 'Unknown Policy Risk'),
        badges),
      el('div', { className: 'finding-meta' },
        el('span', null, 'Package: ', el('strong', null, `${f.package_name}@${f.package_version}`)),
        el('span', null, 'Type: ', el('span', { className: 'capsule', style: 'text-transform: capitalize;' }, f.finding_type ?? '—')),
        el('span', null, 'Status: ', el('span', { className: 'capsule', style: 'color:var(--danger);' }, f.status ?? '—'))),
      el('p', { className: 'finding-description' }, description),
      f.fix_version
        ? el('div', { style: 'margin-top:0.4rem; font-size:0.8rem; color:var(--success);' }, 'Fixed in: ', el('strong', null, f.fix_version))
        : null));
}

async function loadScanFindings() {
  const scanId = byId('findings-scan-select').value;
  const container = byId('findings-container');
  const loading = byId('findings-loading');

  if (!scanId) {
    clear(container).appendChild(emptyState('alert-triangle', 'No scan selected', 'Select a completed scan above to view its findings.'));
    refreshIcons();
    return;
  }

  loading.style.display = 'block';
  container.style.display = 'none';

  try {
    const { data } = await api(apiPath('scans', scanId, 'findings'));

    loading.style.display = 'none';
    container.style.display = 'block';
    clear(container);

    if (!Array.isArray(data) || data.length === 0) {
      container.appendChild(emptyState('shield-check', 'Compliance Clean!', 'No vulnerabilities or license risks were found for this scan.', ' color:var(--success); opacity:1;'));
      refreshIcons();
      return;
    }

    for (const f of data) container.appendChild(renderFinding(f));
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    container.style.display = 'block';
    clear(container).appendChild(el('div', { className: 'empty-state' }, el('p', null, 'Error loading findings')));
    reportError(e, 'Error loading findings');
  }
}

// ── Load SBOM Tab
const SBOM_FORMAT_LABELS = {
  cyclonedx_json: 'CycloneDX (JSON)',
  cyclonedx_xml: 'CycloneDX (XML)',
  spdx_json: 'SPDX (JSON)',
  spdx_tag_value: 'SPDX (Tag-Value)',
};

function renderSbomRow(doc) {
  const formatLabel = Object.prototype.hasOwnProperty.call(SBOM_FORMAT_LABELS, doc.format) ? SBOM_FORMAT_LABELS[doc.format] : doc.format;
  return el('tr', null,
    el('td', null, el('strong', null, formatLabel ?? '—')),
    el('td', null, el('span', { className: 'capsule' }, doc.specVersion ?? '—')),
    el('td', null, formatBytes(doc.fileSizeBytes)),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, formatDate(doc.generatedAt)),
    el('td', { style: 'font-family: monospace; font-size: 0.78rem; color: var(--text-muted);' }, `${String(doc.checksumSha256 ?? '').slice(0, 16)}...`),
    el('td', null,
      el('a', {
        className: 'btn btn-sm',
        href: apiPath('sbom', doc.id, 'download'),
        target: '_blank',
        rel: 'noopener',
        style: 'text-decoration:none; display:inline-flex; align-items:center; gap:0.25rem;',
      }, icon('download', 'width:12px;height:12px;'), ' Download')));
}

async function loadScanSboms() {
  const scanId = byId('sbom-scan-select').value;
  const container = byId('sbom-manager-container');
  const empty = byId('sbom-empty-state');
  const loading = byId('sbom-loading');
  const tbody = byId('sbom-documents-tbody');
  const tableEmpty = byId('sbom-docs-empty');
  const tableWrapper = byId('sbom-table-wrapper');

  if (!scanId) {
    container.style.display = 'none';
    empty.style.display = 'block';
    return;
  }

  loading.style.display = 'block';
  container.style.display = 'none';
  empty.style.display = 'none';

  try {
    const { data } = await api(apiPath('scans', scanId, 'sbom'));

    loading.style.display = 'none';
    container.style.display = 'block';
    clear(tbody);

    if (!Array.isArray(data) || data.length === 0) {
      tableEmpty.style.display = 'block';
      tableWrapper.style.display = 'none';
      return;
    }

    tableEmpty.style.display = 'none';
    tableWrapper.style.display = 'block';
    for (const doc of data) tbody.appendChild(renderSbomRow(doc));
    refreshIcons();
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, 'Failed to load SBOM documents');
  }
}

async function generateNewSbom() {
  const scanId = byId('sbom-scan-select').value;
  const format = byId('sbom-format-select').value;
  const genBtn = byId('generate-sbom-btn');

  if (!scanId) return;

  genBtn.disabled = true;
  setButtonContent(genBtn, 'loader-2', 'Generating...', true);

  try {
    await api(apiPath('scans', scanId, 'sbom'), { method: 'POST', body: { format } });
    showToast('SBOM document generated successfully!');
    await loadScanSboms();
  } catch (e) {
    reportError(e, 'Failed to generate SBOM');
  } finally {
    genBtn.disabled = false;
    setButtonContent(genBtn, 'plus', 'Generate Document');
  }
}

// ── Load Users & Roles Tab
function renderUserRow(u) {
  const roles = (Array.isArray(u.roles) ? u.roles : []).map((role) => el('span', {
    className: 'capsule',
    style: 'background:rgba(139,92,246,0.1); color:var(--primary); font-weight:600; text-transform:capitalize; margin-right:0.25rem;',
  }, role));
  return el('tr', null,
    el('td', null, el('strong', null, u.display_name || '—')),
    // Plain text: only http/https may be used as href (no mailto: built from API data).
    el('td', { style: 'color:var(--primary);' }, u.email || '—'),
    el('td', null, roles),
    el('td', null, el('span', { className: 'status-badge status-healthy', style: 'text-transform: capitalize;' }, u.status || 'active')),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, timeAgo(u.created_at)));
}

async function loadUsersList() {
  const loading = byId('users-loading');
  const container = byId('users-container');
  const tbody = byId('users-list-tbody');

  loading.style.display = 'block';
  container.style.display = 'none';

  try {
    const { data } = await api('/api/users');

    loading.style.display = 'none';
    container.style.display = 'block';
    clear(tbody);

    if (!Array.isArray(data) || data.length === 0) {
      emptyRow(tbody, 5, 'No users registered');
      return;
    }

    for (const u of data) tbody.appendChild(renderUserRow(u));
  } catch (e) {
    loading.style.display = 'none';
    reportError(e, 'Failed to load users');
  }
}

// ════════════════════════════════════════════════════════════════════
// API Keys view (REQ-007 AC-AK-1…4, contract section 9; REQ-002 D-22).
// One-time reveal rule: the plain key lives only in the local variable of the
// function that handles the POST response and in the `value` property of
// #api-key-value. It is never assigned to a module-level variable, written to
// localStorage/sessionStorage/URL/console, or put into an error/toast text.
// The reveal panel is removed on Done, view switch, pagehide and session end.
// ════════════════════════════════════════════════════════════════════

/** Metadata only: true/false once the list has loaded, null while unknown. */
let apiKeysHasActive = null;
let apiKeysLoadSeq = 0;

function removeApiKeyReveal() {
  const panel = byId('api-key-reveal');
  if (!panel) return;
  const field = byId('api-key-value');
  if (field) field.value = '';
  panel.remove();
}

function setApiKeysState(state) {
  const body = byId('api-keys-body');
  if (!body) return;
  body.dataset.state = state;
  const parts = { loading: 'api-keys-loading', error: 'api-keys-error', empty: 'api-keys-empty', ready: 'api-keys-table' };
  for (const [name, id] of Object.entries(parts)) {
    const node = byId(id);
    if (node) node.hidden = name !== state;
  }
}

function renderApiKeyRow(row) {
  const prefix = String(row.keyPrefix ?? '');
  const active = row.revokedAt === null || row.revokedAt === undefined;
  let action = null;
  if (active) {
    action = el('button', {
      type: 'button',
      className: 'btn btn-sm',
      'aria-label': `Revoke API key ${prefix}`,
    }, 'Revoke');
    action.addEventListener('click', fire(() => revokeApiKey(row.id, prefix, action)));
  }
  return el('tr', null,
    el('td', null, row.name ? String(row.name) : '—'),
    el('td', null, el('code', null, prefix)),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, formatDate(row.createdAt)),
    el('td', { style: 'color:var(--text-muted); font-size:0.85rem;' }, row.lastUsedAt ? formatDate(row.lastUsedAt) : 'Never'),
    el('td', null, active
      ? el('span', { className: 'status-badge status-healthy' }, 'Active')
      : el('span', { className: 'status-badge status-pending' }, `Revoked ${formatDate(row.revokedAt)}`)),
    el('td', null, action));
}

async function loadApiKeys() {
  const seq = ++apiKeysLoadSeq;
  setApiKeysState('loading');
  try {
    const { data } = await api('/api/auth/api-keys');
    if (seq !== apiKeysLoadSeq) return;
    const rows = Array.isArray(data) ? data.filter((r) => r && typeof r === 'object') : [];
    apiKeysHasActive = rows.some((r) => r.revokedAt === null || r.revokedAt === undefined);
    const tbody = clear(byId('api-keys-tbody'));
    for (const r of rows) tbody.appendChild(renderApiKeyRow(r));
    setApiKeysState(rows.length ? 'ready' : 'empty');
    refreshIcons();
  } catch (e) {
    if (seq !== apiKeysLoadSeq) return;
    apiKeysHasActive = null;
    setApiKeysState('error');
    reportError(e, 'Could not load API keys');
  }
}

/** Builds the one-time reveal panel. `keyValue` is only held by this call and the input's value property. */
function showApiKeyReveal(keyId, keyValue) {
  removeApiKeyReveal();
  const slot = byId('api-key-reveal-slot');
  if (!slot) return;

  const field = el('input', {
    type: 'text',
    id: 'api-key-value',
    className: 'form-control',
    readonly: true,
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-label': 'New API key',
    style: 'flex:1; min-width:240px; font-family:monospace;',
  });
  // Property, not attribute: the key does not appear in serialised markup.
  field.value = keyValue;

  const status = el('span', { id: 'api-key-copy-status', 'aria-live': 'polite', style: 'color:var(--text-muted); font-size:0.85rem;' });
  const copyBtn = el('button', { type: 'button', id: 'api-key-copy-btn', className: 'btn btn-sm' }, icon('copy', 'width:12px;height:12px;'), ' Copy');
  const doneBtn = el('button', { type: 'button', id: 'api-key-dismiss-btn', className: 'btn btn-sm btn-ghost' }, 'Done');

  copyBtn.addEventListener('click', fire(async () => {
    const current = byId('api-key-value');
    if (!current) return;
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(current.value);
      status.textContent = 'Copied to clipboard';
    } catch {
      current.focus();
      current.select();
      status.textContent = 'Press Ctrl+C to copy';
    }
  }));
  doneBtn.addEventListener('click', () => {
    removeApiKeyReveal();
    const createBtn = byId('api-key-create-btn');
    if (createBtn) createBtn.focus();
  });

  const panel = el('div', {
    id: 'api-key-reveal',
    dataset: { keyId: String(keyId ?? '') },
    style: 'background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.35); border-radius:14px; padding:1rem 1.25rem; margin-top:1rem;',
  },
    el('p', { style: 'margin-bottom:0.75rem; font-weight:600;' }, 'Copy this key now. It will not be shown again.'),
    el('div', { style: 'display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;' }, field, copyBtn, doneBtn),
    el('div', { style: 'margin-top:0.5rem; min-height:1.2rem;' }, status));
  slot.appendChild(panel);
  refreshIcons();
  field.focus();
  field.select();
}

async function createApiKey() {
  const btn = byId('api-key-create-btn');
  const nameInput = byId('api-key-name');
  if (!btn || !nameInput || btn.disabled) return;
  const name = nameInput.value.trim();
  // Unknown list state (still loading or failed) is treated as "may have an active key".
  if (apiKeysHasActive !== false
    && !window.confirm('Creating a new key revokes the current active key. Continue?')) return;

  btn.disabled = true;
  const viewAtStart = currentActiveView;
  try {
    const { data } = await api('/api/auth/api-keys', { method: 'POST', body: name ? { name } : {} });
    const valid = data && typeof data.key === 'string' && data.key !== '';
    if (!valid) throw new Error('Unexpected response from the server');
    nameInput.value = '';
    if (!currentUser || currentActiveView !== 'api-keys' || viewAtStart !== 'api-keys') {
      // The view was left (or the session ended) while the request was in flight:
      // the key is not rendered into a hidden view.
      showToast('A new API key was created but not shown because the page changed. Create another key to see it.', 'error');
    } else {
      showApiKeyReveal(data.id, data.key);
    }
    await loadApiKeys();
  } catch (e) {
    reportError(e, 'Could not create API key');
  } finally {
    btn.disabled = false;
  }
}

async function revokeApiKey(id, prefix, button) {
  if (!window.confirm(`Revoke API key ${prefix}? Clients using it will stop working.`)) return;
  if (button) button.disabled = true;
  try {
    await api(apiPath('auth', 'api-keys', id), { method: 'DELETE' });
    const panel = byId('api-key-reveal');
    if (panel && panel.dataset.keyId === String(id)) removeApiKeyReveal();
    showToast('API key revoked');
    await loadApiKeys();
  } catch (e) {
    if (button && button.isConnected) button.disabled = false;
    reportError(e, 'Could not revoke API key');
  }
}

// ── Modal Handlers
function openModal() {
  byId('scanModal').classList.add('open');
  const nameInput = byId('projectName');
  if (nameInput) nameInput.focus();
}
function closeModal() {
  const modal = byId('scanModal');
  if (!modal) return;
  modal.classList.remove('open');
  byId('projectName').value = '';
  byId('repoPath').value = '';
}

// ── Launch Scan modal submission
async function launchScan() {
  const name = byId('projectName').value.trim();
  const repoPath = byId('repoPath').value.trim();
  const ecosystems = Array.from(byId('ecosystems').selectedOptions).map((o) => o.value);

  if (!name) { showToast('Project name is required', 'error'); return; }
  if (!repoPath) { showToast('Repository path is required', 'error'); return; }

  const launchBtn = byId('launch-btn');
  launchBtn.disabled = true;
  setButtonContent(launchBtn, 'loader-2', 'Creating...', true);

  try {
    // 1. Create project
    const { data: project } = await api('/api/projects', { method: 'POST', body: { name, repoUrl: repoPath, ecosystems } });
    // 2. Queue scan
    await api('/api/scans', { method: 'POST', body: { projectId: project.id, trigger: 'manual' } });

    closeModal();
    showToast(`Scan queued for "${name}". Results will appear shortly.`);
    // Force switch to Dashboard to view progress
    await switchView('dashboard');
  } catch (e) {
    reportError(e, 'Launch failed');
  } finally {
    launchBtn.disabled = false;
    setButtonContent(launchBtn, 'play', 'Launch Scanner');
  }
}

// ── View router
const VIEWS = {
  dashboard: {
    title: 'OSS License & Security Dashboard',
    subtitle: 'Real-time open source package compliance metrics',
    headerActions: true,
    load: () => Promise.all([loadScans(), updateStats(), loadVulnerabilityDataStatus()]),
    refresh: () => Promise.all([loadScans(), updateStats(), loadVulnerabilityDataStatus()]),
  },
  scans: {
    title: 'Scan History',
    subtitle: 'Historical log of compliance taramaları',
    load: () => loadAllScansHistory(),
    refresh: () => loadAllScansHistory(),
  },
  findings: {
    title: 'Vulnerabilities & Findings',
    subtitle: 'Security vulnerabilities and license policy alerts',
    load: () => populateScansDropdown('findings-scan-select', loadScanFindings),
    refresh: () => loadScanFindings(),
  },
  projects: {
    title: 'Projects',
    subtitle: 'Manage registered local codebases and integration repositories',
    load: () => loadProjectsList(),
    refresh: () => loadProjectsList(),
  },
  sbom: {
    title: 'SBOM Center',
    subtitle: 'Software Bill of Materials (SBOM) generation and download registry',
    load: () => populateScansDropdown('sbom-scan-select', loadScanSboms),
    refresh: () => loadScanSboms(),
  },
  users: {
    title: 'Users & Roles',
    subtitle: 'Access management and role-based permissions',
    load: () => loadUsersList(),
    refresh: () => loadUsersList(),
  },
  'api-keys': {
    title: 'API Keys',
    subtitle: 'Personal API key for the oss-risk CLI and CI',
    // refreshAll only reloads the list; it never removes or rebuilds the reveal panel.
    load: () => loadApiKeys(),
    refresh: () => loadApiKeys(),
  },
};

async function switchView(targetView) {
  if (!Object.prototype.hasOwnProperty.call(VIEWS, targetView)) return;
  const cfg = VIEWS[targetView];
  // A freshly created API key is shown only while the API Keys view stays open.
  if (!(targetView === 'api-keys' && currentActiveView === 'api-keys')) removeApiKeyReveal();

  document.querySelectorAll('#sidebar-nav .nav-item').forEach((b) => {
    const active = b.dataset.view === targetView;
    b.classList.toggle('active', active);
    if (active) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  currentActiveView = targetView;

  document.querySelectorAll('.view-section').forEach((sec) => { sec.style.display = 'none'; });
  byId(`view-${targetView}`).style.display = 'block';

  setText('page-title', cfg.title);
  setText('page-subtitle', cfg.subtitle);
  document.querySelector('.header-actions').style.display = cfg.headerActions ? 'flex' : 'none';

  await cfg.load();
}

// ── Global refresher
async function refreshAll() {
  const refreshIcon = byId('refresh-icon');
  if (refreshIcon) refreshIcon.classList.add('spin');
  try {
    await Promise.all([VIEWS[currentActiveView].refresh(), checkHealth()]);
  } finally {
    const iconAfter = byId('refresh-icon');
    if (iconAfter) iconAfter.classList.remove('spin');
  }
}

// ════════════════════════════════════════════════════════════════════
// Auth (AC-P02-4): 401 setup_required -> setup form, 401 unauthenticated
// -> login form. Password values are never stored or logged; the fields
// are cleared after each attempt.
// ════════════════════════════════════════════════════════════════════

const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 1024;

function setAuthMessage(text, kind) {
  const box = byId('auth-error');
  if (!box) return;
  box.textContent = text ? String(text) : '';
  box.className = `auth-message ${kind === 'info' ? 'info' : 'error'}`;
}

/** Clears data rendered for the previous session so it does not linger in the DOM. */
function clearAppData() {
  ['scans-tbody', 'scans-list-tbody', 'projects-list-tbody', 'users-list-tbody', 'sbom-documents-tbody', 'api-keys-tbody'].forEach((id) => clear(byId(id)));
  apiKeysHasActive = null;
  const keyName = byId('api-key-name');
  if (keyName) keyName.value = '';
  ['findings-scan-select', 'sbom-scan-select'].forEach((id) => clear(byId(id)));
  const findings = byId('findings-container');
  if (findings) clear(findings).appendChild(emptyState('alert-triangle', 'No scan selected', 'Select a completed scan above to view its dependency findings.'));
  ['stat-projects', 'stat-packages', 'stat-license-alerts', 'stat-critical-cves'].forEach((id) => setText(id, '—'));
  setText('current-user-name', '');
  setText('last-updated', '');
}

function showAuth(mode, notice) {
  const wasInApp = currentUser !== null;
  currentUser = null;
  stopAllPolling();
  closeModal();
  // Session ended (logout or 401 redirect): drop any one-time API key display.
  removeApiKeyReveal();
  if (wasInApp) clearAppData();

  const appRoot = byId('app-root');
  const screen = byId('auth-screen');
  if (!appRoot || !screen) return;
  appRoot.hidden = true;
  screen.hidden = false;

  if (authMode === mode && byId('auth-form')) {
    if (notice) setAuthMessage(notice, 'info');
    return;
  }
  authMode = mode;
  renderAuthForm(screen, mode, notice);
}

function renderAuthForm(screen, mode, notice) {
  const isSetup = mode === 'setup';

  const password = el('input', {
    type: 'password',
    id: 'auth-password',
    name: 'password',
    className: 'form-control',
    autocomplete: isSetup ? 'new-password' : 'current-password',
    maxlength: MAX_PASSWORD_LENGTH,
    required: true,
    'aria-describedby': isSetup ? 'auth-password-hint auth-error' : 'auth-error',
  });
  const confirmField = isSetup
    ? el('input', {
      type: 'password',
      id: 'auth-password-confirm',
      name: 'password-confirm',
      className: 'form-control',
      autocomplete: 'new-password',
      maxlength: MAX_PASSWORD_LENGTH,
      required: true,
      'aria-describedby': 'auth-error',
    })
    : null;
  const message = el('p', { id: 'auth-error', className: 'auth-message error', role: 'alert', 'aria-live': 'assertive' });
  const submit = el('button', { type: 'submit', className: 'btn', id: 'auth-submit' },
    icon(isSetup ? 'key-round' : 'log-in'), isSetup ? ' Set password & continue' : ' Sign in');

  const form = el('form', { id: 'auth-form', novalidate: true, 'aria-labelledby': 'auth-title' },
    el('div', { className: 'form-group' },
      el('label', { for: 'auth-password' }, isSetup ? 'New password' : 'Password'),
      password,
      isSetup ? el('small', { id: 'auth-password-hint', className: 'auth-hint' },
        `At least ${MIN_PASSWORD_LENGTH} characters. The server validates it again.`) : null),
    isSetup
      ? el('div', { className: 'form-group' }, el('label', { for: 'auth-password-confirm' }, 'Confirm password'), confirmField)
      : null,
    message,
    el('div', { className: 'form-actions' }, submit));

  form.addEventListener('submit', fire(async (ev) => {
    ev.preventDefault();
    const value = password.value;

    if (isSetup) {
      if (value.length < MIN_PASSWORD_LENGTH) {
        setAuthMessage(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`, 'error');
        password.focus();
        return;
      }
      if (value.length > MAX_PASSWORD_LENGTH) {
        setAuthMessage(`Password must be at most ${MAX_PASSWORD_LENGTH} characters.`, 'error');
        password.focus();
        return;
      }
      if (confirmField && value !== confirmField.value) {
        setAuthMessage('Passwords do not match.', 'error');
        confirmField.focus();
        return;
      }
    } else if (!value) {
      setAuthMessage('Password is required.', 'error');
      password.focus();
      return;
    }

    submit.disabled = true;
    setAuthMessage('', 'info');
    try {
      await api(isSetup ? '/api/auth/setup' : '/api/auth/login', {
        method: 'POST',
        body: { password: value },
        authRedirect: false,
      });
      // Setup 201 already sets the session cookie (auto login); no separate login call.
      await enterApp();
    } catch (e) {
      if (e && e.authRedirect) return;
      if (e && e.code === 'setup_already_done') {
        showAuth('login', 'A password has already been set. Please sign in.');
      } else if (!isSetup && e && e.code === 'setup_required') {
        showAuth('setup', 'No password has been set yet. Create one to continue.');
      } else {
        setAuthMessage(e && e.message ? e.message : 'Request failed', 'error');
        password.focus();
      }
    } finally {
      password.value = '';
      if (confirmField) confirmField.value = '';
      submit.disabled = false;
    }
  }));

  const card = el('section', { className: 'auth-card', 'aria-labelledby': 'auth-title' },
    el('div', { className: 'logo-container' },
      el('div', { className: 'logo-icon' }, icon('shield-alert')),
      el('div', { className: 'logo-text' }, 'Compliance Hub')),
    el('h2', { className: 'modal-title', id: 'auth-title' }, isSetup ? 'Set administrator password' : 'Sign in'),
    el('p', { className: 'modal-subtitle' }, isSetup
      ? 'No password has been set for this installation yet. Choose one to finish setup; you will be signed in automatically.'
      : 'Enter your password to continue.'),
    form);

  clear(screen).appendChild(card);
  if (notice) setAuthMessage(notice, 'info');
  refreshIcons();
  password.focus();
}

async function enterApp() {
  const { data } = await api('/api/auth/me');
  currentUser = data || {};
  authMode = null;

  const screen = byId('auth-screen');
  clear(screen).hidden = true;
  byId('app-root').hidden = false;

  const label = currentUser.displayName || currentUser.email || 'Signed in';
  setText('current-user-name', label);
  const nameEl = byId('current-user-name');
  if (nameEl) nameEl.title = currentUser.email ? String(currentUser.email) : '';

  await switchView('dashboard');
}

async function logout() {
  const btn = byId('logout-btn');
  if (btn) btn.disabled = true;
  try {
    await api('/api/auth/logout', { method: 'POST', authRedirect: false });
    // Only this browser session is closed; other sessions are not affected.
    showAuth('login', 'You have been signed out of this browser session.');
  } catch (e) {
    if (e && e.status === 401) showAuth('login', 'Your session had already ended. Please sign in again.');
    else reportError(e, 'Logout failed');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Event wiring (no inline handlers)
function bindHandlers() {
  document.querySelectorAll('#sidebar-nav .nav-item').forEach((btn) => {
    btn.addEventListener('click', fire(() => switchView(btn.dataset.view)));
  });
  byId('refresh-btn').addEventListener('click', fire(refreshAll));
  byId('new-scan-btn').addEventListener('click', fire(openModal));
  byId('add-project-btn').addEventListener('click', fire(openModal));
  byId('modal-close-btn').addEventListener('click', fire(closeModal));
  byId('modal-cancel-btn').addEventListener('click', fire(closeModal));
  byId('launch-btn').addEventListener('click', fire(launchScan));
  byId('generate-sbom-btn').addEventListener('click', fire(generateNewSbom));
  byId('logout-btn').addEventListener('click', fire(logout));
  byId('findings-scan-select').addEventListener('change', fire(loadScanFindings));
  byId('sbom-scan-select').addEventListener('change', fire(loadScanSboms));
  // No native form submission (REQ-002: a null Origin would be rejected); fetch only.
  byId('api-key-create-form').addEventListener('submit', fire((e) => {
    e.preventDefault();
    return createApiKey();
  }));
  window.addEventListener('pagehide', removeApiKeyReveal);

  byId('scanModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && byId('scanModal').classList.contains('open')) closeModal();
  });

  // Delegated: per-project "Scan Now" buttons carry their values in data-* attributes.
  byId('projects-list-tbody').addEventListener('click', fire((e) => {
    const target = e.target instanceof Element ? e.target.closest('button[data-action="scan-project"]') : null;
    if (!target) return undefined;
    return triggerManualScan(target.dataset.projectId, target.dataset.projectName);
  }));
}

// ── Initialize App
async function init() {
  refreshIcons();
  bindHandlers();
  await checkHealth();
  try {
    await enterApp();
  } catch (e) {
    if (e && e.authRedirect) return; // setup/login form is already shown
    showAuth('login', `Could not verify the session: ${e && e.message ? e.message : 'unknown error'}`);
  }
}

fire(init)();

// Auto-refresh stats/scans every 30 seconds
setInterval(fire(async () => {
  if (currentUser && currentActiveView === 'dashboard') {
    await loadScans();
    await updateStats();
    await loadVulnerabilityDataStatus();
  }
}), 30000);
