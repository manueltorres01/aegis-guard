'use strict';

const PREVIEW_MODE = new URLSearchParams(window.location.search).get('preview') === '1';

const VIEW_META = Object.freeze({
  home: { title: 'Inicio', eyebrow: 'Resumen' },
  scan: { title: 'Analizar', eyebrow: 'Detección local' },
  protection: { title: 'Protección', eyebrow: 'Vigilancia de Descargas' },
  network: { title: 'Red', eyebrow: 'Auditoría local' },
  results: { title: 'Resultados', eyebrow: 'Historial de análisis' },
  quarantine: { title: 'Cuarentena', eyebrow: 'Almacén cifrado' },
  settings: { title: 'Ajustes', eyebrow: 'Preferencias' }
});

const state = {
  activeView: 'home',
  settings: { theme: 'system', autoQuarantine: false, launchAtStartup: true },
  version: '—',
  engineVersion: '—',
  definitionsVersion: '—',
  results: [],
  resultsTruncated: 0,
  reportAvailable: false,
  network: null,
  quarantine: [],
  quarantineInventory: { total: 0, truncatedCount: 0, corruptCount: 0, oversizedCount: 0 },
  activity: [],
  lastScan: null,
  totalScanned: 0,
  scan: {
    running: false,
    phase: 'idle',
    scanned: 0,
    total: null,
    threats: 0,
    errors: 0,
    skipped: 0,
    policySkipped: 0,
    traversalSkipped: 0,
    linksSkipped: 0,
    percent: 0,
    targetLabel: '',
    mode: null,
    rootsTotal: null,
    rootsCompleted: 0,
    currentRootLabel: '',
    startedAt: null
  },
  protection: { active: false, paused: false, targetLabel: 'Descargas', sessionOnly: true },
  startup: { supported: true, enabled: true, requested: true, launchesInBackground: true },
  monitor: { active: false, target: null },
  selectedMonitorTarget: null,
  resultFilter: 'all',
  restoreId: null,
  isolateRequest: null,
  unsubscribe: null
};

const byId = id => document.getElementById(id);
const all = selector => [...document.querySelectorAll(selector)];

const els = {};
let api = null;
let systemThemeQuery = null;
let scanClock = null;

function cacheElements() {
  const ids = [
    'page-title', 'page-eyebrow', 'preview-pill', 'theme-cycle', 'engine-status',
    'sidebar-version', 'about-version', 'engine-version', 'definitions-version', 'about-definitions',
    'home-status-card', 'status-emblem', 'status-overline', 'home-heading', 'home-status-description',
    'last-scan-label', 'metric-scanned', 'metric-findings', 'metric-quarantine', 'activity-list',
    'export-report-json', 'export-report-csv', 'run-network-audit', 'export-network-json', 'export-network-csv',
    'network-summary', 'network-firewall-state', 'network-defender-state', 'network-event-count', 'network-alert-count', 'network-body', 'network-empty',
    'home-monitor-title', 'home-monitor-status', 'results-badge', 'quarantine-badge',
    'scan-choices', 'scan-workspace', 'scan-state-icon', 'scan-phase-label', 'scan-status-title',
    'scan-target-label', 'cancel-scan', 'scan-progress-track', 'scan-progress-value',
    'scan-progress-meta', 'scan-elapsed-label', 'scan-progress-context', 'scan-scope-note',
    'scan-scope-title', 'scan-scope-copy',
    'scan-count-scanned', 'scan-count-total', 'scan-count-threats', 'scan-count-errors',
    'scan-skipped-counter', 'scan-count-skipped',
    'scan-current-file', 'protection-visual', 'protection-overline', 'protection-status-heading',
    'protection-description', 'protection-target-label', 'toggle-protection', 'protection-pause-warning',
    'monitor-overline', 'monitor-heading', 'monitor-description', 'monitor-target-label',
    'choose-monitor-target', 'start-monitor', 'stop-monitor', 'results-summary',
    'results-body', 'results-empty', 'quarantine-body', 'quarantine-empty', 'refresh-quarantine',
    'quarantine-inventory-warning', 'quarantine-inventory-warning-copy',
    'theme-select', 'auto-quarantine', 'start-with-windows', 'startup-setting-note',
    'check-updates', 'restart-update', 'update-status', 'run-simulation',
    'settings-save-status', 'fatal-panel', 'fatal-message', 'toast-region', 'restore-dialog',
    'restore-dialog-copy', 'restore-cancel', 'restore-confirm', 'isolate-dialog',
    'isolate-dialog-copy', 'isolate-cancel', 'isolate-confirm', 'pause-protection-dialog',
    'pause-protection-cancel', 'pause-protection-confirm'
  ];
  for (const id of ids) els[id] = byId(id);
}

function createIcon(symbol) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#${symbol}`);
  svg.append(use);
  return svg;
}

function safeString(value, fallback = '') {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback;
}

function safeNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function clamp(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, value));
}

function fileName(value) {
  const text = safeString(value, 'Archivo sin nombre');
  return text.split(/[\\/]/).filter(Boolean).pop() || text;
}

function parentPath(value) {
  const text = safeString(value);
  const index = Math.max(text.lastIndexOf('\\'), text.lastIndexOf('/'));
  return index > 0 ? text.slice(0, index) : '';
}

function formatCount(value) {
  return new Intl.NumberFormat('es-ES').format(Math.max(0, safeNumber(value)));
}

function formatDate(value, fallback = 'Fecha desconocida') {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return new Intl.DateTimeFormat('es-ES', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'
  }).format(date);
}

function relativeDate(value) {
  if (!value) return 'Aún no se ha realizado ningún análisis';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Análisis reciente';
  const elapsed = Date.now() - date.getTime();
  if (elapsed >= 0 && elapsed < 60_000) return 'Último análisis: hace unos segundos';
  if (elapsed >= 0 && elapsed < 3_600_000) return `Último análisis: hace ${Math.max(1, Math.floor(elapsed / 60_000))} min`;
  return `Último análisis: ${formatDate(value)}`;
}

function normalizeVerdict(value) {
  const verdict = safeString(value, 'clean').toLowerCase();
  if (['malicious', 'malicioso', 'threat'].includes(verdict)) return 'malicious';
  if (['suspicious', 'sospechoso', 'warning'].includes(verdict)) return 'suspicious';
  if (['error', 'unreadable'].includes(verdict)) return 'error';
  if (['skipped', 'omitted', 'omitido'].includes(verdict)) return 'skipped';
  return 'clean';
}

function normalizeScanMode(value, fallback = null) {
  const mode = safeString(value).toLowerCase();
  if (mode === 'custom') return 'deep';
  return ['quick', 'full', 'deep', 'simulation'].includes(mode) ? mode : fallback;
}

function verdictLabel(verdict) {
  return {
    clean: 'Sin detección',
    suspicious: 'Sospechoso',
    malicious: 'Malicioso',
    error: 'No analizado',
    skipped: 'Omitido / No analizado'
  }[normalizeVerdict(verdict)];
}

function getSummary(source = {}) {
  const summary = source.summary && typeof source.summary === 'object' ? source.summary : source;
  const traversalErrors = safeNumber(summary.traversalErrors);
  const policySkipped = safeNumber(summary.skipped);
  const traversalSkipped = safeNumber(summary.traversalSkipped);
  return {
    scanned: safeNumber(summary.scanned ?? summary.completed ?? summary.filesScanned),
    total: safeNumber(summary.total ?? summary.discovered ?? summary.filesFound, 0),
    malicious: safeNumber(summary.malicious ?? summary.threats),
    suspicious: safeNumber(summary.suspicious),
    errors: safeNumber(summary.errors) + traversalErrors,
    traversalErrors,
    skipped: policySkipped + traversalSkipped,
    policySkipped,
    traversalSkipped,
    linksSkipped: safeNumber(summary.linksSkipped),
    quarantined: safeNumber(summary.quarantined ?? summary.isolated)
  };
}

function setEngineStatus(label, kind = 'ready') {
  els['engine-status'].classList.toggle('is-busy', kind === 'busy');
  els['engine-status'].classList.toggle('is-error', kind === 'error');
  const text = els['engine-status'].querySelector('span:last-child');
  text.textContent = label;
}

function showToast(title, message, kind = 'info', timeout = 5200) {
  const toast = document.createElement('div');
  toast.className = `toast is-${kind}`;
  toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  toast.append(createIcon(kind === 'error' || kind === 'warning' ? 'i-alert' : 'i-check'));

  const copy = document.createElement('div');
  const strong = document.createElement('strong');
  const span = document.createElement('span');
  strong.textContent = title;
  span.textContent = message;
  copy.append(strong, span);

  const close = document.createElement('button');
  close.type = 'button';
  close.setAttribute('aria-label', 'Cerrar aviso');
  close.textContent = '×';
  close.addEventListener('click', () => toast.remove());
  toast.append(copy, close);
  els['toast-region'].append(toast);
  window.setTimeout(() => toast.remove(), timeout);
}

function errorMessage(error, fallback = 'Se ha producido un error inesperado.') {
  return safeString(error?.message, fallback);
}

async function callApi(method, ...args) {
  if (!api || typeof api[method] !== 'function') {
    throw new Error(`La función segura «${method}» no está disponible.`);
  }
  return api[method](...args);
}

function setView(name, { focus = false } = {}) {
  if (!VIEW_META[name]) return;
  state.activeView = name;
  for (const view of all('.view')) {
    const active = view.id === `view-${name}`;
    view.hidden = !active;
    view.classList.toggle('is-active', active);
  }
  for (const button of all('.nav-item')) {
    const active = button.dataset.view === name;
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
  els['page-title'].textContent = VIEW_META[name].title;
  els['page-eyebrow'].textContent = VIEW_META[name].eyebrow;
  if (name === 'quarantine') void refreshQuarantine({ quiet: true });
  if (focus) byId(`view-${name}`)?.querySelector('h2')?.focus?.();
}

function resolvedTheme(theme) {
  if (theme === 'light' || theme === 'dark') return theme;
  return systemThemeQuery?.matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  const accepted = ['system', 'light', 'dark'].includes(theme) ? theme : 'system';
  state.settings.theme = accepted;
  document.documentElement.dataset.theme = resolvedTheme(accepted);
  if (els['theme-select']) els['theme-select'].value = accepted;
  const labels = { system: 'del sistema', light: 'claro', dark: 'oscuro' };
  els['theme-cycle']?.setAttribute('aria-label', `Tema ${labels[accepted]}. Cambiar tema`);
  els['theme-cycle']?.setAttribute('title', `Tema ${labels[accepted]}`);
}

function renderHomeStatus() {
  const summary = state.lastScan ? getSummary(state.lastScan) : null;
  const emblem = els['status-emblem'];
  emblem.classList.remove('is-safe', 'is-warning', 'is-danger');

  if (!summary) {
    emblem.classList.add('is-warning');
    els['status-overline'].textContent = 'Estado de Aegis';
    els['home-heading'].textContent = 'Aún no hay un análisis reciente';
    els['home-status-description'].textContent = 'Inicia un análisis para comprobar archivos con las definiciones locales de Aegis. Microsoft Defender debe permanecer activado.';
    els['last-scan-label'].textContent = 'Aún no se ha realizado ningún análisis';
  } else if (summary.malicious > 0) {
    emblem.classList.add('is-danger');
    els['status-overline'].textContent = 'El último análisis requiere atención';
    els['home-heading'].textContent = `Aegis detectó ${formatCount(summary.malicious)} ${summary.malicious === 1 ? 'amenaza' : 'amenazas'}`;
    els['home-status-description'].textContent = summary.quarantined > 0
      ? 'Revisa los resultados y los elementos aislados antes de decidir si debes restaurarlos.'
      : 'Revisa los resultados. Los archivos no se eliminan automáticamente salvo que lo hayas activado en Ajustes.';
    els['last-scan-label'].textContent = relativeDate(state.lastScan.completedAt ?? state.lastScan.date);
  } else if (summary.suspicious > 0 || summary.errors > 0 || summary.skipped > 0) {
    emblem.classList.add('is-warning');
    els['status-overline'].textContent = 'El último análisis requiere revisión';
    els['home-heading'].textContent = 'Hay archivos que conviene revisar';
    els['home-status-description'].textContent = 'Aegis encontró indicios o dejó elementos sin analizar por límites, permisos o seguridad. Consulta los motivos en Resultados.';
    els['last-scan-label'].textContent = relativeDate(state.lastScan.completedAt ?? state.lastScan.date);
  } else {
    emblem.classList.add('is-safe');
    els['status-overline'].textContent = 'Estado del último análisis';
    els['home-heading'].textContent = 'Sin amenazas detectadas por Aegis';
    els['home-status-description'].textContent = 'Este estado refleja únicamente los archivos que Aegis ha analizado. Microsoft Defender debe permanecer activado.';
    els['last-scan-label'].textContent = relativeDate(state.lastScan.completedAt ?? state.lastScan.date);
  }

  els['metric-scanned'].textContent = formatCount(state.totalScanned);
  els['metric-findings'].textContent = formatCount(summary ? summary.malicious + summary.suspicious : 0);
  els['metric-quarantine'].textContent = formatCount(Math.max(
    state.quarantine.length,
    safeNumber(state.quarantineInventory?.total, state.quarantine.length)
  ));
}

function renderActivity() {
  const container = els['activity-list'];
  container.replaceChildren();
  const entries = state.activity.slice(0, 4);
  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-compact';
    empty.append(createIcon('i-clock'));
    const copy = document.createElement('span');
    copy.textContent = 'No hay actividad registrada todavía.';
    empty.append(copy);
    container.append(empty);
    return;
  }

  for (const entry of entries) {
    const row = document.createElement('div');
    row.className = 'activity-item';
    const icon = document.createElement('span');
    icon.className = 'activity-icon';
    icon.append(createIcon(entry.kind === 'quarantine' ? 'i-vault' : entry.kind === 'monitor' ? 'i-radar' : 'i-scan'));
    const copy = document.createElement('div');
    const title = document.createElement('strong');
    const description = document.createElement('span');
    title.textContent = safeString(entry.title, 'Actividad de Aegis');
    description.textContent = safeString(entry.description, 'Sin detalles adicionales');
    copy.append(title, description);
    const time = document.createElement('time');
    const timestamp = entry.at ?? entry.date ?? entry.createdAt;
    time.dateTime = safeString(timestamp);
    time.textContent = formatDate(timestamp, 'Reciente');
    row.append(icon, copy, time);
    container.append(row);
  }
}

function renderProtection() {
  const active = Boolean(state.protection.active) && !state.protection.paused;
  const paused = Boolean(state.protection.paused);
  els['protection-visual'].classList.toggle('is-active', active);
  els['protection-visual'].classList.toggle('is-paused', paused);
  els['protection-target-label'].textContent = safeString(state.protection.targetLabel, 'Descargas');
  els['protection-pause-warning'].hidden = !paused;
  els['toggle-protection'].disabled = false;

  const iconUse = els['toggle-protection'].querySelector('use');
  const buttonLabel = els['toggle-protection'].querySelector('span');
  if (active) {
    els['protection-overline'].textContent = 'Vigilancia de Descargas activa';
    els['protection-status-heading'].textContent = 'Observando cambios en Descargas';
    els['protection-description'].textContent = 'Aegis analizará los archivos nuevos o modificados de Descargas durante esta sesión.';
    buttonLabel.textContent = 'Pausar hasta reiniciar Aegis';
    iconUse.setAttribute('href', '#i-stop');
    els['toggle-protection'].classList.remove('primary');
    els['toggle-protection'].classList.add('secondary');
    els['home-monitor-title'].textContent = 'Activa en Descargas';
    els['home-monitor-status'].textContent = 'En curso';
  } else if (paused) {
    els['protection-overline'].textContent = 'Pausa limitada a esta sesión';
    els['protection-status-heading'].textContent = 'La vigilancia en tiempo real está pausada';
    els['protection-description'].textContent = 'Aegis no vigila ahora Descargas ni otras carpetas configuradas, pero los análisis manuales siguen funcionando.';
    buttonLabel.textContent = 'Reanudar protección';
    iconUse.setAttribute('href', '#i-play');
    els['toggle-protection'].classList.remove('secondary');
    els['toggle-protection'].classList.add('primary');
    els['home-monitor-title'].textContent = 'Pausada hasta reiniciar';
    els['home-monitor-status'].textContent = 'En pausa';
  } else {
    els['protection-overline'].textContent = 'Vigilancia no disponible';
    els['protection-status-heading'].textContent = 'La protección de Descargas no está activa';
    els['protection-description'].textContent = 'Puedes intentar reanudarla. Microsoft Defender debe permanecer activo.';
    buttonLabel.textContent = 'Reanudar protección';
    iconUse.setAttribute('href', '#i-play');
    els['toggle-protection'].classList.remove('secondary');
    els['toggle-protection'].classList.add('primary');
    els['home-monitor-title'].textContent = 'No disponible';
    els['home-monitor-status'].textContent = 'Detenida';
  }
  els['home-monitor-status'].classList.toggle('is-active', active);
}

function renderMonitor() {
  const paused = Boolean(state.protection.paused);
  const active = Boolean(state.monitor.active);
  const target = state.monitor.target || state.selectedMonitorTarget;
  const label = safeString(target?.label ?? target?.name, 'Ninguna carpeta seleccionada');
  els['monitor-target-label'].textContent = label;
  els['choose-monitor-target'].disabled = active;
  els['start-monitor'].disabled = paused || active || !target?.targetId;
  els['start-monitor'].hidden = active;
  els['stop-monitor'].hidden = !active;

  if (paused && active) {
    els['monitor-overline'].textContent = 'Pausada con la protección global';
    els['monitor-heading'].textContent = 'La carpeta adicional se conserva';
    els['monitor-description'].textContent = 'Volverá a vigilarse al reanudar. Puedes quitarla ahora si ya no la necesitas.';
    els['stop-monitor'].querySelector('span').textContent = 'Quitar carpeta';
  } else if (paused) {
    els['monitor-overline'].textContent = 'Protección global en pausa';
    els['monitor-heading'].textContent = target ? 'Carpeta preparada' : 'Elige una carpeta adicional';
    els['monitor-description'].textContent = 'Podrás iniciar esta vigilancia cuando reanudes la protección de la sesión.';
  } else if (active) {
    els['monitor-overline'].textContent = 'Vigilancia adicional activa';
    els['monitor-heading'].textContent = 'Observando cambios en esta carpeta';
    els['monitor-description'].textContent = 'Esta carpeta se vigila además de Descargas mientras Aegis permanece en ejecución.';
    els['stop-monitor'].querySelector('span').textContent = 'Detener vigilancia';
  } else {
    els['monitor-overline'].textContent = 'Carpeta adicional opcional';
    els['monitor-heading'].textContent = target ? 'Carpeta preparada' : 'Elige otra carpeta para vigilar';
    els['monitor-description'].textContent = 'Aegis puede observar una carpeta adicional durante esta sesión.';
  }
}

function renderStartupSetting() {
  const requested = state.settings.launchAtStartup !== false;
  els['start-with-windows'].checked = requested;
  els['start-with-windows'].disabled = !state.startup.supported;
  if (!state.startup.supported) {
    els['startup-setting-note'].textContent = 'El inicio automático no está disponible en esta instalación.';
  } else if (!requested) {
    els['startup-setting-note'].textContent = 'Aegis no se abrirá automáticamente al iniciar tu sesión de Windows.';
  } else if (state.startup.requested && !state.startup.enabled) {
    els['startup-setting-note'].textContent = 'El inicio automático está solicitado, pero Windows todavía no lo confirma.';
  } else {
    els['startup-setting-note'].textContent = 'Aegis se abrirá con Windows para iniciar la protección de Descargas. Activado por defecto.';
  }
}

function resultReason(result) {
  if (safeString(result.reason)) return safeString(result.reason);
  if (safeString(result.error)) return safeString(result.error);
  const findings = Array.isArray(result.findings) ? result.findings : [];
  return findings.length
    ? safeString(findings[0]?.description ?? findings[0]?.name ?? findings[0]?.id, 'Regla local')
    : normalizeVerdict(result.verdict) === 'clean'
      ? 'Ninguna regla activada'
      : normalizeVerdict(result.verdict) === 'skipped' ? 'Omitido por los límites del modo de análisis' : 'Revisión recomendada';
}

function renderResults() {
  const body = els['results-body'];
  const visible = state.results.filter(result => {
    const verdict = normalizeVerdict(result.verdict);
    if (state.resultFilter === 'suspicious') return verdict === 'suspicious';
    if (state.resultFilter === 'malicious') return verdict === 'malicious';
    if (state.resultFilter === 'not-scanned') return verdict === 'error' || verdict === 'skipped';
    return true;
  });
  body.replaceChildren();
  els['results-empty'].hidden = visible.length > 0;
  body.parentElement.parentElement.hidden = visible.length === 0;

  const attention = state.results.filter(result => ['malicious', 'suspicious', 'error', 'skipped'].includes(normalizeVerdict(result.verdict))).length;
  els['results-summary'].textContent = state.results.length
    ? `${formatCount(state.results.length)} ${state.results.length === 1 ? 'detalle registrado' : 'detalles registrados'}; ${formatCount(attention)} ${attention === 1 ? 'requiere' : 'requieren'} atención.${state.resultsTruncated > 0 ? ` ${formatCount(state.resultsTruncated)} detalles adicionales no se muestran; los contadores sí incluyen todo.` : ''}`
    : 'Todavía no hay análisis registrados.';
  els['results-badge'].hidden = attention === 0;
  els['results-badge'].textContent = attention > 99 ? '99+' : String(attention);
  els['export-report-json'].disabled = !state.reportAvailable;
  els['export-report-csv'].disabled = !state.reportAvailable;

  for (const result of visible) {
    const row = document.createElement('tr');
    const verdict = normalizeVerdict(result.verdict);

    const verdictCell = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `verdict-pill ${verdict}`;
    pill.textContent = verdictLabel(verdict);
    verdictCell.append(pill);

    const fileCell = document.createElement('td');
    fileCell.className = 'file-cell';
    const fileStrong = document.createElement('strong');
    const fileSmall = document.createElement('small');
    const location = result.path ?? result.filePath ?? result.label ?? result.name;
    fileStrong.textContent = safeString(result.name, fileName(location));
    fileStrong.title = fileStrong.textContent;
    fileSmall.textContent = safeString(result.parentLabel ?? result.directory, parentPath(location));
    fileSmall.title = fileSmall.textContent;
    fileCell.append(fileStrong, fileSmall);

    const scoreCell = document.createElement('td');
    scoreCell.className = 'score-cell';
    scoreCell.textContent = ['error', 'skipped'].includes(verdict) ? '—' : `${formatCount(result.score)} / 100`;

    const reasonCell = document.createElement('td');
    reasonCell.textContent = resultReason(result);

    const actionCell = document.createElement('td');
    const isolated = Boolean(result.quarantined ?? result.isolated ?? result.action === 'quarantined');
    if (!isolated && ['malicious', 'suspicious'].includes(verdict) && result.scanId && result.resultId) {
      const isolate = document.createElement('button');
      isolate.type = 'button';
      isolate.className = 'button danger-quiet compact';
      isolate.textContent = 'Aislar';
      isolate.addEventListener('click', () => openIsolateDialog(result));
      actionCell.append(isolate);
    } else {
      const action = document.createElement('span');
      action.className = `state-note${isolated ? ' is-isolated' : ''}`;
      action.textContent = isolated ? 'Aislado' : verdict === 'clean' ? 'Sin acción' : verdict === 'skipped' ? 'No analizado' : 'Revisar';
      actionCell.append(action);
    }

    row.append(verdictCell, fileCell, scoreCell, reasonCell, actionCell);
    body.append(row);
  }
}

function renderNetwork() {
  const report = state.network;
  const events = Array.isArray(report?.events) ? report.events : [];
  const summary = report?.summary ?? {};
  const firewall = Array.isArray(report?.windowsSecurity?.firewall) ? report.windowsSecurity.firewall : [];
  const defender = report?.windowsSecurity?.defender;
  els['network-summary'].textContent = report?.completedAt ? `Última captura: ${formatDate(report.completedAt)}.` : 'Realiza una captura para atribuir conexiones salientes a sus procesos.';
  els['network-firewall-state'].textContent = firewall.length && firewall.every(profile => profile.enabled) ? 'Firewall activo' : firewall.length ? 'Revisar Firewall' : 'Firewall sin comprobar';
  els['network-defender-state'].textContent = defender?.antivirusEnabled && defender?.realTimeProtectionEnabled ? 'Defender activo' : defender ? 'Revisar Defender' : 'Defender sin comprobar';
  els['network-event-count'].textContent = `${formatCount(summary.connections ?? events.length)} conexiones`;
  els['network-alert-count'].textContent = `${formatCount(summary.suspicious)} coincidencias con indicadores.`;
  els['export-network-json'].disabled = !report?.reportAvailable;
  els['export-network-csv'].disabled = !report?.reportAvailable;
  els['network-empty'].hidden = events.length > 0;
  const body = els['network-body']; body.replaceChildren(); body.parentElement.parentElement.hidden = events.length === 0;
  for (const event of events) {
    const row=document.createElement('tr');
    const status=document.createElement('td'); const pill=document.createElement('span'); pill.className=`verdict-pill ${event.verdict==='suspicious'?'suspicious':'clean'}`; pill.textContent=event.verdict==='suspicious'?'Sospechoso':'Observado'; status.append(pill);
    const destination=document.createElement('td'); destination.className='file-cell'; const target=document.createElement('strong'); target.textContent=event.domain||event.remoteAddress||'Destino desconocido'; const endpoint=document.createElement('small'); endpoint.textContent=`${event.remoteAddress||'—'}:${safeNumber(event.remotePort)}`; destination.append(target,endpoint);
    const processCell=document.createElement('td'); processCell.className='file-cell'; const processName=document.createElement('strong'); processName.textContent=safeString(event.process?.name,'Proceso desconocido'); const processPath=document.createElement('small'); processPath.textContent=safeString(event.process?.path,`PID ${safeNumber(event.process?.id)}`); processCell.append(processName,processPath);
    const signature=document.createElement('td'); signature.textContent=event.signature?.status==='valid'?safeString(event.signature.publisher,'Firma válida'):'Sin verificar';
    const explanation=document.createElement('td'); explanation.textContent=safeString(event.explanation,'Conexión observada.');
    row.append(status,destination,processCell,signature,explanation); body.append(row);
  }
}

async function runNetworkAudit() {
  els['run-network-audit'].disabled=true; setEngineStatus('Auditando red','busy');
  try { state.network=await callApi('runNetworkAudit'); renderNetwork(); showToast('Auditoría completada',`${formatCount(state.network?.summary?.connections)} conexiones observadas.`,'success'); }
  catch(error){ showToast('No se pudo auditar la red',errorMessage(error),'error'); }
  finally { els['run-network-audit'].disabled=false; setEngineStatus('Motor listo'); }
}

async function exportNetworkReport(format) {
  try { const response=await callApi('exportNetworkReport',{format}); if(!response?.cancelled)showToast('Informe guardado',safeString(response?.label,'Informe de red exportado.'),'success'); }
  catch(error){ showToast('No se pudo exportar',errorMessage(error),'error'); }
}

function renderQuarantine() {
  const body = els['quarantine-body'];
  body.replaceChildren();
  const items = state.quarantine;
  const inventory = state.quarantineInventory ?? {};
  const total = Math.max(items.length, safeNumber(inventory.total, items.length));
  const truncatedCount = Math.max(0, safeNumber(inventory.truncatedCount, total - items.length));
  const corruptCount = Math.max(0, safeNumber(inventory.corruptCount));
  const oversizedCount = Math.max(0, safeNumber(inventory.oversizedCount));
  const inventoryWarnings = [];
  if (truncatedCount) inventoryWarnings.push(`Se muestran ${formatCount(items.length)} de ${formatCount(total)} elementos; ${formatCount(truncatedCount)} no caben en esta vista.`);
  if (corruptCount) inventoryWarnings.push(`${formatCount(corruptCount)} entradas dañadas se omitieron de forma segura.`);
  if (oversizedCount) inventoryWarnings.push(`${formatCount(oversizedCount)} entradas con metadatos demasiado grandes se omitieron de forma segura.`);
  els['quarantine-inventory-warning'].hidden = inventoryWarnings.length === 0;
  els['quarantine-inventory-warning-copy'].textContent = inventoryWarnings.join(' ');
  els['quarantine-empty'].hidden = items.length > 0;
  body.parentElement.parentElement.hidden = items.length === 0;
  els['quarantine-badge'].hidden = total === 0;
  els['quarantine-badge'].textContent = total > 99 ? '99+' : String(total);
  els['metric-quarantine'].textContent = formatCount(total);

  for (const item of items) {
    const row = document.createElement('tr');
    const pathCell = document.createElement('td');
    pathCell.className = 'file-cell';
    const name = document.createElement('strong');
    const parent = document.createElement('small');
    const location = item.originalPath ?? item.path ?? item.label;
    name.textContent = safeString(item.name, fileName(location));
    name.title = name.textContent;
    parent.textContent = safeString(item.parentLabel, parentPath(location));
    parent.title = parent.textContent;
    pathCell.append(name, parent);

    const dateCell = document.createElement('td');
    dateCell.textContent = formatDate(item.quarantinedAt ?? item.createdAt);

    const verdictCell = document.createElement('td');
    const verdict = normalizeVerdict(item.verdict);
    const pill = document.createElement('span');
    pill.className = `verdict-pill ${verdict}`;
    pill.textContent = verdictLabel(verdict);
    verdictCell.append(pill);

    const idCell = document.createElement('td');
    const identifier = safeString(item.id, '—');
    idCell.textContent = identifier.length > 12 ? `${identifier.slice(0, 8)}…` : identifier;
    idCell.title = identifier;

    const actionCell = document.createElement('td');
    const restore = document.createElement('button');
    restore.type = 'button';
    restore.className = 'button secondary';
    restore.textContent = 'Restaurar';
    restore.addEventListener('click', () => openRestoreDialog(item));
    actionCell.append(restore);
    row.append(pathCell, dateCell, verdictCell, idCell, actionCell);
    body.append(row);
  }
}

function formatElapsed(milliseconds) {
  const totalSeconds = Math.max(0, Math.floor(milliseconds / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return hours > 0
    ? `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
    : `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function updateScanElapsed() {
  if (!state.scan.startedAt) return;
  els['scan-elapsed-label'].textContent = `Tiempo transcurrido · ${formatElapsed(Date.now() - state.scan.startedAt)}`;
}

function syncScanClock() {
  if (state.scan.running && !scanClock) {
    scanClock = window.setInterval(updateScanElapsed, 1000);
  } else if (!state.scan.running && scanClock) {
    window.clearInterval(scanClock);
    scanClock = null;
  }
  updateScanElapsed();
}

function renderScanScope() {
  const mode = state.scan.mode;
  if (mode === 'quick') {
    els['scan-scope-title'].textContent = 'Primer nivel de Descargas';
    els['scan-scope-copy'].textContent = 'Incluye archivos regulares ocultos, pero no subcarpetas. Puede omitir archivos mayores de 128 MiB y registra los accesos rechazados.';
  } else if (mode === 'full') {
    els['scan-scope-title'].textContent = 'Unidades locales con letra accesibles';
    els['scan-scope-copy'].textContent = 'Incluye archivos regulares ocultos y subcarpetas sin límite por nombre o tamaño. No sigue enlaces, junctions ni puntos de reanálisis; contabiliza los fallos de acceso.';
  } else if (mode === 'deep') {
    els['scan-scope-title'].textContent = 'Ruta elegida, analizada en profundidad';
    els['scan-scope-copy'].textContent = 'La selección procede del diálogo de Windows. Las carpetas incluyen ocultos y subcarpetas, sin seguir enlaces o puntos de reanálisis; los permisos denegados cuentan como errores.';
  } else if (mode === 'simulation') {
    els['scan-scope-title'].textContent = 'Simulación inofensiva';
    els['scan-scope-copy'].textContent = 'Esta prueba usa únicamente un archivo de texto creado por Aegis y no ejecuta código.';
  } else {
    els['scan-scope-title'].textContent = 'Cobertura transparente';
    els['scan-scope-copy'].textContent = 'Selecciona un análisis para ver su alcance. Los archivos sin permisos de lectura no se fuerzan ni se abren.';
  }
}

function setScanUi(update = {}) {
  Object.assign(state.scan, update);
  const scan = state.scan;
  scan.skipped = safeNumber(scan.policySkipped) + safeNumber(scan.traversalSkipped);
  if (scan.running && !scan.startedAt) scan.startedAt = Date.now();
  const running = scan.running;
  const discovery = running && scan.phase === 'discovery';
  const indeterminate = running && (discovery || scan.total == null);
  const completed = scan.phase === 'completed';
  const cancelled = scan.phase === 'cancelled';
  els['cancel-scan'].hidden = !running;
  els['cancel-scan'].disabled = false;
  for (const button of all('[data-action="quick-scan"], [data-action="full-scan"], [data-action="deep-scan"]')) button.disabled = running;
  els['scan-progress-track'].classList.toggle('is-indeterminate', indeterminate);
  els['scan-progress-track'].setAttribute('aria-busy', String(running));
  const percent = completed ? 100 : clamp(safeNumber(scan.percent), 0, 100);
  if (indeterminate) els['scan-progress-track'].removeAttribute('aria-valuenow');
  else els['scan-progress-track'].setAttribute('aria-valuenow', String(Math.round(percent)));
  els['scan-progress-value'].value = percent;
  els['scan-count-scanned'].textContent = formatCount(scan.scanned);
  els['scan-count-total'].textContent = scan.total == null ? '—' : formatCount(scan.total);
  els['scan-count-threats'].textContent = formatCount(scan.threats);
  els['scan-count-errors'].textContent = formatCount(scan.errors);
  els['scan-count-skipped'].textContent = formatCount(scan.skipped);
  const skippedDescription = `Omitidos: ${formatCount(scan.skipped)}. ${formatCount(scan.policySkipped)} archivos por política o límites y ${formatCount(scan.traversalSkipped)} ubicaciones por seguridad; ${formatCount(scan.linksSkipped)} fueron enlaces o puntos de reanálisis.`;
  els['scan-skipped-counter'].setAttribute('aria-label', skippedDescription);
  els['scan-skipped-counter'].title = skippedDescription;
  els['scan-progress-meta'].hidden = !scan.startedAt;
  if (discovery) {
    els['scan-progress-context'].textContent = scan.mode === 'quick'
      ? 'Enumerando el primer nivel de Descargas, incluidos ocultos…'
      : 'Enumerando archivos, ocultos y subcarpetas…';
  } else if (running && indeterminate) {
    els['scan-progress-context'].textContent = `${formatCount(scan.scanned)} analizados · el total sigue calculándose`;
  } else if (scan.total != null) {
    els['scan-progress-context'].textContent = `${formatCount(scan.scanned)} de ${formatCount(scan.total)} archivos`;
  } else {
    els['scan-progress-context'].textContent = 'El análisis terminó antes de calcular un total.';
  }
  els['scan-target-label'].textContent = safeString(scan.targetLabel, 'El progreso y los resultados aparecerán aquí.');
  els['scan-state-icon'].classList.toggle('is-success', completed && scan.threats === 0 && scan.errors === 0 && scan.skipped === 0);
  els['scan-state-icon'].classList.toggle('is-warning', completed && (scan.threats > 0 || scan.errors > 0 || scan.skipped > 0) || cancelled);

  if (discovery) {
    els['scan-phase-label'].textContent = 'Descubriendo archivos';
    els['scan-status-title'].textContent = scan.mode === 'full'
      ? 'Enumerando las unidades locales…'
      : scan.mode === 'deep' ? 'Preparando el recorrido profundo…' : 'Preparando el análisis…';
  } else if (running) {
    els['scan-phase-label'].textContent = indeterminate
      ? 'Analizando · total en cálculo'
      : `Analizando · ${Math.round(percent)} %`;
    if (scan.mode === 'full' && scan.rootsTotal) {
      const currentRoot = Math.min(scan.rootsTotal, scan.rootsCompleted + 1);
      els['scan-status-title'].textContent = `Análisis exhaustivo · unidad ${currentRoot} de ${scan.rootsTotal}`;
    } else if (scan.mode === 'deep') {
      els['scan-status-title'].textContent = 'Análisis profundo en curso';
    } else {
      els['scan-status-title'].textContent = 'Análisis en curso';
    }
  } else if (completed) {
    els['scan-phase-label'].textContent = 'Análisis finalizado';
    els['scan-status-title'].textContent = scan.threats > 0
      ? `${formatCount(scan.threats)} ${scan.threats === 1 ? 'hallazgo requiere' : 'hallazgos requieren'} atención`
      : scan.errors > 0 || scan.skipped > 0 ? 'Análisis terminado con elementos no analizados' : 'Sin amenazas detectadas por Aegis';
  } else if (cancelled) {
    els['scan-phase-label'].textContent = 'Análisis cancelado';
    els['scan-status-title'].textContent = 'Se detuvo antes de terminar';
  } else {
    els['scan-phase-label'].textContent = 'Preparado';
    els['scan-status-title'].textContent = 'Selecciona un tipo de análisis';
  }
  renderScanScope();
  syncScanClock();
}

function normalizeResults(value) {
  if (Array.isArray(value)) return value.filter(item => item && typeof item === 'object');
  if (Array.isArray(value?.results)) return value.results.filter(item => item && typeof item === 'object');
  return [];
}

function applyCompletedScan(report = {}, { announce = true } = {}) {
  const summary = getSummary(report);
  const results = normalizeResults(report);
  if (results.length) state.results = results;
  state.reportAvailable = report.reportAvailable !== false;
  state.resultsTruncated = safeNumber(report.resultsTruncated);
  const completedAt = report.completedAt ?? report.finishedAt ?? new Date().toISOString();
  state.lastScan = { ...summary, completedAt };
  state.totalScanned += summary.scanned;
  setScanUi({
    running: false,
    phase: 'completed',
    scanned: summary.scanned,
    total: summary.total || summary.scanned,
    threats: summary.malicious + summary.suspicious,
    errors: summary.errors,
    skipped: summary.skipped,
    policySkipped: summary.policySkipped,
    traversalSkipped: summary.traversalSkipped,
    linksSkipped: summary.linksSkipped,
    percent: 100,
    mode: normalizeScanMode(report.mode, state.scan.mode),
    targetLabel: safeString(report.targetLabel ?? report.target?.label ?? report.label ?? report.path, state.scan.targetLabel)
  });
  setEngineStatus('Motor listo');
  state.activity.unshift({
    kind: 'scan', title: 'Análisis completado',
    description: `${formatCount(summary.scanned)} archivos; ${formatCount(summary.malicious + summary.suspicious)} hallazgos; ${formatCount(summary.skipped)} omitidos`,
    at: completedAt
  });
  renderResults();
  renderActivity();
  renderHomeStatus();
  void refreshQuarantine({ quiet: true });
  if (announce) {
    const findings = summary.malicious + summary.suspicious;
    const incomplete = summary.errors + summary.skipped;
    showToast(
      'Análisis completado',
      findings > 0
        ? 'Hay elementos que requieren atención.'
        : incomplete > 0
          ? `${formatCount(summary.skipped)} omitidos y ${formatCount(summary.errors)} errores; no todos los elementos pudieron analizarse.`
          : 'Aegis no detectó amenazas en los archivos analizados.',
      findings > 0 || incomplete > 0 ? 'warning' : 'success'
    );
  }
}

async function startScan(mode) {
  if (state.scan.running) return;
  try {
    let payload;
    let targetLabel;
    if (mode === 'quick') {
      payload = { mode: 'quick' };
      targetLabel = 'Descargas de Windows';
    } else if (mode === 'full') {
      payload = { mode: 'full' };
      targetLabel = 'Este equipo · todas las unidades locales accesibles';
    } else if (mode === 'deep') {
      const target = await callApi('chooseScanTarget', { purpose: 'scan' });
      if (!target) return;
      if (!safeString(target.targetId)) throw new Error('La selección no devolvió un identificador seguro.');
      payload = { mode: 'deep', targetId: target.targetId };
      targetLabel = safeString(target.label, target.kind === 'file' ? 'Archivo seleccionado' : 'Carpeta seleccionada');
    } else {
      throw new Error('Tipo de análisis desconocido.');
    }

    setView('scan');
    setScanUi({
      running: true, phase: 'discovery', scanned: 0, total: null, threats: 0, errors: 0, skipped: 0,
      policySkipped: 0, traversalSkipped: 0, linksSkipped: 0, percent: 0,
      targetLabel, mode, rootsTotal: null, rootsCompleted: 0, currentRootLabel: '', startedAt: Date.now()
    });
    setEngineStatus('Analizando', 'busy');
    const response = await callApi('startScan', payload);
    const looksCompleted = response && (
      Array.isArray(response.results) || response.completedAt || response.finishedAt || response.status === 'completed'
    );
    if (looksCompleted && state.scan.running) applyCompletedScan(response);
  } catch (error) {
    setScanUi({ running: false, phase: 'cancelled' });
    setEngineStatus('Error del motor', 'error');
    showToast('No se pudo analizar', errorMessage(error), 'error');
  }
}

async function cancelScan() {
  if (!state.scan.running) return;
  els['cancel-scan'].disabled = true;
  els['cancel-scan'].textContent = 'Cancelando…';
  try {
    await callApi('cancelScan');
  } catch (error) {
    showToast('No se pudo cancelar', errorMessage(error), 'error');
    els['cancel-scan'].disabled = false;
  } finally {
    els['cancel-scan'].textContent = 'Cancelar';
  }
}

function applyProtectionState(value = {}) {
  state.protection = {
    active: Boolean(value.active),
    paused: Boolean(value.paused),
    targetLabel: safeString(value.targetLabel, state.protection.targetLabel || 'Descargas'),
    autoQuarantine: Boolean(value.autoQuarantine),
    sessionOnly: value.sessionOnly !== false
  };
  renderProtection();
  renderMonitor();
}

function toggleProtection() {
  if (state.protection.active && !state.protection.paused) {
    els['pause-protection-dialog'].showModal();
    return;
  }
  void resumeProtection();
}

async function pauseProtection() {
  els['pause-protection-confirm'].disabled = true;
  const retainedMonitor = state.monitor.active ? { active: true, target: state.monitor.target } : null;
  try {
    const response = await callApi('pauseProtection');
    applyProtectionState(response);
    if (retainedMonitor) {
      state.monitor = retainedMonitor;
      renderMonitor();
    }
    els['pause-protection-dialog'].close();
    showToast(
      'Vigilancia en tiempo real pausada',
      'La pausa termina al reanudar o reiniciar Aegis. Los análisis manuales siguen disponibles.',
      'warning'
    );
  } catch (error) {
    showToast('No se pudo pausar la protección', errorMessage(error), 'error');
  } finally {
    els['pause-protection-confirm'].disabled = false;
  }
}

async function resumeProtection() {
  els['toggle-protection'].disabled = true;
  try {
    const response = await callApi('resumeProtection');
    applyProtectionState(response);
    showToast('Protección reanudada', 'Aegis vuelve a vigilar Descargas y las carpetas adicionales activas.', 'success');
  } catch (error) {
    showToast('No se pudo reanudar la protección', errorMessage(error), 'error');
  } finally {
    els['toggle-protection'].disabled = false;
  }
}

async function chooseMonitorTarget() {
  try {
    const target = await callApi('chooseScanTarget', { kind: 'directory', purpose: 'monitor' });
    if (!target) return;
    if (!safeString(target.targetId)) throw new Error('La selección no devolvió un identificador seguro.');
    state.selectedMonitorTarget = { targetId: target.targetId, label: safeString(target.label, 'Carpeta seleccionada'), kind: 'directory' };
    renderMonitor();
  } catch (error) {
    showToast('No se pudo elegir la carpeta', errorMessage(error), 'error');
  }
}

async function startMonitor() {
  if (state.protection.paused) {
    showToast('Protección en pausa', 'Reanuda la protección antes de iniciar otra carpeta vigilada.', 'warning');
    return;
  }
  const target = state.selectedMonitorTarget || state.monitor.target;
  if (!target?.targetId) return;
  els['start-monitor'].disabled = true;
  try {
    const response = await callApi('startMonitor', {
      targetId: target.targetId
    });
    if (!state.monitor.active) {
      state.monitor = { active: true, target: { ...target, label: safeString(response?.label, target.label) } };
      renderMonitor();
    }
    showToast('Vigilancia iniciada', 'Se mantendrá activa únicamente mientras Aegis Guard esté abierto.', 'success');
  } catch (error) {
    showToast('No se pudo iniciar la vigilancia', errorMessage(error), 'error');
  } finally {
    renderMonitor();
  }
}

async function stopMonitor() {
  els['stop-monitor'].disabled = true;
  try {
    await callApi('stopMonitor');
    state.monitor.active = false;
    state.monitor.target = null;
    state.selectedMonitorTarget = null;
    renderMonitor();
    showToast(
      state.protection.paused ? 'Carpeta adicional retirada' : 'Vigilancia detenida',
      'Aegis ya no conserva esta carpeta para la vigilancia adicional.',
      'info'
    );
  } catch (error) {
    showToast('No se pudo detener la vigilancia', errorMessage(error), 'error');
  } finally {
    els['stop-monitor'].disabled = false;
  }
}

async function refreshQuarantine({ quiet = false } = {}) {
  if (!api || typeof api.listQuarantine !== 'function') return;
  els['refresh-quarantine'].disabled = true;
  try {
    const response = await callApi('listQuarantine');
    state.quarantine = Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : [];
    state.quarantineInventory = Array.isArray(response)
      ? { total: response.length, truncatedCount: 0, corruptCount: 0, oversizedCount: 0 }
      : {
          total: safeNumber(response?.total, state.quarantine.length),
          truncatedCount: safeNumber(response?.truncatedCount),
          corruptCount: safeNumber(response?.corruptCount),
          oversizedCount: safeNumber(response?.oversizedCount)
        };
    renderQuarantine();
    renderHomeStatus();
  } catch (error) {
    if (!quiet) showToast('No se pudo abrir la cuarentena', errorMessage(error), 'error');
  } finally {
    els['refresh-quarantine'].disabled = false;
  }
}

function openRestoreDialog(item) {
  state.restoreId = safeString(item?.id);
  if (!state.restoreId) return;
  els['restore-dialog-copy'].textContent = `Vas a restaurar «${fileName(item.originalPath ?? item.path ?? item.label)}». Elige una ubicación segura y analízalo con Microsoft Defender antes de abrirlo.`;
  els['restore-dialog'].showModal();
}

function openIsolateDialog(result) {
  const scanId = safeString(result?.scanId);
  const resultId = safeString(result?.resultId);
  if (!scanId || !resultId) return;
  state.isolateRequest = { scanId, resultId };
  els['isolate-dialog-copy'].textContent = `Aegis moverá «${fileName(result.path ?? result.label ?? result.name)}» a la cuarentena cifrada. Podrás restaurarlo más adelante.`;
  els['isolate-dialog'].showModal();
}

async function confirmIsolate() {
  const request = state.isolateRequest;
  if (!request) return;
  els['isolate-confirm'].disabled = true;
  try {
    const item = await callApi('isolateResult', request);
    const result = state.results.find(candidate => candidate.resultId === request.resultId);
    if (result) {
      result.action = 'quarantined';
      result.quarantineId = item?.id;
    }
    els['isolate-dialog'].close();
    state.isolateRequest = null;
    renderResults();
    await refreshQuarantine({ quiet: true });
    showToast('Archivo aislado', 'Se movió a la cuarentena cifrada sin eliminarlo definitivamente.', 'success');
  } catch (error) {
    showToast('No se pudo aislar', errorMessage(error), 'error');
  } finally {
    els['isolate-confirm'].disabled = false;
  }
}

async function confirmRestore() {
  const id = state.restoreId;
  if (!id) return;
  els['restore-confirm'].disabled = true;
  try {
    const response = await callApi('restoreQuarantine', { id });
    if (response?.cancelled) return;
    els['restore-dialog'].close();
    state.restoreId = null;
    await refreshQuarantine({ quiet: true });
    state.activity.unshift({
      kind: 'quarantine', title: 'Archivo restaurado',
      description: safeString(response?.label ?? response?.destinationLabel, 'Restauración completada'),
      at: new Date().toISOString()
    });
    renderActivity();
    showToast('Archivo restaurado', 'Aegis verificó la integridad antes de restaurarlo.', 'success');
  } catch (error) {
    showToast('No se pudo restaurar', errorMessage(error), 'error');
  } finally {
    els['restore-confirm'].disabled = false;
  }
}

async function exportReport(format) {
  const button = els[`export-report-${format}`];
  button.disabled = true;
  try {
    const response = await callApi('exportReport', { format });
    if (response?.cancelled) return;
    showToast('Informe guardado', `${format.toUpperCase()} completo: ${formatCount(response?.count)} registros.`, 'success');
  } catch (error) {
    showToast('No se pudo guardar el informe', errorMessage(error), 'error');
  } finally {
    button.disabled = !state.reportAvailable;
  }
}

async function saveSettings() {
  const previous = { ...state.settings };
  const next = {
    theme: els['theme-select'].value,
    autoQuarantine: Boolean(els['auto-quarantine'].checked),
    launchAtStartup: Boolean(els['start-with-windows'].checked)
  };
  state.settings = next;
  applyTheme(next.theme);
  els['settings-save-status'].textContent = 'Guardando…';
  try {
    const response = await callApi('saveSettings', next);
    if (response?.settings) state.settings = { ...next, ...response.settings };
    if (response?.startup && typeof response.startup === 'object') {
      state.startup = {
        supported: response.startup.supported !== false,
        enabled: Boolean(response.startup.enabled),
        requested: Boolean(response.startup.requested),
        launchesInBackground: response.startup.launchesInBackground !== false
      };
    }
    renderStartupSetting();
    els['settings-save-status'].textContent = 'Cambios guardados.';
  } catch (error) {
    state.settings = previous;
    els['theme-select'].value = previous.theme;
    els['auto-quarantine'].checked = previous.autoQuarantine;
    applyTheme(previous.theme);
    renderStartupSetting();
    els['settings-save-status'].textContent = 'No se pudieron guardar los cambios.';
    showToast('No se guardaron los ajustes', errorMessage(error), 'error');
  }
}

async function checkForUpdates() {
  els['check-updates'].disabled = true;
  els['update-status'].textContent = 'Buscando actualizaciones…';
  try {
    const response = await callApi('checkForUpdates');
    const status = safeString(response?.status, 'unknown');
    if (status === 'available') {
      els['update-status'].textContent = `Hay una actualización disponible${response.version ? `: ${response.version}` : ''}.`;
    } else if (status === 'downloading') {
      els['update-status'].textContent = 'Descargando la actualización firmada…';
    } else if (status === 'downloaded') {
      els['update-status'].textContent = 'Actualización descargada y lista para instalar.';
      els['restart-update'].hidden = false;
    } else if (status === 'unsupported' || status === 'unavailable') {
      els['update-status'].textContent = safeString(response.message, 'Las actualizaciones estarán disponibles en la versión instalada.');
    } else {
      els['update-status'].textContent = 'Aegis Guard está actualizado.';
    }
  } catch (error) {
    els['update-status'].textContent = errorMessage(error, 'No se pudo comprobar si hay actualizaciones.');
  } finally {
    els['check-updates'].disabled = false;
  }
}

async function restartAndUpdate() {
  els['restart-update'].disabled = true;
  els['update-status'].textContent = 'Cerrando Aegis de forma segura…';
  try {
    await callApi('restartAndUpdate');
  } catch (error) {
    els['restart-update'].disabled = false;
    els['update-status'].textContent = errorMessage(error, 'No se pudo iniciar la actualización.');
  }
}

async function runSimulation() {
  els['run-simulation'].disabled = true;
  els['run-simulation'].textContent = 'Ejecutando prueba…';
  try {
    setView('scan');
    setScanUi({
      running: true, phase: 'discovery', scanned: 0, total: null, threats: 0, errors: 0, skipped: 0,
      policySkipped: 0, traversalSkipped: 0, linksSkipped: 0, percent: 0,
      targetLabel: 'Simulación de texto inofensiva', mode: 'simulation', startedAt: Date.now()
    });
    setEngineStatus('Probando', 'busy');
    const response = await callApi('createAndScanSimulation');
    if (response && state.scan.running) applyCompletedScan(response);
  } catch (error) {
    setScanUi({ running: false, phase: 'cancelled' });
    setEngineStatus('Error del motor', 'error');
    showToast('La prueba no se completó', errorMessage(error), 'error');
  } finally {
    els['run-simulation'].disabled = false;
    els['run-simulation'].textContent = 'Ejecutar simulación inofensiva';
  }
}

function eventPayload(event) {
  if (event?.payload && typeof event.payload === 'object') return { ...event, ...event.payload };
  if (event?.detail && typeof event.detail === 'object') return { ...event, ...event.detail };
  return event && typeof event === 'object' ? event : {};
}

function handleAppEvent(rawEvent) {
  const event = eventPayload(rawEvent);
  const type = safeString(event.type ?? event.name).toLowerCase();

  if (type === 'scan-started') {
    setScanUi({
      running: true, phase: 'discovery', scanned: 0, total: null, threats: 0, errors: 0, skipped: 0,
      policySkipped: 0, traversalSkipped: 0, linksSkipped: 0, percent: 0,
      targetLabel: safeString(event.targetLabel ?? event.label, state.scan.targetLabel),
      mode: normalizeScanMode(event.mode ?? event.target?.mode, state.scan.mode),
      rootsTotal: null,
      rootsCompleted: 0,
      currentRootLabel: ''
    });
    setEngineStatus('Analizando', 'busy');
    return;
  }

  if (type === 'scan-progress') {
    const phase = safeString(event.phase ?? event.stage, 'scanning').toLowerCase();
    const progressMode = normalizeScanMode(event.mode, state.scan.mode);
    const exhaustiveStreaming = ['full', 'deep'].includes(progressMode) && event.total == null;
    const total = exhaustiveStreaming ? null : (event.total ?? event.discovered ?? event.filesFound);
    const scanned = safeNumber(event.scanned ?? event.completed ?? event.processed, state.scan.scanned);
    const numericTotal = exhaustiveStreaming
      ? null
      : total == null ? state.scan.total : Math.max(0, safeNumber(total));
    const percent = event.percent != null
      ? safeNumber(event.percent)
      : numericTotal ? (scanned / numericTotal) * 100 : state.scan.percent;
    const progressVerdict = event.result ? normalizeVerdict(event.result.verdict) : null;
    const liveErrors = event.errors == null
      ? state.scan.errors + (progressVerdict === 'error' ? 1 : 0)
      : safeNumber(event.errors);
    const livePolicySkipped = event.skipped == null
      ? state.scan.policySkipped + (safeString(event.result?.verdict).toLowerCase() === 'skipped' ? 1 : 0)
      : safeNumber(event.skipped);
    const liveTraversalSkipped = event.traversalSkipped == null
      ? state.scan.traversalSkipped
      : safeNumber(event.traversalSkipped);
    const liveLinksSkipped = event.linksSkipped == null
      ? state.scan.linksSkipped
      : safeNumber(event.linksSkipped);
    setScanUi({
      running: true,
      phase: phase.includes('discover') ? 'discovery' : 'scanning',
      scanned,
      total: numericTotal,
      threats: safeNumber(event.threats ?? event.malicious ?? event.detections, state.scan.threats),
      errors: liveErrors,
      policySkipped: livePolicySkipped,
      traversalSkipped: liveTraversalSkipped,
      linksSkipped: liveLinksSkipped,
      percent,
      targetLabel: safeString(event.targetLabel ?? event.label, state.scan.targetLabel),
      rootsTotal: event.rootsTotal == null ? state.scan.rootsTotal : safeNumber(event.rootsTotal),
      rootsCompleted: safeNumber(event.rootsCompleted, state.scan.rootsCompleted),
      currentRootLabel: safeString(event.currentRootLabel, state.scan.currentRootLabel)
    });
    const current = event.currentFile ?? event.path ?? event.currentLabel;
    const rootContext = safeString(event.currentRootLabel);
    const currentLabel = rootContext && safeString(current) ? `${rootContext} · ${safeString(current)}` : safeString(current, rootContext);
    els['scan-current-file'].hidden = !currentLabel;
    if (currentLabel) els['scan-current-file'].querySelector('span:last-child').textContent = currentLabel;
    return;
  }

  if (type === 'scan-detection' || type === 'scan-result') {
    const result = event.result && typeof event.result === 'object' ? event.result : event;
    const key = result.id ?? result.path ?? result.label;
    const index = state.results.findIndex(item => (item.id ?? item.path ?? item.label) === key);
    if (index >= 0) state.results[index] = result;
    else state.results.unshift(result);
    const verdict = normalizeVerdict(result.verdict);
    if (verdict === 'malicious' || verdict === 'suspicious') {
      setScanUi({ threats: state.scan.threats + 1 });
    }
    renderResults();
    return;
  }

  if (type === 'scan-traversal-error') {
    setScanUi({ errors: state.scan.errors + 1 });
    return;
  }

  if (type === 'scan-traversal-skipped') {
    const linkSkipped = ['link', 'outside-root'].includes(safeString(event.reason));
    // Immediate feedback only. The next scan-progress event replaces these
    // values with its authoritative accumulated counters, instead of adding.
    setScanUi({
      traversalSkipped: state.scan.traversalSkipped + 1,
      linksSkipped: state.scan.linksSkipped + (linkSkipped ? 1 : 0)
    });
    return;
  }

  if (type === 'scan-completed') {
    applyCompletedScan(event.report ?? event.result ?? event);
    return;
  }

  if (type === 'scan-cancelled') {
    const partialSummary = getSummary(event);
    const partialResults = normalizeResults(event);
    if (partialResults.length) state.results = partialResults;
    state.resultsTruncated = safeNumber(event.resultsTruncated);
    setScanUi({
      running: false,
      phase: 'cancelled',
      scanned: partialSummary.scanned || state.scan.scanned,
      total: partialSummary.total || state.scan.total,
      threats: partialSummary.malicious + partialSummary.suspicious || state.scan.threats,
      errors: partialSummary.errors || state.scan.errors,
      skipped: partialSummary.skipped || state.scan.skipped,
      policySkipped: partialSummary.policySkipped || state.scan.policySkipped,
      traversalSkipped: partialSummary.traversalSkipped || state.scan.traversalSkipped,
      linksSkipped: partialSummary.linksSkipped || state.scan.linksSkipped,
      mode: normalizeScanMode(event.mode, state.scan.mode),
      targetLabel: safeString(event.targetLabel ?? event.target?.label, state.scan.targetLabel)
    });
    setEngineStatus('Motor listo');
    renderResults();
    showToast('Análisis cancelado', `${formatCount(state.scan.scanned)} archivos procesados; los resultados parciales permanecen disponibles.`, 'info');
    return;
  }

  if (type === 'scan-error') {
    setScanUi({ running: false, phase: 'cancelled' });
    setEngineStatus('Error del motor', 'error');
    showToast('Error durante el análisis', safeString(event.message, 'El análisis no pudo terminar.'), 'error');
    return;
  }

  if (type === 'scan-warning') {
    const historyWarning = safeString(event.code) === 'STATE_NOT_PERSISTED';
    showToast(
      historyWarning ? 'Actividad completada, historial no guardado' : 'Aviso del análisis',
      historyWarning
        ? 'La acción terminó, pero Windows no permitió guardar su historial en disco.'
        : safeString(event.message, 'El análisis terminó con una advertencia.'),
      'warning'
    );
    return;
  }

  if (type === 'quarantine-updated' || type === 'quarantine-changed' || type === 'file-quarantined') {
    void refreshQuarantine({ quiet: true });
    return;
  }

  if (type === 'protection-state-changed') {
    applyProtectionState(event);
    return;
  }

  if (type === 'protection-error') {
    applyProtectionState({ ...state.protection, active: false, paused: false });
    showToast('La protección de Descargas se detuvo', safeString(event.message, 'No se pudo mantener la vigilancia en tiempo real.'), 'error');
    return;
  }

  if (type === 'protection-warning') {
    showToast('La vigilancia necesita atención', safeString(event.message, 'Conviene ejecutar un análisis manual de Descargas.'), 'warning');
    return;
  }

  if (type === 'monitor-started') {
    const target = state.selectedMonitorTarget || state.monitor.target || {};
    state.monitor = { active: true, target: { ...target, label: safeString(event.label ?? event.targetLabel, target.label) } };
    renderMonitor();
    return;
  }

  if (type === 'monitor-stopped') {
    if (!state.protection.paused) state.monitor.active = false;
    renderMonitor();
    return;
  }

  if (type === 'monitor-detection' || type === 'protection-detection') {
    const result = event.result && typeof event.result === 'object' ? event.result : event;
    state.results.unshift(result);
    state.activity.unshift({
      kind: 'monitor', title: type === 'protection-detection' ? 'Descarga analizada' : 'Cambio analizado',
      description: `${fileName(result.path ?? result.label)} · ${verdictLabel(result.verdict)}`,
      at: new Date().toISOString()
    });
    renderResults();
    renderActivity();
    if (normalizeVerdict(result.verdict) !== 'clean') showToast('La vigilancia encontró un indicio', 'Consulta Resultados para ver los detalles.', 'warning');
    return;
  }

  if (type === 'settings-changed') {
    state.settings = {
      theme: ['system', 'light', 'dark'].includes(event.theme) ? event.theme : state.settings.theme,
      autoQuarantine: event.autoQuarantine === true,
      launchAtStartup: event.launchAtStartup !== false
    };
    els['theme-select'].value = state.settings.theme;
    els['auto-quarantine'].checked = state.settings.autoQuarantine;
    renderStartupSetting();
    applyTheme(state.settings.theme);
    return;
  }

  if (type === 'update-available') {
    els['update-status'].textContent = `Actualización disponible${event.version ? `: ${event.version}` : ''}.`;
  } else if (type === 'update-progress') {
    els['update-status'].textContent = `Descargando actualización firmada · ${Math.round(safeNumber(event.percent))} %`;
  } else if (type === 'update-downloaded') {
    els['update-status'].textContent = 'Actualización descargada y lista para instalar.';
    els['restart-update'].hidden = false;
  } else if (type === 'update-error') {
    els['update-status'].textContent = safeString(event.message, 'No se pudo comprobar la actualización.');
  }
}

function normalizeBootstrap(data = {}) {
  const appInfo = data.app && typeof data.app === 'object' ? data.app : {};
  const definitions = data.definitions && typeof data.definitions === 'object' ? data.definitions : {};
  const engine = data.engine && typeof data.engine === 'object' ? data.engine : {};
  const settings = data.settings && typeof data.settings === 'object' ? data.settings : {};
  const persisted = data.state && typeof data.state === 'object' ? data.state : {};
  const quarantine = Array.isArray(data.quarantine) ? data.quarantine
    : Array.isArray(data.quarantineItems) ? data.quarantineItems
      : Array.isArray(data.quarantine?.items) ? data.quarantine.items : [];
  const rawQuarantineInventory = data.quarantineInventory ?? (data.quarantine && !Array.isArray(data.quarantine) ? data.quarantine : {});
  const results = normalizeResults(data.results?.length ? data.results : persisted.lastResults ?? data.lastScan);
  const lastScan = data.lastScan ?? persisted.lastScan ?? null;
  const stats = data.stats && typeof data.stats === 'object' ? data.stats : {};
  return {
    version: safeString(data.version ?? data.appVersion ?? appInfo.version, '—'),
    engineVersion: safeString(data.engineVersion ?? engine.version, '—'),
    definitionsVersion: safeString(data.definitionsVersion ?? definitions.version, 'locales'),
    settings: {
      theme: ['system', 'light', 'dark'].includes(settings.theme) ? settings.theme : 'system',
      autoQuarantine: settings.autoQuarantine === true,
      launchAtStartup: settings.launchAtStartup !== false
    },
    quarantine,
    quarantineInventory: {
      total: safeNumber(rawQuarantineInventory.total, quarantine.length),
      truncatedCount: safeNumber(rawQuarantineInventory.truncatedCount),
      corruptCount: safeNumber(rawQuarantineInventory.corruptCount),
      oversizedCount: safeNumber(rawQuarantineInventory.oversizedCount)
    },
    results,
    reportAvailable: Boolean(data.reportAvailable),
    network: data.network && typeof data.network === 'object' ? data.network : null,
    activity: Array.isArray(data.activity ?? data.history) ? (data.activity ?? data.history) : [],
    lastScan,
    totalScanned: safeNumber(stats.totalScanned ?? data.totalScanned ?? persisted.totalScanned ?? getSummary(lastScan ?? {}).scanned),
    protection: data.protection && typeof data.protection === 'object'
      ? data.protection
      : { active: true, paused: false, targetLabel: 'Descargas', sessionOnly: true },
    startup: data.startup && typeof data.startup === 'object'
      ? data.startup
      : { supported: true, enabled: settings.launchAtStartup !== false, requested: settings.launchAtStartup !== false, launchesInBackground: true },
    monitor: data.monitor && typeof data.monitor === 'object' ? data.monitor : { active: false, target: null }
  };
}

function applyBootstrap(rawData) {
  const data = normalizeBootstrap(rawData);
  state.version = data.version;
  state.engineVersion = data.engineVersion;
  state.definitionsVersion = data.definitionsVersion;
  state.settings = data.settings;
  state.quarantine = data.quarantine;
  state.quarantineInventory = data.quarantineInventory;
  state.results = data.results;
  state.reportAvailable = data.reportAvailable;
  state.network = data.network;
  state.activity = data.activity;
  state.lastScan = data.lastScan;
  state.totalScanned = data.totalScanned;
  state.protection = {
    active: Boolean(data.protection.active),
    paused: Boolean(data.protection.paused),
    targetLabel: safeString(data.protection.targetLabel, 'Descargas'),
    autoQuarantine: Boolean(data.protection.autoQuarantine),
    sessionOnly: data.protection.sessionOnly !== false
  };
  state.startup = {
    supported: data.startup.supported !== false,
    enabled: Boolean(data.startup.enabled),
    requested: Boolean(data.startup.requested),
    launchesInBackground: data.startup.launchesInBackground !== false
  };
  state.monitor = {
    active: Boolean(data.monitor.active),
    target: data.monitor.target ?? (data.monitor.targetId ? {
      targetId: data.monitor.targetId,
      label: safeString(data.monitor.targetLabel ?? data.monitor.label, 'Carpeta seleccionada')
    } : null)
  };

  els['sidebar-version'].textContent = data.version;
  els['about-version'].textContent = data.version;
  els['engine-version'].textContent = data.engineVersion;
  els['definitions-version'].textContent = data.definitionsVersion;
  els['about-definitions'].textContent = data.definitionsVersion;
  els['theme-select'].value = data.settings.theme;
  els['auto-quarantine'].checked = data.settings.autoQuarantine;
  renderStartupSetting();
  applyTheme(data.settings.theme);
  renderHomeStatus();
  renderActivity();
  renderProtection();
  renderMonitor();
  renderResults();
  renderNetwork();
  renderQuarantine();
}

function bindEvents() {
  for (const button of all('.nav-item')) button.addEventListener('click', () => setView(button.dataset.view));
  for (const button of all('[data-view-link]')) button.addEventListener('click', () => setView(button.dataset.viewLink));
  for (const button of all('[data-action="quick-scan"]')) button.addEventListener('click', () => void startScan('quick'));
  for (const button of all('[data-action="full-scan"]')) button.addEventListener('click', () => void startScan('full'));
  for (const button of all('[data-action="deep-scan"]')) button.addEventListener('click', () => void startScan('deep'));
  els['cancel-scan'].addEventListener('click', () => void cancelScan());
  els['toggle-protection'].addEventListener('click', toggleProtection);
  els['choose-monitor-target'].addEventListener('click', () => void chooseMonitorTarget());
  els['start-monitor'].addEventListener('click', () => void startMonitor());
  els['stop-monitor'].addEventListener('click', () => void stopMonitor());
  els['refresh-quarantine'].addEventListener('click', () => void refreshQuarantine());
  els['export-report-json'].addEventListener('click', () => void exportReport('json'));
  els['export-report-csv'].addEventListener('click', () => void exportReport('csv'));
  els['run-network-audit'].addEventListener('click', () => void runNetworkAudit());
  els['export-network-json'].addEventListener('click', () => void exportNetworkReport('json'));
  els['export-network-csv'].addEventListener('click', () => void exportNetworkReport('csv'));

  for (const button of all('.filter-button')) {
    button.addEventListener('click', () => {
      state.resultFilter = button.dataset.filter;
      for (const candidate of all('.filter-button')) {
        const selected = candidate === button;
        candidate.classList.toggle('is-selected', selected);
        candidate.setAttribute('aria-pressed', String(selected));
      }
      renderResults();
    });
  }

  els['theme-select'].addEventListener('change', () => void saveSettings());
  els['auto-quarantine'].addEventListener('change', () => void saveSettings());
  els['start-with-windows'].addEventListener('change', () => void saveSettings());
  els['theme-cycle'].addEventListener('click', () => {
    const order = ['system', 'light', 'dark'];
    els['theme-select'].value = order[(order.indexOf(state.settings.theme) + 1) % order.length];
    void saveSettings();
  });
  els['check-updates'].addEventListener('click', () => void checkForUpdates());
  els['restart-update'].addEventListener('click', () => void restartAndUpdate());
  els['run-simulation'].addEventListener('click', () => void runSimulation());
  els['restore-cancel'].addEventListener('click', () => els['restore-dialog'].close());
  els['restore-confirm'].addEventListener('click', () => void confirmRestore());
  els['restore-dialog'].addEventListener('close', () => { state.restoreId = null; });
  els['restore-dialog'].addEventListener('click', event => {
    if (event.target === els['restore-dialog']) els['restore-dialog'].close();
  });
  els['isolate-cancel'].addEventListener('click', () => els['isolate-dialog'].close());
  els['isolate-confirm'].addEventListener('click', () => void confirmIsolate());
  els['isolate-dialog'].addEventListener('close', () => { state.isolateRequest = null; });
  els['isolate-dialog'].addEventListener('click', event => {
    if (event.target === els['isolate-dialog']) els['isolate-dialog'].close();
  });
  els['pause-protection-cancel'].addEventListener('click', () => els['pause-protection-dialog'].close());
  els['pause-protection-confirm'].addEventListener('click', () => void pauseProtection());
  els['pause-protection-dialog'].addEventListener('click', event => {
    if (event.target === els['pause-protection-dialog']) els['pause-protection-dialog'].close();
  });

  systemThemeQuery.addEventListener('change', () => {
    if (state.settings.theme === 'system') applyTheme('system');
  });
}

function showFatal(message) {
  for (const view of all('.view')) view.hidden = true;
  els['fatal-panel'].hidden = false;
  els['fatal-message'].textContent = message;
  setEngineStatus('Sin conexión', 'error');
}

async function initialize() {
  cacheElements();
  systemThemeQuery = window.matchMedia('(prefers-color-scheme: dark)');
  api = PREVIEW_MODE ? createPreviewBridge() : window.aegis;
  bindEvents();
  els['preview-pill'].hidden = !PREVIEW_MODE;

  if (!api || typeof api.getBootstrap !== 'function' || typeof api.onEvent !== 'function') {
    showFatal('El puente seguro con el proceso principal no está disponible. Abre la aplicación de escritorio o usa ?preview=1 exclusivamente para la revisión visual.');
    return;
  }

  try {
    state.unsubscribe = api.onEvent(handleAppEvent);
    const bootstrap = await callApi('getBootstrap');
    applyBootstrap(bootstrap);
    setEngineStatus('Motor listo');
  } catch (error) {
    showFatal(errorMessage(error, 'No se pudieron cargar los datos iniciales de Aegis.'));
  }
}

function createPreviewBridge() {
  const listeners = new Set();
  let previewSettings = { theme: 'system', autoQuarantine: false, launchAtStartup: true };
  let previewProtection = { active: true, paused: false, targetLabel: 'Descargas', autoQuarantine: false, sessionOnly: true };
  let scanSequence = 0;
  let monitorActive = false;
  let quarantine = [{
    id: 'd95071bf-80b8-44ee-a533-b75136e69c66',
    originalPath: 'C:\\Usuarios\\Demo\\Descargas\\muestra-antigua.txt',
    quarantinedAt: '2026-08-17T18:42:00.000Z', verdict: 'malicious', score: 100
  }];

  const emit = event => {
    for (const listener of listeners) window.queueMicrotask(() => listener(Object.freeze({ ...event })));
  };
  const delay = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds));
  const previewScanId = '76d2809c-2614-45df-908f-587506ab3949';
  const cleanResults = [
    { scanId: previewScanId, resultId: '182452d6-a237-4a12-9552-f29849535227', path: 'C:\\Usuarios\\Demo\\Descargas\\presupuesto.pdf', verdict: 'clean', score: 0, findings: [] },
    { scanId: previewScanId, resultId: '765d1fc3-45d5-474a-81cf-00042deef3b4', path: 'C:\\Usuarios\\Demo\\Descargas\\foto-vacaciones.jpg', verdict: 'clean', score: 0, findings: [] },
    { scanId: previewScanId, resultId: '971ea9f6-32a3-4f08-b087-4d33c1bb3192', path: 'C:\\Usuarios\\Demo\\Descargas\\instalador-revisar.exe', verdict: 'suspicious', score: 35, findings: [{ description: 'Extensión ejecutable y nombre genérico' }] }
  ];

  async function previewScan(label, simulation = false, mode = 'quick') {
    const sequence = ++scanSequence;
    const full = mode === 'full';
    const deep = mode === 'deep';
    const exhaustive = full || deep;
    emit({ type: 'scan-started', mode, targetLabel: label });
    emit({ type: 'scan-progress', phase: 'discovery', discovered: 0, rootsTotal: full ? 3 : undefined, rootsCompleted: 0, targetLabel: label });
    await delay(380);
    if (sequence !== scanSequence) return { status: 'cancelled' };
    const total = simulation ? 1 : full ? 72 : deep ? 46 : 24;
    emit({ type: 'scan-progress', phase: 'scanning', completed: 0, total: exhaustive ? null : total, percent: 0, rootsTotal: full ? 3 : undefined, rootsCompleted: 0, targetLabel: label });
    const steps = simulation ? [1] : full ? [12, 26, 41, 57, 72] : deep ? [7, 16, 28, 38, 46] : [4, 9, 15, 20, 24];
    for (const [index, scanned] of steps.entries()) {
      await delay(260);
      if (sequence !== scanSequence) return { status: 'cancelled' };
      if (exhaustive && index === 1) emit({ type: 'scan-traversal-skipped', reason: 'link', mode });
      emit({
        type: 'scan-progress', phase: 'scanning', completed: scanned, total: exhaustive ? null : total,
        percent: (scanned / total) * 100,
        currentLabel: simulation ? 'aegis-simulacion-inofensiva.txt' : `archivo-demostracion-${scanned}.dat`,
        threats: simulation ? 1 : 0,
        skipped: mode === 'quick' ? 1 : 0,
        traversalSkipped: exhaustive ? Math.min(2, index) : 0,
        linksSkipped: exhaustive && index > 0 ? 1 : 0,
        rootsTotal: full ? 3 : undefined,
        rootsCompleted: full ? Math.min(2, Math.floor(index * 3 / steps.length)) : undefined,
        currentRootLabel: full ? ['Windows (C:)', 'Datos (D:)', 'Copia local (E:)'][Math.min(2, Math.floor(index * 3 / steps.length))] : undefined,
        targetLabel: label
      });
    }

    const results = simulation ? [{
      path: 'C:\\Temporal\\aegis-simulacion-inofensiva.txt', verdict: 'malicious', score: 100,
      findings: [{ description: 'Firma de simulación segura de Aegis' }], quarantined: true
    }] : cleanResults;
    if (simulation) {
      quarantine = [{
        id: '717e568b-c61b-4dbc-b4c6-3847813eb75e',
        originalPath: 'C:\\Temporal\\aegis-simulacion-inofensiva.txt',
        quarantinedAt: new Date().toISOString(), verdict: 'malicious', score: 100
      }, ...quarantine];
      emit({ type: 'quarantine-updated' });
    }
    const report = {
      status: 'completed', scanId: previewScanId, mode, completedAt: new Date().toISOString(), targetLabel: label, results,
      resultsTruncated: exhaustive ? Math.max(0, total - results.length) : 0,
      reportAvailable: true,
      summary: {
        scanned: total, total,
        malicious: simulation ? 1 : 0,
        suspicious: simulation ? 0 : 1,
        errors: 0,
        skipped: mode === 'quick' ? 1 : 0,
        traversalSkipped: exhaustive ? 2 : 0,
        linksSkipped: exhaustive ? 1 : 0,
        quarantined: simulation ? 1 : 0
      }
    };
    emit({ type: 'scan-completed', report });
    return report;
  }

  return Object.freeze({
    async getBootstrap() {
      return {
        app: { version: '0.2.3-preview' },
        engine: { version: '0.2.3' },
        definitions: { version: '2026.08.18-local' },
        settings: previewSettings,
        protection: previewProtection,
        startup: { supported: true, enabled: previewSettings.launchAtStartup, requested: previewSettings.launchAtStartup, launchesInBackground: true },
        stats: { totalScanned: 148 },
        reportAvailable: true,
        network: { completedAt:'2026-08-20T09:30:00.000Z',reportAvailable:true,summary:{connections:2,suspicious:0,unsignedProcesses:1,truncated:false},windowsSecurity:{firewall:[{name:'Domain',enabled:true},{name:'Private',enabled:true},{name:'Public',enabled:true}],defender:{antivirusEnabled:true,realTimeProtectionEnabled:true,networkInspectionEnabled:true}},events:[{verdict:'observed',explanation:'Conexión saliente observada; no coincide con los indicadores locales disponibles.',protocol:'tcp',remoteAddress:'162.159.135.234',remotePort:443,domain:'discord.com',process:{id:4120,name:'Discord',path:'C:\\Usuarios\\Demo\\AppData\\Local\\Discord\\Discord.exe'},signature:{status:'valid',publisher:'Discord Inc.'}},{verdict:'observed',explanation:'Conexión saliente observada; no coincide con los indicadores locales disponibles.',protocol:'tcp',remoteAddress:'20.190.160.1',remotePort:443,domain:'login.microsoftonline.com',process:{id:1052,name:'msedge',path:'C:\\Program Files\\Microsoft\\Edge\\msedge.exe'},signature:{status:'valid',publisher:'Microsoft Corporation'}}]},
        lastScan: {
          completedAt: '2026-08-18T08:35:00.000Z',
          summary: { scanned: 24, total: 24, malicious: 0, suspicious: 0, errors: 0, quarantined: 0 }
        },
        results: cleanResults,
        quarantine,
        activity: [
          { kind: 'scan', title: 'Análisis rápido completado', description: '24 archivos; sin amenazas detectadas', at: '2026-08-18T08:35:00.000Z' },
          { kind: 'quarantine', title: 'Elemento aislado', description: 'muestra-antigua.txt', at: '2026-08-17T18:42:00.000Z' }
        ],
        monitor: { active: false, target: null }
      };
    },
    onEvent(listener) {
      if (typeof listener !== 'function') throw new TypeError('El listener debe ser una función.');
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    async chooseScanTarget(options = {}) {
      return {
        targetId: `preview-${options.kind === 'directory' ? 'folder' : 'target'}-1`,
        label: options.kind === 'directory' ? 'Documentos · Proyecto Aegis' : 'Documentos · Carpeta de prueba',
        kind: options.kind === 'directory' ? 'directory' : 'directory'
      };
    },
    async startScan(payload = {}) {
      const label = payload.mode === 'quick'
        ? 'Descargas de Windows'
        : payload.mode === 'full' ? 'Este equipo' : payload.mode === 'deep' ? 'Documentos · Carpeta de prueba' : 'Ruta de prueba';
      return previewScan(label, false, payload.mode);
    },
    async cancelScan() {
      scanSequence += 1;
      emit({ type: 'scan-cancelled' });
      return { cancelled: true };
    },
    async listQuarantine() {
      return quarantine.map(item => ({ ...item }));
    },
    async restoreQuarantine({ id } = {}) {
      if (!safeString(id)) throw new Error('Identificador no válido.');
      quarantine = quarantine.filter(item => item.id !== id);
      emit({ type: 'quarantine-updated' });
      return { label: 'Documentos · Archivo restaurado' };
    },
    async exportReport({ format } = {}) {
      if (!['json', 'csv'].includes(format)) throw new Error('Formato no válido.');
      return { cancelled: false, format, count: 24, label: `Aegis-Guard-informe-preview.${format}` };
    },
    async runNetworkAudit() {
      await delay(350);
      return { completedAt:new Date().toISOString(),reportAvailable:true,summary:{connections:2,suspicious:0,unsignedProcesses:0,truncated:false},windowsSecurity:{firewall:[{name:'Domain',enabled:true},{name:'Private',enabled:true},{name:'Public',enabled:true}],defender:{antivirusEnabled:true,realTimeProtectionEnabled:true,networkInspectionEnabled:true}},events:[{verdict:'observed',explanation:'Conexión saliente observada; no coincide con los indicadores locales disponibles.',protocol:'tcp',remoteAddress:'162.159.135.234',remotePort:443,domain:'discord.com',process:{id:4120,name:'Discord',path:'C:\\Usuarios\\Demo\\AppData\\Local\\Discord\\Discord.exe'},signature:{status:'valid',publisher:'Discord Inc.'}}]};
    },
    async exportNetworkReport({ format } = {}) {
      if (!['json','csv'].includes(format)) throw new Error('Formato no válido.');
      return {cancelled:false,format,count:2,label:`Aegis-Guard-red-preview.${format}`};
    },
    async isolateResult({ scanId, resultId } = {}) {
      if (!safeString(scanId) || !safeString(resultId)) throw new Error('Identificador no válido.');
      const result = cleanResults.find(item => item.resultId === resultId);
      if (!result) throw new Error('El resultado ya no está disponible.');
      const item = {
        id: '680269da-2368-49c5-b1a9-f34337a70dde',
        originalPath: result.path,
        quarantinedAt: new Date().toISOString(),
        verdict: result.verdict,
        score: result.score
      };
      quarantine = [item, ...quarantine.filter(candidate => candidate.id !== item.id)];
      emit({ type: 'quarantine-updated' });
      return item;
    },
    async startMonitor({ targetId } = {}) {
      if (!safeString(targetId)) throw new Error('Selecciona una carpeta.');
      monitorActive = true;
      emit({ type: 'monitor-started', label: 'Documentos · Proyecto Aegis' });
      return { active: true, label: 'Documentos · Proyecto Aegis' };
    },
    async stopMonitor() {
      monitorActive = false;
      emit({ type: 'monitor-stopped' });
      return { active: monitorActive };
    },
    async pauseProtection() {
      previewProtection = { ...previewProtection, active: false, paused: true };
      emit({ type: 'protection-state-changed', ...previewProtection });
      return { ...previewProtection };
    },
    async resumeProtection() {
      previewProtection = { ...previewProtection, active: true, paused: false };
      emit({ type: 'protection-state-changed', ...previewProtection });
      return { ...previewProtection };
    },
    async saveSettings(settings) {
      previewSettings = {
        theme: ['system', 'light', 'dark'].includes(settings?.theme) ? settings.theme : 'system',
        autoQuarantine: settings?.autoQuarantine === true,
        launchAtStartup: settings?.launchAtStartup !== false
      };
      return { settings: { ...previewSettings } };
    },
    async createAndScanSimulation() {
      return previewScan('Simulación de texto inofensiva', true, 'simulation');
    },
    async checkForUpdates() {
      await delay(520);
      return { status: 'up-to-date', version: '0.2.0-preview' };
    },
    async restartAndUpdate() {
      return { status: 'unavailable' };
    }
  });
}

window.addEventListener('DOMContentLoaded', () => void initialize(), { once: true });
window.addEventListener('beforeunload', () => {
  if (scanClock) window.clearInterval(scanClock);
  if (typeof state.unsubscribe === 'function') state.unsubscribe();
}, { once: true });
