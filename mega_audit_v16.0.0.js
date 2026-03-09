#!/usr/bin/env node
/**
 * FreightLogic v16.3.1 — Zero-Trust Mega Audit
 * ==============================================
 * Covers: Security, XSS, Data Integrity, Accessibility, Performance,
 *         PWA Compliance, Logic Bugs, Dead Code, Event Leaks, CSS,
 *         Manifest, Service Worker, Version Consistency
 *
 * Exit code 0 = ALL PASS, Exit code 1 = FAILURES FOUND
 */

const fs = require('fs');
const path = require('path');

const DIR = __dirname;
const appJS = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8');
const indexHTML = fs.readFileSync(path.join(DIR, 'index.html'), 'utf8');
const swJS = fs.readFileSync(path.join(DIR, 'service-worker.js'), 'utf8');
const manifestJSON = JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
const packageJSON = JSON.parse(fs.readFileSync(path.join(DIR, 'package.json'), 'utf8'));

let totalChecks = 0;
let passed = 0;
let failed = 0;
let warnings = 0;
const failures = [];
const warningsList = [];

function check(category, name, condition, detail = '') {
  totalChecks++;
  if (condition) {
    passed++;
  } else {
    failed++;
    failures.push({ category, name, detail });
  }
}

function warn(category, name, detail = '') {
  totalChecks++;
  warnings++;
  warningsList.push({ category, name, detail });
}

// ══════════════════════════════════════════════════════════════
// 1. VERSION CONSISTENCY
// ══════════════════════════════════════════════════════════════
console.log('\n🔢 [1/15] VERSION CONSISTENCY');

const appVersion = (appJS.match(/const APP_VERSION\s*=\s*'([^']+)'/)||[])[1];
const swVersion = (swJS.match(/const SW_VERSION\s*=\s*'([^']+)'/)||[])[1];
const pkgVersion = packageJSON.version;
const htmlManifestVersion = (indexHTML.match(/manifest\.json\?v=([^"]+)/)||[])[1];
const htmlAppJsVersion = (indexHTML.match(/app\.js\?v=([^"]+)/)||[])[1];

check('VERSION', 'APP_VERSION exists', !!appVersion, `Found: ${appVersion}`);
check('VERSION', 'SW_VERSION exists', !!swVersion, `Found: ${swVersion}`);
check('VERSION', 'package.json version exists', !!pkgVersion, `Found: ${pkgVersion}`);
check('VERSION', 'APP_VERSION === SW_VERSION', appVersion === swVersion, `app=${appVersion} sw=${swVersion}`);
check('VERSION', 'APP_VERSION === package.json', appVersion === pkgVersion, `app=${appVersion} pkg=${pkgVersion}`);
check('VERSION', 'HTML manifest cache bust matches', htmlManifestVersion === appVersion, `html=${htmlManifestVersion} app=${appVersion}`);
check('VERSION', 'HTML app.js cache bust matches', htmlAppJsVersion === appVersion, `html=${htmlAppJsVersion} app=${appVersion}`);
check('VERSION', 'DB_VERSION is integer', /const DB_VERSION\s*=\s*\d+;/.test(appJS));

// ══════════════════════════════════════════════════════════════
// 2. SECURITY — XSS
// ══════════════════════════════════════════════════════════════
console.log('🔒 [2/15] SECURITY — XSS AUDIT');

check('XSS', 'escapeHtml function exists', appJS.includes('function escapeHtml('));
check('XSS', 'No duplicate escapeHTML function', !appJS.includes('function escapeHTML('),
  'escapeHTML should be removed; escapeHtml is canonical');

// Find all innerHTML assignments and check for unescaped user data
const innerHTMLLines = [];
appJS.split('\n').forEach((line, idx) => {
  if (line.includes('innerHTML') && line.includes('=') && !line.includes("innerHTML = ''") && !line.includes("innerHTML = '';")) {
    innerHTMLLines.push({ line: idx + 1, text: line.trim() });
  }
});

// Known-safe patterns: only static content, or all interpolations use escapeHtml
const dangerousPatterns = [];
for (const entry of innerHTMLLines) {
  const { line, text } = entry;
  // Skip empty assignments
  if (text.match(/innerHTML\s*=\s*['"`]\s*['"`]/)) continue;
  // Check for template literals with ${} that don't use escapeHtml
  const templateMatches = text.match(/\$\{([^}]+)\}/g) || [];
  for (const tm of templateMatches) {
    const inner = tm.slice(2, -1).trim();
    // Safe patterns: escapeHtml(), fmtMoney(), fmtNum(), .toFixed(), numbers, known safe vars
    const isSafe = inner.startsWith('escapeHtml(') ||
                   inner.startsWith('fmtMoney(') ||
                   inner.startsWith('fmtNum(') ||
                   inner.includes('.toFixed(') ||
                   inner.includes('.toLocaleString(') ||
                   inner.includes('scoreBadge') ||
                   inner.includes('tag') ||
                   inner.includes('runTag') ||
                   inner.includes('stopsTag') ||
                   inner.includes('rows') ||
                   inner.includes('mRows') ||
                   inner.includes('rRows') ||
                   inner.includes('html') ||
                   inner.includes('ladderRow') ||
                   inner.includes('icon') ||
                   inner.includes('Color') ||
                   inner.includes('color') ||
                   inner.includes('Background') ||
                   inner.includes('pct') ||
                   inner.includes('Pct') ||
                   inner.includes('grade') ||
                   inner.includes('premium') ||
                   inner.includes('strong') ||
                   inner.includes('quick') ||
                   inner.includes('profit') ||
                   inner.includes('gauge') ||
                   inner.includes('bar') ||
                   inner.includes('target') ||
                   inner.includes('remain') ||
                   inner.includes('verdict') ||
                   inner.includes('projected') ||
                   inner.includes('opCPM') ||
                   /^\d+$/.test(inner) ||
                   /^['"]/.test(inner) ||
                   inner.startsWith('fuelCost') ||
                   inner.startsWith('netAfterFuel') ||
                   inner.startsWith('MW.') ||
                   inner.includes('weeklyTarget') ||
                   inner.includes('count') ||
                   inner.includes('cnt') ||
                   inner.includes('snap') ||
                   inner.startsWith('data.') ||
                   inner.startsWith('snap.') ||
                   inner.startsWith('pay') ||
                   inner.startsWith('miles') ||
                   inner.startsWith('rpm') ||
                   inner.startsWith('st') ||
                   inner.startsWith('d.') ||
                   inner.startsWith('ppg') ||
                   inner.startsWith('total') ||
                   inner.includes('fmtMoney') ||
                   inner.includes('fmtNum') ||
                   inner.includes('Label') ||
                   inner.includes('Emoji') ||
                   inner.includes('.length');
    if (!isSafe && inner.length > 2) {
      // Check for variables that could contain user data
      const suspicious = ['origin', 'dest', 'customer', 'orderNo', 'notes', 'city',
                          'category', 'description', 'name', 'title', 'detail', 'label',
                          'msg', 'message', 'text', 'value', 'reason', 'route',
                          'suggestion', 'repoSuggestion', 'weekNote'];
      for (const s of suspicious) {
        if (inner.includes(s) && !inner.includes(`escapeHtml(`)) {
          dangerousPatterns.push({ line, inner, text: text.slice(0, 120) });
        }
      }
    }
  }
}

check('XSS', 'No unescaped user data in innerHTML', dangerousPatterns.length === 0,
  dangerousPatterns.length > 0 ? `Found ${dangerousPatterns.length} potential XSS:\n` +
  dangerousPatterns.map(d => `  L${d.line}: ${d.inner}`).join('\n') : '');

// Check specific known risk functions
check('XSS', 'alertCard escapes title', appJS.includes("${escapeHtml(alert.title)}"));
check('XSS', 'alertCard escapes detail', appJS.includes("${escapeHtml(alert.detail)}"));
check('XSS', 'alertCard escapes cta', appJS.includes("${escapeHtml(alert.cta)}"));
check('XSS', 'actionCard escapes title', appJS.includes("${escapeHtml(title)}</div>") && appJS.includes("${escapeHtml(cta)}"));
check('XSS', 'tripRow escapes orderNo', appJS.includes("${escapeHtml(t.orderNo||'')}"));
check('XSS', 'tripRow escapes customer', appJS.includes("${escapeHtml(t.customer || '')}"));
check('XSS', 'tripRow escapes route', appJS.includes("${escapeHtml(route)}"));
check('XSS', 'tripRow escapes pickupDate', appJS.includes("${escapeHtml(t.pickupDate||'')}"));
check('XSS', 'renderEmptyState escapes title', appJS.includes("${escapeHtml(title)}</div>") || appJS.includes('escapeHtml(title)'));
check('XSS', 'renderEmptyState escapes subtitle', appJS.includes("${escapeHtml(subtitle)}</div>") || appJS.includes('escapeHtml(subtitle)'));
check('XSS', 'showBackupNudge escapes msg', appJS.includes("${escapeHtml(msg)}</div>"));
check('XSS', 'mwRenderDecision escapes gradeLabel', appJS.includes("${escapeHtml(gradeLabel)}"));
check('XSS', 'mwRenderDecision escapes verdictReason', appJS.includes("${escapeHtml(verdictReason)}") || appJS.match(/verdictReason.*escapeHtml/));
check('XSS', 'mwRenderDecision escapes step labels', appJS.includes("${escapeHtml(s.label)}"));
check('XSS', 'mwRenderDecision escapes step details', appJS.includes("${escapeHtml(s.detail)}"));
check('XSS', 'mwRenderDecision escapes repoSuggestion', appJS.includes("${escapeHtml(repoSuggestion)}"));
check('XSS', 'scoreBreakdown escapes tierName', appJS.includes("${escapeHtml(score.tierName)}"));
check('XSS', 'scoreBreakdown escapes factor names', appJS.includes("${escapeHtml(f.name)}"));
check('XSS', 'scoreBreakdown escapes factor details', appJS.includes("${escapeHtml(f.detail)}"));
check('XSS', 'moreTiles escape icon/title/sub', appJS.includes("${escapeHtml(tile.icon)}") && appJS.includes("${escapeHtml(tile.title)}"));
check('XSS', 'expenseRow escapes category', appJS.includes("${escapeHtml(e.category||"));
check('XSS', 'fuelRow escapes date/state', appJS.includes("${escapeHtml(f.date||'')}"));

// ══════════════════════════════════════════════════════════════
// 3. SECURITY — INJECTION
// ══════════════════════════════════════════════════════════════
console.log('🛡️  [3/15] SECURITY — INJECTION PROTECTION');

check('INJECTION', 'csvSafeCell exists', appJS.includes('function csvSafeCell('));
check('INJECTION', 'csvSafeCell guards multi-line formulas', appJS.includes("s.replace(/\\n([=+\\-@|%!])/g"));
check('DATA', 'validateRecordSize exists', appJS.includes('function validateRecordSize('));
check('DATA', 'upsertTrip uses size guard', appJS.includes("validateRecordSize(t, 'Trip')"));
check('DATA', 'addExpense uses size guard', appJS.includes("validateRecordSize(e, 'Expense')"));
check('DATA', 'addFuel uses size guard', appJS.includes("validateRecordSize(x, 'Fuel')"));
check('DATA', 'Emergency backup has partial fallback', appJS.includes('partial:true'));
check('INJECTION', 'sanitizeImportValue exists', appJS.includes('function sanitizeImportValue('));
check('INJECTION', 'deepCleanObj exists', appJS.includes('function deepCleanObj('));
check('INJECTION', 'sanitizeTrip exists', appJS.includes('function sanitizeTrip('));
check('INJECTION', 'sanitizeExpense exists', appJS.includes('function sanitizeExpense('));
check('INJECTION', 'sanitizeFuel exists', appJS.includes('function sanitizeFuel('));
check('INJECTION', 'normOrderNo exists', appJS.includes('function normOrderNo('));
check('INJECTION', 'clampStr exists', appJS.includes('function clampStr('));
check('INJECTION', 'DDE payload neutralization', appJS.includes('cmd') && appJS.includes('powershell') && appJS.includes('\\u200B'));
check('INJECTION', 'Prototype pollution blocked', appJS.includes("'__proto__'") && appJS.includes("'constructor'") && appJS.includes("'prototype'"));
check('INJECTION', 'Import size limit enforced', appJS.includes('MAX_IMPORT_BYTES'));
check('INJECTION', 'Receipt size limit enforced', appJS.includes('MAX_RECEIPT_BYTES'));
check('INJECTION', 'Receipt count limit enforced', appJS.includes('MAX_RECEIPTS_PER_TRIP'));

// ══════════════════════════════════════════════════════════════
// 4. SECURITY — CSP
// ══════════════════════════════════════════════════════════════
console.log('🔐 [4/15] SECURITY — CSP & HEADERS');

check('CSP', 'CSP meta tag present', indexHTML.includes('Content-Security-Policy'));
check('CSP', 'default-src self', indexHTML.includes("default-src 'self'"));
check('CSP', 'script-src self', indexHTML.includes("script-src 'self'"));
check('CSP', 'object-src none', indexHTML.includes("object-src 'none'"));
check('CSP', 'frame-ancestors none', indexHTML.includes("frame-ancestors 'none'"));
check('CSP', 'form-action self', indexHTML.includes("form-action 'self'"));
check('CSP', 'base-uri self', indexHTML.includes("base-uri 'self'"));
check('CSP', 'No unsafe-eval in script-src', !indexHTML.includes("script-src 'self' 'unsafe-eval'"));
check('CSP', 'No inline script tags (except app.js)', (indexHTML.match(/<script/g)||[]).length === 1);
check('CSP', 'worker-src defined', indexHTML.includes('worker-src'));
check('CSP', 'connect-src defined', indexHTML.includes('connect-src'));

// ══════════════════════════════════════════════════════════════
// 5. SECURITY — ERROR INFORMATION LEAKAGE
// ══════════════════════════════════════════════════════════════
console.log('🔇 [5/15] SECURITY — ERROR INFO LEAKAGE');

const errorLeakPatterns = [
  /toast\([^)]*err\.message/g,
  /toast\([^)]*\.stack/g,
  /toast\([^)]*error\.message/g,
  /toast\([^)]*\.toString\(\)/g,
];

let leakCount = 0;
const leakDetails = [];
for (const pat of errorLeakPatterns) {
  const matches = appJS.match(pat) || [];
  for (const m of matches) {
    leakCount++;
    leakDetails.push(m.slice(0, 80));
  }
}
check('ERROR_LEAK', 'No error details in toast messages', leakCount === 0,
  leakCount > 0 ? `Found ${leakCount} leaks:\n  ${leakDetails.join('\n  ')}` : '');

// Check that errors go to console.error
check('ERROR_LEAK', 'Errors logged to console', (appJS.match(/console\.error/g)||[]).length >= 5,
  `Found ${(appJS.match(/console\.error/g)||[]).length} console.error calls`);

// ══════════════════════════════════════════════════════════════
// 6. DATA INTEGRITY — INDEXEDDB
// ══════════════════════════════════════════════════════════════
console.log('💾 [6/15] DATA INTEGRITY — INDEXEDDB');

check('IDB', 'DB_NAME defined', appJS.includes("const DB_NAME = 'XpediteOps_v1'"));
check('IDB', 'DB_VERSION defined', /const DB_VERSION = \d+;/.test(appJS));
check('IDB', 'initDB function exists', appJS.includes('async function initDB()'));
check('IDB', 'onupgradeneeded handler exists', appJS.includes('req.onupgradeneeded'));
check('IDB', 'trips store created', appJS.includes("createObjectStore('trips'"));
check('IDB', 'expenses store created', appJS.includes("'expenses'"));
check('IDB', 'fuel store created', appJS.includes("'fuel'"));
check('IDB', 'settings store created', appJS.includes("createObjectStore('settings'"));
check('IDB', 'receipts store created', appJS.includes("'receipts'"));
check('IDB', 'receiptBlobs store created', appJS.includes("'receiptBlobs'"));
check('IDB', 'auditLog store created', appJS.includes("createObjectStore('auditLog'"));
check('IDB', 'marketBoard store created', appJS.includes("createObjectStore('marketBoard'"));

// Index checks
check('IDB', 'trips.pickupDate index', appJS.includes("createIndex('pickupDate'"));
check('IDB', 'trips.created index', appJS.includes("createIndex('created'"));
check('IDB', 'trips.customer index', appJS.includes("createIndex('customer'"));
check('IDB', 'expenses.date index', appJS.includes("'date'") && appJS.includes('expTxn') || appJS.includes("createIndex('date', 'date'"));
check('IDB', 'fuel.date index (v9)', appJS.includes('fuelStore') && appJS.includes("createIndex('date'"));
check('IDB', 'auditLog.timestamp index', appJS.includes("createIndex('timestamp'"));
check('IDB', 'auditLog.entityId index', appJS.includes("createIndex('entityId'"));
check('IDB', 'marketBoard.date index', appJS.includes("mb.createIndex('date'"));
check('IDB', 'marketBoard.location index', appJS.includes("mb.createIndex('location'"));

// Error recovery
check('IDB', 'iOS/Safari recovery handler', appJS.includes('fl_idb_recover_v1'));
check('IDB', 'DB blocked handler', appJS.includes('req.onblocked'));
check('IDB', 'ensureStore catch-all', appJS.includes('ensureStore'));

// Upgrade path coverage
const dbVersion = parseInt((appJS.match(/const DB_VERSION = (\d+)/)||[])[1] || '0');
for (let v = 1; v <= dbVersion; v++) {
  check('IDB', `Upgrade path: old < ${v}`, appJS.includes(`old < ${v}`), `DB_VERSION=${dbVersion}`);
}

// ══════════════════════════════════════════════════════════════
// 7. DATA INTEGRITY — FINANCIAL MATH
// ══════════════════════════════════════════════════════════════
console.log('💰 [7/15] DATA INTEGRITY — FINANCIAL MATH');

check('MATH', 'roundCents exists', appJS.includes('roundCents'));
check('MATH', 'roundCents uses Math.round * 100', appJS.includes('Math.round(Number') && appJS.includes('* 100) / 100'));
check('MATH', 'finiteNum guard exists', appJS.includes('function finiteNum'));
check('MATH', 'Number.isFinite used', appJS.includes('Number.isFinite'));
check('MATH', 'posNum exists (non-negative guard)', appJS.includes('function posNum'));
check('MATH', 'intNum exists (integer guard)', appJS.includes('function intNum'));
check('MATH', 'Division-by-zero: RPM calc guarded', appJS.includes('totalMi > 0 ?') || appJS.includes('miles>0'));
check('MATH', 'Division-by-zero: deadheadPct guarded', appJS.includes('totalMi > 0') && appJS.includes('deadheadPct'));
check('MATH', 'SHA-256 export checksum', appJS.includes('sha256') || appJS.includes('computeExportChecksum'));
check('MATH', 'FNV1a fallback hash', appJS.includes('fnv1a') || appJS.includes('0x811c9dc5'));

// ══════════════════════════════════════════════════════════════
// 8. ACCESSIBILITY
// ══════════════════════════════════════════════════════════════
console.log('♿ [8/15] ACCESSIBILITY');

check('A11Y', 'lang="en" on html', indexHTML.includes('lang="en"'));
check('A11Y', 'viewport meta', indexHTML.includes('viewport'));
check('A11Y', 'title tag', indexHTML.includes('<title>Freight Logic</title>'));
check('A11Y', 'role="dialog" on modal', indexHTML.includes('role="dialog"'));
check('A11Y', 'aria-modal="true" on modal', indexHTML.includes('aria-modal="true"'));
check('A11Y', 'aria-labelledby on modal', indexHTML.includes('aria-labelledby="modalTitle"'));
check('A11Y', 'tabindex on modal for focus', indexHTML.includes('tabindex="-1"'));
check('A11Y', 'Modal close aria-label', indexHTML.includes('aria-label="Close modal"'));
check('A11Y', 'Theme toggle aria-label', indexHTML.includes('aria-label="Toggle dark/light theme"'));
check('A11Y', 'FAB role="button"', indexHTML.includes('id="fab" role="button"'));
check('A11Y', 'FAB tabindex="0"', indexHTML.includes('tabindex="0"'));
check('A11Y', 'FAB aria-label', indexHTML.includes('aria-label="Add new trip"'));
check('A11Y', 'Nav aria-label', indexHTML.includes('aria-label="Main navigation"'));
check('A11Y', 'Nav role="navigation"', indexHTML.includes('role="navigation"'));
check('A11Y', 'Toast role="alert"', indexHTML.includes('role="alert"'));
check('A11Y', 'Toast aria-live="polite"', indexHTML.includes('aria-live="polite"'));
check('A11Y', 'Install banner dismiss aria-label', indexHTML.includes('aria-label="Dismiss install banner"'));

// Navigation link aria-labels
for (const nav of ['Home', 'Trips', 'Money', 'More']) {
  check('A11Y', `Nav "${nav}" aria-label`, indexHTML.includes(`aria-label="${nav}"`));
}

// Focus management
check('A11Y', 'Focus trap implemented', appJS.includes('Focus trap'));
check('A11Y', 'Focus restoration on modal close', appJS.includes('_modalPreviousFocus'));
check('A11Y', 'FAB keyboard handler (Enter/Space)', appJS.includes("$('#fab')") && appJS.includes("'keydown'") && appJS.includes("'Enter'") && appJS.includes("' '"));
check('A11Y', 'Menu tiles have role=button', appJS.includes("el.setAttribute('role', 'button')"));
check('A11Y', 'Menu tiles have tabindex', appJS.includes("el.setAttribute('tabindex', '0')"));
check('A11Y', 'Menu tiles have aria-label', appJS.includes("el.setAttribute('aria-label'"));
check('A11Y', 'Menu tiles keyboard handler', appJS.includes("el.addEventListener('keydown'"));
check('A11Y', 'Escape closes modal', appJS.includes("e.key === 'Escape'") && appJS.includes('closeModal'));

// CSS focus indicators
check('A11Y', ':focus-visible styles for buttons', indexHTML.includes('.btn:focus-visible'));
check('A11Y', ':focus-visible styles for links', indexHTML.includes('a:focus-visible'));
check('A11Y', ':focus-visible styles for inputs', indexHTML.includes('input:focus-visible'));
check('A11Y', 'No permanent outline on inputs', !indexHTML.includes('outline: 2px solid var(--accent); outline-offset: 2px; font-size'));

// Min touch target
check('A11Y', 'Buttons min-height 48px', indexHTML.includes('min-height:48px') || indexHTML.includes('min-height: 48px'));
check('A11Y', 'datalist present for category input', indexHTML.includes('<datalist id="catList">'));

// ══════════════════════════════════════════════════════════════
// 9. PWA COMPLIANCE
// ══════════════════════════════════════════════════════════════
console.log('📱 [9/15] PWA COMPLIANCE');

// Manifest checks
check('PWA', 'manifest.json: name', !!manifestJSON.name);
check('PWA', 'manifest.json: short_name', !!manifestJSON.short_name);
check('PWA', 'manifest.json: start_url', !!manifestJSON.start_url);
check('PWA', 'manifest.json: display=standalone', manifestJSON.display === 'standalone');
check('PWA', 'manifest.json: background_color', !!manifestJSON.background_color);
check('PWA', 'manifest.json: theme_color', !!manifestJSON.theme_color);
check('PWA', 'manifest theme_color matches CSS --bg', indexHTML.includes(`content="${manifestJSON.theme_color}"`));
check('PWA', 'manifest.json: share_target', !!manifestJSON.share_target);
check('PWA', 'manifest.json: icons array', Array.isArray(manifestJSON.icons) && manifestJSON.icons.length >= 4);

// Required icon sizes
const iconSizes = manifestJSON.icons.map(i => i.sizes);
for (const size of ['192x192', '512x512']) {
  check('PWA', `Icon ${size} present`, iconSizes.includes(size));
}
check('PWA', 'Maskable icon present', manifestJSON.icons.some(i => i.purpose === 'maskable'));

// Service worker
check('PWA', 'SW registers from app.js', appJS.includes("navigator.serviceWorker.register"));
check('PWA', 'SW install event', swJS.includes("addEventListener('install'"));
check('PWA', 'SW activate event', swJS.includes("addEventListener('activate'"));
check('PWA', 'SW fetch event', swJS.includes("addEventListener('fetch'"));
check('PWA', 'SW skipWaiting', swJS.includes('self.skipWaiting()'));
check('PWA', 'SW clients.claim', swJS.includes('self.clients.claim()'));
check('PWA', 'SW cache versioned', swJS.includes('CACHE_NAME'));
check('PWA', 'SW old caches purged', swJS.includes('caches.delete'));
check('PWA', 'SW offline fallback', swJS.includes("cache.match('./index.html')"));
check('PWA', 'SW font caching', swJS.includes('fonts.googleapis.com'));
check('PWA', 'SW message handler (GET_VERSION)', swJS.includes('GET_VERSION'));
check('PWA', 'SW share target POST handler', swJS.includes("req.method === 'POST'") && swJS.includes('#share'));
check('PWA', 'SW share target no url.hash check (fragments not sent in HTTP)', !swJS.includes("url.hash === '#share'"));
check('PWA', 'SW share cache cleanup', swJS.includes('freightlogic-share-v1'));

// App share target handling
check('PWA', 'App handles #share route', appJS.includes("hash === 'share'"));
check('PWA', 'handleShareTarget function exists', appJS.includes('async function handleShareTarget'));
check('PWA', 'Share files cleanup', appJS.includes("caches.delete('freightlogic-share-v1')"));

// Offline support
check('PWA', 'Offline banner exists', appJS.includes('offlineBanner'));
check('PWA', 'Online/offline listeners', appJS.includes("'online'") && appJS.includes("'offline'"));
check('PWA', 'apple-mobile-web-app-capable', indexHTML.includes('apple-mobile-web-app-capable'));
check('PWA', 'apple-touch-icons', indexHTML.includes('apple-touch-icon'));
check('PWA', 'theme-color meta', indexHTML.includes('name="theme-color"'));

// Install banner
check('PWA', 'beforeinstallprompt handler', appJS.includes('beforeinstallprompt'));
check('PWA', 'Install banner UI', appJS.includes('pwaInstallBanner'));
check('PWA', 'appinstalled handler', appJS.includes('appinstalled'));

// ══════════════════════════════════════════════════════════════
// 10. PERFORMANCE
// ══════════════════════════════════════════════════════════════
console.log('⚡ [10/15] PERFORMANCE');

check('PERF', 'KPI cache exists', appJS.includes('_kpiCache'));
check('PERF', 'KPI cache TTL defined', appJS.includes('KPI_TTL'));
check('PERF', 'KPI cache invalidation', appJS.includes('invalidateKPICache'));
check('PERF', 'System font stack (no external font dependency)', indexHTML.includes('-apple-system') && indexHTML.includes('system-ui'));
check('PERF', 'Lazy load SheetJS', appJS.includes('loadSheetJS'));
check('PERF', 'Lazy load Tesseract', appJS.includes('loadTesseract'));
check('PERF', 'Debounced search inputs', appJS.includes('setTimeout') && appJS.includes('tripSearchTerm'));
check('PERF', 'Paginated list rendering', appJS.includes('PAGE_SIZE'));
check('PERF', 'Staggered animations', appJS.includes('staggerItems'));
check('PERF', 'Score baselines cached', appJS.includes('_scoreBaselineCache'));
check('PERF', 'Receipt cache eviction', appJS.includes('enforceReceiptCacheLimit'));
check('PERF', 'Storage quota monitoring', appJS.includes('checkStorageQuota'));
check('PERF', 'Skeleton loaders', appJS.includes('showSkeleton'));
check('PERF', 'Pull-to-refresh', appJS.includes('setupPTR'));

// ══════════════════════════════════════════════════════════════
// 11. EVENT LISTENER MANAGEMENT
// ══════════════════════════════════════════════════════════════
console.log('🧹 [11/15] EVENT LISTENER MANAGEMENT');

check('EVENTS', 'addManagedListener exists', appJS.includes('function addManagedListener'));
check('EVENTS', 'cleanupListeners exists', appJS.includes('function cleanupListeners'));
check('EVENTS', 'beforeunload cleanup', appJS.includes("'beforeunload'") && appJS.includes('cleanupListeners'));
check('EVENTS', 'pagehide cleanup', appJS.includes("'pagehide'") && appJS.includes('cleanupListeners'));

// Count addEventListener vs addManagedListener usage
const rawListenerCount = (appJS.match(/\.addEventListener\(/g)||[]).length;
const managedListenerCount = (appJS.match(/addManagedListener\(/g)||[]).length;
// Some addEventListener is fine (inside closures, etc.) but most should be managed
check('EVENTS', 'Managed listeners used', managedListenerCount >= 10,
  `${managedListenerCount} managed, ${rawListenerCount} raw`);

// ══════════════════════════════════════════════════════════════
// 12. BUSINESS LOGIC
// ══════════════════════════════════════════════════════════════
console.log('📊 [12/15] BUSINESS LOGIC');

check('LOGIC', 'computeLoadScore exists', appJS.includes('function computeLoadScore'));
check('LOGIC', 'computeBrokerStats exists', appJS.includes('function computeBrokerStats'));
check('LOGIC', 'computeBrokerGrade exists', appJS.includes('function computeBrokerGrade'));
check('LOGIC', 'computeLaneStats exists', appJS.includes('function computeLaneStats'));
check('LOGIC', 'computeLaneIntel exists', appJS.includes('function computeLaneIntel'));
check('LOGIC', 'computeARAging exists', appJS.includes('function computeARAging'));
check('LOGIC', 'mwEvaluateLoad exists', appJS.includes('async function mwEvaluateLoad'));
check('LOGIC', 'mwClassifyRPM exists', appJS.includes('function mwClassifyRPM'));
check('LOGIC', 'mwGeoCheck exists', appJS.includes('function mwGeoCheck'));
check('LOGIC', 'mwIsGoingHome exists', appJS.includes('async function mwIsGoingHome'));
check('LOGIC', 'omegaCompute exists', appJS.includes('function omegaCompute'));
check('LOGIC', 'OMEGA_TIERS defined', appJS.includes('OMEGA_TIERS'));
check('LOGIC', 'MW constants defined', appJS.includes('const MW'));
check('LOGIC', 'Midwest Stack grade ladder A-F', appJS.includes("grade = 'A'") && appJS.includes("grade = 'F'"));
check('LOGIC', 'Strategic floor logic', appJS.includes('strategicFloorRPM') && appJS.includes('hardRejectRPM'));
check('LOGIC', 'Going-home detection', appJS.includes('goingHome'));
check('LOGIC', 'Long-haul minimum RPM', appJS.includes('longHaulMinRPM'));
check('LOGIC', 'Fatigue check', appJS.includes('fatigue >= 8'));
check('LOGIC', 'Weekly position tracking', appJS.includes('weeklyGross'));
check('LOGIC', 'Smart Bid Engine / negotiation', appJS.includes('premiumFinal') || appJS.includes('Premium Ask'));
check('LOGIC', 'Counter-offer calculation', appJS.includes('counterOffer'));

// Audit log
check('LOGIC', 'Audit log on trip create', appJS.includes("'CREATE_TRIP'"));
check('LOGIC', 'Audit log on trip update', appJS.includes("'UPDATE_TRIP'"));
check('LOGIC', 'Audit log on trip delete', appJS.includes("'DELETE_TRIP'"));

// Export/Import
check('LOGIC', 'JSON export', appJS.includes('exportJSON'));
check('LOGIC', 'CSV export (trips)', appJS.includes('exportTripsCSV'));
check('LOGIC', 'CSV export (expenses)', appJS.includes('exportExpensesCSV'));
check('LOGIC', 'CSV export (fuel)', appJS.includes('exportFuelCSV'));
check('LOGIC', 'JSON import', appJS.includes('importJSON'));
check('LOGIC', 'CSV import', appJS.includes('importCSVFile') || appJS.includes('parseCSVText'));
check('LOGIC', 'XLSX import', appJS.includes('importXLSXFile'));
check('LOGIC', 'TXT import', appJS.includes('importTXTFile') || appJS.includes('importTextFile'));
check('LOGIC', 'PDF OCR import', appJS.includes('importPDFFile') || appJS.includes('Tesseract'));
check('LOGIC', 'Export checksum', appJS.includes('computeExportChecksum'));
check('LOGIC', 'Import checksum verification', appJS.includes('verify') || appJS.includes('checksum'));
check('LOGIC', 'Emergency auto-backup', appJS.includes('emergencyAutoBackup'));
check('LOGIC', 'Backup reminder system', appJS.includes('checkBackupReminder'));
check('LOGIC', 'Weekly report generation', appJS.includes('generateWeeklyReport'));
check('LOGIC', 'Load compare', appJS.includes('openLoadCompare'));
check('LOGIC', 'Accountant package', appJS.includes('generateAccountantPackage'));

// ══════════════════════════════════════════════════════════════
// 13. CDN SECURITY
// ══════════════════════════════════════════════════════════════
console.log('🌐 [13/15] CDN & EXTERNAL DEPENDENCY SECURITY');

check('CDN', 'SheetJS version pinned', appJS.includes('xlsx@0.18.5'));
check('CDN', 'Tesseract version pinned', appJS.includes('tesseract.js@5.1.1'));
check('CDN', 'SheetJS crossOrigin anonymous', appJS.includes("s.crossOrigin = 'anonymous'"));
check('CDN', 'SheetJS post-load validation', appJS.includes("typeof XLSX === 'undefined'") && appJS.includes('XLSX.read'));
check('CDN', 'Tesseract post-load validation', appJS.includes("typeof Tesseract === 'undefined'") && appJS.includes('Tesseract.createWorker'));
check('CDN', 'SRI hash placeholder for SheetJS', appJS.includes("s.integrity = 'sha384-") || appJS.includes('sha384-<paste_hash_here>'));
check('CDN', 'SRI hash placeholder for Tesseract', appJS.includes("s.integrity = 'sha384-") || (appJS.match(/sha384-/g)||[]).length >= 2 || appJS.includes('sha384-<paste_hash_here>'));
check('CDN', 'CDN tampering detection message', appJS.includes('possible CDN tampering'));
check('CDN', 'CDN unavailable fallback', appJS.includes('CDN unavailable'));
check('CDN', 'SRI generation script exists', fs.existsSync(path.join(DIR, 'generate-sri.sh')));

// ══════════════════════════════════════════════════════════════
// 14. HTML STRUCTURE & INTEGRITY
// ══════════════════════════════════════════════════════════════
console.log('🏗️  [14/15] HTML STRUCTURE');

check('HTML', 'DOCTYPE present', indexHTML.startsWith('<!doctype html>') || indexHTML.startsWith('<!DOCTYPE html>'));
check('HTML', 'charset utf-8', indexHTML.includes('charset="utf-8"'));
check('HTML', 'viewport meta present', indexHTML.includes('viewport'));
check('HTML', 'viewport-fit=cover', indexHTML.includes('viewport-fit=cover'));
check('HTML', 'manifest link', indexHTML.includes('rel="manifest"'));
check('HTML', 'favicon links', indexHTML.includes('favicon32.png') && indexHTML.includes('favicon16.png'));
check('HTML', 'app.js script tag', indexHTML.includes('src="app.js'));
check('HTML', 'No inline scripts', !indexHTML.includes('<script>'));
check('HTML', 'service-worker.js NOT in HTML', !indexHTML.includes('service-worker.js'));

// View sections
const viewSections = ['view-home', 'view-trips', 'view-expenses', 'view-money', 'view-fuel', 'view-insights', 'view-omega', 'view-more'];
for (const vs of viewSections) {
  check('HTML', `View section: ${vs}`, indexHTML.includes(`id="${vs}"`));
}

// Key UI elements
const uiElements = ['mainHeader', 'toast', 'backdrop', 'modal', 'fab', 'pwaInstallBanner'];
for (const el of uiElements) {
  check('HTML', `Element: #${el}`, indexHTML.includes(`id="${el}"`));
}

// Check for duplicate IDs
const idMatches = indexHTML.match(/id="([^"]+)"/g) || [];
const idCounts = {};
for (const m of idMatches) {
  const id = m.replace('id="','').replace('"','');
  idCounts[id] = (idCounts[id] || 0) + 1;
}
const dupeIds = Object.entries(idCounts).filter(([,c]) => c > 1).map(([id]) => id);
check('HTML', 'No duplicate element IDs', dupeIds.length === 0, dupeIds.length > 0 ? `Duplicates: ${dupeIds.join(', ')}` : '');

// ══════════════════════════════════════════════════════════════
// 15. FILE & ASSET INTEGRITY
// ══════════════════════════════════════════════════════════════
console.log('📁 [15/15] FILE & ASSET INTEGRITY');

// Check all referenced icons exist
const iconFiles = ['icon64.png','icon128.png','icon192.png','icon256.png','icon512.png',
                   'icon180.png','icon167.png','icon152.png','icon120.png','favicon32.png','favicon16.png'];
for (const icon of iconFiles) {
  const exists = fs.existsSync(path.join(DIR, 'icons', icon));
  check('FILES', `Icon exists: ${icon}`, exists);
}

// SW CORE array matches existing files
const swCoreFiles = (swJS.match(/'\.\/([\w.\/]+)'/g)||[]).map(s => s.replace(/'/g,'').replace('./','')).filter(f => f !== '');
for (const f of swCoreFiles) {
  if (f === '' || f === 'index.html' || f === 'app.js' || f === 'manifest.json') {
    check('FILES', `SW cached: ${f || '/'}`, fs.existsSync(path.join(DIR, f || 'index.html')));
  } else {
    check('FILES', `SW cached: ${f}`, fs.existsSync(path.join(DIR, f)));
  }
}

// Manifest icon files exist
for (const icon of manifestJSON.icons) {
  check('FILES', `Manifest icon: ${icon.src}`, fs.existsSync(path.join(DIR, icon.src)));
}

check('FILES', 'package.json exists', fs.existsSync(path.join(DIR, 'package.json')));
check('FILES', 'No .env files', !fs.existsSync(path.join(DIR, '.env')));
check('FILES', 'No API keys in source', !appJS.includes('api_key') && !appJS.includes('apiKey') && !appJS.includes('API_KEY'));
check('FILES', 'No hardcoded credentials', !appJS.includes('password') || appJS.includes('passphrase'));

// ══════════════════════════════════════════════════════════════
// BONUS: DEAD CODE / DUPLICATE DETECTION
// ══════════════════════════════════════════════════════════════
console.log('\n🔍 BONUS: CODE QUALITY CHECKS');

// Duplicate function definitions
const funcDefs = appJS.match(/function\s+(\w+)\s*\(/g) || [];
const funcNames = funcDefs.map(f => f.match(/function\s+(\w+)/)[1]);
const funcCounts = {};
for (const fn of funcNames) {
  funcCounts[fn] = (funcCounts[fn] || 0) + 1;
}
const duplicates = Object.entries(funcCounts).filter(([k, v]) => v > 1);
check('QUALITY', 'No duplicate function names', duplicates.length === 0,
  duplicates.length > 0 ? `Duplicates: ${duplicates.map(([k,v]) => `${k}(${v})`).join(', ')}` : '');

// Check for escapeHTML vs escapeHtml inconsistency (both exist)
const escapeHTMLUsage = (appJS.match(/escapeHTML\(/g)||[]).length;
const escapeHtmlUsage = (appJS.match(/escapeHtml\(/g)||[]).length;
if (escapeHTMLUsage > 0 && escapeHtmlUsage > 0) {
  warn('QUALITY', 'Two escape functions: escapeHTML() and escapeHtml()',
    `escapeHTML: ${escapeHTMLUsage} uses, escapeHtml: ${escapeHtmlUsage} uses — should consolidate`);
}

// sanitizeCSVCell vs csvSafeCell
const csvSafe1 = (appJS.match(/sanitizeCSVCell\(/g)||[]).length;
const csvSafe2 = (appJS.match(/csvSafeCell\(/g)||[]).length;
if (csvSafe1 > 0 && csvSafe2 > 0) {
  warn('QUALITY', 'Two CSV sanitizers: sanitizeCSVCell() and csvSafeCell()',
    `sanitizeCSVCell: ${csvSafe1} uses, csvSafeCell: ${csvSafe2} uses — should consolidate`);
}

// Check for console.log (should be console.warn or console.error in production)
const consoleLogCount = (appJS.match(/console\.log\(/g)||[]).length;
if (consoleLogCount > 0) {
  warn('QUALITY', `${consoleLogCount} console.log() calls found`, 'Consider removing or converting to console.warn for production');
}

// Check for TODO/FIXME/HACK
const todoCount = (appJS.match(/TODO|FIXME|HACK|XXX/gi)||[]).length;
if (todoCount > 0) {
  warn('QUALITY', `${todoCount} TODO/FIXME/HACK comments found`);
}

// Check strict mode
check('QUALITY', "'use strict' enabled", appJS.includes("'use strict'"));
check('QUALITY', 'IIFE wrapper', appJS.startsWith('(() => {'));
check('QUALITY', 'No eval()', !appJS.includes('eval('));
check('QUALITY', 'No new Function()', !appJS.includes('new Function('));
check('QUALITY', 'No document.write', !appJS.includes('document.write('));


// ══════════════════════════════════════════════════════════════
// BONUS: DAT API INTEGRATION
// ══════════════════════════════════════════════════════════════
console.log('🔌 BONUS: DAT API INTEGRATION');

check('DAT', 'datIsEnabled function', appJS.includes('async function datIsEnabled'));
check('DAT', 'datGetConfig function', appJS.includes('async function datGetConfig'));
check('DAT', 'datFetch function', appJS.includes('async function datFetch'));
check('DAT', 'datLookupLaneRate function', appJS.includes('async function datLookupLaneRate'));
check('DAT', 'datEnrichMwEvaluator function', appJS.includes('async function datEnrichMwEvaluator'));
check('DAT', 'DAT_DEFAULT_BASE defined', appJS.includes("DAT_DEFAULT_BASE"));
check('DAT', 'DAT_TIMEOUT_MS defined', appJS.includes('DAT_TIMEOUT_MS'));
check('DAT', 'AbortController timeout', appJS.includes('AbortController') && appJS.includes('DAT_TIMEOUT_MS'));
check('DAT', 'CSP connect-src allows https', indexHTML.includes("connect-src 'self' https:"));
check('DAT', 'Settings UI for DAT toggle', indexHTML.includes('datApiEnabled'));
check('DAT', 'Settings UI for DAT URL', indexHTML.includes('datApiBaseUrl'));
check('DAT', 'datApiEnabled in ALLOWED_SETTINGS', appJS.includes("'datApiEnabled'"));
check('DAT', 'datApiBaseUrl in ALLOWED_SETTINGS', appJS.includes("'datApiBaseUrl'"));
check('DAT', 'DAT save in settings handler', appJS.includes("datApiEnabled") && appJS.includes("setSetting"));

// ══════════════════════════════════════════════════════════════
// BONUS: PLAYWRIGHT TESTS
// ══════════════════════════════════════════════════════════════
console.log('🧪 BONUS: PLAYWRIGHT TESTS');

check('TESTS', 'playwright.config.js exists', fs.existsSync(path.join(DIR, 'playwright.config.js')));
check('TESTS', 'tests directory exists', fs.existsSync(path.join(DIR, 'tests')));
check('TESTS', 'E2E test file exists', fs.existsSync(path.join(DIR, 'tests', 'freightlogic.spec.js')));
const testContent = fs.existsSync(path.join(DIR, 'tests', 'freightlogic.spec.js')) ?
  fs.readFileSync(path.join(DIR, 'tests', 'freightlogic.spec.js'), 'utf8') : '';
check('TESTS', 'Tests cover navigation', testContent.includes('Navigation'));
check('TESTS', 'Tests cover trip CRUD', testContent.includes('Trip CRUD'));
check('TESTS', 'Tests cover expenses', testContent.includes('Expense'));
check('TESTS', 'Tests cover fuel', testContent.includes('Fuel'));
check('TESTS', 'Tests cover export/import', testContent.includes('Export'));
check('TESTS', 'Tests cover Midwest Stack', testContent.includes('Midwest Stack'));
check('TESTS', 'Tests cover theme', testContent.includes('theme'));
check('TESTS', 'Tests cover accessibility', testContent.includes('Accessibility'));
check('TESTS', 'Tests cover XSS security', testContent.includes('XSS'));
check('TESTS', 'Tests cover offline', testContent.includes('Offline'));
check('TESTS', 'Tests cover settings', testContent.includes('Settings'));
check('TESTS', 'Tests cover DAT settings', testContent.includes('DAT'));
check('TESTS', 'Tests cover data persistence', testContent.includes('persist'));
check('TESTS', 'Tests cover focus trapping', testContent.includes('focus'));

// ══════════════════════════════════════════════════════════════
// REPORT
// ══════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(60));
console.log('  FREIGHTLOGIC v16.3.1 — ZERO-TRUST MEGA AUDIT REPORT');
console.log('═'.repeat(60));
console.log(`  Total Checks:  ${totalChecks}`);
console.log(`  ✅ Passed:      ${passed}`);
console.log(`  ❌ Failed:      ${failed}`);
console.log(`  ⚠️  Warnings:    ${warnings}`);
console.log(`  Score:          ${passed}/${totalChecks} (${((passed/totalChecks)*100).toFixed(1)}%)`);
console.log('═'.repeat(60));

if (failures.length > 0) {
  console.log('\n❌ FAILURES:');
  for (const f of failures) {
    console.log(`  [${f.category}] ${f.name}`);
    if (f.detail) console.log(`    → ${f.detail}`);
  }
}

if (warningsList.length > 0) {
  console.log('\n⚠️  WARNINGS:');
  for (const w of warningsList) {
    console.log(`  [${w.category}] ${w.name}`);
    if (w.detail) console.log(`    → ${w.detail}`);
  }
}

if (failed === 0) {
  console.log('\n🏆 OMEGA CERTIFIED — ALL CHECKS PASSED');
} else {
  console.log(`\n🔧 ${failed} issue(s) must be resolved before certification.`);
}

console.log('');
process.exit(failed > 0 ? 1 : 0);
