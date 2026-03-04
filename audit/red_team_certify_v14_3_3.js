#!/usr/bin/env node
/**
 * FreightLogic v14.3.4-hardened — Zero-Trust Adversarial Certification
 *
 * Purpose:
 *   - Fast, deterministic, offline certification for the shipped PWA bundle.
 *   - Detects common regression classes: missing functions, CSP drift, SW version drift,
 *     import limits, sanitization, ID sync, etc.
 *
 * Notes:
 *   - This is a static audit (no browser execution).
 *   - It intentionally avoids brittle “balanced brace” logic across regex/template literals.
 *     Use `node --check app.js` as the syntax authority.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const read = (p) => fs.readFileSync(path.join(process.cwd(), p), 'utf8');

const app = read('app.js');
const html = read('index.html');
const sw = read('service-worker.js');
const mf = JSON.parse(read('manifest.json'));

let pass = 0, fail = 0, warn = 0;
const errors = [];
const warnings = [];
const categories = Object.create(null);
let currentCat = 'INIT';

function _cat() {
  if (!categories[currentCat]) categories[currentCat] = { pass: 0, fail: 0, warn: 0 };
  return categories[currentCat];
}

function T(cond, msg) {
  const c = _cat();
  if (cond) { pass++; c.pass++; }
  else { fail++; c.fail++; errors.push(`[${currentCat}] ${msg}`); }
}

function W(cond, msg) {
  const c = _cat();
  if (cond) { pass++; c.pass++; }
  else { warn++; c.warn++; warnings.push(`[${currentCat}] ${msg}`); }
}

function S(name) {
  currentCat = name;
  _cat();
  console.log(`\n━━ ${name} ━━`);
}

// ------------------------------------------------------------------
// 1) SYNTAX + VERSION
// ------------------------------------------------------------------
S('1. SYNTAX + VERSION');

T(app.startsWith('(() => {'), 'IIFE opens with (() => {');
T(app.trimEnd().endsWith('})();'), 'IIFE closes with })();');
T(app.includes("'use strict'"), 'Strict mode enabled');
T(app.includes("const APP_VERSION = '14.3.4-hardened'"), 'APP_VERSION is 14.3.4-hardened');

// These are best-effort static checks. Real syntax authority is node --check.
W(!app.includes('debugger'), 'No debugger statements');
W(!/\bconsole\.log\s*\(/.test(app), 'No console.log() in production bundle');
W(!/\beval\s*\(/.test(app), 'No eval()');
W(!/new\s+Function\s*\(/.test(app), 'No new Function()');

// ------------------------------------------------------------------
// 2) REQUIRED FUNCTIONS
// ------------------------------------------------------------------
S('2. REQUIRED FUNCTIONS');

const requiredFns = [
  'escapeHtml','clampStr','normOrderNo','csvSafeCell','sanitizeImportValue',
  'haptic','toast','randId','numVal',
  'finiteNum','posNum','intNum',
  'initDB','tx','waitTxn','idbReq','getSetting','setSetting',
  'newTripTemplate','sanitizeTrip','tripExists','upsertTrip','deleteTrip','listTrips',
  'sanitizeExpense','addExpense','updateExpense','deleteExpense','listExpenses',
  'sanitizeFuel','addFuel','updateFuel','deleteFuel','listFuel',
  'dumpStore','exportJSON','importJSON','downloadCSV',
  'computeKPIs','computeQuickKPIs','invalidateKPICache','computeTaxView',
  'computeARAging','computeBrokerStats','daysBetweenISO',
  'queryTripsByPickupRange','queryExpensesByDateRange','queryUnpaidTotal',
  'computeLoadScore','scoreBadgeHTML','openScoreBreakdown','showScoreFlash','renderLiveScore',
  'normLaneCity','laneKey','laneKeyDisplay','computeLaneStats','computeLaneIntel','laneIntelHTML',
  'renderTopLanes','openLaneBreakdown',
  'computeBrokerGrade','brokerGradeHTML','openBrokerScorecard','brokerIntelHTML',
  'renderTrendAlerts','alertCard',
  'mwClassifyRPM','mwFuelCost','mwEvaluateLoad','mwSaveMarketEntry','mwRenderBoardLog',
  'omegaTierForMiles','omegaCompute','omegaApplyAdder','omegaFormatMoneyRange','omegaShiftOneTierLower',
  'renderHome','renderCommandCenter','renderTrips','renderExpenses','renderFuel','renderAR','renderInsights','renderOmega','renderMore',
  'navigate','setActiveNav','actionCard','tripRow','expenseRow','fuelRow',
  'openModal','closeModal','staggerItems','showSkeleton','setupPTR','pulseKPI',
  'openTripWizard','openExpenseForm','openFuelForm','openReceiptManager','openQuickAddSheet',
  'computeExportChecksum','importCSVFile','importXLSXFile','importTXTFile','importPDFFile','importFile','openUniversalImport',
  'parseCSVText','parseCSVLines','parseCSVTextAsync',
  'generateWeeklyReport','openLoadCompare','generateAccountantPackage',
  'attachAutoComplete','openSnapLoad','parseLoadText','loadTesseract',
  'requestPersistentStorage','checkStorageQuota','showSafariWarning',
  'checkBackupReminder','sha256',
  'refreshStorageHealth','countStore','storageHealthSnapshot'
];

for (const fn of requiredFns) {
  const exists = app.includes(`function ${fn}(`) || app.includes(`async function ${fn}(`);
  T(exists, `Missing function: ${fn}()`);
}

// Arrow helpers
for (const afn of ['fmtMoney','fmtNum','isoDate','roundCents']) {
  T(new RegExp(`\\bconst\\s+${afn}\\s*=\\s*\\(`).test(app), `Missing arrow helper const ${afn} = (`);
}

// ------------------------------------------------------------------
// 3) PWA + SERVICE WORKER
// ------------------------------------------------------------------
S('3. PWA + SERVICE WORKER');

T(sw.includes("const SW_VERSION = '14.3.4-hardened'"), 'SW_VERSION matches 14.3.4-hardened');
T(/self\.addEventListener\(\s*'install'/.test(sw), 'SW has install handler');
T(/self\.addEventListener\(\s*'activate'/.test(sw), 'SW has activate handler');
T(/self\.addEventListener\(\s*'fetch'/.test(sw), 'SW has fetch handler');

T(mf && typeof mf === 'object', 'manifest.json parses');
T(mf.name && /Freight/i.test(mf.name), 'manifest name present');
T(mf.start_url, 'manifest start_url present');
T(mf.display === 'standalone', 'manifest display=standalone');
T(Array.isArray(mf.icons) && mf.icons.length >= 3, 'manifest has >= 3 icons');

// iOS meta
T(/apple-mobile-web-app-capable/i.test(html), 'iOS web-app-capable meta');
T(/apple-touch-icon/i.test(html), 'apple-touch-icon present');

// ------------------------------------------------------------------
// 4) CSP BASELINE
// ------------------------------------------------------------------
S('4. CSP BASELINE');

T(/Content-Security-Policy/i.test(html), 'CSP meta present');
T(/default-src\s+'self'/.test(html), "CSP default-src 'self'");
T(/object-src\s+'none'/.test(html), "CSP object-src 'none'");
T(/base-uri\s+'self'/.test(html), "CSP base-uri 'self'");
T(/frame-ancestors\s+'none'/.test(html), "CSP frame-ancestors 'none'");
W(!/unsafe-eval/.test(html), 'CSP does not include unsafe-eval');

// NOTE: style-src unsafe-inline is expected for a single-file CSS bundle.
T(/style-src\s+'self'\s+'unsafe-inline'/.test(html), "CSP style-src includes 'unsafe-inline' (expected)");

// ------------------------------------------------------------------
// 5) HARDENING PATCH CONFIRMATION
// ------------------------------------------------------------------
S('5. v14.3.1 HARDENING CONFIRMATION');

// Numeric caps
T(app.includes('posNum(raw.pay, 0, 1000000)'), 'Trip pay cap $1,000,000');
T(app.includes('posNum(raw.loadedMiles, 0, 300000)'), 'Loaded miles cap 300,000');
T(app.includes('posNum(raw.emptyMiles, 0, 300000)'), 'Empty miles cap 300,000');
T(app.includes('posNum(raw.amount, 0, 1000000)'), 'Expense amount cap $1,000,000');
T(app.includes('posNum(raw.gallons, 0, 100000)'), 'Fuel gallons cap 100,000');
T(app.includes('intNum(raw.id, 0, 1e12)'), 'Record id cap 1e12');

// IDB self-heal (key + deleteDatabase + reload)
T(app.includes('fl_idb_recover_v1'), 'IDB self-heal session key');
T(app.includes('indexedDB.deleteDatabase'), 'IDB deleteDatabase used for recovery');
T(/location\.reload\(\)/.test(app), 'Reload after recovery');

// CSV chunking
T(app.includes('lines.length <= 4000'), 'CSV fast-path threshold 4000 lines');
T(app.includes('async function parseCSVTextAsync'), 'Async CSV parser exists');
T(app.includes('(n % 750) === 0') || app.includes('(n%750)===0'), 'CSV yields every 750 rows');

// Menu tile escaping
T(app.includes('escapeHtml(tile.icon)') && app.includes('escapeHtml(tile.title)') && app.includes('escapeHtml(tile.sub)'), 'Menu tile fields escaped');

// ------------------------------------------------------------------
// 6) HTML ↔ JS ID SANITY (lightweight)
// ------------------------------------------------------------------
S('6. HTML ↔ JS ID SANITY');

// Collect ids from HTML (both " and ')
const htmlIds = new Set();
for (const m of html.matchAll(/\bid\s*=\s*(['"])([^'"\s>]+)\1/g)) htmlIds.add(m[2]);

// Collect #id references from JS
const jsIds = new Set();
for (const m of app.matchAll(/\bquerySelector(All)?\s*\(\s*['"]#([a-zA-Z0-9_-]+)['"]\s*\)/g)) jsIds.add(m[2]);
for (const m of app.matchAll(/\bgetElementById\s*\(\s*['"]([a-zA-Z0-9_-]+)['"]\s*\)/g)) jsIds.add(m[1]);

// Known dynamic ids (created at runtime inside modals/onboarding banners)
const dynamicIds = new Set([
  'welcomeAddTrip',
  'nudgeExport','backupNudge',
  'safariWarnDismiss',
  'rm_files','rm_save',
  'rf_rating','rf_structured','rf_wins','rf_mistakes','rf_lessons','rf_save'
]);

let missing = 0;
for (const id of jsIds) {
  if (!htmlIds.has(id) && !dynamicIds.has(id)) { missing++; }
}
W(missing === 0, `JS referenced ${jsIds.size} ids; missing in HTML: ${missing}`);

// ------------------------------------------------------------------
// SUMMARY
// ------------------------------------------------------------------
console.log(`\n${'═'.repeat(70)}`);
console.log(`  FreightLogic v14.3.3 — Zero-Trust Certification (static)`);
console.log(`  Total checks: ${pass + fail + warn}`);
console.log(`${'═'.repeat(70)}`);
console.log(`  ✅ PASSED:    ${pass}`);
console.log(`  ❌ FAILED:    ${fail}`);
console.log(`  ⚠️  WARNINGS:  ${warn}`);
const rate = (pass / (pass + fail + warn)) * 100;
console.log(`  📊 PASS RATE: ${rate.toFixed(1)}%`);
console.log(`${'═'.repeat(70)}`);

console.log(`\n  📋 CATEGORY BREAKDOWN:`);
for (const [cat, data] of Object.entries(categories)) {
  const total = data.pass + data.fail + data.warn;
  const pct = total ? ((data.pass / total) * 100).toFixed(0) : '0';
  const status = data.fail === 0 && data.warn === 0 ? '✅' : (data.fail > 0 ? '❌' : '⚠️');
  console.log(`    ${status} ${cat}: ${data.pass}/${total} (${pct}%)`);
}

if (errors.length) {
  console.log(`\n  ❌ FAILURES (${errors.length}):`);
  errors.forEach((e, i) => console.log(`    ${i + 1}. ${e}`));
}
if (warnings.length) {
  console.log(`\n  ⚠️  WARNINGS (${warnings.length}):`);
  warnings.forEach((e, i) => console.log(`    ${i + 1}. ${e}`));
}

console.log(`\n${'═'.repeat(70)}`);
if (fail === 0) console.log('  🏆 CERTIFICATION: PASSED — PRODUCTION-READY');
else if (fail <= 5) console.log('  🟡 CERTIFICATION: CONDITIONAL — Minor issues found');
else console.log('  🔴 CERTIFICATION: FAILED — Fix blocking issues');
console.log(`${'═'.repeat(70)}\n`);

process.exit(fail ? 1 : 0);

// v14.3.2 NAV sanity
S('NAVIGATION');
T(app.includes('function openTripNavigation'), 'NAV: openTripNavigation present');
T(app.includes('maps.apple.com') && app.includes('google.com/maps/dir'), 'NAV: Apple+Google URL patterns');
T(app.includes('data-act="nav"'), 'NAV: Nav button present');
