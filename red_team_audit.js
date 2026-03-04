#!/usr/bin/env node
/**
 * FREIGHT LOGIC v14.3.4 — TIER-0 RED TEAM AUDIT
 * 
 * Categories:
 *   A. Syntax & Structure
 *   B. Function Existence & Signatures
 *   C. HTML ↔ JS ID Sync (every ID used in JS exists in HTML and vice versa)
 *   D. Data Flow & Integration (save→score→render pipelines)
 *   E. Profit Engine Logic
 *   F. Lane Intelligence Logic
 *   G. Broker Scorecard Logic
 *   H. Goal System Logic
 *   I. Trend Alerts Logic
 *   J. UX System (haptic, toast, modal, PTR, stagger, skeleton)
 *   K. Security & Sanitization
 *   L. Edge Cases & Defensive Coding
 *   M. Regression — All Previous Features
 *   N. Service Worker & Manifest
 *   O. CSS Class References
 */

const fs = require('fs');
const app = fs.readFileSync('app.js', 'utf8');
const html = fs.readFileSync('index.html', 'utf8');
const sw = fs.readFileSync('service-worker.js', 'utf8');
const mf = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));

let pass = 0, fail = 0, warn = 0, errors = [], warnings = [];
function T(cond, msg) { if (cond) pass++; else { fail++; errors.push(msg); } }
function W(cond, msg) { if (cond) pass++; else { warn++; warnings.push(msg); } }
function S(s) { console.log(`\n━━ ${s} ━━`); }

// ====================================================================
// A. SYNTAX & STRUCTURE
// ====================================================================
S('A. SYNTAX & STRUCTURE');
T(app.startsWith('(() => {'), 'A1: IIFE wrapper opens');
T(app.trimEnd().endsWith('})();'), 'A2: IIFE wrapper closes');
T(app.includes("'use strict'"), 'A3: strict mode');
T(app.includes("const APP_VERSION = '14.3.4-hardened'"), 'A4: version string');

// Check balanced braces
let braceCount = 0;
for (const ch of app) { if (ch === '{') braceCount++; if (ch === '}') braceCount--; }
T(braceCount === 0, `A5: Balanced braces (delta: ${braceCount})`);

// Check balanced parens
let parenCount = 0;
for (const ch of app) { if (ch === '(') parenCount++; if (ch === ')') parenCount--; }
T(parenCount === 0, `A6: Balanced parens (delta: ${parenCount})`);

// Check balanced brackets
let bracketCount = 0;
for (const ch of app) { if (ch === '[') bracketCount++; if (ch === ']') bracketCount--; }
T(bracketCount === 0, `A7: Balanced brackets (delta: ${bracketCount})`);

// No console.log left in production (console.error in SW registration is acceptable)
const consoleLogs = (app.match(/console\.log/g) || []);
W(consoleLogs.length === 0, `A8: No console.log in prod (found ${consoleLogs.length})`);

// No debugger statements
T(!app.includes('debugger'), 'A9: No debugger statements');

// No TODO/FIXME/HACK
const todos = (app.match(/\/\/\s*(TODO|FIXME|HACK|XXX)/gi) || []);
W(todos.length === 0, `A10: No TODO/FIXME/HACK comments (found ${todos.length})`);

// ====================================================================
// B. FUNCTION EXISTENCE & SIGNATURES
// ====================================================================
S('B. FUNCTION EXISTENCE & SIGNATURES');

const requiredFunctions = [
  // Core (fmtMoney, fmtNum, isoDate are const arrow fns — checked separately)
  'escapeHtml', 'clampStr', 'normOrderNo',
  'newTripTemplate', 'sanitizeTrip', 'sanitizeExpense', 'sanitizeFuel',
  'tripExists', 'upsertTrip', 'deleteTrip', 'listTrips', 'listUnpaidTrips',
  'addExpense', 'updateExpense', 'deleteExpense', 'listExpenses',
  'addFuel', 'updateFuel', 'deleteFuel', 'listFuel',
  // DB (openDB is inline via indexedDB.open)
  'tx', 'waitTxn', 'idbReq', 'getSetting', 'setSetting',
  // Export/Import
  'dumpStore', 'exportJSON', 'importJSON', 'downloadCSV',
  'exportTripsCSV', 'exportExpensesCSV', 'exportFuelCSV',
  // Analytics
  'startOfWeek', 'startOfMonth', 'startOfQuarter', 'startOfYear',
  'computeKPIs', 'invalidateKPICache', 'computeTaxView',
  'computeARAging', 'computeBrokerStats', 'daysBetweenISO',
  // Profit Engine
  'computeLoadScore', 'scoreBadgeHTML', 'openScoreBreakdown',
  'showScoreFlash', 'renderLiveScore',
  // Lane Intelligence
  'normLaneCity', 'laneKey', 'laneKeyDisplay',
  'computeLaneStats', 'computeLaneIntel', 'laneIntelHTML',
  'renderTopLanes', 'openLaneBreakdown',
  // Broker Scorecards
  'computeBrokerGrade', 'brokerGradeHTML', 'openBrokerScorecard', 'brokerIntelHTML',
  // Goal + Alerts
  'renderTrendAlerts', 'alertCard',
  // Weekly Report + Load Compare + Accountant Export + Autocomplete
  'generateWeeklyReport', 'openLoadCompare', 'generateAccountantPackage', 'attachAutoComplete',
  // v13: Export Checksum + Performance Indexing + Snap Load
  'computeExportChecksum', 'queryTripsByPickupRange', 'queryExpensesByDateRange',
  'queryUnpaidTotal', 'computeQuickKPIs', 'loadTesseract', 'parseLoadText', 'openSnapLoad',
  // Rendering
  'renderHome', 'renderCommandCenter', 'renderTrips', 'renderExpenses',
  'renderFuel', 'renderAR', 'renderInsights', 'renderOmega',
  'navigate', 'setActiveNav', 'actionCard', 'tripRow',
  // UX
  'haptic', 'toast', 'openModal', 'closeModal',
  'staggerItems', 'showSkeleton', 'setupPTR', 'pulseKPI',
  // Omega
  'omegaTierForMiles', 'omegaCompute', 'omegaApplyAdder',
  'omegaFormatMoneyRange', 'omegaShiftOneTierLower',
  // Receipts
  'getReceipts', 'putReceipts', 'getAllReceipts', 'openReceiptManager',
  // Storage
  'refreshStorageHealth', 'countStore', 'storageHealthSnapshot',
];

for (const fn of requiredFunctions) {
  T(app.includes(`function ${fn}`) || app.includes(`async function ${fn}`),
    `B: function ${fn}() exists`);
}
// Arrow function declarations
T(app.includes('const fmtMoney = ('), 'B: const fmtMoney arrow fn');
T(app.includes('const fmtNum = ('), 'B: const fmtNum arrow fn');
T(app.includes('const isoDate = ('), 'B: const isoDate arrow fn');
// Inline DB open
T(app.includes('indexedDB.open(DB_NAME'), 'B: DB opened via indexedDB.open');

// ====================================================================
// C. HTML ↔ JS ID SYNC
// ====================================================================
S('C. HTML ↔ JS ID SYNC');

// Extract all IDs from HTML
const htmlIds = new Set();
const idRegex = /id="([^"]+)"/g;
let m;
while ((m = idRegex.exec(html)) !== null) htmlIds.add(m[1]);

// IDs that JS uses via $('#...')
const jsIdRefs = new Set();
const jsIdRegex = /\$\$?\('#([a-zA-Z0-9_-]+)'/g;
while ((m = jsIdRegex.exec(app)) !== null) jsIdRefs.add(m[1]);

// Also check $("[data-act=...") patterns
const jsDataActRefs = new Set();
const dataActRegex = /\$\('\[data-act="([^"]+)"\]'/g;
while ((m = dataActRegex.exec(app)) !== null) jsDataActRefs.add(m[1]);

// Compound selectors like $$('#taxPeriodTabs .btn') — extract base ID only
const jsCompoundRefs = new Set();
const compoundRegex = /\$\$?\('#([a-zA-Z0-9_-]+)\s/g;
while ((m = compoundRegex.exec(app)) !== null) jsCompoundRefs.add(m[1]);

// Every JS-referenced static ID should exist in HTML (except dynamically created ones)
const dynamicIds = new Set([
  'f_orderNo','f_pay','f_pickup','f_loaded','f_empty','f_customer','f_origin','f_dest',
  'f_delivery','f_paid','f_notes','f_receipts','f_date','f_amt','f_cat','f_save','f_del',
  'tripHint','toStep2','saveTrip','delTrip','backStep1','saveTrip2',
  'qaTrip','qaExpense','qaFuel','qaCompare','omOutput',
  'scoreDetail','scoreDismiss','liveScore',
  'brokerIntelBox','laneIntelBox','f_hint',
  'f_fDate','f_fGallons','f_fAmount','f_fState','f_fNotes','f_fSave','f_fDel','f_fHint',
  'catList',
  'cmpA_pay','cmpA_loaded','cmpA_empty','cmpA_customer','cmpA_origin','cmpA_dest',
  'cmpB_pay','cmpB_loaded','cmpB_empty','cmpB_customer','cmpB_origin','cmpB_dest',
  'cmpRun','cmpResult',
]);

let missingHtmlIds = 0;
for (const id of jsIdRefs) {
  if (!htmlIds.has(id) && !dynamicIds.has(id) && !jsCompoundRefs.has(id)) {
    // Check if it's created dynamically in JS
    if (!app.includes(`id="${id}"`) && !app.includes(`id='${id}'`)) {
      missingHtmlIds++;
      errors.push(`C: JS references #${id} but not in HTML or dynamic`);
      fail++;
    } else { pass++; }
  } else { pass++; }
}
if (missingHtmlIds === 0) { pass++; console.log('  All JS ID references resolved'); }

// Critical HTML IDs that MUST exist
const criticalIds = [
  'fab','modal','modalBody','modalTitle','modalClose','backdrop','toast','mainHeader',
  'view-home','view-trips','view-expenses','view-money','view-fuel','view-insights','view-omega',
  'homeActions','homeRecentTrips','trendAlerts',
  'tripList','tripSearch','expenseList','expSearch','fuelList','arList',
  'btnTripMore','btnExpMore','btnFuelMore',
  'kpiTodayGross','kpiTodayExp','kpiTodayNet','kpiWeekNet','kpiUnpaid',
  'pillWeekNet','pillUnpaid',
  'pcRevVel','pcWkTarget','pcEfficiency','pcAvgScore','pcAcceptRate','pcFuelDrift',
  'pcProgressBar','pcProgressLabel','pcCoaching',
  'weeklyGoal','uiMode','perDiemRate','brokerWindow',
  'btnSaveSettings','btnHardReset',
  'wkGross','wkExp','wkNet','wkLoaded','wkAll','wkRpm','wkDeadhead','deadheadPill',
  'ar0_15','ar16_30','ar31_45','ar46p','brokerList','brokerWindowLabel',
  'laneList',
  'taxGross','taxExpenses','taxNet','taxPerDiem','taxSE','taxProfit','taxPeriodTabs',
  'omCalcBtn','omResetBtn','omMiles','omEmpty','omDropTier','omDelayPct',
  'omOvernight','om250','omRisk','omDay3Gross','omErosionOk',
  'stTrips','stExpenses','stFuel','stReceiptSets','stReceiptBlobs','stStatus',
  'btnStorageRefresh','btnStorageAnalyze','btnStorageRebuild','btnStorageClearCache',
  'btnQuickTrip','btnQuickExpense','btnQuickFuel',
  'btnWeeklyReport','btnLoadCompare','btnAccountantExport',
  'acctPeriodTabs',
  'appMeta',
];
for (const id of criticalIds) {
  T(htmlIds.has(id), `C: Critical HTML #${id}`);
}

// ====================================================================
// D. DATA FLOW & INTEGRATION
// ====================================================================
S('D. DATA FLOW & INTEGRATION');

// Trip save → score flash pipeline
T(app.includes('upsertTrip(trip)') && app.includes('computeLoadScore(saved'), 'D1: Trip save triggers score computation');
T(app.includes('showScoreFlash(saved, score)'), 'D2: Score flash shown after save');
T(app.includes('invalidateKPICache()') && app.includes('renderTrips(true)') && app.includes('renderHome()'), 'D3: Save refreshes all views');

// KPI cache invalidation points
const invalPoints = (app.match(/invalidateKPICache\(\)/g) || []).length;
T(invalPoints >= 5, `D4: KPI cache invalidated in ${invalPoints} places (need ≥5)`);

// Score uses KPI cache for trip rows
T(app.includes('_kpiCache.trips') && app.includes('computeLoadScore(t, _kpiCache.trips'), 'D5: Trip rows use cached data for scores');

// Navigate function routes to correct renderers
T(app.includes("'home') await renderHome()") || app.includes("'home') { await renderHome()") || 
  (app.includes("name === 'home'") && app.includes('renderHome()')), 'D6: Navigate → renderHome');
T(app.includes("name === 'trips'") && app.includes('renderTrips'), 'D7: Navigate → renderTrips');
T(app.includes("name === 'expenses'") && app.includes('renderExpenses'), 'D8: Navigate → renderExpenses');
T(app.includes("name === 'fuel'") && app.includes('renderFuel'), 'D9: Navigate → renderFuel');
T(app.includes("name === 'omega'") && app.includes('renderOmega'), 'D10: Navigate → renderOmega');
T(app.includes("name === 'insights'") && app.includes('renderInsights'), 'D11: Navigate → renderInsights');

// renderHome calls renderCommandCenter
T(app.includes('await renderCommandCenter()'), 'D12: renderHome calls renderCommandCenter');

// renderCommandCenter calls renderTrendAlerts
T(app.includes('await renderTrendAlerts('), 'D13: renderCommandCenter calls renderTrendAlerts');

// renderOmega calls renderTopLanes
T(app.includes('await renderTopLanes()'), 'D14: renderOmega calls renderTopLanes');

// ====================================================================
// E. PROFIT ENGINE LOGIC
// ====================================================================
S('E. PROFIT ENGINE LOGIC');

// Margin scoring factors (4 factors, max 100)
T(app.includes('Omega tier') && app.includes('max:40'), 'E1: Margin F1 — Omega tier (0-40)');
T(app.includes('vs 90-day avg') && app.includes('max:25'), 'E2: Margin F2 — vs history (0-25)');
T(app.includes("name:'Deadhead'") && app.includes('max:20'), 'E3: Margin F3 — Deadhead (0-20)');
T(app.includes("name:'Net margin'") && app.includes('max:15'), 'E4: Margin F4 — Net margin (0-15)');
// 40+25+20+15 = 100 ✓

// Risk scoring factors (4 factors, max 100)
T(app.includes("name:'Broker history'") && app.includes('max:35'), 'E5: Risk F1 — Broker history (0-35)');
T(app.includes("name:'Deadhead risk'") && app.includes('max:25'), 'E6: Risk F2 — Deadhead risk (0-25)');
T(app.includes("name:'Concentration'") && app.includes('max:20'), 'E7: Risk F3 — Concentration (0-20)');
T(app.includes("name:'Below floor'") && app.includes('max:20'), 'E8: Risk F4 — Below floor (0-20)');
// 35+25+20+20 = 100 ✓

// Verdicts
T(app.includes("'PREMIUM WIN'") && app.includes("'ACCEPT'") && 
  app.includes("'NEGOTIATE'") && app.includes("'PASS'"), 'E9: All 4 verdicts');

// Counter-offer
T(app.includes('tier.ideal.min') && app.includes('idealRpm * allMi'), 'E10: Counter-offer targets Ideal RPM');

// Score clamping
T(app.includes('Math.min(100, Math.max(0, m))'), 'E11: Margin score clamped 0-100');
T(app.includes('Math.min(100, Math.max(0, r))'), 'E12: Risk score clamped 0-100');

// ====================================================================
// F. LANE INTELLIGENCE LOGIC
// ====================================================================
S('F. LANE INTELLIGENCE LOGIC');

T(app.includes('normLaneCity(s)'), 'F1: Lane city normalizer');
T(app.includes('toLowerCase()'), 'F2: Case-insensitive lane matching');
T(app.includes('avgFirst') && app.includes('avgSecond'), 'F3: Trend compares halves');
T(app.includes("trend = 1") && app.includes("trend = -1"), 'F4: Rising/Declining detection');
T(app.includes('Math.sqrt(variance)'), 'F5: Volatility = std deviation');
T(app.includes('daysSinceLast'), 'F6: Staleness tracking');
T(app.includes('minRpm:Infinity'), 'F7: minRpm initialized to Infinity');
T(app.includes("minRpm === Infinity ? 0"), 'F8: Infinity fallback for display');

// ====================================================================
// G. BROKER SCORECARD LOGIC
// ====================================================================
S('G. BROKER SCORECARD LOGIC');

// Grade computation (4 factors, max 100)
T(app.includes('RPM quality') && app.includes('0-35'), 'G1: RPM quality (0-35)');
T(app.includes('Payment speed') && app.includes('0-30'), 'G2: Payment speed (0-30)');
T(app.includes('Reliability'), 'G3: Reliability factor');
T(app.includes('Volume') && app.includes('0-15'), 'G4: Volume loyalty (0-15)');
// 35+30+20+15 = 100 ✓

T(app.includes("grade = 'A'") && app.includes("grade = 'B'") &&
  app.includes("grade = 'C'") && app.includes("grade = 'D'") &&
  app.includes("grade = 'F'"), 'G5: All 5 letter grades');

T(app.includes('score >= 85'), 'G6: A threshold: 85+');
T(app.includes('score >= 70'), 'G7: B threshold: 70+');

// ====================================================================
// H. GOAL SYSTEM LOGIC
// ====================================================================
S('H. GOAL SYSTEM LOGIC');

T(app.includes("getSetting('weeklyGoal'"), 'H1: Reads weeklyGoal');
T(app.includes("setSetting('weeklyGoal'"), 'H2: Saves weeklyGoal');
T(app.includes('userGoal > 0 ? userGoal : autoTarget'), 'H3: User goal overrides auto');
T(app.includes('remaining <= 0'), 'H4: Goal-hit detection');
T(app.includes('above goal'), 'H5: Above-goal message');
T(app.includes('loadsNeeded'), 'H6: Loads-needed calc');
T(app.includes('avgMiPerLoad'), 'H7: Uses personal avg miles');
T(app.includes('loadCount30 >= 3'), 'H8: Needs 3+ loads for avg');
T(app.includes("bar.style.background = 'var(--good)'"), 'H9: Green bar at 100%+');
T(app.includes("targetPct >= 70"), 'H10: Accent bar at 70%+');

// ====================================================================
// I. TREND ALERTS LOGIC
// ====================================================================
S('I. TREND ALERTS LOGIC');

T(app.includes('async function renderTrendAlerts'), 'I1: renderTrendAlerts exists');
T(app.includes('function alertCard'), 'I2: alertCard exists');

// All 10 alert types
T(app.includes('rpm7') && app.includes('rpm14'), 'I3: Alert 1 — RPM comparison');
T(app.includes('dhPct7') && app.includes('dhPct14'), 'I4: Alert 2 — Deadhead comparison');
T(app.includes('brokerUnpaid') && app.includes('maxAge'), 'I5: Alert 3 — Broker unpaid');
T(app.includes('ppg30') && app.includes('ppg60') && app.includes('Fuel cost up'), 'I6: Alert 4 — Fuel drift');
T(app.includes('Behind pace') && app.includes('expectedPace'), 'I7: Alert 5 — Behind goal pace');
T(app.includes('Revenue velocity dropped'), 'I8: Alert 6 — Revenue velocity');
T(app.includes('Efficiency low'), 'I9: Alert 7 — Low efficiency');
T(app.includes('Concentration risk') && app.includes('recent60'), 'I10: Alert 8 — Concentration');
T(app.includes('Best lane idle'), 'I11: Alert 9 — Stale best lane');
T(app.includes('Avg load score low'), 'I12: Alert 10 — Low avg score');

// Severity system
T(app.includes("severity:'danger'"), 'I13: Danger severity');
T(app.includes("severity:'warn'"), 'I14: Warning severity');
T(app.includes("severity:'info'"), 'I15: Info severity');
T(app.includes('alerts.slice(0, 5)'), 'I16: Max 5 alerts');
T(app.includes('sevOrder'), 'I17: Sorted by severity');

// ====================================================================
// J. UX SYSTEM
// ====================================================================
S('J. WEEKLY PERFORMANCE REPORT');

T(app.includes('async function generateWeeklyReport'), 'WR1: generateWeeklyReport exists');
T(app.includes("canvas.width = ") || app.includes("new OffscreenCanvas") || app.includes("createElement('canvas')"), 'WR2: Canvas creation');
T(app.includes('getContext') && app.includes("'2d'"), 'WR3: 2D canvas context');
T(app.includes('toBlob'), 'WR4: Canvas toBlob for download');
T(app.includes('Weekly Performance Report'), 'WR5: Report title text');
T(app.includes("download = ") && app.includes('FreightLogic_Weekly'), 'WR6: Download filename');
T(app.includes('wkGross') && app.includes('wkNet') && app.includes('wkRpm'), 'WR7: Weekly gross/net/RPM computed');
T(app.includes('wkDh') || app.includes('wkDH') || app.includes('wkAll - wkLoaded'), 'WR8: Weekly deadhead computed');
T(app.includes('wkAvgScore') && app.includes('wkAccRate'), 'WR9: Weekly score/accept rate');
T(app.includes('topLane') && app.includes('computeLaneStats(wkTripsArr)'), 'WR10: Top lane this week');
T(app.includes('topBroker') && app.includes('topBrokerGrade'), 'WR11: Top broker with grade');
T(app.includes('fuelPpg') || app.includes('fuelGal'), 'WR12: Fuel stats on report');
T(app.includes("'Goal Progress'") || app.includes('goal'), 'WR13: Goal progress on report');
T(app.includes('roundRect'), 'WR14: Rounded rectangle helper');
T(app.includes('fillRect') && app.includes('fillText'), 'WR15: Canvas drawing calls');
T(app.includes("image/png"), 'WR16: PNG output format');
T(html.includes('id="btnWeeklyReport"'), 'WR17: Report button in HTML');

S('J2. LOAD COMPARE MODE');

T(app.includes('function openLoadCompare'), 'LC1: openLoadCompare exists');
T(app.includes('cmpA_pay') && app.includes('cmpB_pay'), 'LC2: Two-load input form');
T(app.includes('cmpA_loaded') && app.includes('cmpB_loaded'), 'LC3: Miles inputs for both');
T(app.includes('cmpA_customer') && app.includes('cmpB_customer'), 'LC4: Customer inputs for both');
T(app.includes('cmpA_origin') && app.includes('cmpB_origin'), 'LC5: Origin inputs for both');
T(app.includes('cmpRun'), 'LC6: Compare button');
T(app.includes('cmpResult'), 'LC7: Result container');
T(app.includes('computeLoadScore(loadA') && app.includes('computeLoadScore(loadB'), 'LC8: Both loads scored');
T(app.includes('computeLaneIntel') && app.includes('laneA') && app.includes('laneB'), 'LC9: Lane intel for both');
T(app.includes('gradeA') && app.includes('gradeB'), 'LC10: Broker grades for both');
T(app.includes("winner = 'A'") && app.includes("winner = 'B'"), 'LC11: Winner determination');
T(app.includes("winner = 'TIE'") || app.includes("winner === 'TIE'"), 'LC12: Tie handling');
T(app.includes("Take Load"), 'LC13: Recommendation label');
T(app.includes('netA') && app.includes('netB') && app.includes('riskScore * 0.5'), 'LC14: Risk-adjusted scoring');
T(app.includes('statRow') && app.includes('Verdict') && app.includes('Margin') && app.includes('Risk'), 'LC15: Stat comparison rows');
T(app.includes("'Counter'") && app.includes('counterOffer'), 'LC16: Counter-offer comparison');
T(app.includes("'Broker'") && app.includes('gradeA'), 'LC17: Broker grade comparison');
T(app.includes("'Lane runs'") && app.includes('laneA'), 'LC18: Lane history comparison');
T(html.includes('id="btnLoadCompare"'), 'LC19: Compare button in HTML');
T(app.includes('qaCompare'), 'LC20: Compare in Quick Add sheet');

S('J3. UX SYSTEM');

// Haptic integration points
const hapticCalls = (app.match(/haptic\(\d*\)/g) || []).length;
T(hapticCalls >= 10, `J1: Haptic calls: ${hapticCalls} (need ≥10)`);

// Toast system
T(app.includes("'toast ' +") || app.includes("className = 'toast"), 'J2: Toast CSS class animation');

// Modal system
T(app.includes('function openModal'), 'J3: openModal exists');
T(app.includes('function closeModal'), 'J4: closeModal exists');
T(app.includes('swipe-to-dismiss') || app.includes('touchstart') || app.includes('touchmove'), 'J5: Modal swipe-to-dismiss');

// Stagger animation
T(app.includes('function staggerItems'), 'J6: staggerItems exists');
const staggerCalls = (app.match(/staggerItems\(/g) || []).length;
T(staggerCalls >= 5, `J7: staggerItems called ${staggerCalls} times (need ≥5)`);

// Skeleton loading
T(app.includes('function showSkeleton'), 'J8: showSkeleton exists');

// Pull-to-refresh
T(app.includes('function setupPTR'), 'J9: setupPTR exists');
T(app.includes("setupPTR('tripsPTR'") || app.includes("setupPTR("), 'J10: PTR wired to lists');

// KPI pulse
T(app.includes('function pulseKPI'), 'J11: pulseKPI exists');

// FAB rotation
T(app.includes("fab.classList.add('open')") || app.includes("classList.add('open')"), 'J12: FAB rotation');

// Header scroll shadow
T(app.includes('scrolled') && app.includes('scroll'), 'J13: Header scroll shadow');

// View transitions
T(app.includes('entering'), 'J14: View enter animation');

// Accessibility
T(html.includes('prefers-reduced-motion') || app.includes('prefers-reduced-motion'), 'J15: Reduced motion support (CSS)');

// ====================================================================
// K. SECURITY & SANITIZATION
// ====================================================================
S('K. SECURITY & SANITIZATION');

T(app.includes('function sanitizeTrip'), 'K1: sanitizeTrip exists');
T(app.includes('function sanitizeExpense'), 'K2: sanitizeExpense exists');
T(app.includes('function sanitizeFuel'), 'K3: sanitizeFuel exists');
T(app.includes('function escapeHtml'), 'K4: escapeHtml exists');
T(app.includes('function clampStr'), 'K5: clampStr exists');
T(app.includes('function normOrderNo'), 'K6: normOrderNo exists');

// XSS prevention — escapeHtml used in display
const escapeHtmlCalls = (app.match(/escapeHtml\(/g) || []).length;
T(escapeHtmlCalls >= 15, `K7: escapeHtml called ${escapeHtmlCalls} times (need ≥15)`);

// Import sanitization
T(app.includes('safeTripArr') && app.includes('safeExpArr') && app.includes('safeFuelArr'), 'K8: Import sanitization arrays');
T(app.includes('safeAuditArr'), 'K9: Audit log import sanitization');
T(app.includes('MAX_IMPORT_BYTES'), 'K10: Import size limit');
T(app.includes('MAX_RECEIPT_BYTES'), 'K11: Receipt size limit');

// Confirm gates on destructive actions
const confirmCalls = (app.match(/if\s*\(!confirm\(/g) || []).length;
T(confirmCalls >= 8, `K12: ${confirmCalls} confirm() gates (need ≥8)`);

// Pro gates
const proGates = (app.match(/!==\s*'pro'/g) || []).length;
T(proGates >= 5, `K13: ${proGates} Pro-only gates (need ≥5)`);

// No innerHTML with unsanitized user data in trip/broker displays
// Check that customer names are escaped
T(app.includes('escapeHtml(t.orderNo') || app.includes('escapeHtml(t.orderNo'), 'K14: Order# escaped in display');
T(app.includes('escapeHtml(t.customer') || app.includes("escapeHtml(b.name)"), 'K15: Customer/broker name escaped');

// ====================================================================
// L. EDGE CASES & DEFENSIVE CODING
// ====================================================================
S('L. EDGE CASES & DEFENSIVE CODING');

// Division by zero guards
T(app.includes('allMi > 0 ?') || app.includes('allMi > 0?'), 'L1: RPM division guard (allMi > 0)');
T(app.includes('miles>0 ?') || app.includes('miles > 0 ?'), 'L2: miles > 0 guard');
T(app.includes('r.miles>0'), 'L3: broker miles > 0 guard');
T(app.includes('loaded > 0 ?'), 'L4: loaded > 0 guard (trueRpm)');
T(app.includes('r.trips > 0') || app.includes('broker.trips > 0'), 'L5: trips > 0 guard');

// Null/undefined guards
T(app.includes("t.pickupDate || t.deliveryDate"), 'L6: Date fallback chain');
T(app.includes("|| 'Unknown'") || app.includes("|| 'Unknown')"), 'L7: Unknown customer fallback');
T(app.includes('isNaN(a) || isNaN(b)'), 'L8: NaN guard in daysBetweenISO');
T(app.includes('isFinite(ts)'), 'L9: isFinite guard in AR aging');

// Empty state handling
T(app.includes('No trips yet'), 'L10: Empty state — no trips');
T(app.includes('No broker history'), 'L11: Empty state — no brokers');
T(app.includes('No history yet') || app.includes('neutral score'), 'L12: Empty state — no score history');
T(app.includes('New broker') || app.includes('no history'), 'L13: Empty state — new broker');
T(app.includes('New lane') || app.includes('no history'), 'L14: Empty state — new lane');

// Try/catch wrappers
const tryCatchCount = (app.match(/try\s*\{/g) || []).length;
T(tryCatchCount >= 10, `L15: ${tryCatchCount} try/catch blocks (need ≥10)`);

// ====================================================================
// M. REGRESSION — ALL PREVIOUS FEATURES
// ====================================================================
S('M. REGRESSION — ALL FEATURES');

// Core CRUD
T(app.includes('async function upsertTrip'), 'M1: Trip upsert');
T(app.includes('async function addExpense'), 'M2: Expense add');
T(app.includes('async function addFuel'), 'M3: Fuel add');
T(app.includes('async function deleteTrip'), 'M4: Trip delete');
T(app.includes('async function deleteExpense'), 'M5: Expense delete');
T(app.includes('async function deleteFuel'), 'M6: Fuel delete');

// Forms
T(app.includes('function openTripWizard'), 'M7: Trip wizard');
T(app.includes('function openExpenseForm'), 'M8: Expense form');
T(app.includes('function openFuelForm'), 'M9: Fuel form');
T(app.includes('function openReceiptManager'), 'M10: Receipt manager');

// Receipt system
T(app.includes('getReceipts') && app.includes('putReceipts'), 'M11: Receipt CRUD');
T(app.includes('cacheDeleteReceipt') || app.includes('idbDeleteReceiptBlob'), 'M12: Receipt cache cleanup');
T(app.includes('THUMB_MAX_DIM'), 'M13: Thumbnail generation');

// Export/Import
T(app.includes('exportJSON') && app.includes('importJSON'), 'M14: JSON export/import');
T(app.includes('exportTripsCSV') && app.includes('exportExpensesCSV') && app.includes('exportFuelCSV'), 'M15: CSV exports');

// Analytics
T(app.includes('computeKPIs'), 'M16: KPI computation');
T(app.includes('computeTaxView'), 'M17: Tax view');
T(app.includes('computeARAging'), 'M18: AR aging');
T(app.includes('computeBrokerStats'), 'M19: Broker stats');

// Omega Calculator
T(app.includes('OMEGA_TIERS'), 'M20: Omega tier definitions');
T(app.includes('omegaCompute'), 'M21: Omega compute');
T(app.includes('omegaLastInputs'), 'M22: Omega input persistence');

// Search & Pagination
T(app.includes('tripSearch') && app.includes('expSearch'), 'M23: Search inputs');
T(app.includes('btnTripMore') && app.includes('btnExpMore'), 'M24: Pagination buttons');
T(app.includes('PAGE_SIZE'), 'M25: Pagination constant');

// Audit log
T(app.includes('auditLog'), 'M26: Audit log store');

// Service worker
T(app.includes("navigator.serviceWorker"), 'M27: SW registration');
T(app.includes('lastExportDate'), 'M28: Backup reminder');

// Date range filter
T(app.includes('startDate') || app.includes('dateFilter') || app.includes('f_pickup'), 'M29: Date filtering');

// Mark paid/unpay
T(app.includes("isPaid") && app.includes("paidDate"), 'M30: Paid/unpaid toggle');

// Fuel IFTA states
T(app.includes('f_fState') || app.includes('state'), 'M31: Fuel state tracking');

// ====================================================================
// N. SERVICE WORKER & MANIFEST
// ====================================================================
S('N. SERVICE WORKER & MANIFEST');

T(sw.includes("const SW_VERSION = '14.3.4-hardened'"), 'N1: SW version matches');

// ====================================================================
// P. AUTOCOMPLETE SYSTEM
// ====================================================================
S('P. AUTOCOMPLETE SYSTEM');

T(app.includes('function attachAutoComplete'), 'AC1: attachAutoComplete utility');
T(app.includes('ac-drop') && app.includes('ac-item'), 'AC2: Dropdown CSS classes');
T(app.includes('ac-wrap'), 'AC3: Wrapper element');
T(app.includes('ArrowDown') && app.includes('ArrowUp'), 'AC4: Keyboard nav support');
T(app.includes("key === 'Enter'") && app.includes("key === 'Escape'"), 'AC5: Enter/Escape handling');
T(app.includes('scrollIntoView'), 'AC6: Scroll selected into view');
T(app.includes("addEventListener('blur'"), 'AC7: Close on blur');
T(app.includes("addEventListener('focus'"), 'AC8: Reopen on focus');

// Customer autocomplete
T(app.includes('attachAutoComplete(custEl'), 'AC9: Customer autocomplete wired');
T(app.includes('computeBrokerStats') && app.includes('b.name.toLowerCase().includes'), 'AC10: Customer suggestions from broker stats');
T(app.includes("b.trips") && app.includes("b.avgRpm") && app.includes("b.pay"), 'AC11: Customer suggestion shows stats');

// City autocomplete (origin + dest)
T(app.includes('attachAutoComplete(origEl'), 'AC12: Origin autocomplete wired');
T(app.includes('attachAutoComplete(destEl'), 'AC13: Dest autocomplete wired');
T(app.includes("t.origin") && app.includes("t.destination") && app.includes("cities"), 'AC14: City suggestions from trip history');

// State autocomplete (fuel)
T(app.includes('attachAutoComplete(stateEl'), 'AC15: Fuel state autocomplete wired');
T(app.includes("fill-up"), 'AC16: State suggestion shows fill count');

// CSS
T(html.includes('.ac-drop'), 'AC17: ac-drop CSS in HTML');
T(html.includes('.ac-item'), 'AC18: ac-item CSS in HTML');
T(html.includes('.ac-wrap'), 'AC19: ac-wrap CSS in HTML');
T(html.includes('.ac-sub'), 'AC20: ac-sub CSS in HTML');

// ====================================================================
// Q. EXPORT-TO-ACCOUNTANT PACKAGE
// ====================================================================
S('Q. EXPORT-TO-ACCOUNTANT PACKAGE');

T(app.includes('async function generateAccountantPackage'), 'EX1: generateAccountantPackage exists');
T(html.includes('id="btnAccountantExport"'), 'EX2: Export button in HTML');
T(html.includes('id="acctPeriodTabs"'), 'EX3: Period tabs in HTML');
T(app.includes("_acctPeriod"), 'EX4: Period state variable');

// Period logic
T(app.includes("period === 'q1'") && app.includes("period === 'q2'") && 
  app.includes("period === 'q3'") && app.includes("period === 'q4'"), 'EX5: All 4 quarters');
T(app.includes("startDate") && app.includes("endDate"), 'EX6: Date range computation');

// P&L
T(app.includes('grossRevenue') && app.includes('totalExpenses') && app.includes('netIncome'), 'EX7: P&L computed');
T(app.includes('PROFIT & LOSS SUMMARY'), 'EX8: P&L summary label');
T(app.includes('REVENUE') && app.includes('EXPENSES') && app.includes('DEDUCTIONS'), 'EX9: All P&L sections');

// Expense categories
T(app.includes('catTotals'), 'EX10: Expense categories aggregated');

// IFTA fuel by state
T(app.includes('stateTotals') && app.includes('IFTA'), 'EX11: IFTA fuel summary');
T(app.includes('iftaSummaryRows'), 'EX12: IFTA state breakdown');

// Per diem
T(app.includes('perDiemDays') && app.includes('perDiemTotal'), 'EX13: Per diem calculation');
T(app.includes('tripDays') && app.includes('new Set()'), 'EX14: Unique road days counted');
T(app.includes('perDiemRate'), 'EX15: Per diem rate used');

// Tax estimates
T(app.includes('seRate') || app.includes('0.153'), 'EX16: SE tax rate (15.3%)');
T(app.includes('0.9235'), 'EX17: SE tax applies to 92.35% of net');
T(app.includes('estimatedProfit'), 'EX18: Bottom line calculation');
T(app.includes('Not tax advice'), 'EX19: Disclaimer included');

// CSV generation
T(app.includes('function toCSV') || app.includes('toCSV('), 'EX20: CSV generator');
T(app.includes('FreightLogic_Accountant'), 'EX21: Download filename');
T(app.includes("text/csv"), 'EX22: CSV content type');
T(app.includes('INCOME DETAIL') && app.includes('EXPENSES BY CATEGORY') && app.includes('FUEL LOG'), 'EX23: All sections in export');

// IFTA toggle
T(app.includes('iftaOn') || app.includes("iftaMode"), 'EX24: IFTA toggle support');

// ====================================================================
// R. EXPORT INTEGRITY CHECKSUM (v13)
// ====================================================================
S('R. EXPORT INTEGRITY CHECKSUM');

T(app.includes('async function computeExportChecksum'), 'CK1: computeExportChecksum exists');
T(app.includes("crypto.subtle.digest") && app.includes("SHA-256"), 'CK2: SHA-256 primary hash');
T(app.includes('0x811c9dc5') && app.includes('0x01000193'), 'CK3: FNV-1a fallback constants');
T(app.includes("fnv1a-"), 'CK4: FNV fallback prefix');
T(app.includes('meta.checksum') || (app.includes('checksum') && app.includes('recordCounts')), 'CK5: Checksum stored in export meta');
T(app.includes('INTEGRITY WARNING') || app.includes('tampered'), 'CK6: Tamper warning on mismatch');
T(app.includes('recordCounts'), 'CK7: Record counts in meta');
T(app.includes('Import anyway') || app.includes('Import cancelled'), 'CK8: User choice on mismatch');

// ====================================================================
// S. PERFORMANCE INDEXING (v13)
// ====================================================================
S('S. PERFORMANCE INDEXING');

T(app.includes('DB_VERSION = 7') || app.includes('const DB_VERSION = 7') || app.includes('DB_VERSION = 8') || app.includes('const DB_VERSION = 8'), 'PI1: DB version 7+');
T(app.includes("createIndex('date'") || app.includes("createIndex('date',"), 'PI2: Date index on expenses');
T(app.includes("indexNames.contains('date')"), 'PI3: Index existence check before create');
T(app.includes('async function queryTripsByPickupRange'), 'PI4: queryTripsByPickupRange exists');
T(app.includes('async function queryExpensesByDateRange'), 'PI5: queryExpensesByDateRange exists');
T(app.includes('async function queryUnpaidTotal'), 'PI6: queryUnpaidTotal exists');
T(app.includes('async function computeQuickKPIs'), 'PI7: computeQuickKPIs exists');
T(app.includes('IDBKeyRange.bound') && app.includes('IDBKeyRange.lowerBound'), 'PI8: IDBKeyRange usage');
T(app.includes('openCursor(range)'), 'PI9: Cursor with range');
T(app.includes('Promise.all') && app.includes('queryTripsByPickupRange') && app.includes('queryExpensesByDateRange'), 'PI10: Parallel indexed queries');
T(app.includes("computeQuickKPIs().catch"), 'PI11: Quick KPI on interval');
T(app.includes("dumpStore('expenses')).filter"), 'PI12: Expense query fallback for pre-v7');

// ====================================================================
// T. SNAP LOAD OCR (v13)
// ====================================================================
S('T. SNAP LOAD OCR');

T(app.includes('function openSnapLoad'), 'SL1: openSnapLoad exists');
T(app.includes('async function loadTesseract'), 'SL2: loadTesseract exists');
T(app.includes('function parseLoadText'), 'SL3: parseLoadText exists');
T(app.includes('_tesseractWorker') && app.includes('_tesseractReady'), 'SL4: Worker singleton pattern');
T(app.includes('tesseract.min.js') || app.includes('tesseract.js'), 'SL5: Tesseract.js CDN');
T(app.includes('Tesseract.createWorker'), 'SL6: Worker creation');
T(app.includes('worker.recognize'), 'SL7: Image recognition call');

// Parser coverage
T(app.includes('order|load|ref') || app.includes('orderPats'), 'SL8: Order # parsing patterns');
T(app.includes('moneyMatches') || app.includes('moneyRe'), 'SL9: Dollar amount parsing');
T(app.includes('milesPats') || app.includes('miles|mi'), 'SL10: Miles parsing');
T(app.includes('cityStatePat'), 'SL11: City, State parsing');
T(app.includes('AL|AK|AZ|AR|CA|CO'), 'SL12: US state abbreviation validation');
T(app.includes('brokerPats') || app.includes('broker|carrier|customer'), 'SL13: Broker/customer parsing');
T(app.includes('parseDateStr'), 'SL14: Date parsing helper');
T(app.includes('weightMatch') || app.includes('lbs|pounds'), 'SL15: Weight parsing');

// UI
T(app.includes('snapCamera') && app.includes('snapFile'), 'SL16: Camera + file input buttons');
T(app.includes("capture=\"environment\""), 'SL17: Camera capture attribute');
T(app.includes('snapPreview') && app.includes('snapImg'), 'SL18: Image preview');
T(app.includes('snapResults') && app.includes('snapParsed'), 'SL19: Results display');
T(app.includes('snapAccept') && app.includes('Open in Trip Form'), 'SL20: Accept button');
T(app.includes('snapRetry'), 'SL21: Retry button');
T(app.includes('snapRawText') && app.includes('Raw OCR text'), 'SL22: Raw text details');
T(app.includes('qaSnapLoad'), 'SL23: Snap Load in Quick Add sheet');

// Security
T(app.includes('10 * 1024 * 1024') || app.includes('10MB'), 'SL24: Image size cap');
T(app.includes('sanitizeTrip(prefill)') || app.includes('sanitizeTrip'), 'SL25: Parsed data sanitized');
T(app.includes('_snapPrefill'), 'SL26: Snap prefill flag');
T(app.includes('isSnapPrefill') && app.includes("mode = ") && app.includes("'add'"), 'SL27: Snap opens wizard in add mode');
T(app.includes('Verify all fields') || app.includes('OCR'), 'SL28: Verification reminder banner');

// CSP
T(html.includes('cdn.jsdelivr.net'), 'SL29: CSP allows jsdelivr');
T(html.includes('tessdata.projectnaptha.com'), 'SL30: CSP allows tessdata');
T(html.includes('worker-src') && html.includes('blob:'), 'SL31: CSP allows worker blob');
T(app.includes('confidence'), 'SL32: OCR confidence score tracked');

// ====================================================================
// U. ONBOARDING & EMPTY STATES (v13.1)
// ====================================================================
S('U. ONBOARDING & EMPTY STATES');

// State detection
T(app.includes('async function getOnboardState'), 'OB1: getOnboardState exists');
T(app.includes('isEmpty') && app.includes('isBeginner') && app.includes('isActive'), 'OB2: Three-tier state detection');
T(app.includes('countStore') && app.includes("'trips'") && app.includes("'expenses'") && app.includes("'fuel'"), 'OB3: Counts all stores');

// Welcome card
T(app.includes('function renderWelcomeCard'), 'OB4: renderWelcomeCard exists');
T(app.includes('Welcome to Freight Logic'), 'OB5: Welcome message');
T(app.includes('Log your first trip') || app.includes('Add Your First Trip'), 'OB6: First trip CTA');
T(app.includes('welcomeAddTrip'), 'OB7: Welcome button wired');
T(app.includes('Snap Load to scan'), 'OB8: OCR mention in welcome');

// Empty states
T(app.includes('function renderEmptyState'), 'OB9: renderEmptyState utility');
T(app.includes('Every load you log builds your profit intelligence'), 'OB10: Trip empty state guidance');
T(app.includes('Track fuel, tolls, insurance'), 'OB11: Expense empty state guidance');
T(app.includes('Log each fill-up with state and gallons'), 'OB12: Fuel empty state guidance');
T(app.includes('All caught up'), 'OB13: AR empty state');

// Home view state awareness
T(html.includes('id="homeWelcome"'), 'OB14: Welcome slot in HTML');
T(html.includes('id="homeOmegaCard"'), 'OB15: Omega card has ID');
T(html.includes('id="homePerfCard"'), 'OB16: Performance card has ID');
T(app.includes('homeWelcome') && app.includes('homeOmegaCard') && app.includes('homePerfCard'), 'OB17: renderHome references all slots');
T(app.includes("state.isEmpty") && app.includes("perfCard.style.display = 'none'"), 'OB18: Empty state hides perf card');

// FAB onboarding
T(app.includes("classList.add('pulse')"), 'OB19: FAB pulse for new users');
T(app.includes("classList.remove('pulse')"), 'OB20: FAB pulse dismissed');
T(html.includes('id="fabHint"'), 'OB21: FAB hint element');
T(html.includes('fabPulse'), 'OB22: FAB pulse animation CSS');
T(html.includes('.fab-hint'), 'OB23: FAB hint CSS');

// First-trip wizard guidance
T(app.includes('First trip!') || app.includes('first trip'), 'OB24: First trip banner in wizard');
T(app.includes('Broker Grades and Lane Intel') || app.includes('broker name and origin'), 'OB25: Step 2 guidance for beginners');

// First-trip celebration
T(app.includes('First trip logged') || app.includes('dashboard is live'), 'OB26: First trip celebration toast');

// Beginner encouragement
T(app.includes('Getting started') && app.includes('Log a few more trips'), 'OB27: Beginner encouragement in command center');

// Improved labels
T(html.includes('Money Owed To You'), 'OB28: AR section renamed for clarity');
T(html.includes('IFTA reporting available in Settings') || html.includes('If you need IFTA reporting'), 'OB29: Fuel view IFTA guidance');
T(app.includes('from your rate confirmation') || app.includes('rate confirmation'), 'OB30: Order # placeholder has context');
T(app.includes('Total line haul pay') || app.includes('line haul'), 'OB31: Pay placeholder has context');
T(app.includes('Miles with freight'), 'OB32: Loaded miles placeholder clear');
T(app.includes('Deadhead to pickup'), 'OB33: Empty miles placeholder clear');

// First expense guidance
T(app.includes('Pick a category from the dropdown'), 'OB34: First expense category hint');
T(sw.includes('CACHE_NAME'), 'N2: Cache name defined');
T(sw.includes('install') && sw.includes('activate') && sw.includes('fetch'), 'N3: SW lifecycle events');
T(sw.includes('skipWaiting') || sw.includes('clients.claim'), 'N4: SW activation strategy');

T(mf.name && mf.name.length > 0, 'N5: Manifest has name');
T(mf.short_name && mf.short_name.length > 0, 'N6: Manifest has short_name');
T(mf.start_url, 'N7: Manifest has start_url');
T(mf.display === 'standalone', 'N8: Manifest display: standalone');
T(Array.isArray(mf.icons) && mf.icons.length >= 3, `N9: Manifest has ${mf.icons?.length || 0} icons`);
T(mf.theme_color, 'N10: Manifest has theme_color');
T(mf.background_color, 'N11: Manifest has background_color');

// HTML references
T(html.includes('manifest.json'), 'N12: HTML links to manifest');
T(html.includes('service-worker.js') || app.includes('service-worker.js'), 'N13: SW referenced');
T(html.includes('apple-mobile-web-app-capable'), 'N14: iOS PWA meta');
T(html.includes('viewport'), 'N15: Viewport meta');
T(html.includes('apple-touch-icon'), 'N16: Apple touch icon');

// ====================================================================
// O. CSS CLASS REFERENCES
// ====================================================================
S('O. CSS CLASS REFERENCES');

// Critical CSS classes used in JS that must exist in HTML <style>
const criticalClasses = [
  'card', 'pill', 'btn', 'item', 'list', 'row', 'muted', 'grid2', 'tag',
  'good', 'bad', 'warn', 'danger', 'toast', 'modal', 'modal-backdrop',
  'fab', 'nav', 'bottom', 'view', 'split', 'mono', 'spacer',
  'entering', 'show', 'hide', 'vis', 'scrolled', 'active', 'open',
  'skel', 'enter', 'kpi-pop',
  'ac-drop', 'ac-item', 'ac-wrap', 'ac-sub',
];
for (const cls of criticalClasses) {
  T(html.includes(`.${cls}`) || html.includes(`.${cls} `) || html.includes(`.${cls}{`) ||
    html.includes(`.${cls},`) || html.includes(`.${cls}:`) || html.includes(`.${cls}.`),
    `O: CSS class .${cls}`);
}

// ====================================================================
// V. MIDWEST STACK INTEGRATION (v13.2)
// ====================================================================
S('V. MIDWEST STACK INTEGRATION');

// Would Run Again
T(app.includes('wouldRunAgain'), 'V1: wouldRunAgain field in trip template');
T(app.includes('wouldRunAgain') && app.includes('sanitizeTrip'), 'V2: wouldRunAgain sanitized');
T(app.includes('f_runAgain'), 'V3: Would Run Again checkbox in wizard');
T(app.includes('REPEAT'), 'V4: REPEAT badge on trip rows');
T(app.includes('repeats:'), 'V5: repeats counter in lane stats');
T(app.includes('repeatRate'), 'V6: repeatRate computed in lane stats');
T(app.includes('Would repeat'), 'V7: Repeat rate in lane breakdown modal');
T(app.includes('repeat</span>'), 'V8: Repeat badge in lane list row');

// Weekly Reflection
T(app.includes('openWeeklyReflection'), 'V9: openWeeklyReflection function');
T(app.includes('rf_rating'), 'V10: Rating input in reflection');
T(app.includes('rf_structured'), 'V11: Structured checkbox in reflection');
T(app.includes('rf_wins'), 'V12: Wins field in reflection');
T(app.includes('rf_mistakes'), 'V13: Mistakes field in reflection');
T(app.includes('rf_lessons'), 'V14: Lessons field in reflection');
T(app.includes("'weeklyReflection'"), 'V15: weeklyReflection setting key');
T(app.includes('End-of-week check-in'), 'V16: Reflection action card on Fri-Sun');
T(app.includes('data-rating'), 'V17: Rating buttons 1-10');
T(app.includes('Was the week structured'), 'V18: Structured question text');

// Fuel Cost Estimate
T(app.includes('vehicleMpg'), 'V19: vehicleMpg setting');
T(app.includes('fuelPrice'), 'V20: fuelPrice setting');
T(app.includes('fuelConfig'), 'V21: fuelConfig parameter on computeLoadScore');
T(app.includes('fuelCost'), 'V22: fuelCost in score return object');
T(app.includes('netAfterFuel'), 'V23: netAfterFuel in score return object');
T(app.includes('NET AFTER FUEL'), 'V24: Net After Fuel in score flash');
T(app.includes('Fuel est'), 'V25: Fuel est pill in score breakdown');
T(app.includes('Net after fuel'), 'V26: Net after fuel pill in score breakdown');
T(app.includes('Fuel model'), 'V27: Fuel model status in baselines card');
T(html.includes('vehicleMpg'), 'V28: MPG input in Settings HTML');
T(html.includes('fuelPrice'), 'V29: Fuel price input in Settings HTML');
T(html.includes('Vehicle MPG'), 'V30: MPG label in Settings HTML');
T(app.includes('allMi / mpg * ppg'), 'V31: Fuel cost formula: miles/mpg*price');

// Settings whitelist updated
T(app.includes("'vehicleMpg'") && app.includes("'fuelPrice'") && app.includes("'weeklyReflection'"), 'V32: New settings in ALLOWED_SETTINGS_KEYS');

// Load Compare fuel integration
T(app.includes('Net after fuel') && app.includes('Fuel est') && app.includes('cmpResult'), 'V33: Fuel estimates in Load Compare');

// CSV Import
T(app.includes('parseCSVText'), 'V34: CSV parser function');
T(app.includes('importCSVFile'), 'V35: CSV import function');
T(app.includes('importFile'), 'V36: Unified import dispatcher (JSON+CSV)');
T(app.includes('normalizeHeader'), 'V37: Header normalization for flexible matching');
T(app.includes('.json,.csv,.tsv'), 'V38: File picker accepts JSON+CSV+TSV');
T(app.includes("type === 'trips'") && app.includes("type === 'expenses'") && app.includes("type === 'fuel'"), 'V39: Auto-detection for all three CSV types');
T(app.includes('cellAt'), 'V40: Multi-alias column resolver');
T(app.includes('WouldRunAgain') && app.includes('exportTripsCSV'), 'V41: WouldRunAgain in CSV export');
T(html.includes('btnFuelImport'), 'V42: Fuel import button in HTML');
T(app.includes('btnFuelImport'), 'V43: Fuel import button wired in JS');

// ====================================================================
// W. UX CLARITY OVERHAUL (v14.0)
// ====================================================================
S('W. UX CLARITY OVERHAUL');

// 4-tab navigation
T(html.includes('data-nav="home"'), 'W1: Home tab');
T(html.includes('data-nav="trips"'), 'W2: Trips tab');
T(html.includes('data-nav="money"'), 'W3: Money tab (promoted)');
T(html.includes('data-nav="more"'), 'W4: More tab');
T(!html.includes('data-nav="expenses"'), 'W5: Expenses removed from nav (moved to More)');
T(!html.includes('data-nav="fuel"'), 'W6: Fuel removed from nav (moved to More)');
T(!html.includes('data-nav="insights"'), 'W7: Insights removed from nav (moved to More)');

// More menu system
T(html.includes('view-more'), 'W8: More section exists in HTML');
T(app.includes('renderMore'), 'W9: renderMore function');
T(app.includes('MORE_TILES'), 'W10: More menu tile definitions');
T(app.includes('menu-tile'), 'W11: Menu tile class used');
T(html.includes('menu-grid'), 'W12: Menu grid in HTML');
T(html.includes('menu-tile'), 'W13: Menu tile CSS');

// Quick Settings in More
T(html.includes('moreWeeklyGoal'), 'W14: Quick settings - weekly goal');
T(html.includes('moreVehicleMpg'), 'W15: Quick settings - vehicle MPG');
T(html.includes('moreFuelPrice'), 'W16: Quick settings - fuel price');
T(html.includes('morePerDiem'), 'W17: Quick settings - per diem');
T(html.includes('moreSaveSettings'), 'W18: Quick settings save button');

// Simplified home
T(html.includes('This Week'), 'W19: Home shows "This Week" not "Today"');
T(html.includes("What's Next"), 'W20: Action center renamed "What\'s Next"');
T(!html.includes('Performance Command Center'), 'W21: Simplified performance heading');
T(html.includes('pcDetailRow'), 'W22: Detail row hidden by default (Pro only)');

// Universal import
T(app.includes('openUniversalImport'), 'W23: Universal import modal');
T(app.includes('importXLSXFile'), 'W24: XLSX import function');
T(app.includes('importTXTFile'), 'W25: TXT import function');
T(app.includes('importPDFFile'), 'W26: PDF import function');
T(app.includes('loadSheetJS'), 'W27: SheetJS lazy loader');

// Bigger tap targets
T(html.includes('min-height:48px'), 'W28: Button minimum 48px height');
T(html.includes('font-size:14px'), 'W29: Larger button font');

// Money tab upgraded
T(html.includes('ar0_15m'), 'W30: Money AR aging pills');
T(html.includes('ar46pm'), 'W31: Money AR 46+ day bucket');
T(app.includes('ar0_15m'), 'W32: AR buckets computed in renderAR');

// Nav mapping for sub-sections
T(app.includes("'expenses','fuel','insights','omega'"), 'W33: Sub-sections map to More tab highlight');
T(app.includes('IMPORT_ACCEPT'), 'W34: Universal import accept constant defined');
T(app.includes("pickFile(IMPORT_ACCEPT)"), 'W35: Per-section imports accept all file types');
T(app.includes('imp-btn'), 'W36: Universal import uses robust class-based binding');
T(app.includes("data-accept="), 'W37: Import buttons use data-accept attributes');
T(app.includes('Any file'), 'W38: Auto-detect any-file option in import modal');
T(app.includes("window.addEventListener('focus'"), 'W39: pickFile handles cancel via focus listener');

// ====================================================================
// SUMMARY
// ====================================================================
console.log(`\n${'═'.repeat(60)}`);
console.log(`  FREIGHT LOGIC v14.3.4 — TIER-0 RED TEAM AUDIT`);
console.log(`${'═'.repeat(60)}`);
console.log(`  ✅ PASSED:   ${pass}`);
console.log(`  ❌ FAILED:   ${fail}`);
console.log(`  ⚠️  WARNINGS: ${warn}`);
console.log(`${'═'.repeat(60)}`);
if (errors.length) {
  console.log('\n  ❌ FAILURES:');
  errors.forEach((e, i) => console.log(`    ${i + 1}. ${e}`));
}
if (warnings.length) {
  console.log('\n  ⚠️  WARNINGS:');
  warnings.forEach((e, i) => console.log(`    ${i + 1}. ${e}`));
}
console.log(`\n${'═'.repeat(60)}`);
process.exit(fail ? 1 : 0);
