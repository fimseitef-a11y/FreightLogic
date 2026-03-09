#!/usr/bin/env node
/**
 * FreightLogic v16.3.1 — OFFLINE-CORE AUDIT
 * Tests specific to the offline-first architecture changes.
 */

const fs = require('fs');
const path = require('path');

const appJS = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const indexHTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const swJS = fs.readFileSync(path.join(__dirname, 'service-worker.js'), 'utf8');

let total = 0, pass = 0, fail = 0;
const failures = [];

function check(cat, name, cond, detail = '') {
  total++;
  if (cond) pass++;
  else { fail++; failures.push({ cat, name, detail }); }
}

console.log('\n🔌 OFFLINE-CORE ARCHITECTURE AUDIT');
console.log('═'.repeat(50));

// ── 1. GOOGLE FONTS REMOVED ──
console.log('\n📡 1. Google Fonts Removal');

check('FONTS', 'No Google Fonts stylesheet link', !indexHTML.includes('fonts.googleapis.com/css'));
check('FONTS', 'No Google Fonts in CSP font-src', !indexHTML.includes("font-src 'self' https://fonts.gstatic.com"));
check('FONTS', 'No Google Fonts in CSP style-src', !indexHTML.includes("style-src 'self' 'unsafe-inline' https://fonts.googleapis.com"));
check('FONTS', 'No preconnect to Google Fonts', !indexHTML.includes('preconnect" href="https://fonts.googleapis.com"'));
check('FONTS', 'No preconnect to gstatic', !indexHTML.includes('preconnect" href="https://fonts.gstatic.com"'));
check('FONTS', 'System font stack used', indexHTML.includes('-apple-system') && indexHTML.includes('system-ui'));
check('FONTS', 'No DM Sans in font stack', !indexHTML.includes("'DM Sans'"));
check('FONTS', 'CSP font-src allows data:', indexHTML.includes("font-src 'self' data:"));

// ── 2. VENDOR LOCAL-FIRST LOADING ──
console.log('📦 2. Vendor Local-First Loading');

check('VENDOR', 'loadScriptWithFallback exists', appJS.includes('async function loadScriptWithFallback'));
check('VENDOR', 'Fallback tries array of URLs', appJS.includes('for (const url of urls)'));
check('VENDOR', 'Fallback runs validation', appJS.includes('validate()'));
check('VENDOR', 'Fallback provides error context', appJS.includes('finalError'));
check('VENDOR', 'crossOrigin set for CDN URLs only', appJS.includes("/^https?:/i.test(url)") && appJS.includes("s.crossOrigin = 'anonymous'"));

// SheetJS
check('VENDOR', 'SheetJS: local path first', appJS.includes("'./vendor/xlsx.full.min.js'"));
check('VENDOR', 'SheetJS: CDN fallback second', appJS.includes("'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js'"));
check('VENDOR', 'SheetJS: post-load validation', appJS.includes("typeof XLSX === 'undefined'") && appJS.includes('XLSX.read'));
check('VENDOR', 'SheetJS: uses loadScriptWithFallback', appJS.includes('loadScriptWithFallback') && appJS.includes('xlsx'));

// Tesseract
check('VENDOR', 'Tesseract: local path first', appJS.includes("'./vendor/tesseract.min.js'"));
check('VENDOR', 'Tesseract: CDN fallback second', appJS.includes("'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js'"));
check('VENDOR', 'Tesseract: post-load validation', appJS.includes("typeof Tesseract === 'undefined'") && appJS.includes('Tesseract.createWorker'));
check('VENDOR', 'Tesseract: uses loadScriptWithFallback', appJS.includes('loadScriptWithFallback') && appJS.includes('tesseract'));

// Tesseract worker/core fallback
check('VENDOR', 'Tesseract worker: local path first', appJS.includes("workerPath: './vendor/worker.min.js'"));
check('VENDOR', 'Tesseract core: local path first', appJS.includes("corePath: './vendor/tesseract-core-simd-lstm.wasm.js'"));
check('VENDOR', 'Tesseract worker: CDN fallback', appJS.includes("workerPath: 'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/worker.min.js'"));
check('VENDOR', 'Tesseract core: CDN fallback', appJS.includes("corePath: 'https://cdn.jsdelivr.net/npm/tesseract.js-core@5.1.0/tesseract-core-simd-lstm.wasm.js'"));

// ── 3. VENDOR DIRECTORY ──
console.log('📂 3. Vendor Directory');

check('VENDOR_DIR', 'vendor/ directory exists', fs.existsSync(path.join(__dirname, 'vendor')));
check('VENDOR_DIR', 'vendor/README.txt exists', fs.existsSync(path.join(__dirname, 'vendor', 'README.txt')));

const readmeTxt = fs.existsSync(path.join(__dirname, 'vendor', 'README.txt'))
  ? fs.readFileSync(path.join(__dirname, 'vendor', 'README.txt'), 'utf8') : '';
check('VENDOR_DIR', 'README lists xlsx.full.min.js', readmeTxt.includes('xlsx.full.min.js'));
check('VENDOR_DIR', 'README lists tesseract.min.js', readmeTxt.includes('tesseract.min.js'));
check('VENDOR_DIR', 'README lists worker.min.js', readmeTxt.includes('worker.min.js'));
check('VENDOR_DIR', 'README lists tesseract-core wasm', readmeTxt.includes('tesseract-core-simd-lstm.wasm.js'));
check('VENDOR_DIR', 'README documents fallback behavior', readmeTxt.includes('falls back') || readmeTxt.includes('fallback'));

// ── 4. BUILD NOTES ──
console.log('📋 4. Build Notes');

const buildNotes = fs.existsSync(path.join(__dirname, 'OFFLINE_CORE_BUILD_NOTES.txt'))
  ? fs.readFileSync(path.join(__dirname, 'OFFLINE_CORE_BUILD_NOTES.txt'), 'utf8') : '';
check('NOTES', 'Build notes file exists', buildNotes.length > 0);
check('NOTES', 'Documents offline capability', buildNotes.includes('fully offline'));
check('NOTES', 'Documents vendor dependency', buildNotes.includes('vendor'));
check('NOTES', 'Documents what works offline', buildNotes.includes('Trips') && buildNotes.includes('expenses'));

// ── 5. CSP INTEGRITY ──
console.log('🔐 5. CSP Integrity (post-font-removal)');

check('CSP', 'default-src self', indexHTML.includes("default-src 'self'"));
check('CSP', 'script-src self + CDN', indexHTML.includes("script-src 'self' https://cdn.jsdelivr.net"));
check('CSP', 'connect-src allows https', indexHTML.includes("connect-src 'self' https:"));
check('CSP', 'object-src none', indexHTML.includes("object-src 'none'"));
check('CSP', 'frame-ancestors none', indexHTML.includes("frame-ancestors 'none'"));
check('CSP', 'No stale Google Fonts in CSP', !indexHTML.includes('fonts.googleapis.com'));

// ── 6. SW FONT CACHING SAFETY ──
console.log('⚙️  6. Service Worker (font caching)');

// SW still has font caching logic — that's fine, it just won't match if no fonts are loaded
check('SW', 'SW still handles font hostname check', swJS.includes('fonts.googleapis.com') || swJS.includes('isFont'));
check('SW', 'SW core assets do not include font files', !swJS.includes('.woff') && !swJS.includes('.ttf'));

// ── 7. CANVAS REPORT FONTS ──
console.log('🖼️  7. Canvas Report System Fonts');

const canvasFontLines = appJS.match(/ctx\.font\s*=\s*['"][^'"]+['"]/g) || [];
let allSystemFonts = true;
for (const line of canvasFontLines) {
  if (line.includes('DM Sans') || line.includes('DM Mono')) {
    allSystemFonts = false;
    break;
  }
}
check('CANVAS', 'Canvas reports use system fonts', allSystemFonts,
  allSystemFonts ? '' : 'Found DM Sans/Mono in canvas font declarations');
check('CANVAS', 'Canvas uses -apple-system', canvasFontLines.some(l => l.includes('-apple-system')));

// ══════════════════════════════════════════════════════════════
// REPORT
// ══════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(50));
console.log('  OFFLINE-CORE AUDIT REPORT');
console.log('═'.repeat(50));
console.log(`  Total: ${total}  ✅ ${pass}  ❌ ${fail}`);
console.log(`  Score: ${pass}/${total} (${((pass/total)*100).toFixed(1)}%)`);
console.log('═'.repeat(50));

if (failures.length > 0) {
  console.log('\n❌ FAILURES:');
  for (const f of failures) {
    console.log(`  [${f.cat}] ${f.name}`);
    if (f.detail) console.log(`    → ${f.detail}`);
  }
}

if (fail === 0) console.log('\n🏆 OFFLINE-CORE: ALL CHECKS PASSED\n');
process.exit(fail > 0 ? 1 : 0);
