(() => {
'use strict';

/** Freight Logic v16.3.1 USA ENGINE
 *  Market Feed + Tomorrow Signal + Strategic Floor (A–E)
 *  DAT API integration ready
 */

const APP_VERSION = '16.3.1';

// escapeHtml is the canonical XSS-safe escape function — see line ~74

// csvSafeCell is the canonical CSV injection guard — see line ~91

const _listeners = new Map();
function addManagedListener(el, evt, handler) {
  if (!el) return;
  el.addEventListener(evt, handler);
  const key = el.id || 'anon';
  if (!_listeners.has(key)) _listeners.set(key, []);
  _listeners.get(key).push({el, evt, handler});
}
function cleanupListeners() {
  _listeners.forEach(list => {
    list.forEach(({el, evt, handler}) => el?.removeEventListener(evt, handler));
  });
  _listeners.clear();
}
window.addEventListener('beforeunload', cleanupListeners);
window.addEventListener('pagehide', cleanupListeners);


const DB_NAME = 'XpediteOps_v1';

// ════════════════════════════════════════════════════════════════════════════
// FREIGHTLOGIC v16.3.1 USA ENGINE — Production Security Hardened
// ════════════════════════════════════════════════════════════════════════════
// TIER 6 OMEGA FIXES APPLIED:
// • XSS Protection (innerHTML sanitization)
// • CSV Injection Protection (formula neutralization)
// • IndexedDB Error Recovery (quota + corruption handling)
// • Memory Leak Prevention (event listener cleanup)
// • Accessibility Improvements (focus, touch targets)
// • Home Location Feature (strategic $1.25 floor)
// • Division-by-Zero Protection
//
// PRODUCTION READY: ✅ Security Hardened | ✅ Accessibility Compliant
// ════════════════════════════════════════════════════════════════════════════

const DB_VERSION = 9;
const PAGE_SIZE = 50;

const LIMITS = Object.freeze({
  MAX_IMPORT_BYTES: 30 * 1024 * 1024,
  MAX_RECEIPT_BYTES: 6 * 1024 * 1024,
  MAX_RECEIPTS_PER_TRIP: 20,
  MAX_RECEIPT_CACHE: 40,
  THUMB_MAX_DIM: 320,
  THUMB_JPEG_QUALITY: 0.72,
});

/** IRS tax data — updated for 2026 tax year.
 *  Per diem: IRS Notice 2025-54. SE tax: IRS Pub 463 / Schedule SE.
 *  Mileage: IRS Notice 2026-10 (effective Jan 1, 2026).
 *  Review annually at irs.gov for updates. */
const IRS = Object.freeze({
  PER_DIEM_CONUS: 80,       // $/day, effective Oct 1, 2024 — unchanged through Sept 30, 2026
  PER_DIEM_OCONUS: 86,      // $/day for Canada/international
  PER_DIEM_PARTIAL: 60,     // 75% of full-day rate
  PER_DIEM_PCT_DOT: 0.80,   // 80% deductible for DOT HOS workers (CDL, semi)
  PER_DIEM_PCT_NON_DOT: 0.50, // 50% deductible for non-DOT (cargo van, sprinter, box truck)
  SE_RATE: 0.153,           // 15.3% (12.4% SS + 2.9% Medicare)
  SE_NET_FACTOR: 0.9235,    // Only 92.35% of net is subject to SE tax
  SS_WAGE_BASE_2026: 184500, // Social Security cap for 2026
  MILEAGE_RATE_2026: 0.725, // $0.725/mile business use, effective Jan 1, 2026
  MILEAGE_RATE_2025: 0.70,  // $0.70/mile, effective Jan 1, 2025
});

const $ = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

function escapeHtml(s){
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
/** T5-FIX: Deep-clone object stripping __proto__, constructor, prototype keys to prevent prototype pollution */
function deepCleanObj(obj, depth=0){
  if (depth > 8 || obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(v => deepCleanObj(v, depth+1));
  const clean = {};
  for (const k of Object.keys(obj)){
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    clean[k] = deepCleanObj(obj[k], depth+1);
  }
  return clean;
}

/** P0-1: Neutralize CSV formula injection (=, +, -, @, TAB, CR, |, %, !) */
function csvSafeCell(val){
  let s = String(val ?? '');
  // Guard formula starts at beginning of string
  if (/^[=+\-@\t\r|%!]/.test(s)) s = '\t' + s;
  // Guard formula starts after newlines (multi-line cells in spreadsheet software)
  s = s.replace(/\n([=+\-@|%!])/g, '\n\t$1');
  // Neutralize DDE payloads
  s = s.replace(/\b(cmd|powershell|mshta|certutil)\b/gi, (m) => m[0] + '\u200B' + m.slice(1));
  return s;
}

/** Strip formula injection from IMPORTED data */
function sanitizeImportValue(val){
  let s = String(val ?? '').trim();
  // Remove leading formula characters
  s = s.replace(/^[\t\r\n]+/, '');
  let guard = 0;
  while (/^[=+\-@|%!]/.test(s) && s.length > 1 && guard++ < 20) s = s.slice(1);
  // Remove DDE-style payloads
  s = s.replace(/\bcmd\s*\|/gi, '').replace(/\bpowershell\b/gi, '');
  return s.trim();
}

const fmtMoney = (n) => {
  const x = Number(n || 0);
  return x.toLocaleString(undefined, { style:'currency', currency:'USD' });
};
/** Round to cents — prevents IEEE-754 drift in financial aggregation */
const roundCents = (n) => Math.round(Number(n || 0) * 100) / 100;
const fmtNum = (n) => {
  const x = Number(n);
  return (Number.isFinite(x) ? x : 0).toLocaleString();
};
const isoDate = (d=new Date()) => new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,10);
function clampStr(s, max=120){ return String(s||'').trim().slice(0,max); }

// ---- Numeric hardening (v14.3.1) ----
function finiteNum(v, def=0){
  const x = Number(v);
  return Number.isFinite(x) ? x : def;
}
function posNum(v, def=0, max=1e9){
  const x = finiteNum(v, def);
  return Math.min(max, Math.max(0, x));
}
function intNum(v, def=0, max=1e9){
  const x = Math.trunc(finiteNum(v, def));
  return Math.min(max, Math.max(0, x));
}

/** Prevent oversized records from bloating IDB and degrading index performance.
 *  Limit: 1MB per record (trips, expenses, fuel). */
function validateRecordSize(obj, label){
  const json = JSON.stringify(obj);
  if (json.length > 1_000_000){
    throw new Error(`${label} record too large (${Math.round(json.length/1024)}KB). Reduce notes or data.`);
  }
}

// ════════════════════════════════════════════════════════════════
// SECURITY HARDENING MODULE (v14.1.0)
// ════════════════════════════════════════════════════════════════

/** Request persistent storage to prevent browser eviction */
async function requestPersistentStorage(){
  try{
    if (navigator.storage && navigator.storage.persist){
      const granted = await navigator.storage.persist();
      // Persistent storage requested
      return granted;
    }
  }catch(e){ console.warn('[SECURITY] persist() failed:', e); }
  return false;
}

/** Check storage quota and warn if low */
async function checkStorageQuota(){
  try{
    if (navigator.storage && navigator.storage.estimate){
      const est = await navigator.storage.estimate();
      const usedMB = Math.round((est.usage || 0) / 1024 / 1024);
      const quotaMB = Math.round((est.quota || 0) / 1024 / 1024);
      const pctUsed = quotaMB > 0 ? Math.round((est.usage / est.quota) * 100) : 0;
      if (pctUsed > 80){
        toast(`⚠️ Storage ${pctUsed}% full (${usedMB}/${quotaMB} MB). Export a backup now!`, true);
      }
      return { usedMB, quotaMB, pctUsed };
    }
  }catch(e){ console.warn('[SECURITY] quota check failed:', e); }
  return null;
}

/** Detect Safari / iOS for ITP warning */
function isSafari(){
  const ua = navigator.userAgent || '';
  return /Safari/i.test(ua) && !/Chrome|Chromium|Edg|OPR|Opera/i.test(ua);
}
function isIOS(){
  return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

/** Show Safari ITP data loss warning */

// ---- NAVIGATION: 1-tap route open (Apple Maps on iOS, Google Maps elsewhere) ----
function openTripNavigation(trip){
  try{
    const destRaw = (trip?.destination || trip?.dest || '').trim();
    const origRaw = (trip?.origin || trip?.orig || '').trim();
    if (!destRaw){
      toast('Add a destination first', true);
      return;
    }
    const dest = encodeURIComponent(destRaw);
    const orig = origRaw ? encodeURIComponent(origRaw) : '';
    let url = '';
    if (isIOS()){
      url = `https://maps.apple.com/?${orig?`saddr=${orig}&`:''}daddr=${dest}&dirflg=d`;
    } else {
      url = `https://www.google.com/maps/dir/?api=1&${orig?`origin=${orig}&`:''}destination=${dest}&travelmode=driving`;
    }
    window.open(url, '_blank', 'noopener,noreferrer');
  } catch (e){
    toast('Could not open navigation', true);
  }
}

function showSafariWarning(){
  if (!isSafari() && !isIOS()) return;
  const dismissed = localStorage.getItem('fl_safari_warn_v1');
  if (dismissed) return;
  const banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;padding:14px 16px;background:linear-gradient(135deg,#ff6b35,#d63031);color:#fff;font-size:13px;line-height:1.5;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.4)';
  banner.innerHTML = `<b>⚠️ Safari/iOS Data Warning</b><br>Safari may delete your data if you don't use this app for 7 days. <b>Add to Home Screen</b> and <b>export backups regularly</b> to protect your records.<br><button id="safariWarnDismiss" style="margin-top:8px;padding:8px 24px;border:2px solid #fff;border-radius:8px;background:transparent;color:#fff;font-weight:700;cursor:pointer;font-size:13px">I Understand — Dismiss</button>`;
  document.body.appendChild(banner);
  banner.querySelector('#safariWarnDismiss').addEventListener('click', ()=>{
    localStorage.setItem('fl_safari_warn_v1', '1');
    banner.remove();
  });
}

/** Check if backup is overdue and show reminder */
async function checkBackupReminder(){
  try{
    const lastBackup = await getSetting('lastBackupDate', null);
    const now = Date.now();
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    const onb = await getOnboardState();
    if (onb.isEmpty) return; // Don't nag empty apps
    if (!lastBackup || (now - lastBackup) > sevenDays){
      // Show non-blocking backup reminder
      const days = lastBackup ? Math.floor((now - lastBackup) / 86400000) : null;
      const msg = days ? `Last backup: ${days} days ago. Export one now?` : 'You haven\'t backed up yet. Your data only exists on this device.';
      showBackupNudge(msg);
    }
  }catch(e){ console.warn('[SECURITY] backup check failed:', e); }
}

function showBackupNudge(msg){
  const el = document.createElement('div');
  el.className = 'card';
  el.id = 'backupNudge';
  el.style.cssText = 'border:1px solid rgba(255,179,0,.4);background:rgba(255,179,0,.08);margin-bottom:14px';
  el.innerHTML = `<div style="display:flex;align-items:center;gap:12px">
    <div style="font-size:24px;line-height:1">💾</div>
    <div style="flex:1"><div style="font-weight:700;font-size:13px;margin-bottom:2px">Backup Reminder</div><div class="muted" style="font-size:12px;line-height:1.4">${escapeHtml(msg)}</div></div>
    <button class="btn primary" id="nudgeExport" style="padding:10px 16px;white-space:nowrap">Export Now</button>
  </div>`;
  const home = document.querySelector('#view-home');
  if (home){
    const existing = home.querySelector('#backupNudge');
    if (existing) existing.remove();
    home.insertBefore(el, home.children[1] || null);
    el.querySelector('#nudgeExport').addEventListener('click', async ()=>{
      haptic(20);
      await exportJSON();
      await setSetting('lastBackupDate', Date.now());
      el.remove();
      toast('Backup exported! Store it somewhere safe.');
    });
  }
}

/** Mark backup timestamp whenever JSON export happens */
async function markBackupDone(){
  await setSetting('lastBackupDate', Date.now());
}

/** Quarterly CPA export reminder — nudge user at end of each quarter */
async function checkQuarterlyExportReminder(){
  try{
    const lastExport = await getSetting('lastExportDate', null);
    const now = new Date();
    const month = now.getMonth(); // 0-based
    // Quarter boundaries: Q1 ends Mar, Q2 ends Jun, Q3 ends Sep, Q4 ends Dec
    // Remind if we're in the last 10 days of a quarter-end month and haven't exported this quarter
    const isQuarterEndMonth = [2, 5, 8, 11].includes(month);
    const dayOfMonth = now.getDate();
    if (!isQuarterEndMonth || dayOfMonth < 21) return;

    const quarterStart = new Date(now.getFullYear(), month - 2, 1).getTime();
    if (lastExport && lastExport > quarterStart) return; // Already exported this quarter

    const qLabel = ['Q1','Q1','Q1','Q2','Q2','Q2','Q3','Q3','Q3','Q4','Q4','Q4'][month];
    showQuarterlyNudge(`${qLabel} ends soon — time to export your records for your CPA.`);
  }catch(e){ console.warn('[FL] Quarterly reminder error:', e); }
}

function showQuarterlyNudge(msg){
  const el = document.createElement('div');
  el.className = 'card';
  el.id = 'quarterlyNudge';
  el.style.cssText = 'border:1px solid rgba(52,211,153,.4);background:rgba(52,211,153,.08);margin-bottom:14px';
  el.innerHTML = `<div style="display:flex;align-items:center;gap:12px">
    <div style="font-size:24px;line-height:1">📊</div>
    <div style="flex:1"><div style="font-weight:700;font-size:13px;margin-bottom:2px">CPA Export Reminder</div><div class="muted" style="font-size:12px;line-height:1.4">${escapeHtml(msg)}</div></div>
    <button class="btn primary" id="nudgeQuarterlyExport" style="padding:10px 16px;white-space:nowrap">Export</button>
  </div>`;
  const home = document.querySelector('#view-home');
  if (home){
    const existing = home.querySelector('#quarterlyNudge');
    if (existing) existing.remove();
    home.insertBefore(el, home.children[2] || null);
    el.querySelector('#nudgeQuarterlyExport').addEventListener('click', ()=>{
      haptic(20);
      // Navigate to the accountant export section
      navigateTo('insights');
      toast('Scroll to "Export to Accountant" and generate your package.');
      el.remove();
    });
  }
}

/** SHA-256 hash for data integrity verification */
async function sha256(text){
  try{
    const buf = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
  }catch{ return null; }
}

// ---- Autocomplete dropdown utility ----
function attachAutoComplete(input, getSuggestions, onSelect, root=document){
  const wrap = document.createElement('div');
  wrap.className = 'ac-wrap';
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  const drop = document.createElement('div');
  drop.className = 'ac-drop';
  wrap.appendChild(drop);

  let selIdx = -1;
  let items = [];

  function render(suggestions){
    items = suggestions;
    selIdx = -1;
    drop.innerHTML = '';
    if (!suggestions.length){ drop.classList.remove('vis'); return; }
    suggestions.forEach((s, i) => {
      const el = document.createElement('div');
      el.className = 'ac-item';
      el.innerHTML = `<div>${escapeHtml(s.label)}</div>${s.sub ? `<div class="ac-sub">${escapeHtml(s.sub)}</div>` : ''}`;
      el.addEventListener('mousedown', (ev) => {
        ev.preventDefault();
        input.value = s.value;
        drop.classList.remove('vis');
        if (onSelect) onSelect(s);
        input.dispatchEvent(new Event('input', { bubbles: true }));
      });
      drop.appendChild(el);
    });
    drop.classList.add('vis');
  }

  let _acTimer = null;
  input.addEventListener('input', () => {
    clearTimeout(_acTimer);
    _acTimer = setTimeout(async () => {
      const val = input.value.trim();
      if (val.length < 1){ drop.classList.remove('vis'); return; }
      const suggestions = await getSuggestions(val);
      render(suggestions);
    }, 200);
  });

  input.addEventListener('keydown', (ev) => {
    if (!drop.classList.contains('vis') || !items.length) return;
    if (ev.key === 'ArrowDown'){ ev.preventDefault(); selIdx = Math.min(selIdx + 1, items.length - 1); updateSel(); }
    else if (ev.key === 'ArrowUp'){ ev.preventDefault(); selIdx = Math.max(selIdx - 1, 0); updateSel(); }
    else if (ev.key === 'Enter' && selIdx >= 0){ ev.preventDefault(); input.value = items[selIdx].value; drop.classList.remove('vis'); if (onSelect) onSelect(items[selIdx]); input.dispatchEvent(new Event('input', { bubbles: true })); }
    else if (ev.key === 'Escape'){ drop.classList.remove('vis'); }
  });

  function updateSel(){
    const els = $$('.ac-item', drop);
    els.forEach((el, i) => el.classList.toggle('sel', i === selIdx));
    if (selIdx >= 0 && els[selIdx]) els[selIdx].scrollIntoView({ block: 'nearest' });
  }

  input.addEventListener('blur', () => { setTimeout(() => drop.classList.remove('vis'), 150); });
  input.addEventListener('focus', () => { if (items.length && input.value.trim().length >= 1) drop.classList.add('vis'); });

  return { destroy(){ clearTimeout(_acTimer); wrap.parentNode?.insertBefore(input, wrap); wrap.remove(); } };
}
function numVal(id, def=0){
  const el = document.getElementById(id);
  const raw = el ? el.value : '';
  const x = Number(raw === '' ? def : raw);
  return Number.isFinite(x) ? x : def;
}

function haptic(ms=10){ try{ navigator?.vibrate?.(ms); }catch{} }

function toast(msg, isErr=false){
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + (isErr ? 'err ' : '') + 'show';
  haptic(isErr ? 30 : 10);
  clearTimeout(toast._tm);
  toast._tm = setTimeout(()=>{ t.className = 'toast hide'; }, 2400);
}

let _modalCloseTimer = null;
let _modalPreviousFocus = null;
function openModal(title, bodyEl){
  // T5-FIX: Cancel any pending close timer to prevent race condition
  // (closeModal sets a 350ms delayed nuke that would destroy this new modal)
  if (_modalCloseTimer){ clearTimeout(_modalCloseTimer); _modalCloseTimer = null; }
  _modalPreviousFocus = document.activeElement;
  $('#modalTitle').textContent = title;
  const mb = $('#modalBody');
  mb.innerHTML = '';
  mb.appendChild(bodyEl);
  const bd = $('#backdrop');
  const md = $('#modal');
  bd.style.display = 'block';
  md.style.display = 'block';
  md.style.transform = '';
  haptic(15);
  requestAnimationFrame(()=>{
    bd.classList.add('vis'); md.classList.add('open');
    // Focus the first focusable element inside the modal
    const focusable = md.querySelector('input:not([type="hidden"]),select,textarea,button,[tabindex]:not([tabindex="-1"])');
    if (focusable) focusable.focus();
    else md.focus();
  });
}
function closeModal(){
  if (_modalCloseTimer){ clearTimeout(_modalCloseTimer); _modalCloseTimer = null; }
  const bd = $('#backdrop');
  const md = $('#modal');
  bd.classList.remove('vis');
  md.classList.remove('open');
  _modalCloseTimer = setTimeout(()=>{ _modalCloseTimer = null; bd.style.display = 'none'; md.style.display = 'none'; $('#modalBody').innerHTML = ''; }, 350);
  // Restore focus to the element that opened the modal
  if (_modalPreviousFocus && typeof _modalPreviousFocus.focus === 'function'){
    try { _modalPreviousFocus.focus(); } catch(e) { /* ignore */ }
    _modalPreviousFocus = null;
  }
}
// Focus trap: keep Tab cycling within modal
$('#modal').addEventListener('keydown', (e)=>{
  if (e.key === 'Escape'){ e.preventDefault(); haptic(); closeModal(); return; }
  if (e.key !== 'Tab') return;
  const md = $('#modal');
  const focusable = md.querySelectorAll('input:not([type="hidden"]),select,textarea,button,[tabindex]:not([tabindex="-1"]),a[href]');
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey){
    if (document.activeElement === first){ e.preventDefault(); last.focus(); }
  } else {
    if (document.activeElement === last){ e.preventDefault(); first.focus(); }
  }
});
// Swipe-to-dismiss modal
(function(){
  const md = $('#modal');
  let startY = 0, currentY = 0, dragging = false;
  md.addEventListener('touchstart', (e)=>{
    if (md.scrollTop > 5) return;
    const t = e.touches[0]; startY = t.clientY; currentY = startY; dragging = true;
  }, {passive:true});
  md.addEventListener('touchmove', (e)=>{
    if (!dragging) return;
    currentY = e.touches[0].clientY;
    const dy = currentY - startY;
    if (dy > 0) md.style.transform = `translateY(${dy}px)`;
  }, {passive:true});
  md.addEventListener('touchend', ()=>{
    if (!dragging) return; dragging = false;
    const dy = currentY - startY;
    if (dy > 120){ closeModal(); }
    else { md.style.transform = ''; md.classList.add('open'); }
  }, {passive:true});
})();
addManagedListener($('#modalClose'), 'click', ()=>{ haptic(); closeModal(); });
addManagedListener($('#backdrop'), 'click', closeModal);

let db = null;

function idbReq(req){
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function initDB(){
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const d = e.target.result;
      const old = e.oldVersion;
      const ensureStore = (name, opts) => { if (!d.objectStoreNames.contains(name)) d.createObjectStore(name, opts); };
      if (old < 1) {
        const tripStore = d.createObjectStore('trips', { keyPath: 'orderNo' });
        tripStore.createIndex('pickupDate', 'pickupDate', { unique: false });
        tripStore.createIndex('created', 'created', { unique: false });
        tripStore.createIndex('customer', 'customer', { unique: false });
        ['fuel','expenses','gpsLogs'].forEach(name => d.createObjectStore(name, { keyPath:'id', autoIncrement:true }));
        d.createObjectStore('settings', { keyPath:'key' });
      }
      if (old < 2) {
        ensureStore('receipts', { keyPath:'tripOrderNo' });
        ensureStore('receiptBlobs', { keyPath:'id' });
      }
      if (old < 3) {
        if (!d.objectStoreNames.contains('auditLog')) {
          const a = d.createObjectStore('auditLog', { keyPath:'id' });
          a.createIndex('timestamp','timestamp',{unique:false});
          a.createIndex('entityId','entityId',{unique:false});
        }
      }
      // Catch-all: ensure stores exist for users upgrading from any version
      ensureStore('settings', { keyPath:'key' });
      ensureStore('receipts', { keyPath:'tripOrderNo' });
      ensureStore('receiptBlobs', { keyPath:'id' });
      ensureStore('auditLog', { keyPath:'id' });
      // v4: Reserved (no schema changes — feature-only release)
      if (old < 4) { /* no-op: schema unchanged */ }
      // v5: Reserved (load scoring engine — no schema changes)
      if (old < 5) { /* no-op: schema unchanged */ }
      // v6: Reserved (broker intelligence — no schema changes)
      if (old < 6) { /* no-op: schema unchanged */ }
      // v7: Add date index on expenses for ranged queries
      if (old < 7) {
        if (d.objectStoreNames.contains('expenses')) {
          const expTxn = e.target.transaction.objectStore('expenses');
          if (!expTxn.indexNames.contains('date')) expTxn.createIndex('date', 'date', { unique: false });
        }
      }
      // v8: Midwest Stack market board
      if (old < 8) {
        if (!d.objectStoreNames.contains('marketBoard')) {
          const mb = d.createObjectStore('marketBoard', { keyPath:'id' });
          mb.createIndex('date','date',{unique:false});
          mb.createIndex('location','location',{unique:false});
        }
      }
      // v9: Add date index on fuel for efficient IFTA date-range queries
      if (old < 9) {
        if (d.objectStoreNames.contains('fuel')) {
          const fuelStore = e.target.transaction.objectStore('fuel');
          if (!fuelStore.indexNames.contains('date')) fuelStore.createIndex('date', 'date', { unique: false });
        }
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => {
      // iOS/Safari IndexedDB can occasionally corrupt; attempt a one-time self-heal.
      try{
        const key = 'fl_idb_recover_v1';
        if (!sessionStorage.getItem(key)){
          sessionStorage.setItem(key,'1');
          try{ indexedDB.deleteDatabase(DB_NAME); }catch(e){ console.warn("[FL]", e); }
          toast('Database issue detected. Recovering…', true);
          setTimeout(()=> location.reload(), 600);
          return;
        }
      }catch(e){ console.warn("[FL]", e); }
      reject(req.error);
    };
    req.onblocked = () => toast('Close other Freight Logic tabs to finish upgrade', true);
  });
}

function tx(storeNames, mode='readonly'){
  const t = db.transaction(storeNames, mode);
  const stores = {};
  for (const n of (Array.isArray(storeNames)? storeNames:[storeNames])) stores[n] = t.objectStore(n);
  return { t, stores };
}
function waitTxn(txn){
  return new Promise((resolve, reject) => {
    txn.oncomplete = () => resolve(true);
    txn.onerror = () => reject(txn.error);
    txn.onabort = () => reject(txn.error || new Error('Transaction aborted'));
  });
}

async function getSetting(key, fallback=null){
  const {stores} = tx('settings');
  const rec = await idbReq(stores.settings.get(key));
  return rec ? rec.value : fallback;
}
async function setSetting(key, value){
  const {t:txn, stores} = tx('settings','readwrite');
  stores.settings.put({ key, value });
  await waitTxn(txn);
  return true;
}

// ---- Trips ----
function normOrderNo(raw){
  return String(raw || '').trim().replace(/\s+/g,' ').replace(/[<>"'`\\]/g,'').slice(0,40);
}

function newTripTemplate(){
  return { orderNo:'', customer:'', pickupDate:isoDate(), deliveryDate:isoDate(),
    origin:'', destination:'', pay:0, loadedMiles:0, emptyMiles:0,
    stops:[], // v14.5.0: multi-stop support [{city, date, type:'stop'|'pickup'|'delivery', notes}]
    notes:'', isPaid:false, paidDate:null, wouldRunAgain:null, created:Date.now(), updated:Date.now() };
}
/** Sanitize a single stop entry */
function sanitizeStop(raw){
  if (!raw || typeof raw !== 'object') return null;
  return {
    city: clampStr(raw.city, 60),
    date: raw.date || '',
    type: ['stop','pickup','delivery'].includes(raw.type) ? raw.type : 'stop',
    notes: clampStr(raw.notes, 200),
  };
}
function sanitizeTrip(raw){
  const t = newTripTemplate();
  t.orderNo = normOrderNo(raw.orderNo);
  t.customer = clampStr(raw.customer, 80);
  t.pickupDate = raw.pickupDate || isoDate();
  t.deliveryDate = raw.deliveryDate || t.pickupDate;
  t.origin = clampStr(raw.origin, 60);
  t.destination = clampStr(raw.destination, 60);
  t.pay = posNum(raw.pay, 0, 1000000);
  t.loadedMiles = posNum(raw.loadedMiles, 0, 300000);
  t.emptyMiles = posNum(raw.emptyMiles, 0, 300000);
  // v14.5.0: multi-stop
  t.stops = Array.isArray(raw.stops) ? raw.stops.slice(0, 10).map(sanitizeStop).filter(Boolean) : [];
  t.notes = clampStr(raw.notes, 500);
  t.isPaid = !!raw.isPaid;
  t.paidDate = raw.paidDate || (t.isPaid ? isoDate() : null);
  t.wouldRunAgain = raw.wouldRunAgain === true ? true : raw.wouldRunAgain === false ? false : null;
  t.created = finiteNum(raw.created, Date.now());
  t.updated = Date.now();
  return t;
}

async function tripExists(orderNo){
  const {stores} = tx('trips');
  return !!(await idbReq(stores.trips.get(orderNo)));
}
async function upsertTrip(trip){
  const t = sanitizeTrip(trip);
  if (!t.orderNo) throw new Error('Order # required');
  validateRecordSize(t, 'Trip');
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['trips','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.trips.get(t.orderNo)); }catch(e){ console.warn("[FL]", e); }
  stores.trips.put(t);
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: t.orderNo, action: beforeData ? 'UPDATE_TRIP' : 'CREATE_TRIP', beforeData: beforeData || null, afterData: t, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(t); txn.onerror = ()=> reject(txn.error); });
}
async function deleteTrip(orderNo){
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['trips','receipts','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.trips.get(orderNo)); }catch(e){ console.warn("[FL]", e); }
  stores.trips.delete(orderNo);
  try{ stores.receipts.delete(orderNo); }catch(e){ console.warn("[FL]", e); }
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: orderNo, action:'DELETE_TRIP', beforeData: beforeData || null, afterData: null, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(true); txn.onerror = ()=> reject(txn.error); });
}
async function listTrips({cursor=null, search='', dateFrom='', dateTo=''}={}){
  const {stores} = tx('trips');
  const idx = stores.trips.index('created');
  const results = [];
  const term = clampStr(search, 80).toUpperCase();
  return new Promise((resolve,reject)=>{
    const range = cursor ? IDBKeyRange.upperBound(cursor, true) : null;
    const req = idx.openCursor(range, 'prev');
    req.onerror = ()=> reject(req.error);
    req.onsuccess = (e)=>{
      const cur = e.target.result;
      if (!cur || results.length >= PAGE_SIZE) {
        resolve({ items: results, nextCursor: results.length ? results[results.length-1].created : null });
        return;
      }
      const v = cur.value;
      // P1-1: date range filtering
      if (dateFrom && (v.pickupDate || '') < dateFrom){ cur.continue(); return; }
      if (dateTo && (v.pickupDate || '') > dateTo){ cur.continue(); return; }
      if (!term) { results.push(v); }
      else {
        const hay = (String(v.orderNo||'')+' '+String(v.customer||'')).toUpperCase();
        if (hay.includes(term)) results.push(v);
      }
      cur.continue();
    };
  });
}

// ---- Expenses ----
function sanitizeExpense(raw){
  return { id: raw.id ? intNum(raw.id, 0, 1e12) : undefined, date: raw.date || isoDate(),
    amount: posNum(raw.amount, 0, 1000000), category: clampStr(raw.category, 60),
    notes: clampStr(raw.notes, 300), created: finiteNum(raw.created, Date.now()),
    updated: Date.now(), type: clampStr(raw.type || 'expense', 20) };
}
async function addExpense(exp){
  const e = sanitizeExpense(exp);
  validateRecordSize(e, 'Expense');
  const {t:txn, stores} = tx(['expenses','auditLog'],'readwrite');
  const req = stores.expenses.add(e);
  return new Promise((resolve,reject)=>{
    req.onerror = ()=> reject(req.error);
    req.onsuccess = ()=>{
      e.id = req.result;
      try{ stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(e.id), action:'CREATE_EXPENSE', beforeData: null, afterData: e, source: 'user' }); }catch(e){ console.warn("[FL]", e); }
    };
    txn.oncomplete = ()=> resolve(e);
    txn.onerror = ()=> reject(txn.error);
    txn.onabort = ()=> reject(txn.error || new Error('Transaction aborted'));
  });
}
async function updateExpense(exp){
  const e = sanitizeExpense(exp);
  if (!e.id) throw new Error('Missing id');
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['expenses','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.expenses.get(e.id)); }catch(e){ console.warn("[FL]", e); }
  stores.expenses.put(e);
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(e.id), action:'UPDATE_EXPENSE', beforeData, afterData: e, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(e); txn.onerror = ()=> reject(txn.error); });
}
async function deleteExpense(id){
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['expenses','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.expenses.get(Number(id))); }catch(e){ console.warn("[FL]", e); }
  stores.expenses.delete(Number(id));
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(id), action:'DELETE_EXPENSE', beforeData, afterData: null, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(true); txn.onerror = ()=> reject(txn.error); });
}
async function listExpenses({cursor=null, search=''}={}){
  const {stores} = tx('expenses');
  const results = [];
  const term = clampStr(search, 80).toUpperCase();
  return new Promise((resolve,reject)=>{
    const req = stores.expenses.openCursor(cursor? IDBKeyRange.upperBound(cursor, true): null, 'prev');
    req.onerror = ()=> reject(req.error);
    req.onsuccess = (e)=>{
      const cur = e.target.result;
      if (!cur || results.length >= PAGE_SIZE) {
        resolve({ items: results, nextCursor: results.length ? results[results.length-1].id : null });
        return;
      }
      const v = cur.value;
      if (!term) results.push(v);
      else { if ((String(v.category||'')+' '+String(v.notes||'')).toUpperCase().includes(term)) results.push(v); }
      cur.continue();
    };
  });
}

// ---- Fuel (P1-3: full CRUD + list) ----
function sanitizeFuel(raw){
  return { id: raw.id ? intNum(raw.id, 0, 1e12) : undefined, date: raw.date || isoDate(),
    gallons: posNum(raw.gallons, 0, 100000), amount: posNum(raw.amount, 0, 1000000),
    state: clampStr(raw.state, 20), notes: clampStr(raw.notes, 200),
    created: finiteNum(raw.created, Date.now()), updated: Date.now() };
}
async function addFuel(f){
  const x = sanitizeFuel(f);
  validateRecordSize(x, 'Fuel');
  const {t:txn, stores} = tx(['fuel','auditLog'],'readwrite');
  const req = stores.fuel.add(x);
  return new Promise((resolve,reject)=>{
    req.onsuccess = ()=> { x.id = req.result; try{ stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(x.id), action:'CREATE_FUEL', beforeData: null, afterData: x, source: 'user' }); }catch(e){ console.warn("[FL]", e); } };
    req.onerror = ()=> reject(req.error);
    txn.oncomplete = ()=> resolve(x);
    txn.onerror = ()=> reject(txn.error);
  });
}
async function updateFuel(f){
  const x = sanitizeFuel(f);
  if (!x.id) throw new Error('Missing id');
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['fuel','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.fuel.get(x.id)); }catch(e){ console.warn("[FL]", e); }
  stores.fuel.put(x);
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(x.id), action:'UPDATE_FUEL', beforeData, afterData: x, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(x); txn.onerror = ()=> reject(txn.error); });
}
async function deleteFuel(id){
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['fuel','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.fuel.get(Number(id))); }catch(e){ console.warn("[FL]", e); }
  stores.fuel.delete(Number(id));
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(id), action:'DELETE_FUEL', beforeData, afterData: null, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(true); txn.onerror = ()=> reject(txn.error); });
}
async function listFuel({cursor=null}={}){
  const {stores} = tx('fuel');
  const results = [];
  return new Promise((resolve,reject)=>{
    const req = stores.fuel.openCursor(cursor? IDBKeyRange.upperBound(cursor, true): null, 'prev');
    req.onerror = ()=> reject(req.error);
    req.onsuccess = (e)=>{
      const cur = e.target.result;
      if (!cur || results.length >= PAGE_SIZE) {
        resolve({ items: results, nextCursor: results.length ? results[results.length-1].id : null });
        return;
      }
      results.push(cur.value);
      cur.continue();
    };
  });
}

// ---- Receipts ----
async function getReceipts(orderNo){ const {stores} = tx('receipts'); return await idbReq(stores.receipts.get(orderNo)); }
async function putReceipts(orderNo, filesArr){
  const {t:txn, stores} = tx('receipts','readwrite');
  stores.receipts.put({ tripOrderNo: orderNo, files: filesArr });
  return new Promise((resolve,reject)=>{ txn.oncomplete=()=>resolve(true); txn.onerror=()=>reject(txn.error); });
}
async function getAllReceipts(){ const {stores} = tx('receipts'); return (await idbReq(stores.receipts.getAll())) || []; }

const RECEIPT_CACHE = 'freightlogic-receipts-v1';
/** P0-3: Sanitize receipt IDs for CacheStorage URL safety — prevent path traversal */
function sanitizeReceiptId(id){
  return String(id || '').replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 60) || 'unknown';
}
function hasCacheStorage(){ try{ return typeof caches !== 'undefined' && caches && typeof caches.open === 'function'; }catch{ return false; } }

async function idbPutReceiptBlob(id, file){
  const safeId = sanitizeReceiptId(id);
  try {
    const {t:txn, stores} = tx('receiptBlobs','readwrite');
    stores.receiptBlobs.put({ id: safeId, blob: file, type: file.type || 'application/octet-stream', added: Date.now() });
    await waitTxn(txn);
  } catch(err) {
    if (err?.name === 'QuotaExceededError' || (err?.message||'').includes('quota')) {
      toast('Storage full — export backup and clear old receipts', true);
    }
    throw err;
  }
}
async function idbGetReceiptBlob(id){
  const {stores} = tx('receiptBlobs');
  const rec = await idbReq(stores.receiptBlobs.get(sanitizeReceiptId(id)));
  if (!rec) return null;
  return { blob: rec.blob, type: rec.type || rec.blob?.type || '' };
}
async function idbDeleteReceiptBlob(id){
  const {t:txn, stores} = tx('receiptBlobs','readwrite');
  stores.receiptBlobs.delete(sanitizeReceiptId(id));
  await waitTxn(txn);
}
async function idbListReceiptBlobMeta(){
  const {stores} = tx('receiptBlobs');
  const all = await idbReq(stores.receiptBlobs.getAll());
  return (all||[]).map(x=>({id:x.id, added:x.added||0})).sort((a,b)=> (a.added||0)-(b.added||0));
}

function randId(){
  if (crypto?.randomUUID) return crypto.randomUUID();
  return 'r_' + Math.random().toString(16).slice(2) + Date.now().toString(16);
}

async function makeThumbDataUrl(file){
  try{
    const type = (file?.type || '').toLowerCase();
    if (type.startsWith('image/')){
      const bmp = await createImageBitmap(file);
      const maxDim = LIMITS.THUMB_MAX_DIM;
      const scale = Math.min(1, maxDim / Math.max(bmp.width, bmp.height));
      const w = Math.max(1, Math.round(bmp.width * scale));
      const h = Math.max(1, Math.round(bmp.height * scale));
      const c = document.createElement('canvas');
      c.width = w; c.height = h;
      c.getContext('2d', { alpha: false }).drawImage(bmp, 0, 0, w, h);
      return c.toDataURL('image/jpeg', LIMITS.THUMB_JPEG_QUALITY);
    }
    const name = clampStr(file?.name || 'Receipt', 18);
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="220"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0B1220"/><stop offset="1" stop-color="#111827"/></linearGradient></defs><rect width="100%" height="100%" rx="18" fill="url(#g)"/><rect x="20" y="20" width="280" height="180" rx="14" fill="rgba(255,255,255,0.06)" stroke="rgba(255,255,255,0.14)"/><text x="40" y="92" font-size="22" fill="rgba(255,255,255,0.9)" font-family="system-ui">PDF</text><text x="40" y="128" font-size="14" fill="rgba(255,255,255,0.7)" font-family="system-ui">${escapeHtml(name)}</text></svg>`;
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  }catch{ return ''; }
}

async function cachePutReceipt(receiptId, file){
  if (!file) return null;
  const safeId = sanitizeReceiptId(receiptId);
  if (hasCacheStorage()){
    const cache = await caches.open(RECEIPT_CACHE);
    const url = new URL(`./__receipt__/${safeId}`, location.href).toString();
    await cache.put(new Request(url, {method:'GET'}), new Response(file, {headers:{'Content-Type': file.type || 'application/octet-stream'}}));
    return url;
  }
  await idbPutReceiptBlob(safeId, file);
  return `idb:receipt:${safeId}`;
}
async function cacheGetReceipt(receiptId){
  const safeId = sanitizeReceiptId(receiptId);
  if (hasCacheStorage()){
    const cache = await caches.open(RECEIPT_CACHE);
    const res = await cache.match(new Request(new URL(`./__receipt__/${safeId}`, location.href).toString(), {method:'GET'}));
    if (!res) return null;
    const blob = await res.blob();
    return { blob, type: res.headers.get('Content-Type') || blob.type || '' };
  }
  return await idbGetReceiptBlob(safeId);
}
async function cacheDeleteReceipt(receiptId){
  const safeId = sanitizeReceiptId(receiptId);
  if (hasCacheStorage()){
    const cache = await caches.open(RECEIPT_CACHE);
    await cache.delete(new Request(new URL(`./__receipt__/${safeId}`, location.href).toString(), {method:'GET'}));
    return;
  }
  await idbDeleteReceiptBlob(safeId);
}
let _evictLock = false;
async function enforceReceiptCacheLimit(){
  if (_evictLock) return;
  _evictLock = true;
  try{
    const max = LIMITS.MAX_RECEIPT_CACHE;
    if (hasCacheStorage()){
      const cache = await caches.open(RECEIPT_CACHE);
      const keys = await cache.keys();
      if (keys.length <= max) return;
      const allMeta = [];
      const receiptsAll = await getAllReceipts();
      for (const r of receiptsAll) for (const f of (r.files||[])) if (f?.id && f.cached) allMeta.push({ id:f.id, added:f.added||0, tripOrderNo:r.tripOrderNo });
      allMeta.sort((a,b)=> (a.added||0)-(b.added||0));
      for (const e of allMeta.slice(0, Math.max(0, allMeta.length - max))){
        await cacheDeleteReceipt(e.id);
        const rec = await getReceipts(e.tripOrderNo);
        if (rec?.files?.length){
          let changed = false;
          rec.files = rec.files.map(x => { if (x?.id === e.id && x.cached){ changed = true; return Object.assign({}, x, { cached: false }); } return x; });
          if (changed) await putReceipts(e.tripOrderNo, rec.files);
        }
      }
      return;
    }
    const all = await idbListReceiptBlobMeta();
    if (all.length <= max) return;
    const receiptsAll = await getAllReceipts();
    for (const e of all.slice(0, Math.max(0, all.length - max))){
      await idbDeleteReceiptBlob(e.id);
      for (const r of receiptsAll){
        if (!r?.files?.length) continue;
        let changed = false;
        r.files = r.files.map(x=>{ if (x?.id === e.id && x.cached){ changed = true; return Object.assign({}, x, { cached:false }); } return x; });
        if (changed) await putReceipts(r.tripOrderNo, r.files);
      }
    }
  }catch(e){ console.warn("[FL]", e); }
  finally { _evictLock = false; }
}

// ---- Export / Import (P0-3: includes auditLog + sanitization) ----
async function dumpStore(name){
  const {stores} = tx(name);
  const out = [];
  return new Promise((resolve,reject)=>{
    const req = stores[name].openCursor();
    req.onerror = ()=> reject(req.error);
    req.onsuccess = (e)=>{ const cur = e.target.result; if (!cur){ resolve(out); return; } out.push(cur.value); cur.continue(); };
  });
}
/** P1-5: SHA-256 checksum for export integrity */
async function computeExportChecksum(trips, expenses, fuel){
  const raw = JSON.stringify({ trips, expenses, fuel });
  const buf = new TextEncoder().encode(raw);
  try {
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
  } catch {
    // Fallback: simple FNV-1a 32-bit hash for environments without SubtleCrypto
    let h = 0x811c9dc5;
    for (let i = 0; i < raw.length; i++) { h ^= raw.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return 'fnv1a-' + (h >>> 0).toString(16).padStart(8, '0');
  }
}

async function exportJSON(){
  const trips = await dumpStore('trips');
  const expenses = await dumpStore('expenses');
  const fuel = await dumpStore('fuel');
  const checksum = await computeExportChecksum(trips, expenses, fuel);
  const payload = {
    meta: { app: 'Freight Logic', version: APP_VERSION, exportedAt: new Date().toISOString(), checksum, recordCounts: { trips: trips.length, expenses: expenses.length, fuel: fuel.length } },
    trips,
    expenses,
    fuel,
    receipts: await dumpStore('receipts'),
    settings: await dumpStore('settings'),
    auditLog: await dumpStore('auditLog'),
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `freight-logic-export-${isoDate()}.json`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=> URL.revokeObjectURL(a.href), 1500);
  // P3-4: track last export date
  await setSetting('lastExportDate', isoDate());
  await markBackupDone();
  toast('Export saved (integrity-verified)');
}

// P1-2: CSV export
function downloadCSV(rows, filename){
  const bom = '\uFEFF';
  const csv = bom + rows.map(r => r.map(c => `"${csvSafeCell(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=> URL.revokeObjectURL(a.href), 1500);
}
async function exportTripsCSV(){
  const trips = await dumpStore('trips');
  const header = ['Order#','Customer','Pickup','Delivery','Origin','Destination','Stops','Pay','LoadedMiles','EmptyMiles','AllMiles','RPM','Paid','PaidDate','WouldRunAgain','Notes'];
  const rows = [header, ...trips.map(t => {
    const all = (Number(t.loadedMiles||0) + Number(t.emptyMiles||0));
    const rpm = all > 0 ? (Number(t.pay||0)/all).toFixed(2) : '0';
    const stopsStr = Array.isArray(t.stops) ? t.stops.map(s => `${s.city||''}(${s.type||'stop'})`).join('; ') : '';
    return [t.orderNo, t.customer, t.pickupDate, t.deliveryDate, t.origin, t.destination, stopsStr, t.pay, t.loadedMiles, t.emptyMiles, all, rpm, t.isPaid?'Yes':'No', t.paidDate||'', t.wouldRunAgain?'Yes':'', t.notes];
  })];
  downloadCSV(rows, `freight-logic-trips-${isoDate()}.csv`);
  toast('CSV exported');
}
async function exportExpensesCSV(){
  const exps = await dumpStore('expenses');
  const header = ['Date','Amount','Category','Notes','Type'];
  const rows = [header, ...exps.map(e => [e.date, e.amount, e.category, e.notes, e.type])];
  downloadCSV(rows, `freight-logic-expenses-${isoDate()}.csv`);
  toast('CSV exported');
}
async function exportFuelCSV(){
  const fuel = await dumpStore('fuel');
  const header = ['Date','Gallons','Amount','PricePerGal','State','Notes'];
  const rows = [header, ...fuel.map(f => [f.date, f.gallons, f.amount, f.gallons>0?(f.amount/f.gallons).toFixed(3):'0', f.state, f.notes])];
  downloadCSV(rows, `freight-logic-fuel-${isoDate()}.csv`);
  toast('CSV exported');
}

async function importJSON(file){
  try{
    if (file?.size && file.size > LIMITS.MAX_IMPORT_BYTES){ toast(`Import too large`, true); return; }
    const data = deepCleanObj(JSON.parse(await file.text()));
    const arr = (x)=> Array.isArray(x) ? x : [];

    // P1-5: Verify export integrity checksum
    if (data.meta?.checksum){
      try {
        const verify = await computeExportChecksum(arr(data.trips), arr(data.expenses), arr(data.fuel));
        if (verify !== data.meta.checksum){
          const proceed = confirm('⚠️ INTEGRITY WARNING\n\nThis export file has been modified since it was created. Data may have been tampered with.\n\nTrips expected: ' + (data.meta.recordCounts?.trips ?? '?') + ', found: ' + arr(data.trips).length + '\nExpenses expected: ' + (data.meta.recordCounts?.expenses ?? '?') + ', found: ' + arr(data.expenses).length + '\n\nImport anyway?');
          if (!proceed){ toast('Import cancelled — integrity check failed', true); return; }
        }
      } catch(e){ console.warn("[FL]", e); }
    }
    const safeTripArr = arr(data.trips).map(t => { try { return sanitizeTrip(t); } catch { return null; } }).filter(Boolean);
    const safeExpArr = arr(data.expenses).map(e => { try { return sanitizeExpense(e); } catch { return null; } }).filter(Boolean);
    const safeFuelArr = arr(data.fuel).map(f => { try { return sanitizeFuel(f); } catch { return null; } }).filter(Boolean);
    const safeReceiptArr = arr(data.receipts).filter(r => r && typeof r === 'object' && typeof r.tripOrderNo === 'string' && Array.isArray(r.files)).map(r => ({
      tripOrderNo: normOrderNo(r.tripOrderNo),
      files: r.files.slice(0, LIMITS.MAX_RECEIPTS_PER_TRIP).filter(f => f && typeof f === 'object').map(f => ({
        id: String(f.id || '').replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 60) || randId(),
        name: clampStr(f.name, 120),
        type: /^(image\/(jpeg|png|gif|webp|heic|heif)|application\/pdf)$/.test(f.type) ? f.type : 'application/octet-stream',
        size: Math.max(0, Math.min(Number(f.size || 0), LIMITS.MAX_RECEIPT_BYTES)),
        added: Number(f.added || Date.now()),
        thumbDataUrl: (typeof f.thumbDataUrl === 'string' && f.thumbDataUrl.length <= 200000) ? f.thumbDataUrl : '',
        cached: false, status: 'imported'
      }))
    }));
    const ALLOWED_SETTINGS_KEYS = new Set(['uiMode','perDiemRate','brokerWindow','weeklyGoal','iftaMode','omegaLastInputs','lastExportDate','vehicleMpg','fuelPrice','weeklyReflection','mwLastInputs','mwLastTab','opCostPerMile','homeLocation','lastBackupDate','datApiEnabled','datApiBaseUrl','mwMode','cloudBackupUrl','cloudBackupPass','cloudBackupToken','lastCloudSync','vehicleClass','canadaEnabled','cadUsdRate','borderAdminCost','canadaDocsReady','scoreWeights']);
    // T5-FIX: Validate settings value types and cap size
    const safeSettingsArr = arr(data.settings).filter(s => s && typeof s === 'object' && typeof s.key === 'string' && ALLOWED_SETTINGS_KEYS.has(s.key) && JSON.stringify(s.value ?? '').length < 50000).map(s => ({
      key: s.key, value: typeof s.value === 'object' && s.value !== null ? deepCleanObj(JSON.parse(JSON.stringify(s.value))) : s.value
    }));
    // P0-3: auditLog sanitization
    const safeAuditArr = arr(data.auditLog).filter(a => a && typeof a === 'object' && typeof a.id === 'string' && typeof a.timestamp === 'number' && typeof a.action === 'string').map(a => ({
      id: clampStr(a.id, 60), timestamp: Number(a.timestamp), entityId: clampStr(a.entityId || '', 60),
      action: clampStr(a.action, 30), data: a.data && typeof a.data === 'object' ? deepCleanObj(JSON.parse(JSON.stringify(a.data))) : undefined
    }));

    const {t:txn, stores} = tx(['trips','expenses','fuel','receipts','settings','auditLog'],'readwrite');
    const putAll = (store, a) => (a||[]).forEach(x => { try{ store.put(x); }catch(e){ console.warn("[FL]", e); } });
    putAll(stores.trips, safeTripArr);
    putAll(stores.expenses, safeExpArr);
    putAll(stores.fuel, safeFuelArr);
    putAll(stores.receipts, safeReceiptArr);
    putAll(stores.settings, safeSettingsArr);
    putAll(stores.auditLog, safeAuditArr);
    await waitTxn(txn);
    toast('Import complete');
  }catch(err){ toast('Import failed (invalid JSON or corrupted export).', true); }
}

// ---- CSV Import (auto-detects trips / expenses / fuel) ----
function parseCSVText(text){
  // Fast path for small CSVs
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (!lines.length) return [];
  if (lines.length <= 4000) return parseCSVLines(lines);
  // Large files: keep memory stable by delegating to async parser
  return null;
}
function parseCSVLines(lines){
  const result = [];
  for (const line of lines){
    const row = []; let cell = ''; let inQuote = false;
    for (let i = 0; i < line.length; i++){
      const ch = line[i];
      if (inQuote){
        if (ch === '"' && line[i+1] === '"'){ cell += '"'; i++; }
        else if (ch === '"') inQuote = false;
        else cell += ch;
      } else {
        if (ch === '"') inQuote = true;
        else if (ch === ','){ row.push(cell.trim()); cell = ''; }
        else cell += ch;
      }
    }
    row.push(cell.trim());
    result.push(row);
  }
  return result;
}
async function parseCSVTextAsync(text){
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (!lines.length) return [];
  const result = [];
  let n = 0;
  for (const line of lines){
    const row = []; let cell = ''; let inQuote = false;
    for (let i = 0; i < line.length; i++){
      const ch = line[i];
      if (inQuote){
        if (ch === '"' && line[i+1] === '"'){ cell += '"'; i++; }
        else if (ch === '"') inQuote = false;
        else cell += ch;
      } else {
        if (ch === '"') inQuote = true;
        else if (ch === ','){ row.push(cell.trim()); cell = ''; }
        else cell += ch;
      }
    }
    row.push(cell.trim());
    result.push(row);
    n++;
    if ((n % 750) === 0) await new Promise(r => setTimeout(r, 0));
  }
  return result;
}


function normalizeHeader(h){ return String(h||'').toLowerCase().replace(/[^a-z0-9]/g,''); }

async function importCSVFile(file){
  try{
    if (file?.size && file.size > LIMITS.MAX_IMPORT_BYTES){ toast('File too large', true); return; }
    const text = await file.text();
    // Strip BOM
    const clean = text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
    let rows = parseCSVText(clean);
    if (!rows) rows = await parseCSVTextAsync(clean);
    if (rows.length < 2){ toast('CSV has no data rows', true); return; }

    const headers = rows[0].map(normalizeHeader);
    const data = rows.slice(1);

    // Auto-detect type by header signatures
    const hasOrder = headers.some(h => ['order','orderno','ordernum','ordernumber','loadid','load'].includes(h));
    const hasPay = headers.some(h => ['pay','revenue','rate','linehaul','amount','total'].includes(h));
    const hasMiles = headers.some(h => ['loadedmiles','miles','loaded','totalmiles','allmiles'].includes(h));
    const hasGallons = headers.some(h => ['gallons','gal','gallonsqty','qty'].includes(h));
    const hasCategory = headers.some(h => ['category','cat','type','expensetype'].includes(h));
    const hasState = headers.some(h => ['state','st','fuelstate'].includes(h));

    let type = 'unknown';
    if (hasGallons || (hasState && !hasMiles)) type = 'fuel';
    else if (hasOrder || hasMiles) type = 'trips';
    else if (hasCategory || (hasPay && !hasMiles && !hasOrder)) type = 'expenses';

    if (type === 'unknown'){
      toast('Could not detect CSV type. Expected trip, expense, or fuel columns.', true);
      return;
    }

    // Column index finder — tries multiple aliases
    function col(...aliases){
      for (const a of aliases){
        const idx = headers.indexOf(normalizeHeader(a));
        if (idx >= 0) return idx;
      }
      return -1;
    }
    function cellAt(row, ...aliases){
      const i = col(...aliases);
      return i >= 0 && i < row.length ? sanitizeImportValue(row[i]) : '';
    }

    let imported = 0;

    if (type === 'trips'){
      const {t:txn, stores} = tx(['trips','auditLog'],'readwrite');
      for (const row of data){
        try{
          const orderNo = cellAt(row, 'Order#','OrderNo','Order','LoadID','Load') || `CSV-${Date.now()}-${Math.random().toString(36).slice(2,6)}`;
          const trip = sanitizeTrip({
            orderNo,
            customer: cellAt(row, 'Customer','Broker','Carrier','Shipper'),
            pickupDate: cellAt(row, 'Pickup','PickupDate','Date','ShipDate') || isoDate(),
            deliveryDate: cellAt(row, 'Delivery','DeliveryDate','DropDate') || '',
            origin: cellAt(row, 'Origin','PickupCity','From','OriginCity'),
            destination: cellAt(row, 'Destination','DropCity','To','DestCity','Dest'),
            pay: Number(cellAt(row, 'Pay','Revenue','Rate','LineHaul','Amount','Total').replace(/[$,]/g,'') || 0),
            loadedMiles: Number(cellAt(row, 'LoadedMiles','Loaded','Miles','LoadMiles').replace(/[,]/g,'') || 0),
            emptyMiles: Number(cellAt(row, 'EmptyMiles','Empty','Deadhead','DeadheadMiles','DH').replace(/[,]/g,'') || 0),
            notes: cellAt(row, 'Notes','Note','Comments','Memo'),
            isPaid: ['yes','true','paid','1'].includes(cellAt(row, 'Paid','IsPaid','Status').toLowerCase()),
            paidDate: cellAt(row, 'PaidDate','PayDate','PaymentDate') || null,
            wouldRunAgain: ['yes','true','1'].includes(cellAt(row, 'WouldRunAgain','RunAgain','Repeat').toLowerCase()) ? true : null,
          });
          if (trip.orderNo) { stores.trips.put(trip); imported++; }
        }catch(e){ console.warn("[FL]", e); }
      }
      await waitTxn(txn);
      toast(`Imported ${imported} trip${imported!==1?'s':''} from CSV`);
      invalidateKPICache();
      await renderTrips(true); await renderHome();

    } else if (type === 'expenses'){
      const {t:txn, stores} = tx('expenses','readwrite');
      for (const row of data){
        try{
          const exp = sanitizeExpense({
            date: cellAt(row, 'Date','ExpDate','ExpenseDate') || isoDate(),
            amount: Number(cellAt(row, 'Amount','Cost','Total','Price').replace(/[$,]/g,'') || 0),
            category: cellAt(row, 'Category','Cat','Type','ExpenseType') || 'Other',
            notes: cellAt(row, 'Notes','Note','Description','Memo','Details'),
            type: cellAt(row, 'Type','ExpType') || '',
          });
          if (exp.amount > 0) { stores.expenses.put(exp); imported++; }
        }catch(e){ console.warn("[FL]", e); }
      }
      await waitTxn(txn);
      toast(`Imported ${imported} expense${imported!==1?'s':''} from CSV`);
      invalidateKPICache();
      await renderExpenses(true); await renderHome();

    } else if (type === 'fuel'){
      const {t:txn, stores} = tx('fuel','readwrite');
      for (const row of data){
        try{
          const fuel = sanitizeFuel({
            date: cellAt(row, 'Date','FuelDate','FillDate') || isoDate(),
            gallons: Number(cellAt(row, 'Gallons','Gal','Qty','GallonsQty').replace(/[,]/g,'') || 0),
            amount: Number(cellAt(row, 'Amount','Cost','Total','Price').replace(/[$,]/g,'') || 0),
            state: cellAt(row, 'State','ST','FuelState','Location') || '',
            notes: cellAt(row, 'Notes','Note','Memo') || '',
          });
          if (fuel.gallons > 0 || fuel.amount > 0) { stores.fuel.put(fuel); imported++; }
        }catch(e){ console.warn("[FL]", e); }
      }
      await waitTxn(txn);
      toast(`Imported ${imported} fuel entr${imported!==1?'ies':'y'} from CSV`);
      invalidateKPICache();
      await renderFuel(true); await renderHome();
    }
  }catch(err){ console.error('[FL] CSV import error:', err); toast('CSV import failed. Check file format.', true); }
}

async function importFile(file){
  if (!file) return;
  try {
  const name = (file.name || '').toLowerCase();
  if (name.endsWith('.csv') || name.endsWith('.tsv') || file.type === 'text/csv'){
    await importCSVFile(file);
  } else if (name.endsWith('.xlsx') || name.endsWith('.xls') || file.type === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'){
    await importXLSXFile(file);
  } else if (name.endsWith('.txt') || file.type === 'text/plain'){
    await importTXTFile(file);
  } else if (name.endsWith('.pdf') || file.type === 'application/pdf'){
    await importPDFFile(file);
  } else {
    await importJSON(file);
  }
  invalidateKPICache();
  await renderHome();
  } catch(err) { console.error('[FL] Import error:', err); toast('Import failed. Check file format.', true); }
}

// ---- XLSX Import (uses SheetJS from CDN — version-pinned + SRI-ready) ----
// SECURITY: Generate SRI hash via: curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A
// Then set s.integrity = 'sha384-<hash>';
async function loadScriptWithFallback(urls, validate, finalError){
  let lastErr = null;
  for (const url of urls){
    try {
      await new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = url;
        if (/^https?:/i.test(url)) s.crossOrigin = 'anonymous';
        s.onload = () => {
          try {
            validate();
            resolve();
          } catch (err){
            reject(err);
          }
        };
        s.onerror = () => reject(new Error(`Failed to load script: ${url}`));
        document.head.appendChild(s);
      });
      return;
    } catch (err){
      lastErr = err;
    }
  }
  throw new Error(finalError + (lastErr ? ` (${lastErr.message})` : ''));
}

async function loadSheetJS(){
  if (typeof XLSX !== 'undefined') return;
  await loadScriptWithFallback([
    './vendor/xlsx.full.min.js',
    'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js',
  ], () => {
    if (typeof XLSX === 'undefined' || typeof XLSX.read !== 'function'){
      throw new Error('SheetJS loaded but XLSX.read missing — possible CDN tampering');
    }
  }, 'Failed to load SheetJS — local vendor file missing and CDN unavailable');
}

async function importXLSXFile(file){
  try{
    toast('Loading Excel parser...');
    await loadSheetJS();
    const data = await file.arrayBuffer();
    const wb = XLSX.read(data, { type:'array' });
    if (!wb.SheetNames.length){ toast('Empty workbook', true); return; }
    // Use first sheet
    const ws = wb.Sheets[wb.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(ws, { header:1, raw:false, defval:'' });
    if (rows.length < 2){ toast('Sheet has no data rows', true); return; }
    // Convert to CSV text and re-import through CSV logic
    const csvText = rows.map(r => r.map(c => `"${String(c||'').replace(/"/g,'""')}"`).join(',')).join('\n');
    const fakeFile = new File([csvText], 'import.csv', { type:'text/csv' });
    await importCSVFile(fakeFile);
  }catch(err){ console.error('[FL] Excel import error:', err); toast('Excel import failed. Check file format.', true); }
}

// ---- TXT Import (auto-detect delimiter) ----
async function importTXTFile(file){
  try{
    let text = await file.text();
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    // Detect delimiter: tab > pipe > comma > space
    const firstLine = text.split(/\r?\n/)[0] || '';
    let delimiter = ',';
    if (firstLine.split('\t').length >= 3) delimiter = '\t';
    else if (firstLine.split('|').length >= 3) delimiter = '|';
    // Replace delimiter with comma for CSV parser
    if (delimiter !== ','){
      const lines = text.split(/\r?\n/);
      text = lines.map(l => l.split(delimiter).map(c => `"${c.trim().replace(/"/g,'""')}"`).join(',')).join('\n');
    }
    const fakeFile = new File([text], 'import.csv', { type:'text/csv' });
    await importCSVFile(fakeFile);
  }catch(err){ console.error('[FL] TXT import error:', err); toast('Text import failed. Check file format.', true); }
}

// ---- PDF Import (routes to Snap Load OCR) ----
async function importPDFFile(file){
  toast('PDF detected — opening Snap Load OCR to extract data...');
  setTimeout(()=> openSnapLoad(file), 300);
}

// ---- Universal Import Modal ----
function openUniversalImport(){
  haptic(20);
  const body = document.createElement('div');
  body.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <div class="muted" style="font-size:13px;margin-bottom:16px;line-height:1.5">Pick a file and we'll figure out what's in it. Supports trips, expenses, and fuel data.</div>
    <div style="display:flex;flex-direction:column;gap:10px">
      <button class="btn primary imp-btn" data-accept=".csv,.tsv" style="padding:16px;font-size:15px;text-align:left">📄 CSV or TSV file</button>
      <button class="btn primary imp-btn" data-accept=".xlsx,.xls" style="padding:16px;font-size:15px;text-align:left">📊 Excel spreadsheet (.xlsx)</button>
      <button class="btn primary imp-btn" data-accept=".json" style="padding:16px;font-size:15px;text-align:left">🔒 Freight Logic backup (.json)</button>
      <button class="btn imp-btn" data-accept=".pdf,application/pdf" style="padding:16px;font-size:15px;text-align:left">📸 Rate confirmation (PDF) — uses OCR</button>
      <button class="btn imp-btn" data-accept=".txt" style="padding:16px;font-size:15px;text-align:left">📝 Plain text file (.txt)</button>
      <button class="btn primary imp-btn" data-accept="${IMPORT_ACCEPT}" style="padding:16px;font-size:15px;text-align:left;border-color:var(--accent)">📂 Any file — auto-detect type</button>
    </div>
    <div class="muted" style="font-size:11px;margin-top:14px;line-height:1.4">CSV/Excel: auto-detects trips vs expenses vs fuel by column headers.<br>PDF: extracts text via OCR and prefills a trip.</div>
  </div>`;

  body.querySelectorAll('.imp-btn').forEach(btn => {
    btn.addEventListener('click', async ()=>{
      haptic(10);
      const f = await pickFile(btn.dataset.accept);
      if (f){ closeModal(); await importFile(f); }
    });
  });

  openModal('📥 Import Data', body);
}

// ---- Analytics (P0-1: targeted queries instead of dumpStore) ----
function startOfWeek(d=new Date()){
  const x = new Date(d); const day = x.getDay();
  x.setDate(x.getDate() + ((day === 0 ? -6 : 1) - day));
  x.setHours(0,0,0,0); return x;
}
function startOfMonth(d=new Date()){ const x = new Date(d); x.setDate(1); x.setHours(0,0,0,0); return x; }
function startOfQuarter(d=new Date()){
  const x = new Date(d); const q = Math.floor(x.getMonth()/3)*3;
  x.setMonth(q, 1); x.setHours(0,0,0,0); return x;
}
function startOfYear(d=new Date()){ const x = new Date(d); x.setMonth(0,1); x.setHours(0,0,0,0); return x; }

let _kpiCache = { trips:null, exps:null, ts:0 };
const KPI_TTL = 120000; // 2 minute cache for full dump (was 15s)

async function _getTripsAndExps(){
  const now = Date.now();
  if (_kpiCache.trips && _kpiCache.exps && (now - _kpiCache.ts) < KPI_TTL) return _kpiCache;
  const trips = await dumpStore('trips');
  const exps = await dumpStore('expenses');
  _kpiCache = { trips, exps, ts: now };
  return _kpiCache;
}
function invalidateKPICache(){ _kpiCache.ts = 0; cloudScheduleSync(); }

// ── P1-6: Indexed range queries for fast KPI refresh ──
async function queryTripsByPickupRange(fromISO, toISO){
  const {stores} = tx('trips');
  const idx = stores.trips.index('pickupDate');
  let range;
  if (fromISO && toISO) range = IDBKeyRange.bound(fromISO, toISO);
  else if (fromISO) range = IDBKeyRange.lowerBound(fromISO);
  else if (toISO) range = IDBKeyRange.upperBound(toISO);
  else range = null;
  const results = [];
  return new Promise((resolve, reject) => {
    const req = idx.openCursor(range);
    req.onerror = () => reject(req.error);
    req.onsuccess = (e) => {
      const cur = e.target.result;
      if (!cur) { resolve(results); return; }
      results.push(cur.value);
      cur.continue();
    };
  });
}
async function queryExpensesByDateRange(fromISO, toISO){
  const {stores} = tx('expenses');
  // Use date index if available (v7+), else fall back to full scan
  let idx;
  try { idx = stores.expenses.index('date'); } catch { return (await dumpStore('expenses')).filter(e => { const d = e.date || ''; return (!fromISO || d >= fromISO) && (!toISO || d <= toISO); }); }
  let range;
  if (fromISO && toISO) range = IDBKeyRange.bound(fromISO, toISO);
  else if (fromISO) range = IDBKeyRange.lowerBound(fromISO);
  else if (toISO) range = IDBKeyRange.upperBound(toISO);
  else range = null;
  const results = [];
  return new Promise((resolve, reject) => {
    const req = idx.openCursor(range);
    req.onerror = () => reject(req.error);
    req.onsuccess = (e) => {
      const cur = e.target.result;
      if (!cur) { resolve(results); return; }
      results.push(cur.value);
      cur.continue();
    };
  });
}
async function queryUnpaidTotal(){
  const {stores} = tx('trips');
  let total = 0;
  return new Promise((resolve, reject) => {
    const req = stores.trips.openCursor();
    req.onerror = () => reject(req.error);
    req.onsuccess = (e) => {
      const cur = e.target.result;
      if (!cur) { resolve(total); return; }
      if (!cur.value.isPaid) total += Number(cur.value.pay || 0);
      cur.continue();
    };
  });
}

/** Fast KPI refresh — indexed queries only, no full dump. Used for 60s interval. */
async function computeQuickKPIs(){
  try {
    const today = isoDate();
    const wkStartISO = isoDate(startOfWeek(new Date()));

    // Indexed queries: only fetch what we need
    const [wkTrips, wkExps, todayTrips, todayExps, unpaid] = await Promise.all([
      queryTripsByPickupRange(wkStartISO, null),
      queryExpensesByDateRange(wkStartISO, null),
      queryTripsByPickupRange(today, today),
      queryExpensesByDateRange(today, today),
      queryUnpaidTotal()
    ]);

    let todayGross = 0, todayExp = 0, wkGross = 0, wkExp = 0, wkLoaded = 0, wkEmpty = 0;
    for (const t of todayTrips) todayGross += Number(t.pay || 0);
    for (const e of todayExps) todayExp += Number(e.amount || 0);
    for (const t of wkTrips){ wkGross += Number(t.pay||0); wkLoaded += Number(t.loadedMiles||0); wkEmpty += Number(t.emptyMiles||0); }
    for (const e of wkExps) wkExp += Number(e.amount || 0);

    const todayNet = todayGross - todayExp;
    const wkNet = wkGross - wkExp;
    const wkAll = wkLoaded + wkEmpty;
    const wkRpm = wkAll > 0 ? wkGross / wkAll : 0;
    const deadheadPct = wkAll > 0 ? ((wkEmpty / wkAll) * 100) : 0;

    $('#kpiTodayGross').textContent = fmtMoney(todayGross);
    $('#kpiTodayExp').textContent = fmtMoney(todayExp);
    $('#kpiTodayNet').textContent = fmtMoney(todayNet);
    const wkNetEl = $('#kpiWeekNet'); const prevNet = wkNetEl.textContent;
    wkNetEl.textContent = fmtMoney(wkNet);
    if (prevNet !== wkNetEl.textContent && prevNet !== '—') pulseKPI($('#pillWeekNet'));
    const unpEl = $('#kpiUnpaid'); const prevUnp = unpEl.textContent;
    unpEl.textContent = fmtMoney(unpaid);
    if (prevUnp !== unpEl.textContent && prevUnp !== '—') pulseKPI($('#pillUnpaid'));
    $('#wkGross').textContent = fmtMoney(wkGross);
    $('#wkExp').textContent = fmtMoney(wkExp);
    $('#wkNet').textContent = fmtMoney(wkNet);
    $('#wkLoaded').textContent = fmtNum(wkLoaded);
    $('#wkAll').textContent = fmtNum(wkAll);
    $('#wkRpm').textContent = `$${wkRpm.toFixed(2)}`;
    const dhEl = $('#wkDeadhead');
    const dhPill = $('#deadheadPill');
    if (dhEl) dhEl.textContent = `${deadheadPct.toFixed(1)}%`;
    if (dhPill) dhPill.className = deadheadPct > 30 ? 'pill danger' : deadheadPct > 20 ? 'pill warn' : 'pill';
  } catch(e){ console.warn("[FL]", e); }
}

async function computeKPIs(){
  const { trips, exps } = await _getTripsAndExps();
  const today = isoDate();
  const wk0 = startOfWeek(new Date()).getTime();

  let todayGross=0, todayExp=0, wkGross=0, wkExp=0, wkLoaded=0, wkEmpty=0, unpaid=0;

  for (const t of trips){
    const pay = Number(t.pay||0);
    const loaded = Number(t.loadedMiles||0);
    const empty = Number(t.emptyMiles||0);
    const dt = t.pickupDate || t.deliveryDate || '';
    if (dt === today) todayGross += pay;
    const ts = new Date(dt || Date.now()).getTime();
    if (ts >= wk0){ wkGross += pay; wkLoaded += loaded; wkEmpty += empty; }
    if (!t.isPaid) unpaid += pay;
  }
  for (const e of exps){
    const amt = Number(e.amount||0);
    const dt = e.date || '';
    if (dt === today) todayExp += amt;
    if (new Date(dt || Date.now()).getTime() >= wk0) wkExp += amt;
  }
  const todayNet = todayGross - todayExp;
  const wkNet = wkGross - wkExp;
  const wkAll = wkLoaded + wkEmpty;
  const wkRpm = wkAll > 0 ? wkGross / wkAll : 0;
  // P3-3: deadhead
  const deadheadPct = wkAll > 0 ? ((wkEmpty / wkAll) * 100) : 0;

  $('#kpiTodayGross').textContent = fmtMoney(todayGross);
  $('#kpiTodayExp').textContent = fmtMoney(todayExp);
  $('#kpiTodayNet').textContent = fmtMoney(todayNet);
  const wkNetEl = $('#kpiWeekNet'); const prevNet = wkNetEl.textContent;
  wkNetEl.textContent = fmtMoney(wkNet);
  if (prevNet !== wkNetEl.textContent && prevNet !== '—') pulseKPI($('#pillWeekNet'));
  const unpEl = $('#kpiUnpaid'); const prevUnp = unpEl.textContent;
  unpEl.textContent = fmtMoney(unpaid);
  if (prevUnp !== unpEl.textContent && prevUnp !== '—') pulseKPI($('#pillUnpaid'));
  $('#wkGross').textContent = fmtMoney(wkGross);
  $('#wkExp').textContent = fmtMoney(wkExp);
  $('#wkNet').textContent = fmtMoney(wkNet);
  $('#wkLoaded').textContent = fmtNum(wkLoaded);
  $('#wkAll').textContent = fmtNum(wkAll);
  $('#wkRpm').textContent = `$${wkRpm.toFixed(2)}`;

  // P3-3: deadhead display with alerts
  const dhEl = $('#wkDeadhead');
  const dhPill = $('#deadheadPill');
  dhEl.textContent = `${deadheadPct.toFixed(1)}%`;
  dhPill.className = deadheadPct > 30 ? 'pill danger' : deadheadPct > 20 ? 'pill warn' : 'pill';

  // AR aging + broker
  const aging = computeARAging(trips, today);
  if ($('#ar0_15')){
    $('#ar0_15').textContent = fmtMoney(aging.b0_15);
    $('#ar16_30').textContent = fmtMoney(aging.b16_30);
    $('#ar31_45').textContent = fmtMoney(aging.b31_45);
    $('#ar46p').textContent = fmtMoney(aging.b46p);
  }
  const brokerDays = Number(await getSetting('brokerWindow', 90) || 90);
  const brokers = computeBrokerStats(trips, today, brokerDays);
  const bwl = $('#brokerWindowLabel');
  if (bwl) bwl.textContent = brokerDays > 0 ? `(last ${brokerDays}d)` : '(all time)';
  if ($('#brokerList')){
    const box = $('#brokerList');
    box.innerHTML = '';
    const top = brokers.slice(0,6);
    // Global avg RPM for grading
    const globalMiles = brokers.reduce((s,b)=> s + b.miles, 0);
    const globalPay = brokers.reduce((s,b)=> s + b.pay, 0);
    const globalAvgRpm = globalMiles > 0 ? globalPay / globalMiles : 0;
    if (!top.length){ box.innerHTML = `<div class="muted" style="font-size:12px">No broker history yet.</div>`; }
    else { top.forEach(b => {
      const gradeObj = computeBrokerGrade(b, globalAvgRpm);
      const el = document.createElement('div'); el.className = 'item'; el.style.cursor = 'pointer';
      const dtp = (b.avgDtp===null) ? '—' : `${Math.round(b.avgDtp)}d`;
      const left = document.createElement('div'); left.className = 'left';
      const nd = document.createElement('div'); nd.className = 'v';
      nd.innerHTML = `<span style="display:inline-flex;align-items:center;gap:8px">${brokerGradeHTML(gradeObj)} ${escapeHtml(b.name)}</span>`;
      const sd = document.createElement('div'); sd.className = 'sub'; sd.textContent = `Trips: ${b.trips} • RPM: $${b.avgRpm.toFixed(2)} • Pay: ${dtp}`;
      left.appendChild(nd); left.appendChild(sd);
      const right = document.createElement('div'); right.className = 'right';
      const ud = document.createElement('div'); ud.className = 'v'; ud.textContent = fmtMoney(b.unpaid);
      const el2 = document.createElement('div'); el2.className = 'sub'; el2.textContent = 'Unpaid';
      right.appendChild(ud); right.appendChild(el2);
      el.appendChild(left); el.appendChild(right); box.appendChild(el);
      el.addEventListener('click', ()=>{ haptic(15); openBrokerScorecard(gradeObj, globalAvgRpm); });
    }); }
  }

  // P1-4: tax quick view
  await computeTaxView(trips, exps);
}

// P1-4: Tax quick view with selectable periods
let _taxPeriod = 'week';
async function computeTaxView(trips, exps){
  const now = new Date();
  let minTs;
  switch(_taxPeriod){
    case 'month': minTs = startOfMonth(now).getTime(); break;
    case 'quarter': minTs = startOfQuarter(now).getTime(); break;
    case 'ytd': minTs = startOfYear(now).getTime(); break;
    default: minTs = startOfWeek(now).getTime();
  }
  let gross=0, exp=0, days = new Set();
  for (const t of trips){
    const dt = t.pickupDate || t.deliveryDate || '';
    const ts = new Date(dt || Date.now()).getTime();
    if (ts >= minTs){ gross += Number(t.pay||0); days.add(dt); }
  }
  for (const e of exps){
    const ts = new Date(e.date || Date.now()).getTime();
    if (ts >= minTs) exp += Number(e.amount||0);
  }
  const net = roundCents(gross - exp);
  const perDiemRate = Number(await getSetting('perDiemRate', 0) || 0);
  const perDiemFull = perDiemRate > 0 ? (perDiemRate * days.size) : 0;
  // IRS Sec 274(n): DOT-regulated drivers (CDL/HOS) get 80%; non-DOT (cargo van <10,001 GVWR) get 50%
  const vehicleClass = await getSetting('vehicleClass', 'cargo_van');
  const perDiemPct = (vehicleClass === 'semi' || vehicleClass === 'box_truck_cdl') ? IRS.PER_DIEM_PCT_DOT : IRS.PER_DIEM_PCT_NON_DOT;
  const perDiem = roundCents(perDiemFull * perDiemPct);
  const se = roundCents(Math.max(0, (net - perDiem) * IRS.SE_NET_FACTOR * IRS.SE_RATE));
  const profit = roundCents(net - perDiem - se);

  $('#taxGross').textContent = fmtMoney(gross);
  $('#taxExpenses').textContent = fmtMoney(exp);
  $('#taxNet').textContent = fmtMoney(net);
  $('#taxPerDiem').textContent = fmtMoney(perDiem);
  $('#taxSE').textContent = fmtMoney(se);
  $('#taxProfit').textContent = fmtMoney(profit);
}


// ---- Broker + AR intelligence ----
function daysBetweenISO(aIso, bIso){
  if (!aIso || !bIso) return null;
  const a = new Date(aIso); const b = new Date(bIso);
  if (isNaN(a) || isNaN(b)) return null;
  return Math.round((b.getTime() - a.getTime())/86400000);
}
function computeARAging(trips, todayIso){
  const buckets = { b0_15:0, b16_30:0, b31_45:0, b46p:0 };
  const now = new Date(todayIso).getTime() || Date.now();
  for (const t of trips){
    if (t.isPaid) continue;
    const amt = Number(t.pay||0);
    const base = t.pickupDate || t.deliveryDate;
    if (!base) continue;
    const ts = new Date(base).getTime();
    if (!isFinite(ts)) continue;
    const days = Math.floor((now - ts)/86400000);
    if (days <= 15) buckets.b0_15 += amt;
    else if (days <= 30) buckets.b16_30 += amt;
    else if (days <= 45) buckets.b31_45 += amt;
    else buckets.b46p += amt;
  }
  return buckets;
}
// P2-6: configurable broker window
function computeBrokerStats(trips, todayIso, windowDays=90){
  const now = new Date(todayIso).getTime() || Date.now();
  const minTs = windowDays > 0 ? (now - (windowDays * 86400000)) : 0;
  const map = new Map();
  for (const t of trips){
    const dt = t.pickupDate || t.deliveryDate;
    const ts = new Date(dt || Date.now()).getTime();
    if (ts < minTs) continue;
    const name = clampStr(t.customer || 'Unknown', 80) || 'Unknown';
    const pay = Number(t.pay||0);
    const allMi = Number(t.loadedMiles||0) + Number(t.emptyMiles||0);
    let rec = map.get(name);
    if (!rec){ rec = { name, trips:0, pay:0, miles:0, paidTrips:0, daysToPaySum:0, unpaid:0 }; map.set(name, rec); }
    rec.trips += 1; rec.pay += pay; rec.miles += allMi;
    if (!t.isPaid) rec.unpaid += pay;
    if (t.isPaid && t.paidDate){
      const d = daysBetweenISO(dt, t.paidDate);
      if (d !== null){ rec.paidTrips += 1; rec.daysToPaySum += d; }
    }
  }
  return Array.from(map.values()).map(r => ({
    ...r, avgRpm: r.miles>0 ? (r.pay/r.miles) : 0, avgDtp: r.paidTrips>0 ? (r.daysToPaySum/r.paidTrips) : null
  })).sort((a,b)=> (b.unpaid - a.unpaid) || (b.trips - a.trips));
}

// ====================================================================
//  LANE INTELLIGENCE ENGINE
// ====================================================================
//  Computes per-lane stats from origin→destination pairs.
//  Surfaces RPM trends, volume, best/worst lanes, and live wizard hints.
// ====================================================================

function normLaneCity(s){ return clampStr(s, 60).replace(/[.,;]/g,'').replace(/\s+/g,' ').trim().toLowerCase(); }
function laneKey(origin, dest){
  const o = normLaneCity(origin); const d = normLaneCity(dest);
  return (o && d) ? `${o}→${d}` : '';
}
function laneKeyDisplay(origin, dest){
  const o = clampStr(origin,60).trim(); const d = clampStr(dest,60).trim();
  return (o && d) ? `${o} → ${d}` : '';
}

function computeLaneStats(trips){
  const map = new Map();
  for (const t of trips){
    const key = laneKey(t.origin, t.destination);
    if (!key) continue;
    const pay = Number(t.pay||0);
    const loaded = Number(t.loadedMiles||0);
    const empty = Number(t.emptyMiles||0);
    const allMi = loaded + empty;
    const rpm = allMi > 0 ? pay / allMi : 0;
    const dt = t.pickupDate || t.deliveryDate || '';

    let rec = map.get(key);
    if (!rec){
      rec = { key, display: laneKeyDisplay(t.origin, t.destination),
        trips:0, totalPay:0, totalMiles:0, rpms:[], dates:[], repeats:0,
        minRpm:Infinity, maxRpm:0, origin:t.origin, destination:t.destination };
      map.set(key, rec);
    }
    rec.trips++;
    rec.totalPay += pay;
    rec.totalMiles += allMi;
    if (t.wouldRunAgain === true) rec.repeats++;
    if (allMi > 0){
      rec.rpms.push({ rpm, date:dt, pay });
      if (rpm < rec.minRpm) rec.minRpm = rpm;
      if (rpm > rec.maxRpm) rec.maxRpm = rpm;
    }
    if (dt) rec.dates.push(dt);
  }

  return Array.from(map.values()).map(r => {
    const avgRpm = r.totalMiles > 0 ? r.totalPay / r.totalMiles : 0;
    const avgPay = r.trips > 0 ? r.totalPay / r.trips : 0;
    // Trend: compare last 3 loads RPM vs first 3 loads RPM
    let trend = 0; // -1 declining, 0 flat, 1 rising
    const sorted = [...r.rpms].sort((a,b)=> (a.date||'').localeCompare(b.date||''));
    if (sorted.length >= 4){
      const half = Math.floor(sorted.length / 2);
      const firstHalf = sorted.slice(0, half);
      const secondHalf = sorted.slice(half);
      const avgFirst = firstHalf.reduce((s,x)=>s+x.rpm,0) / firstHalf.length;
      const avgSecond = secondHalf.reduce((s,x)=>s+x.rpm,0) / secondHalf.length;
      if (avgSecond > avgFirst * 1.05) trend = 1;
      else if (avgSecond < avgFirst * 0.95) trend = -1;
    }
    // Volatility: std deviation of RPM
    let volatility = 0;
    if (r.rpms.length >= 3){
      const mean = avgRpm;
      const variance = r.rpms.reduce((s,x)=> s + Math.pow(x.rpm - mean, 2), 0) / r.rpms.length;
      volatility = Math.sqrt(variance);
    }
    // Last run date
    const lastDate = r.dates.sort().pop() || '';
    const daysSinceLast = lastDate ? daysBetweenISO(lastDate, isoDate()) : null;

    return {
      ...r,
      avgRpm: +avgRpm.toFixed(2),
      avgPay: +avgPay.toFixed(0),
      minRpm: r.minRpm === Infinity ? 0 : +r.minRpm.toFixed(2),
      maxRpm: +r.maxRpm.toFixed(2),
      trend, // -1, 0, 1
      trendLabel: trend > 0 ? 'Rising' : trend < 0 ? 'Declining' : 'Stable',
      volatility: +volatility.toFixed(3),
      repeatRate: r.trips > 0 ? Math.round((r.repeats / r.trips) * 100) : null,
      lastDate,
      daysSinceLast,
    };
  }).sort((a,b)=> b.trips - a.trips);
}

function computeLaneIntel(origin, dest, trips){
  const key = laneKey(origin, dest);
  if (!key) return null;
  const stats = computeLaneStats(trips);
  return stats.find(s => s.key === key) || null;
}

// Render lane intel card (for wizard + breakdown)
function laneIntelHTML(intel){
  if (!intel) return '';
  const trendIcon = intel.trend > 0 ? '📈' : intel.trend < 0 ? '📉' : '➡️';
  const trendColor = intel.trend > 0 ? 'var(--good)' : intel.trend < 0 ? 'var(--bad)' : 'var(--muted)';
  return `<div style="padding:10px 0">
    <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:6px">LANE INTELLIGENCE</div>
    <div style="font-size:13px;font-weight:700;margin-bottom:8px">${escapeHtml(intel.display)}</div>
    <div style="display:flex;flex-wrap:wrap;gap:8px">
      <span class="pill" style="padding:4px 8px"><span class="muted">Runs</span> <b>${intel.trips}</b></span>
      <span class="pill" style="padding:4px 8px"><span class="muted">Avg RPM</span> <b>$${intel.avgRpm}</b></span>
      <span class="pill" style="padding:4px 8px"><span class="muted">Range</span> <b>$${intel.minRpm}–$${intel.maxRpm}</b></span>
      <span class="pill" style="padding:4px 8px"><span class="muted">Avg Pay</span> <b>${fmtMoney(intel.avgPay)}</b></span>
      <span class="pill" style="padding:4px 8px;border-color:${trendColor}"><span class="muted">Trend</span> <b style="color:${trendColor}">${trendIcon} ${intel.trendLabel}</b></span>
      ${intel.daysSinceLast !== null ? `<span class="pill" style="padding:4px 8px"><span class="muted">Last run</span> <b>${intel.daysSinceLast}d ago</b></span>` : ''}
    </div>
  </div>`;
}

// ====================================================================
//  BROKER SCORECARD SYSTEM
// ====================================================================
//  Grades each broker A–F based on:
//    RPM consistency (vs your avg)
//    Payment speed (days-to-pay)
//    Unpaid rate
//    Volume (loyalty bonus)
// ====================================================================

function computeBrokerGrade(broker, globalAvgRpm){
  // broker = one item from computeBrokerStats()
  let score = 0; // 0-100 → maps to A-F

  // 1. RPM quality (0-35 pts)
  if (globalAvgRpm > 0){
    const ratio = broker.avgRpm / globalAvgRpm;
    if (ratio >= 1.15) score += 35;
    else if (ratio >= 1.05) score += 28;
    else if (ratio >= 0.95) score += 22;
    else if (ratio >= 0.85) score += 14;
    else if (ratio >= 0.75) score += 7;
  } else score += 18; // no baseline

  // 2. Payment speed (0-30 pts)
  if (broker.avgDtp !== null){
    if (broker.avgDtp <= 15) score += 30;
    else if (broker.avgDtp <= 25) score += 24;
    else if (broker.avgDtp <= 35) score += 16;
    else if (broker.avgDtp <= 45) score += 8;
    // >45 = 0
  } else score += 12; // unknown

  // 3. Unpaid rate (0-20 pts)
  if (broker.trips > 0){
    const unpaidCount = broker.trips - broker.paidTrips;
    const unpaidRate = unpaidCount / broker.trips;
    if (unpaidRate <= 0.1) score += 20;
    else if (unpaidRate <= 0.25) score += 14;
    else if (unpaidRate <= 0.5) score += 8;
    // >50% = 0
  } else score += 10;

  // 4. Volume loyalty (0-15 pts)
  if (broker.trips >= 20) score += 15;
  else if (broker.trips >= 10) score += 12;
  else if (broker.trips >= 5) score += 8;
  else if (broker.trips >= 2) score += 4;

  // Map to letter grade
  let grade, gradeColor;
  if (score >= 85){ grade = 'A'; gradeColor = '#6bff95'; }
  else if (score >= 70){ grade = 'B'; gradeColor = '#6bff95'; }
  else if (score >= 55){ grade = 'C'; gradeColor = '#ffb300'; }
  else if (score >= 40){ grade = 'D'; gradeColor = '#ffb300'; }
  else { grade = 'F'; gradeColor = '#ff6b6b'; }

  return { grade, gradeColor, score, broker };
}

function brokerGradeHTML(gradeObj){
  return `<span class="tag" style="font-weight:800;color:${gradeObj.gradeColor};border-color:${gradeObj.gradeColor}40;background:${gradeObj.gradeColor}15;min-width:28px;text-align:center">${gradeObj.grade}</span>`;
}

// Full broker scorecard modal
async function openBrokerScorecard(gradeObj, globalAvgRpm){
  const b = gradeObj.broker;
  const body = document.createElement('div');
  body.style.padding = '0';

  const header = document.createElement('div');
  header.style.cssText = 'text-align:center;padding:14px 0';
  header.innerHTML = `
    <div style="font-size:56px;font-weight:900;color:${gradeObj.gradeColor};line-height:1">${gradeObj.grade}</div>
    <div style="font-size:18px;font-weight:700;margin-top:6px">${escapeHtml(b.name)}</div>
    <div class="muted" style="font-size:12px">Broker Score: ${gradeObj.score}/100</div>`;
  body.appendChild(header);

  const metrics = document.createElement('div');
  metrics.className = 'row';
  metrics.style.cssText = 'margin:0 0 14px;justify-content:center';
  const dtp = b.avgDtp !== null ? `${Math.round(b.avgDtp)}d` : '—';
  const unpaidRate = b.trips > 0 ? Math.round(((b.trips - b.paidTrips) / b.trips) * 100) : 0;
  metrics.innerHTML = `
    <div class="pill"><span class="muted">Loads</span> <b>${b.trips}</b></div>
    <div class="pill"><span class="muted">Avg RPM</span> <b>$${b.avgRpm.toFixed(2)}</b></div>
    <div class="pill"><span class="muted">Avg Pay Speed</span> <b>${dtp}</b></div>
    <div class="pill"><span class="muted">Unpaid Rate</span> <b>${unpaidRate}%</b></div>
    <div class="pill"><span class="muted">Total Rev</span> <b>${fmtMoney(b.pay)}</b></div>
    <div class="pill"><span class="muted">Outstanding</span> <b>${fmtMoney(b.unpaid)}</b></div>`;
  body.appendChild(metrics);

  // Scoring breakdown
  const card = document.createElement('div');
  card.className = 'card';
  card.style.marginBottom = '14px';

  const factors = [];
  // RPM quality
  let rpmPts = 18;
  if (globalAvgRpm > 0){
    const ratio = b.avgRpm / globalAvgRpm;
    if (ratio >= 1.15) rpmPts = 35;
    else if (ratio >= 1.05) rpmPts = 28;
    else if (ratio >= 0.95) rpmPts = 22;
    else if (ratio >= 0.85) rpmPts = 14;
    else if (ratio >= 0.75) rpmPts = 7;
    else rpmPts = 0;
    factors.push({ name:'RPM quality', pts:rpmPts, max:35, detail:`${(ratio*100).toFixed(0)}% of your $${globalAvgRpm.toFixed(2)} avg` });
  } else { factors.push({ name:'RPM quality', pts:rpmPts, max:35, detail:'No baseline yet' }); }

  // Payment speed
  let payPts = 12;
  if (b.avgDtp !== null){
    if (b.avgDtp <= 15) payPts = 30;
    else if (b.avgDtp <= 25) payPts = 24;
    else if (b.avgDtp <= 35) payPts = 16;
    else if (b.avgDtp <= 45) payPts = 8;
    else payPts = 0;
    factors.push({ name:'Payment speed', pts:payPts, max:30, detail:`${Math.round(b.avgDtp)} day average` });
  } else { factors.push({ name:'Payment speed', pts:payPts, max:30, detail:'No payment data' }); }

  // Reliability
  let relPts = 10;
  if (b.trips > 0){
    if (unpaidRate <= 10) relPts = 20;
    else if (unpaidRate <= 25) relPts = 14;
    else if (unpaidRate <= 50) relPts = 8;
    else relPts = 0;
    factors.push({ name:'Reliability', pts:relPts, max:20, detail:`${unpaidRate}% unpaid rate` });
  } else { factors.push({ name:'Reliability', pts:relPts, max:20, detail:'No data' }); }

  // Volume
  let volPts = 0;
  if (b.trips >= 20) volPts = 15;
  else if (b.trips >= 10) volPts = 12;
  else if (b.trips >= 5) volPts = 8;
  else if (b.trips >= 2) volPts = 4;
  factors.push({ name:'Volume', pts:volPts, max:15, detail:`${b.trips} load(s)` });

  let rows = '';
  for (const f of factors){
    const pct = f.max > 0 ? (f.pts / f.max) * 100 : 0;
    const barColor = pct >= 60 ? 'var(--good)' : pct >= 30 ? 'var(--warn)' : 'var(--bad)';
    rows += `<div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:12px"><span>${escapeHtml(f.name)}</span><span style="font-weight:700">${f.pts}/${f.max}</span></div>
      <div style="height:4px;border-radius:2px;background:rgba(255,255,255,.06);margin-top:4px"><div style="height:100%;width:${pct}%;border-radius:2px;background:${barColor};transition:width .3s"></div></div>
      <div class="muted" style="font-size:11px;margin-top:2px">${escapeHtml(f.detail)}</div></div>`;
  }
  card.innerHTML = `<h3>Grade Breakdown</h3>${rows}`;
  body.appendChild(card);

  // ── Broker Notes (persisted in settings) ──
  const noteKey = 'broker_note_' + b.name.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 40);
  const notesCard = document.createElement('div');
  notesCard.className = 'card';
  notesCard.style.marginBottom = '14px';
  const existingNote = await getSetting(noteKey, '');
  notesCard.innerHTML = `<h3>Your Notes on This Broker</h3>
    <textarea id="brokerNoteInput" rows="3" placeholder="e.g., Always late with paperwork, dispatchers ghost after booking…" style="width:100%;font-size:13px">${escapeHtml(existingNote)}</textarea>
    <button class="btn" id="brokerNoteSave" style="margin-top:8px;width:100%">Save Note</button>
    <div class="muted" style="font-size:11px;margin-top:4px">Private — only visible to you.</div>`;
  body.appendChild(notesCard);

  openModal(`Scorecard • ${escapeHtml(b.name)}`, body);

  // Wire up save
  const saveBtn = $('#brokerNoteSave');
  if (saveBtn){
    saveBtn.addEventListener('click', async ()=>{
      const val = clampStr($('#brokerNoteInput')?.value || '', 500);
      await setSetting(noteKey, val);
      toast('Broker note saved');
    });
  }
}

// Broker intel hint for wizard (compact)
function brokerIntelHTML(customer, trips){
  if (!customer) return '';
  const brokerStats = computeBrokerStats(trips, isoDate(), 0); // all-time for this broker
  const match = brokerStats.find(b => b.name === customer);
  if (!match || match.trips < 1) return `<div style="padding:8px 0"><span class="muted" style="font-size:12px">New broker — no history</span></div>`;

  const globalMiles = brokerStats.reduce((s,b)=> s + b.miles, 0);
  const globalPay = brokerStats.reduce((s,b)=> s + b.pay, 0);
  const globalAvgRpm = globalMiles > 0 ? globalPay / globalMiles : 0;
  const gradeObj = computeBrokerGrade(match, globalAvgRpm);
  const dtp = match.avgDtp !== null ? `${Math.round(match.avgDtp)}d` : '—';
  return `<div style="padding:8px 0">
    <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:6px">BROKER INTELLIGENCE</div>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
      ${brokerGradeHTML(gradeObj)}
      <span style="font-weight:700;font-size:13px">${escapeHtml(match.name)}</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:6px">
      <span class="pill" style="padding:4px 8px"><span class="muted">Loads</span> <b>${match.trips}</b></span>
      <span class="pill" style="padding:4px 8px"><span class="muted">RPM</span> <b>$${match.avgRpm.toFixed(2)}</b></span>
      <span class="pill" style="padding:4px 8px"><span class="muted">Pay speed</span> <b>${dtp}</b></span>
      <span class="pill" style="padding:4px 8px"><span class="muted">Owed</span> <b>${fmtMoney(match.unpaid)}</b></span>
    </div>
  </div>`;
}

// ====================================================================
//  PROFIT ENGINE — Load Decision Score
// ====================================================================
//
//  Every trip gets scored on two axes:
//    Margin Score (0-100): How profitable is this load?
//    Risk Score (0-100):   How risky is this load?
//
//  Produces: Verdict + Counter-offer + Detailed breakdown
//
//  Verdicts:
//    PREMIUM WIN  — Margin ≥80, Risk ≤25
//    ACCEPT       — Margin ≥55, Risk ≤50
//    NEGOTIATE    — Margin 35-54 OR Risk 51-65
//    PASS         — Margin <35 OR Risk >65
//
// ====================================================================

// ── Pre-compute shared baselines for computeLoadScore (avoids O(n²) on list render) ──
let _scoreBaselineCache = { key: '', baselines: null };
function _getScoreBaselines(allTrips, allExps){
  // Cache key: trip count + expense count (invalidated when data changes)
  const key = `${allTrips.length}:${allExps.length}:${_kpiCache.ts}`;
  if (_scoreBaselineCache.key === key && _scoreBaselineCache.baselines) return _scoreBaselineCache.baselines;
  const now = Date.now();
  const d90 = now - 90 * 86400000;
  const d30 = now - 30 * 86400000;
  const recent = allTrips.filter(t => {
    const dt = t.pickupDate || t.deliveryDate;
    return dt && new Date(dt).getTime() >= d90;
  });
  let histRpmSum = 0, histMiSum = 0, histPaySum = 0, histCount = 0;
  let histDeadheadSum = 0, histDhCount = 0;
  for (const t of recent){
    const p = Number(t.pay || 0);
    const l = Number(t.loadedMiles || 0);
    const e = Number(t.emptyMiles || 0);
    const m = l + e;
    if (m > 0){ histRpmSum += p; histMiSum += m; histCount++; }
    if (m > 0){ histDeadheadSum += (e / m) * 100; histDhCount++; }
    histPaySum += p;
  }
  let exp30 = 0;
  for (const e of allExps){
    if (e.date && new Date(e.date).getTime() >= d30) exp30 += Number(e.amount || 0);
  }
  const baselines = {
    recent, d90, d30, now,
    histAvgRpm: histMiSum > 0 ? histRpmSum / histMiSum : 0,
    histAvgDeadhead: histDhCount > 0 ? histDeadheadSum / histDhCount : 15,
    histAvgPay: histCount > 0 ? histPaySum / histCount : 0,
    dailyFixedCost: exp30 / 30 || 0,
  };
  _scoreBaselineCache = { key, baselines };
  return baselines;
}

function computeLoadScore(trip, allTrips, allExps, fuelConfig=null){
  const pay = Number(trip.pay || 0);
  const loaded = Number(trip.loadedMiles || 0);
  const empty = Number(trip.emptyMiles || 0);
  const allMi = loaded + empty;
  const rpm = allMi > 0 ? pay / allMi : 0;
  const trueRpm = loaded > 0 ? pay / loaded : 0; // loaded-only CPM
  const deadheadPct = allMi > 0 ? (empty / allMi) * 100 : 0;
  const customer = clampStr(trip.customer || '', 80);

  // ── Historical baselines (cached — shared across all calls in same render) ──
  const bl = _getScoreBaselines(allTrips, allExps);
  const { recent, histAvgRpm, histAvgDeadhead, histAvgPay, dailyFixedCost } = bl;

  // ── MARGIN SCORE (0-100) ──
  const margin = { total: 0, factors: [] };

  // Factor 1: RPM vs Omega tiers (0-40 pts)
  // Maps RPM to where it lands in the Omega tier system
  const tierIdx = omegaTierForMiles(allMi || 1);
  const tier = OMEGA_TIERS[tierIdx];
  let omegaPts = 0;
  if (rpm >= tier.premium.min){ omegaPts = 40; margin.factors.push({ name:'Omega tier', pts:40, max:40, detail:'Premium Win range' }); }
  else if (rpm >= tier.ideal.min){ omegaPts = 32; margin.factors.push({ name:'Omega tier', pts:32, max:40, detail:'Ideal Target range' }); }
  else if (rpm >= tier.strong.min){ omegaPts = 24; margin.factors.push({ name:'Omega tier', pts:24, max:40, detail:'Strong Accept range' }); }
  else if (rpm >= tier.floor.min){ omegaPts = 16; margin.factors.push({ name:'Omega tier', pts:16, max:40, detail:'Floor Accept range' }); }
  else if (rpm >= tier.under.min){ omegaPts = 8; margin.factors.push({ name:'Omega tier', pts:8, max:40, detail:'Under-Floor range' }); }
  else { omegaPts = 0; margin.factors.push({ name:'Omega tier', pts:0, max:40, detail:'Below all tiers' }); }
  margin.total += omegaPts;

  // Factor 2: RPM vs personal 90-day average (0-25 pts)
  let histPts = 12; // default neutral if no history
  if (histAvgRpm > 0){
    const ratio = rpm / histAvgRpm;
    if (ratio >= 1.20){ histPts = 25; }
    else if (ratio >= 1.05){ histPts = 20; }
    else if (ratio >= 0.95){ histPts = 15; }
    else if (ratio >= 0.85){ histPts = 10; }
    else if (ratio >= 0.75){ histPts = 5; }
    else { histPts = 0; }
    margin.factors.push({ name:'vs 90-day avg', pts:histPts, max:25, detail:`${(ratio*100).toFixed(0)}% of your $${histAvgRpm.toFixed(2)} avg RPM` });
  } else {
    margin.factors.push({ name:'vs 90-day avg', pts:histPts, max:25, detail:'No history yet — neutral score' });
  }
  margin.total += histPts;

  // Factor 3: Deadhead efficiency (0-20 pts)
  let dhPts = 0;
  if (deadheadPct <= 5){ dhPts = 20; }
  else if (deadheadPct <= 12){ dhPts = 16; }
  else if (deadheadPct <= 20){ dhPts = 12; }
  else if (deadheadPct <= 30){ dhPts = 6; }
  else { dhPts = 0; }
  margin.factors.push({ name:'Deadhead', pts:dhPts, max:20, detail:`${deadheadPct.toFixed(1)}% empty` });
  margin.total += dhPts;

  // Factor 4: Net margin after daily costs (0-15 pts)
  let costPts = 8; // default if no expense data
  if (dailyFixedCost > 0){
    const estDays = allMi > 0 ? Math.max(1, Math.ceil(allMi / 450)) : 1; // ~450mi/day
    const costForLoad = dailyFixedCost * estDays;
    const netMargin = pay > 0 ? ((pay - costForLoad) / pay) * 100 : 0;
    if (netMargin >= 60){ costPts = 15; }
    else if (netMargin >= 45){ costPts = 12; }
    else if (netMargin >= 30){ costPts = 9; }
    else if (netMargin >= 15){ costPts = 5; }
    else { costPts = 0; }
    margin.factors.push({ name:'Net margin', pts:costPts, max:15, detail:`${netMargin.toFixed(0)}% after ~${fmtMoney(costForLoad)}/day costs` });
  } else {
    margin.factors.push({ name:'Net margin', pts:costPts, max:15, detail:'No expense data — neutral score' });
  }
  margin.total += costPts;

  // ── RISK SCORE (0-100, lower = safer) ──
  const risk = { total: 0, factors: [] };

  // Factor 1: Broker payment history (0-35 pts risk)
  let brokerRisk = 15; // unknown broker baseline
  if (customer){
    const brokerTrips = allTrips.filter(t => (t.customer || '') === customer);
    if (brokerTrips.length >= 2){
      const unpaidCount = brokerTrips.filter(t => !t.isPaid).length;
      const unpaidRate = unpaidCount / brokerTrips.length;
      let dtpAvg = null;
      const paidWithDate = brokerTrips.filter(t => t.isPaid && t.paidDate);
      if (paidWithDate.length){
        const dtpSum = paidWithDate.reduce((s, t) => {
          const d = daysBetweenISO(t.pickupDate || t.deliveryDate, t.paidDate);
          return s + (d !== null ? d : 0);
        }, 0);
        dtpAvg = dtpSum / paidWithDate.length;
      }

      if (unpaidRate > 0.5){ brokerRisk = 35; risk.factors.push({ name:'Broker history', pts:35, max:35, detail:`${(unpaidRate*100).toFixed(0)}% unpaid rate (${brokerTrips.length} loads)` }); }
      else if (dtpAvg !== null && dtpAvg > 45){ brokerRisk = 30; risk.factors.push({ name:'Broker history', pts:30, max:35, detail:`Slow payer: ${Math.round(dtpAvg)}d avg (${brokerTrips.length} loads)` }); }
      else if (dtpAvg !== null && dtpAvg > 30){ brokerRisk = 20; risk.factors.push({ name:'Broker history', pts:20, max:35, detail:`${Math.round(dtpAvg)}d avg pay (${brokerTrips.length} loads)` }); }
      else if (dtpAvg !== null && dtpAvg <= 20){ brokerRisk = 5; risk.factors.push({ name:'Broker history', pts:5, max:35, detail:`Fast payer: ${Math.round(dtpAvg)}d avg (${brokerTrips.length} loads)` }); }
      else { brokerRisk = 10; risk.factors.push({ name:'Broker history', pts:10, max:35, detail:`${brokerTrips.length} loads, payment data incomplete` }); }
    } else if (brokerTrips.length === 1){
      brokerRisk = 18;
      risk.factors.push({ name:'Broker history', pts:18, max:35, detail:'Only 1 previous load — limited data' });
    } else {
      brokerRisk = 22;
      risk.factors.push({ name:'Broker history', pts:22, max:35, detail:'New broker — no history' });
    }
  } else {
    brokerRisk = 15;
    risk.factors.push({ name:'Broker history', pts:15, max:35, detail:'No customer entered' });
  }
  risk.total += brokerRisk;

  // Factor 2: Deadhead risk (0-25 pts)
  let dhRisk = 0;
  if (deadheadPct > 35){ dhRisk = 25; }
  else if (deadheadPct > 25){ dhRisk = 18; }
  else if (deadheadPct > 15){ dhRisk = 10; }
  else if (deadheadPct > 8){ dhRisk = 5; }
  risk.factors.push({ name:'Deadhead risk', pts:dhRisk, max:25, detail:`${deadheadPct.toFixed(1)}% empty miles` });
  risk.total += dhRisk;

  // Factor 3: Concentration risk (0-20 pts)
  let concRisk = 0;
  if (customer && recent.length >= 5){
    const brokerRecent = recent.filter(t => (t.customer || '') === customer).length;
    const concPct = (brokerRecent / recent.length) * 100;
    if (concPct > 60){ concRisk = 20; }
    else if (concPct > 40){ concRisk = 12; }
    else if (concPct > 25){ concRisk = 5; }
    risk.factors.push({ name:'Concentration', pts:concRisk, max:20, detail:`${concPct.toFixed(0)}% of recent loads from this broker` });
  } else {
    risk.factors.push({ name:'Concentration', pts:0, max:20, detail:'Not enough data to assess' });
  }
  risk.total += concRisk;

  // Factor 4: Below-floor risk (0-20 pts)
  let floorRisk = 0;
  if (allMi > 0){
    if (rpm < tier.under.min){ floorRisk = 20; risk.factors.push({ name:'Below floor', pts:20, max:20, detail:`$${rpm.toFixed(2)} RPM is below all Omega tiers` }); }
    else if (rpm < tier.floor.min){ floorRisk = 12; risk.factors.push({ name:'Below floor', pts:12, max:20, detail:`$${rpm.toFixed(2)} RPM is under-floor range` }); }
    else { risk.factors.push({ name:'Below floor', pts:0, max:20, detail:'RPM is at or above floor' }); }
  } else {
    risk.factors.push({ name:'Below floor', pts:0, max:20, detail:'No mileage entered' });
  }
  risk.total += floorRisk;

  // ── VERDICT ──
  const m = margin.total;
  const r = risk.total;
  let verdict, verdictColor;
  if (m >= 80 && r <= 25){ verdict = 'PREMIUM WIN'; verdictColor = '#6bff95'; }
  else if (m >= 55 && r <= 50){ verdict = 'ACCEPT'; verdictColor = '#6bff95'; }
  else if (m >= 35 || r <= 65){ verdict = 'NEGOTIATE'; verdictColor = '#ffb300'; }
  else { verdict = 'PASS'; verdictColor = '#ff6b6b'; }

  // ── COUNTER-OFFER ──
  // Target the Ideal tier for this mileage
  const idealRpm = tier.ideal.min;
  const counterOffer = allMi > 0 ? Math.round(idealRpm * allMi) : 0;
  const counterRpm = idealRpm;

  // ── FUEL COST ESTIMATE ──
  let fuelCost = null, netAfterFuel = null;
  const mpg = fuelConfig?.mpg || 0;
  const ppg = fuelConfig?.pricePerGal || 0;
  if (mpg > 0 && ppg > 0 && allMi > 0){
    fuelCost = +(allMi / mpg * ppg).toFixed(2);
    netAfterFuel = +(pay - fuelCost).toFixed(2);
  }

  return {
    marginScore: Math.min(100, Math.max(0, m)),
    riskScore: Math.min(100, Math.max(0, r)),
    verdict, verdictColor,
    rpm: +rpm.toFixed(2),
    trueRpm: +trueRpm.toFixed(2),
    deadheadPct: +deadheadPct.toFixed(1),
    tierName: tier.name,
    counterOffer, counterRpm,
    margin, risk,
    histAvgRpm: +histAvgRpm.toFixed(2),
    dailyFixedCost: +dailyFixedCost.toFixed(2),
    fuelCost, netAfterFuel,
  };
}

// ════════════════════════════════════════════════════════════════
// BID RECOMMENDATION ENGINE (Spec §18)
// Generates bid ranges based on True Miles + market conditions
// ════════════════════════════════════════════════════════════════

function generateBidRange(totalMiles, opts={}){
  const { urgencyBoost = 0, crossBorder = false } = opts;
  if (!totalMiles || totalMiles <= 0) return null;
  // Base RPM tiers per spec
  const tiers = {
    minimum:      { rpm: 1.40, label: 'Minimum' },
    professional: { rpm: 1.60, label: 'Professional' },
    strong:       { rpm: 1.75, label: 'Strong' },
    premium:      { rpm: 2.00, label: 'Premium' },
  };
  // Cross-border loads need higher threshold to cover friction
  const borderAdj = crossBorder ? 0.10 : 0;
  // Urgency allows premium pricing
  const urgAdj = urgencyBoost;

  const bids = {};
  for (const [key, tier] of Object.entries(tiers)){
    const adjRpm = roundCents(tier.rpm + borderAdj + urgAdj);
    bids[key] = {
      label: tier.label,
      rpm: adjRpm,
      amount: Math.round(adjRpm * totalMiles),
    };
  }
  return bids;
}

/** Render bid range HTML for display in evaluator/scorecard */
function bidRangeHTML(bids){
  if (!bids) return '';
  let html = '<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px"><div style="font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:var(--text-tertiary);margin-bottom:8px">Bid Range</div>';
  const colors = { minimum: 'var(--bad)', professional: 'var(--warn)', strong: '#58a6ff', premium: 'var(--good)' };
  for (const [key, bid] of Object.entries(bids)){
    const color = colors[key] || 'var(--text)';
    html += `<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:13px">
      <span style="color:var(--text-secondary)">${escapeHtml(bid.label)}</span>
      <span><span style="color:${color};font-weight:700;font-family:var(--font-mono)">${fmtMoney(bid.amount)}</span> <span class="muted" style="font-size:11px">($${bid.rpm.toFixed(2)}/mi)</span></span>
    </div>`;
  }
  html += '</div>';
  return html;
}

// ════════════════════════════════════════════════════════════════
// URGENCY DETECTION ENGINE (Spec §15)
// Scans load notes/description for urgency signals
// ════════════════════════════════════════════════════════════════

const URGENCY_KEYWORDS = [
  { pattern: /\basap\b/i,        weight: 0.15, label: 'ASAP' },
  { pattern: /\bdirect\b/i,      weight: 0.08, label: 'Direct' },
  { pattern: /\bhot\s*(load|shot|freight)?\b/i, weight: 0.12, label: 'Hot' },
  { pattern: /\bline\s*down\b/i, weight: 0.20, label: 'Line Down' },
  { pattern: /\bsame[\s-]*day\b/i,  weight: 0.15, label: 'Same-Day' },
  { pattern: /\brush\b/i,        weight: 0.10, label: 'Rush' },
  { pattern: /\bemergency\b/i,   weight: 0.18, label: 'Emergency' },
  { pattern: /\bcritical\b/i,    weight: 0.12, label: 'Critical' },
  { pattern: /\bexpedite[ds]?\b/i, weight: 0.10, label: 'Expedited' },
  { pattern: /\btime[\s-]*sensitive\b/i, weight: 0.10, label: 'Time-Sensitive' },
];

/** Scan text for urgency signals. Returns { isUrgent, boost, matches[] } */
function detectUrgency(text){
  if (!text) return { isUrgent: false, boost: 0, matches: [] };
  const matches = [];
  let totalBoost = 0;
  for (const kw of URGENCY_KEYWORDS){
    if (kw.pattern.test(text)){
      matches.push(kw.label);
      totalBoost += kw.weight;
    }
  }
  // Cap boost at $0.30 RPM — don't let stacked keywords go crazy
  totalBoost = Math.min(0.30, totalBoost);
  return { isUrgent: matches.length > 0, boost: roundCents(totalBoost), matches };
}

/** Render urgency badge */
function urgencyBadgeHTML(urgency){
  if (!urgency || !urgency.isUrgent) return '';
  return `<span class="tag" style="background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.4);color:var(--warn);font-weight:700">⚡ ${escapeHtml(urgency.matches.join(' • '))}</span>`;
}

// ════════════════════════════════════════════════════════════════
// CONFIGURABLE SCORING WEIGHTS (Spec §9)
// Default weights match spec. User can adjust via settings.
// ════════════════════════════════════════════════════════════════

const DEFAULT_SCORE_WEIGHTS = Object.freeze({
  trueRpm:         30,  // 30%
  marketDensity:   15,  // 15%
  destinationRole: 10,  // 10%
  corridorStrength:10,  // 10%
  trapRisk:        10,  // 10%
  repositionEffect:10,  // 10%
  urgencySignals:   5,  //  5%
  companyBehavior:  5,  //  5%
  vehicleFit:       5,  //  5%
});

/** Get scoring weights — returns user-configured or defaults */
async function getScoreWeights(){
  const saved = await getSetting('scoreWeights', null);
  if (saved && typeof saved === 'object'){
    // Merge with defaults to ensure all keys exist
    return { ...DEFAULT_SCORE_WEIGHTS, ...saved };
  }
  return { ...DEFAULT_SCORE_WEIGHTS };
}

// ── Score badge for trip rows ──
function scoreBadgeHTML(score){
  if (!score) return '';
  const m = score.marginScore;
  let bg, border;
  if (m >= 80){ bg = 'rgba(107,255,149,.12)'; border = 'rgba(107,255,149,.4)'; }
  else if (m >= 55){ bg = 'rgba(107,255,149,.08)'; border = 'rgba(107,255,149,.25)'; }
  else if (m >= 35){ bg = 'rgba(255,179,0,.1)'; border = 'rgba(255,179,0,.35)'; }
  else { bg = 'rgba(255,107,107,.1)'; border = 'rgba(255,107,107,.35)'; }
  return `<span class="tag" style="background:${bg};border-color:${border};color:${score.verdictColor};font-weight:700;cursor:pointer" data-act="score">${score.verdict} ${m}</span>`;
}

// ── Score breakdown modal ──
function openScoreBreakdown(trip, score){
  const body = document.createElement('div');
  body.style.cssText = 'padding:0';

  const header = document.createElement('div');
  header.style.cssText = 'text-align:center;padding:16px 0 12px';
  header.innerHTML = `
    <div style="font-size:48px;font-weight:900;color:${score.verdictColor};line-height:1">${score.verdict}</div>
    <div style="display:flex;justify-content:center;gap:20px;margin-top:12px">
      <div><div class="muted" style="font-size:11px">MARGIN</div><div style="font-size:28px;font-weight:800;color:${score.marginScore>=55?'var(--good)':'var(--warn)'}">${score.marginScore}</div></div>
      <div><div class="muted" style="font-size:11px">RISK</div><div style="font-size:28px;font-weight:800;color:${score.riskScore<=50?'var(--good)':'var(--bad)'}">${score.riskScore}</div></div>
    </div>`;
  body.appendChild(header);

  // Key metrics
  const metrics = document.createElement('div');
  metrics.className = 'row';
  metrics.style.cssText = 'margin:0 0 14px;justify-content:center';
  metrics.innerHTML = `
    <div class="pill"><span class="muted">RPM</span> <b>$${score.rpm}</b></div>
    <div class="pill"><span class="muted">True RPM</span> <b>$${score.trueRpm}</b></div>
    <div class="pill"><span class="muted">DH%</span> <b>${score.deadheadPct}%</b></div>
    <div class="pill"><span class="muted">Tier</span> <b>${escapeHtml(score.tierName)}</b></div>
    ${score.fuelCost !== null ? `<div class="pill"><span class="muted">Fuel est</span> <b>${fmtMoney(score.fuelCost)}</b></div>` : ''}
    ${score.netAfterFuel !== null ? `<div class="pill" style="border-color:rgba(107,255,149,.3)"><span class="muted">Net after fuel</span> <b style="color:${score.netAfterFuel>0?'var(--good)':'var(--bad)'}">${fmtMoney(score.netAfterFuel)}</b></div>` : ''}`;
  body.appendChild(metrics);

  // Counter-offer
  if (score.counterOffer > 0 && score.marginScore < 80){
    const counter = document.createElement('div');
    counter.className = 'card';
    counter.style.cssText = 'border-color:rgba(255,179,0,.3);background:rgba(255,179,0,.05);margin-bottom:14px';
    counter.innerHTML = `<h3 style="color:var(--accent)">Counter-Offer Target</h3>
      <div style="font-size:24px;font-weight:800;color:var(--accent)">${fmtMoney(score.counterOffer)} <span class="muted" style="font-size:14px">($${score.counterRpm.toFixed(2)} RPM)</span></div>
      <div class="muted" style="font-size:12px;margin-top:6px">Ideal Target rate for ${fmtNum(Number(trip.loadedMiles||0)+Number(trip.emptyMiles||0))} miles</div>`;
    body.appendChild(counter);
  }

  // Margin breakdown
  const mCard = document.createElement('div');
  mCard.className = 'card';
  mCard.style.cssText = 'margin-bottom:14px';
  let mRows = '';
  for (const f of score.margin.factors){
    const pct = f.max > 0 ? (f.pts / f.max) * 100 : 0;
    const barColor = pct >= 60 ? 'var(--good)' : pct >= 30 ? 'var(--warn)' : 'var(--bad)';
    mRows += `<div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:12px"><span>${escapeHtml(f.name)}</span><span style="font-weight:700">${f.pts}/${f.max}</span></div>
      <div style="height:4px;border-radius:2px;background:rgba(255,255,255,.06);margin-top:4px"><div style="height:100%;width:${pct}%;border-radius:2px;background:${barColor};transition:width .3s"></div></div>
      <div class="muted" style="font-size:11px;margin-top:2px">${escapeHtml(f.detail)}</div></div>`;
  }
  mCard.innerHTML = `<h3 style="color:var(--good)">Margin Breakdown (${score.marginScore}/100)</h3>${mRows}`;
  body.appendChild(mCard);

  // Risk breakdown
  const rCard = document.createElement('div');
  rCard.className = 'card';
  let rRows = '';
  for (const f of score.risk.factors){
    const pct = f.max > 0 ? (f.pts / f.max) * 100 : 0;
    const barColor = pct <= 30 ? 'var(--good)' : pct <= 60 ? 'var(--warn)' : 'var(--bad)';
    rRows += `<div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:12px"><span>${escapeHtml(f.name)}</span><span style="font-weight:700">${f.pts}/${f.max}</span></div>
      <div style="height:4px;border-radius:2px;background:rgba(255,255,255,.06);margin-top:4px"><div style="height:100%;width:${pct}%;border-radius:2px;background:${barColor};transition:width .3s"></div></div>
      <div class="muted" style="font-size:11px;margin-top:2px">${escapeHtml(f.detail)}</div></div>`;
  }
  rCard.innerHTML = `<h3 style="color:var(--bad)">Risk Breakdown (${score.riskScore}/100)</h3>${rRows}`;
  body.appendChild(rCard);

  // Context
  if (score.histAvgRpm > 0){
    const ctx = document.createElement('div');
    ctx.className = 'card';
    ctx.style.cssText = 'margin-top:14px';
    ctx.innerHTML = `<h3>Your Baselines</h3><div class="row">
      <div class="pill"><span class="muted">90d avg RPM</span> <b>$${score.histAvgRpm}</b></div>
      <div class="pill"><span class="muted">Daily cost</span> <b>${fmtMoney(score.dailyFixedCost)}</b></div>
      ${score.fuelCost !== null ? `<div class="pill"><span class="muted">Fuel model</span> <b>Set ✓</b></div>` : `<div class="pill"><span class="muted">Fuel model</span> <b style="color:var(--warn)">Not set</b></div>`}
      </div>${score.fuelCost === null ? '<div class="muted" style="font-size:11px;margin-top:8px">Set MPG and fuel price in Settings → More to see Net After Fuel estimates</div>' : ''}`;
    body.appendChild(ctx);
  }

  openModal(`Load Score • ${escapeHtml(trip.orderNo || 'Preview')}`, body);
}

// ── Score flash after trip save ──
function showScoreFlash(trip, score){
  haptic(30);
  const body = document.createElement('div');
  body.style.cssText = 'text-align:center;padding:8px 0';
  body.innerHTML = `
    <div style="font-size:14px;font-weight:700;color:var(--muted);margin-bottom:6px">LOAD DECISION SCORE</div>
    <div style="font-size:52px;font-weight:900;color:${score.verdictColor};line-height:1.1">${score.verdict}</div>
    <div style="display:flex;justify-content:center;gap:24px;margin:14px 0">
      <div><div class="muted" style="font-size:11px">MARGIN</div><div style="font-size:32px;font-weight:800;color:${score.marginScore>=55?'var(--good)':'var(--warn)'}">${score.marginScore}</div></div>
      <div><div class="muted" style="font-size:11px">RISK</div><div style="font-size:32px;font-weight:800;color:${score.riskScore<=50?'var(--good)':'var(--bad)'}">${score.riskScore}</div></div>
    </div>
    <div class="row" style="justify-content:center;margin-bottom:14px">
      <div class="pill"><span class="muted">RPM</span> <b>$${score.rpm}</b></div>
      <div class="pill"><span class="muted">DH%</span> <b>${score.deadheadPct}%</b></div>
      ${score.fuelCost !== null ? `<div class="pill"><span class="muted">Fuel est</span> <b>${fmtMoney(score.fuelCost)}</b></div>` : ''}
    </div>
    ${score.netAfterFuel !== null ? `<div style="padding:8px 12px;border-radius:10px;background:rgba(107,255,149,.06);border:1px solid rgba(107,255,149,.15);margin-bottom:14px;text-align:center">
      <div class="muted" style="font-size:11px">NET AFTER FUEL</div>
      <div style="font-size:22px;font-weight:800;color:${score.netAfterFuel > 0 ? 'var(--good)' : 'var(--bad)'}">${fmtMoney(score.netAfterFuel)}</div>
    </div>` : ''}
    ${score.counterOffer > 0 && score.marginScore < 80 ? `<div style="padding:12px;border-radius:14px;border:1px solid rgba(255,179,0,.3);background:rgba(255,179,0,.05);margin-bottom:14px">
      <div class="muted" style="font-size:11px;margin-bottom:4px">COUNTER-OFFER TARGET</div>
      <div style="font-size:24px;font-weight:800;color:var(--accent)">${fmtMoney(score.counterOffer)} <span class="muted" style="font-size:13px">($${score.counterRpm.toFixed(2)} RPM)</span></div>
    </div>` : ''}
    <div class="btn-row" style="justify-content:center">
      <button class="btn" id="scoreDetail">Full Breakdown</button>
      <button class="btn primary" id="scoreDismiss">Got it</button>
    </div>`;

  openModal(`Score • ${escapeHtml(trip.orderNo)}`, body);
  $('#scoreDismiss', body).addEventListener('click', closeModal);
  $('#scoreDetail', body).addEventListener('click', ()=>{ closeModal(); setTimeout(()=> openScoreBreakdown(trip, score), 400); });
}

// ── Live score preview in trip wizard ──
function renderLiveScore(container, tripData, allTrips, allExps){
  if (!container) return;
  const pay = Number(tripData.pay || 0);
  const loaded = Number(tripData.loadedMiles || 0);
  const empty = Number(tripData.emptyMiles || 0);
  const allMi = loaded + empty;
  if (pay <= 0 || allMi <= 0){ container.innerHTML = ''; return; }

  const score = computeLoadScore(tripData, allTrips, allExps);
  container.innerHTML = `<div style="display:flex;align-items:center;gap:10px;padding:10px 0;flex-wrap:wrap">
    <span style="font-weight:800;font-size:14px;color:${score.verdictColor}">${score.verdict}</span>
    <span class="pill" style="padding:4px 8px"><span class="muted">M</span> <b>${score.marginScore}</b></span>
    <span class="pill" style="padding:4px 8px"><span class="muted">R</span> <b>${score.riskScore}</b></span>
    <span class="pill" style="padding:4px 8px"><span class="muted">RPM</span> <b>$${score.rpm}</b></span>
    ${score.counterOffer > 0 && score.marginScore < 80 ? `<span class="pill" style="padding:4px 8px;border-color:rgba(255,179,0,.3)"><span class="muted">Target</span> <b style="color:var(--accent)">${fmtMoney(score.counterOffer)}</b></span>` : ''}
  </div>`;
}

// ---- Share Target Handler ----
async function handleShareTarget(){
  try {
    if (!hasCacheStorage()) { toast('Sharing not supported in this browser', true); return; }
    const shareCache = await caches.open('freightlogic-share-v1');
    const metaRes = await shareCache.match('/shared-meta');
    if (!metaRes) { toast('No shared files found'); return; }
    const meta = await metaRes.json();
    if (!meta.count || meta.count < 1) { toast('No shared files found'); return; }
    // Reject stale shares (>5 minutes old)
    if (Date.now() - (meta.ts || 0) > 300000) {
      await caches.delete('freightlogic-share-v1');
      toast('Shared files expired. Please share again.', true);
      return;
    }
    const files = [];
    for (let i = 0; i < meta.count; i++) {
      const res = await shareCache.match(`/shared-file-${i}`);
      if (res) {
        const blob = await res.blob();
        const filename = res.headers.get('X-Filename') || `shared-${i}`;
        files.push(new File([blob], filename, { type: blob.type }));
      }
    }
    // Clean up share cache
    await caches.delete('freightlogic-share-v1');
    if (!files.length) { toast('Could not read shared files', true); return; }
    // Check if files are receipts (images/PDFs)
    const receiptFiles = files.filter(f => ALLOWED_RECEIPT_TYPES.has(f.type));
    if (receiptFiles.length > 0) {
      toast(`Received ${receiptFiles.length} file${receiptFiles.length > 1 ? 's' : ''} — opening Snap Load`);
      // Open Snap Load with the first image, or receipt manager for new trip
      const imageFile = receiptFiles.find(f => f.type.startsWith('image/'));
      if (imageFile) {
        setTimeout(() => openSnapLoad(imageFile), 300);
      } else {
        // PDF receipt — prompt to attach to a trip
        toast(`Received ${receiptFiles.length} receipt${receiptFiles.length > 1 ? 's' : ''}. Create a trip to attach them.`);
        setTimeout(() => openTripWizard(), 300);
      }
    } else {
      toast('Unsupported file type shared', true);
    }
  } catch(e) {
    console.error('[FL] Share target error:', e);
    toast('Failed to process shared files', true);
    try { await caches.delete('freightlogic-share-v1'); } catch(ex) { /* ignore */ }
  }
}

// ---- Router ----
const views = { home:$('#view-home'), trips:$('#view-trips'), expenses:$('#view-expenses'),
  money:$('#view-money'), fuel:$('#view-fuel'), insights:$('#view-insights'), omega:$('#view-omega'), more:$('#view-more') };

function setActiveNav(name){
  // Sub-sections accessible from More menu highlight the More tab
  const navName = ['expenses','fuel','insights','omega'].includes(name) ? 'more' : name;
  $$('[data-nav]').forEach(a => {
    const isActive = a.dataset.nav === navName;
    a.classList.toggle('active', isActive);
    if (isActive) haptic(5);
  });
}

async function navigate(){
  const hash = (location.hash || '#home').slice(1);

  // ── Handle share target: process shared files, then redirect to home ──
  if (hash === 'share') {
    await handleShareTarget();
    location.hash = '#home';
    return;
  }

  const name = views[hash] ? hash : 'home';
  Object.entries(views).forEach(([k,el]) => {
    if (k === name){
      el.style.display = '';
      el.classList.remove('entering');
      void el.offsetWidth; // force reflow
      el.classList.add('entering');
    } else { el.style.display = 'none'; el.classList.remove('entering'); }
  });
  setActiveNav(name);
  window.scrollTo({top:0, behavior:'instant'});
  if (name === 'home') await renderHome();
  if (name === 'trips') await renderTrips(true);
  if (name === 'expenses') await renderExpenses(true);
  if (name === 'money') await renderAR();
  if (name === 'fuel') await renderFuel(true);
  if (name === 'insights') await renderInsights();
  if (name === 'omega') await renderOmega();
  if (name === 'more') await renderMore();
}
window.addEventListener('hashchange', navigate);

// Header scroll shadow
window.addEventListener('scroll', ()=>{
  $('#mainHeader').classList.toggle('scrolled', window.scrollY > 8);
}, {passive:true});

// ---- UX: Stagger animation for list items ----
function staggerItems(container){
  const items = container.querySelectorAll('.item:not(.enter)');
  items.forEach((el, i) => {
    el.classList.add('enter');
    el.style.animationDelay = `${i * 40}ms`;
  });
}

function showSkeleton(container, count=3){
  container.innerHTML = '';
  for (let i = 0; i < count; i++){
    const s = document.createElement('div'); s.className = 'skel';
    s.style.animationDelay = `${i * 100}ms`;
    container.appendChild(s);
  }
}

// ---- UX: Pull-to-refresh ----
function setupPTR(ptrId, listId, refreshFn){
  const list = $(listId);
  if (!list) return;
  const ptrEl = $(`#${ptrId}`);
  if (!ptrEl) return;
  let startY = 0, pulling = false;
  list.parentElement.addEventListener('touchstart', (e)=>{
    if (window.scrollY > 30) return;
    startY = e.touches[0].clientY; pulling = true;
  }, {passive:true});
  list.parentElement.addEventListener('touchmove', (e)=>{
    if (!pulling) return;
    const dy = e.touches[0].clientY - startY;
    if (dy > 60) ptrEl.classList.add('active');
    else ptrEl.classList.remove('active');
  }, {passive:true});
  list.parentElement.addEventListener('touchend', async ()=>{
    if (!pulling) return; pulling = false;
    if (ptrEl.classList.contains('active')){
      ptrEl.innerHTML = '<span class="ptr-spin"></span> Refreshing…';
      haptic(20);
      try{ await refreshFn(); }catch(e){ console.warn("[FL]", e); }
      ptrEl.innerHTML = '';
    }
    ptrEl.classList.remove('active');
  }, {passive:true});
}

// ---- UX: KPI pulse animation ----
function pulseKPI(el){
  el.classList.remove('kpi-pop');
  void el.offsetWidth;
  el.classList.add('kpi-pop');
}

// ---- UI: Home ----
async function renderHome(){
  const state = await getOnboardState();
  const trips = await listTrips({cursor:null});
  const recent = trips.items.slice(0,6);
  const box = $('#homeRecentTrips');
  box.innerHTML = '';

  // ── Welcome card (replaces Ω calculator card for new users) ──
  const welcomeSlot = $('#homeWelcome');
  const omegaLink = $('#homeOmegaCard');
  const perfCard = $('#homePerfCard');

  if (state.isEmpty){
    // Show welcome, hide omega card and performance center
    if (welcomeSlot){
      welcomeSlot.innerHTML = renderWelcomeCard();
      welcomeSlot.style.display = '';
      welcomeSlot.querySelector('#welcomeAddTrip')?.addEventListener('click', ()=> { haptic(); openQuickAddSheet(); });
    }
    if (omegaLink) omegaLink.style.display = 'none';
    if (perfCard) perfCard.style.display = 'none';
    box.innerHTML = '';
  } else {
    // Hide welcome, show normal cards
    if (welcomeSlot) welcomeSlot.style.display = 'none';
    if (omegaLink) omegaLink.style.display = '';
    if (perfCard) perfCard.style.display = '';

    if (!recent.length) box.innerHTML = `<div class="muted" style="font-size:12px">No trips yet. Tap ＋ to add your first trip.</div>`;
    else { recent.forEach(t => box.appendChild(tripRow(t, {compact:true}))); staggerItems(box); }
  }

  // ── Beginner encouragement in performance card ──
  const coachEl = $('#pcCoaching');
  if (state.isBeginner && coachEl){
    coachEl.innerHTML = `<div style="padding:10px 12px;border-radius:10px;background:rgba(255,179,0,.08);border:1px solid rgba(255,179,0,.15);font-size:12px">
      <span style="font-weight:700;color:var(--accent)">Getting started!</span>
      <span class="muted"> Log a few more trips and your dashboard will show RPM trends, broker grades, and profit scores automatically.</span>
    </div>`;
  }

  const actions = $('#homeActions');
  actions.innerHTML = '';

  if (state.isEmpty){
    actions.appendChild(actionCard('Ready to roll?', 'Add First Trip', ()=> openQuickAddSheet()));
    actions.appendChild(actionCard('Got a rate confirmation?', 'Snap Load (OCR)', ()=> openSnapLoad()));
  } else {
    const unpaidList = await listUnpaidTrips(6);
    if (unpaidList.length) actions.appendChild(actionCard(`You have ${unpaidList.length} unpaid trip(s)`, 'Go to Money', ()=> location.hash = '#money'));
    else actions.appendChild(actionCard('All caught up', 'View Trips', ()=> location.hash = '#trips'));

    // P3-4: backup reminder
    const lastExp = await getSetting('lastExportDate', null);
    if (!lastExp || daysBetweenISO(lastExp, isoDate()) > 7){
      actions.appendChild(actionCard(`Haven't backed up in ${lastExp ? daysBetweenISO(lastExp, isoDate()) + ' days' : 'a while'}`, 'Export Now', ()=> exportJSON()));
    } else {
      actions.appendChild(actionCard('Export a backup', 'Export JSON', ()=> exportJSON()));
    }

    // Weekly reflection: show Fri-Sun if not yet done this week
    const dayOfWeek = new Date().getDay(); // 0=Sun, 5=Fri, 6=Sat
    if (dayOfWeek >= 5 || dayOfWeek === 0){
      const weekStart = startOfWeek(new Date()).toISOString().slice(0,10);
      const reflection = await getSetting('weeklyReflection', null);
      const lastReflectWeek = reflection?.week || '';
      if (lastReflectWeek !== weekStart){
        actions.appendChild(actionCard('End-of-week check-in', 'Reflect on Your Week', ()=> openWeeklyReflection()));
      }
    }
  }
  staggerItems(actions);

  invalidateKPICache();
  await computeKPIs();
  if (!state.isEmpty) await Promise.all([
    renderCommandCenter(),
    renderWeeklyChart().catch(()=>{}),
    checkOverduePayments(),
  ]);
  await refreshStorageHealth('');
}

// ---- Performance Command Center ----
async function renderCommandCenter(){
  try{
    const { trips, exps } = await _getTripsAndExps();
    const now = new Date();
    const today = isoDate();
    const wk0 = startOfWeek(now).getTime();
    const d7 = now.getTime() - 7 * 86400000;
    const d14 = now.getTime() - 14 * 86400000;
    const d30 = now.getTime() - 30 * 86400000;

    // Revenue velocity: $/day over last 7 days vs previous 7
    let rev7 = 0, rev14 = 0;
    for (const t of trips){
      const dt = t.pickupDate || t.deliveryDate;
      if (!dt) continue;
      const ts = new Date(dt).getTime();
      const pay = Number(t.pay || 0);
      if (ts >= d7) rev7 += pay;
      else if (ts >= d14) rev14 += pay;
    }
    const velNow = rev7 / 7;
    const velPrev = rev14 / 7;
    const velEl = $('#pcRevVel');
    if (velEl){
      velEl.textContent = `${fmtMoney(velNow)}/d`;
      const parent = velEl.closest('.pill');
      if (parent){
        if (velPrev > 0 && velNow < velPrev * 0.8) parent.className = 'pill danger';
        else if (velPrev > 0 && velNow > velPrev * 1.1) parent.className = 'pill';
        else parent.className = 'pill';
      }
    }

    // Weekly target: user goal if set, else auto from 30-day avg
    const userGoal = Number(await getSetting('weeklyGoal', 0) || 0);
    let gross30 = 0, trips30 = 0;
    for (const t of trips){
      const dt = t.pickupDate || t.deliveryDate;
      if (dt && new Date(dt).getTime() >= d30){ gross30 += Number(t.pay || 0); trips30++; }
    }
    const autoTarget = (gross30 / 30) * 7 || 0;
    const weeklyTarget = userGoal > 0 ? userGoal : autoTarget;
    let wkGross = 0;
    for (const t of trips){
      const dt = t.pickupDate || t.deliveryDate;
      if (dt && new Date(dt).getTime() >= wk0) wkGross += Number(t.pay || 0);
    }
    const targetPct = weeklyTarget > 0 ? Math.min(200, (wkGross / weeklyTarget) * 100) : 0;

    const tgtEl = $('#pcWkTarget');
    if (tgtEl){
      tgtEl.textContent = weeklyTarget > 0 ? fmtMoney(weeklyTarget) : '\u2014';
      if (userGoal > 0) tgtEl.style.color = 'var(--accent)';
      else tgtEl.style.color = '';
    }

    const bar = $('#pcProgressBar');
    if (bar){
      bar.style.width = `${Math.min(100, targetPct)}%`;
      if (targetPct >= 100) bar.style.background = 'var(--good)';
      else if (targetPct >= 70) bar.style.background = 'var(--accent)';
      else bar.style.background = 'var(--warn)';
    }
    const label = $('#pcProgressLabel');
    if (label) label.textContent = weeklyTarget > 0
      ? `${fmtMoney(wkGross)} of ${fmtMoney(weeklyTarget)}${userGoal > 0 ? ' goal' : ' target'} (${targetPct.toFixed(0)}%)`
      : 'Set a weekly goal in Settings \u2192 Insights';

    // Goal coaching
    const coachEl = $('#pcCoaching');
    if (coachEl && weeklyTarget > 0){
      const remaining = Math.max(0, weeklyTarget - wkGross);
      const dayOfWeek = now.getDay();
      const daysLeft = dayOfWeek === 0 ? 1 : 7 - dayOfWeek;
      let avgMiPerLoad = 350;
      const recent30mi = trips.filter(t => {
        const dt = t.pickupDate || t.deliveryDate;
        return dt && new Date(dt).getTime() >= d30;
      });
      let totalMi30 = 0, loadCount30 = 0;
      for (const t of recent30mi){
        const mi = Number(t.loadedMiles||0) + Number(t.emptyMiles||0);
        if (mi > 0){ totalMi30 += mi; loadCount30++; }
      }
      if (loadCount30 >= 3) avgMiPerLoad = Math.round(totalMi30 / loadCount30);

      if (remaining <= 0){
        coachEl.innerHTML = `<div style="padding:8px 12px;border-radius:10px;background:rgba(107,255,149,.08);border:1px solid rgba(107,255,149,.2);font-size:12px;color:var(--good);font-weight:700">Target hit! ${fmtMoney(wkGross - weeklyTarget)} above goal</div>`;
      } else {
        const minRpm = avgMiPerLoad > 0 ? (remaining / avgMiPerLoad) : 0;
        const loadsNeeded = trips30 > 0 ? Math.ceil(remaining / (gross30 / trips30 || remaining)) : '?';
        coachEl.innerHTML = `<div style="padding:8px 12px;border-radius:10px;background:rgba(255,179,0,.06);border:1px solid rgba(255,179,0,.2);font-size:12px">
          <span style="font-weight:700;color:var(--accent)">${fmtMoney(remaining)} to go</span>
          <span class="muted"> \u2022 ${daysLeft}d left \u2022 ~${loadsNeeded} load${loadsNeeded!==1?'s':''} at avg \u2022 Min RPM for ${fmtNum(avgMiPerLoad)}mi: <b>$${minRpm.toFixed(2)}</b></span>
        </div>`;
      }
    } else if (coachEl){ coachEl.innerHTML = ''; }

    // Efficiency score
    let ld30 = 0, all30 = 0;
    for (const t of trips){
      const dt = t.pickupDate || t.deliveryDate;
      if (dt && new Date(dt).getTime() >= d30){
        ld30 += Number(t.loadedMiles || 0);
        all30 += Number(t.loadedMiles || 0) + Number(t.emptyMiles || 0);
      }
    }
    const eff = all30 > 0 ? ((ld30 / all30) * 100) : 0;
    const effEl = $('#pcEfficiency');
    if (effEl){
      effEl.textContent = all30 > 0 ? `${eff.toFixed(0)}%` : '\u2014';
      const pp = effEl.closest('.pill');
      if (pp){
        if (eff >= 85) pp.className = 'pill';
        else if (eff >= 70) pp.className = 'pill warn';
        else if (all30 > 0) pp.className = 'pill danger';
      }
    }

    // Average load score (last 30 days)
    let scoreSum = 0, scoreCnt = 0, acceptCount = 0;
    const recent30 = trips.filter(t => {
      const dt = t.pickupDate || t.deliveryDate;
      return dt && new Date(dt).getTime() >= d30;
    });
    for (const t of recent30){
      const mi = Number(t.loadedMiles||0) + Number(t.emptyMiles||0);
      if (mi <= 0) continue;
      try{
        const s = computeLoadScore(t, trips, exps);
        scoreSum += s.marginScore; scoreCnt++;
        if (s.verdict === 'PREMIUM WIN' || s.verdict === 'ACCEPT') acceptCount++;
      }catch(e){ console.warn("[FL]", e); }
    }
    const avgScore = scoreCnt > 0 ? Math.round(scoreSum / scoreCnt) : 0;
    const acceptRate = scoreCnt > 0 ? Math.round((acceptCount / scoreCnt) * 100) : 0;

    const asEl = $('#pcAvgScore');
    if (asEl){
      asEl.textContent = scoreCnt > 0 ? `${avgScore}` : '\u2014';
      const pp = asEl.closest('.pill');
      if (pp){
        if (avgScore >= 60) pp.className = 'pill';
        else if (avgScore >= 40) pp.className = 'pill warn';
        else if (scoreCnt > 0) pp.className = 'pill danger';
      }
    }
    const arEl = $('#pcAcceptRate');
    if (arEl) arEl.textContent = scoreCnt > 0 ? `${acceptRate}%` : '\u2014';

    // Fuel cost drift
    const allFuel = await dumpStore('fuel');
    const fuel30 = allFuel.filter(f => f.date && new Date(f.date).getTime() >= d30);
    const fuel60 = allFuel.filter(f => {
      if (!f.date) return false;
      const ts = new Date(f.date).getTime();
      const d60 = now.getTime() - 60 * 86400000;
      return ts >= d60 && ts < d30;
    });
    let gal30 = 0, amt30 = 0, gal60 = 0, amt60 = 0;
    for (const f of fuel30){ gal30 += Number(f.gallons||0); amt30 += Number(f.amount||0); }
    for (const f of fuel60){ gal60 += Number(f.gallons||0); amt60 += Number(f.amount||0); }
    const ppg30 = gal30 > 0 ? amt30 / gal30 : 0;
    const ppg60 = gal60 > 0 ? amt60 / gal60 : 0;
    const fdEl = $('#pcFuelDrift');
    if (fdEl){
      if (ppg30 > 0 && ppg60 > 0){
        const drift = ((ppg30 - ppg60) / ppg60) * 100;
        fdEl.textContent = `${drift >= 0 ? '+' : ''}${drift.toFixed(1)}%`;
        const pp = fdEl.closest('.pill');
        if (pp){
          if (drift > 5) pp.className = 'pill danger';
          else if (drift > 0) pp.className = 'pill warn';
          else pp.className = 'pill';
        }
      } else { fdEl.textContent = '\u2014'; }
    }

    // Show secondary stats row in Pro mode
    const detailRow = $('#pcDetailRow');
    if (detailRow){
      const uiMode = await getSetting('uiMode','simple');
      detailRow.style.display = uiMode === 'pro' ? '' : 'none';
    }

    // \u2500\u2500 Trend Alerts \u2500\u2500
    await renderTrendAlerts(trips, exps, allFuel, {
      wkGross, weeklyTarget, userGoal, velNow, velPrev,
      eff, all30, avgScore, scoreCnt, ppg30, ppg60,
      d7, d14, d30, wk0, now, today
    });
  }catch(e){ console.warn("[FL]", e); }
}

// ====================================================================
//  TREND ALERTS \u2014 Passive intelligence on Home
// ====================================================================
async function renderTrendAlerts(trips, exps, fuel, ctx){
  const box = $('#trendAlerts');
  if (!box) return;
  box.innerHTML = '';
  const alerts = [];

  // 1. RPM declining
  let rpm7mi = 0, rpm7pay = 0, rpm14mi = 0, rpm14pay = 0;
  for (const t of trips){
    const dt = t.pickupDate || t.deliveryDate;
    if (!dt) continue;
    const ts = new Date(dt).getTime();
    const mi = Number(t.loadedMiles||0) + Number(t.emptyMiles||0);
    const pay = Number(t.pay||0);
    if (ts >= ctx.d7){ rpm7mi += mi; rpm7pay += pay; }
    else if (ts >= ctx.d14){ rpm14mi += mi; rpm14pay += pay; }
  }
  const rpm7 = rpm7mi > 0 ? rpm7pay / rpm7mi : 0;
  const rpm14 = rpm14mi > 0 ? rpm14pay / rpm14mi : 0;
  if (rpm14 > 0 && rpm7 > 0 && rpm7 < rpm14 * 0.88){
    const drop = ((1 - rpm7/rpm14) * 100).toFixed(0);
    alerts.push({ severity:'danger', title:`RPM down ${drop}% this week`, detail:`$${rpm7.toFixed(2)} vs $${rpm14.toFixed(2)} last week`, action:()=> location.hash='#omega', cta:'Check \u03a9 tiers' });
  } else if (rpm14 > 0 && rpm7 > 0 && rpm7 < rpm14 * 0.95){
    const drop = ((1 - rpm7/rpm14) * 100).toFixed(0);
    alerts.push({ severity:'warn', title:`RPM dipping ${drop}%`, detail:`$${rpm7.toFixed(2)} vs $${rpm14.toFixed(2)} prior week`, action:()=> location.hash='#omega', cta:'Review pricing' });
  }

  // 2. Deadhead trending up
  let dh7 = 0, mi7 = 0, dh14 = 0, mi14 = 0;
  for (const t of trips){
    const dt = t.pickupDate || t.deliveryDate;
    if (!dt) continue;
    const ts = new Date(dt).getTime();
    const e = Number(t.emptyMiles||0);
    const m = Number(t.loadedMiles||0) + e;
    if (ts >= ctx.d7){ dh7 += e; mi7 += m; }
    else if (ts >= ctx.d14){ dh14 += e; mi14 += m; }
  }
  const dhPct7 = mi7 > 0 ? (dh7/mi7)*100 : 0;
  const dhPct14 = mi14 > 0 ? (dh14/mi14)*100 : 0;
  if (mi7 > 0 && dhPct7 > 25){
    alerts.push({ severity:'danger', title:`Deadhead at ${dhPct7.toFixed(0)}%`, detail:`High empty miles. Prior week: ${dhPct14.toFixed(0)}%`, action:()=> location.hash='#insights', cta:'View insights' });
  } else if (mi7 > 0 && mi14 > 0 && dhPct7 > dhPct14 * 1.3 && dhPct7 > 15){
    alerts.push({ severity:'warn', title:`Deadhead trending up`, detail:`${dhPct7.toFixed(0)}% this week vs ${dhPct14.toFixed(0)}% prior`, action:()=> location.hash='#insights', cta:'View insights' });
  }

  // 3. Broker with old unpaid loads (>30 days)
  const brokerUnpaid = new Map();
  for (const t of trips){
    if (t.isPaid) continue;
    const dt = t.pickupDate || t.deliveryDate;
    if (!dt) continue;
    const age = daysBetweenISO(dt, ctx.today);
    if (age !== null && age > 30){
      const name = t.customer || 'Unknown';
      if (!brokerUnpaid.has(name)) brokerUnpaid.set(name, { count:0, total:0, maxAge:0 });
      const rec = brokerUnpaid.get(name);
      rec.count++; rec.total += Number(t.pay||0); rec.maxAge = Math.max(rec.maxAge, age);
    }
  }
  for (const [name, rec] of brokerUnpaid){
    if (rec.count >= 2 || rec.maxAge > 45){
      alerts.push({ severity:'danger', title:`${name}: ${rec.count} unpaid load${rec.count>1?'s':''} (${rec.maxAge}d old)`, detail:`${fmtMoney(rec.total)} outstanding`, action:()=> location.hash='#money', cta:'View AR' });
    } else {
      alerts.push({ severity:'warn', title:`${name}: unpaid ${rec.maxAge}d`, detail:`${fmtMoney(rec.total)} outstanding`, action:()=> location.hash='#money', cta:'View AR' });
    }
  }

  // 4. Fuel cost rising
  if (ctx.ppg30 > 0 && ctx.ppg60 > 0){
    const drift = ((ctx.ppg30 - ctx.ppg60) / ctx.ppg60) * 100;
    if (drift > 8){
      alerts.push({ severity:'danger', title:`Fuel cost up ${drift.toFixed(0)}%`, detail:`$${ctx.ppg30.toFixed(3)}/gal vs $${ctx.ppg60.toFixed(3)} prior month`, action:()=> location.hash='#fuel', cta:'Review fuel' });
    } else if (drift > 3){
      alerts.push({ severity:'warn', title:`Fuel cost up ${drift.toFixed(1)}%`, detail:`$${ctx.ppg30.toFixed(3)}/gal vs $${ctx.ppg60.toFixed(3)} prior`, action:()=> location.hash='#fuel', cta:'Review fuel' });
    }
  }

  // 5. Below weekly goal pace
  if (ctx.userGoal > 0 && ctx.weeklyTarget > 0){
    const dayOfWeek = ctx.now.getDay();
    const daysIn = dayOfWeek === 0 ? 7 : dayOfWeek;
    const expectedPace = (ctx.weeklyTarget / 7) * daysIn;
    if (ctx.wkGross < expectedPace * 0.7 && daysIn >= 3){
      const pct = ((ctx.wkGross / expectedPace) * 100).toFixed(0);
      alerts.push({ severity:'warn', title:`Behind pace: ${pct}% of expected`, detail:`${fmtMoney(ctx.wkGross)} of ${fmtMoney(expectedPace)} expected by day ${daysIn}`, action:null, cta:null });
    }
  }

  // 6. Revenue velocity dropping
  if (ctx.velPrev > 0 && ctx.velNow < ctx.velPrev * 0.7 && ctx.velPrev > 100){
    alerts.push({ severity:'warn', title:`Revenue velocity dropped`, detail:`${fmtMoney(ctx.velNow)}/day vs ${fmtMoney(ctx.velPrev)}/day last week`, action:()=> location.hash='#trips', cta:'View trips' });
  }

  // 7. Low efficiency
  if (ctx.all30 > 0 && ctx.eff < 70){
    alerts.push({ severity:'warn', title:`Efficiency low: ${ctx.eff.toFixed(0)}%`, detail:`${(100-ctx.eff).toFixed(0)}% of miles are deadhead (30d avg)`, action:()=> location.hash='#insights', cta:'View insights' });
  }

  // 8. Concentration risk
  const d60 = ctx.now.getTime() - 60 * 86400000;
  const recent60 = trips.filter(t => {
    const dt = t.pickupDate || t.deliveryDate;
    return dt && new Date(dt).getTime() >= d60;
  });
  if (recent60.length >= 8){
    const bMap = new Map();
    for (const t of recent60) bMap.set(t.customer||'Unknown', (bMap.get(t.customer||'Unknown')||0)+1);
    for (const [name, count] of bMap){
      const pct = (count / recent60.length) * 100;
      if (pct > 60) alerts.push({ severity:'warn', title:`Concentration risk: ${name}`, detail:`${pct.toFixed(0)}% of your last ${recent60.length} loads`, action:()=> location.hash='#omega', cta:'Diversify' });
    }
  }

  // 9. Stale best lane
  const lanes = computeLaneStats(trips);
  const topLanes = lanes.filter(l => l.trips >= 3).sort((a,b) => b.avgRpm - a.avgRpm);
  if (topLanes.length > 0){
    const best = topLanes[0];
    if (best.daysSinceLast !== null && best.daysSinceLast > 30){
      alerts.push({ severity:'info', title:`Best lane idle ${best.daysSinceLast}d`, detail:`${best.display} ($${best.avgRpm} avg RPM)`, action:()=> location.hash='#omega', cta:'View lanes' });
    }
  }

  // 10. Average load score low
  if (ctx.scoreCnt >= 5 && ctx.avgScore < 40){
    alerts.push({ severity:'warn', title:`Avg load score low: ${ctx.avgScore}`, detail:`Recent loads scoring below target`, action:()=> location.hash='#omega', cta:'Check \u03a9 tiers' });
  }

  // Render (max 5, sorted by severity)
  if (!alerts.length) return;
  const sevOrder = { danger:0, warn:1, info:2 };
  alerts.sort((a,b) => (sevOrder[a.severity]||9) - (sevOrder[b.severity]||9));
  alerts.slice(0, 5).forEach(a => box.appendChild(alertCard(a)));
  staggerItems(box);
}

function alertCard(alert){
  const d = document.createElement('div'); d.className = 'item';
  const borderColor = alert.severity === 'danger' ? 'rgba(255,107,107,.35)' :
    alert.severity === 'warn' ? 'rgba(255,179,0,.35)' : 'rgba(88,166,255,.25)';
  const bgColor = alert.severity === 'danger' ? 'rgba(255,107,107,.04)' :
    alert.severity === 'warn' ? 'rgba(255,179,0,.04)' : 'rgba(88,166,255,.04)';
  const icon = alert.severity === 'danger' ? '\ud83d\udd34' : alert.severity === 'warn' ? '\ud83d\udfe1' : '\ud83d\udd35';
  d.style.cssText = `border-left:3px solid ${borderColor};background:${bgColor};border-radius:10px;padding:10px 12px;margin-bottom:6px`;
  d.innerHTML = `<div class="left">
    <div class="v" style="font-size:13px">${icon} ${escapeHtml(alert.title)}</div>
    <div class="sub" style="font-size:12px">${escapeHtml(alert.detail)}</div>
  </div>${alert.cta ? `<div class="right"><button class="btn sm">${escapeHtml(alert.cta)}</button></div>` : ''}`;
  if (alert.action){
    const btn = $('button', d);
    if (btn) btn.addEventListener('click', alert.action);
  }
  return d;
}

function actionCard(title, cta, onClick){
  const d = document.createElement('div'); d.className = 'item';
  d.innerHTML = `<div class="left"><div class="v">${escapeHtml(title)}</div><div class="sub">Tap once — no clutter</div></div><div class="right"><button class="btn">${escapeHtml(cta)}</button></div>`;
  $('button', d).addEventListener('click', onClick);
  return d;
}

// ---- UI: Trips list ----
let tripCursor = null;
let tripSearchTerm = '';
let tripFilterDateFrom = '';
let tripFilterDateTo = '';

async function renderTrips(reset=false){
  const list = $('#tripList');
  if (reset){ tripCursor = null; showSkeleton(list); }
  const res = await listTrips({cursor: tripCursor, search: tripSearchTerm, dateFrom: tripFilterDateFrom, dateTo: tripFilterDateTo});
  tripCursor = res.nextCursor;
  if (reset) list.innerHTML = '';
  if (!res.items.length && reset){
    const empty = renderEmptyState('🚚', 'No trips yet', 'Every load you log builds your profit intelligence — RPM trends, broker grades, and lane analysis all start here.', '＋ Add Trip', ()=> openQuickAddSheet());
    list.innerHTML = '';
    list.appendChild(empty);
  }
  else { res.items.forEach(t => list.appendChild(tripRow(t))); staggerItems(list); }
  $('#btnTripMore').disabled = !tripCursor;
  await computeKPIs();
  await refreshStorageHealth('');
}

// P2-2: trip row shows RPM, route, paid tag, LOAD SCORE
function tripRow(t, {compact=false}={}){
  const d = document.createElement('div'); d.className = 'item';
  const pay = fmtMoney(t.pay||0);
  const miles = (Number(t.loadedMiles||0) + Number(t.emptyMiles||0));
  const rpm = miles>0 ? (Number(t.pay||0)/miles) : 0;
  const tag = t.isPaid ? `<span class="tag good">PAID</span>` : `<span class="tag bad">UNPAID</span>`;
  const runTag = t.wouldRunAgain ? `<span class="tag" style="background:rgba(88,166,255,.1);border-color:rgba(88,166,255,.3);color:#58a6ff;font-size:10px">↻ REPEAT</span>` : '';
  const route = (t.origin && t.destination) ? `${t.origin} → ${t.destination} • ` : '';
  const stopCount = Array.isArray(t.stops) ? t.stops.length : 0;
  const stopsTag = stopCount > 0 ? `<span class="tag" style="background:rgba(139,92,246,.1);border-color:rgba(139,92,246,.3);color:#a78bfa;font-size:10px">${stopCount} stop${stopCount>1?'s':''}</span>` : '';
  // Compute load score for badge (uses cached KPI data)
  let scoreBadge = '';
  if (miles > 0 && _kpiCache.trips){
    try {
      const score = computeLoadScore(t, _kpiCache.trips, _kpiCache.exps || []);
      scoreBadge = scoreBadgeHTML(score);
      d._loadScore = score;
    } catch(e){ console.warn("[FL]", e); }
  }
  d.innerHTML = `
    <div class="left">
      <div class="split"><div class="v">${escapeHtml(t.orderNo||'')}</div>${tag}${runTag}${stopsTag}${scoreBadge}</div>
      <div class="sub">${escapeHtml(t.customer || '')}${t.customer ? ' • ' : ''}${escapeHtml(route)}${escapeHtml(t.pickupDate||'')}</div>
      ${compact ? '' : `<div class="k">${fmtNum(miles)} mi • <b>$${rpm.toFixed(2)} RPM</b></div>`}
    </div>
    <div class="right">
      <div class="v">${pay}</div>
      <div class="split">
        <button class="btn sm" data-act="edit">Edit</button>
        <button class="btn sm" data-act="receipts">Receipts</button>
        <button class="btn sm" data-act="nav">Nav</button>
        <button class="btn sm" data-act="paid">${t.isPaid?'Unpay':'Paid'}</button>
      </div>
    </div>`;
  // Score badge tap → open breakdown
  const scoreEl = $('[data-act="score"]', d);
  if (scoreEl){
    scoreEl.addEventListener('click', (e)=>{
      e.stopPropagation();
      haptic(15);
      if (d._loadScore) openScoreBreakdown(t, d._loadScore);
    });
  }
  $('[data-act="edit"]', d).addEventListener('click', ()=> openTripWizard(t));
  $('[data-act="receipts"]', d).addEventListener('click', ()=> openReceiptManager(t.orderNo));

  $('[data-act="nav"]', d).addEventListener('click', (e)=>{ e.stopPropagation(); haptic(15); openTripNavigation(t); });
  $('[data-act="paid"]', d).addEventListener('click', async ()=>{
    haptic(15);
    t.isPaid = !t.isPaid; t.paidDate = t.isPaid ? isoDate() : null;
    await upsertTrip(t); invalidateKPICache();
    toast(t.isPaid ? 'Marked paid' : 'Marked unpaid');
    await renderAR(); await renderTrips(true);
  });
  return d;
}

// ---- UI: Receipt Manager ----
async function openReceiptManager(orderNo){
  const body = document.createElement('div');
  body.className = 'card'; body.style.cssText = 'border:0; box-shadow:none; background:transparent; padding:0';
  const rec = await getReceipts(orderNo);
  const files = rec?.files || [];

  if (!files.length){
    body.innerHTML = `<div class="muted" style="font-size:12px">No receipts for this trip.</div>`;
    const addWrap = document.createElement('div'); addWrap.style.marginTop = '12px';
    addWrap.innerHTML = `<label>Add receipts</label><input id="rm_files" type="file" accept="image/*,application/pdf" multiple /><div class="btn-row" style="margin-top:10px"><button class="btn primary" id="rm_save">Upload</button></div>`;
    body.appendChild(addWrap);
    addWrap.querySelector('#rm_save').addEventListener('click', async ()=>{
      const inp = addWrap.querySelector('#rm_files');
      if (!inp.files?.length){ toast('Select files first', true); return; }
      await saveNewReceipts(orderNo, inp.files); toast('Receipts saved'); closeModal(); await renderTrips(true);
    });
    openModal(`Receipts • ${orderNo}`, body); return;
  }

  const grid = document.createElement('div');
  grid.style.cssText = 'display:flex; flex-wrap:wrap; gap:10px; margin-bottom:12px';
  for (const f of files){
    const card = document.createElement('div');
    card.style.cssText = 'position:relative; border:1px solid var(--line); border-radius:12px; overflow:hidden; width:120px; background:rgba(255,255,255,.03)';
    if (f.thumbDataUrl){
      const img = document.createElement('img'); img.src = f.thumbDataUrl;
      img.style.cssText = 'width:100%; height:90px; object-fit:cover; display:block'; card.appendChild(img);
    } else {
      const ph = document.createElement('div');
      ph.style.cssText = 'width:100%; height:90px; display:grid; place-items:center; font-size:11px; color:var(--muted)';
      ph.textContent = f.name || 'receipt'; card.appendChild(ph);
    }
    const info = document.createElement('div');
    info.style.cssText = 'padding:6px; font-size:11px; color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap';
    info.textContent = f.name || 'receipt'; card.appendChild(info);

    const viewBtn = document.createElement('button'); viewBtn.className = 'btn';
    viewBtn.style.cssText = 'width:100%; border-radius:0 0 12px 12px; font-size:11px; padding:6px';
    viewBtn.textContent = f.cached ? 'View' : 'Thumb only';
    if (f.cached){
      viewBtn.addEventListener('click', async ()=>{
        try{ const data = await cacheGetReceipt(f.id); if (!data){ toast('Receipt not in cache', true); return; }
          const url = URL.createObjectURL(data.blob); window.open(url, '_blank', 'noopener,noreferrer'); setTimeout(()=> URL.revokeObjectURL(url), 30000);
        }catch{ toast('Failed to open receipt', true); }
      });
    } else viewBtn.disabled = true;
    card.appendChild(viewBtn);

    const delBtn = document.createElement('button');
    delBtn.style.cssText = 'position:absolute; top:4px; right:4px; width:22px; height:22px; border-radius:50%; border:1px solid rgba(255,107,107,.4); background:rgba(255,107,107,.15); color:#ff6b6b; font-size:12px; cursor:pointer; display:grid; place-items:center';
    delBtn.textContent = '✕';
    delBtn.addEventListener('click', async ()=>{
      if (!confirm(`Delete ${f.name || 'this receipt'}?`)) return;
      try{ await cacheDeleteReceipt(f.id); }catch(e){ console.warn("[FL]", e); }
      await putReceipts(orderNo, files.filter(x => x.id !== f.id));
      toast('Receipt removed'); closeModal(); await openReceiptManager(orderNo);
    });
    card.appendChild(delBtn); grid.appendChild(card);
  }
  body.appendChild(grid);

  const addWrap = document.createElement('div');
  addWrap.innerHTML = `<label>Add more receipts</label><input id="rm_files" type="file" accept="image/*,application/pdf" multiple /><div class="btn-row" style="margin-top:10px"><button class="btn primary" id="rm_save">Upload</button></div>`;
  body.appendChild(addWrap);
  addWrap.querySelector('#rm_save').addEventListener('click', async ()=>{
    const inp = addWrap.querySelector('#rm_files');
    if (!inp.files?.length){ toast('Select files first', true); return; }
    await saveNewReceipts(orderNo, inp.files); toast('Receipts saved'); closeModal(); await openReceiptManager(orderNo);
  });
  openModal(`Receipts • ${orderNo} (${files.length})`, body);
}

const ALLOWED_RECEIPT_TYPES = new Set(['image/jpeg','image/png','image/gif','image/webp','image/heic','image/heif','application/pdf']);
async function saveNewReceipts(orderNo, fileList){
  const arr = [];
  for (const file of fileList){
    if (arr.length >= LIMITS.MAX_RECEIPTS_PER_TRIP){ toast(`Limit: ${LIMITS.MAX_RECEIPTS_PER_TRIP} receipts per trip`, true); break; }
    if (file.size > LIMITS.MAX_RECEIPT_BYTES){ toast(`Skipping ${file.name}: too large`, true); continue; }
    if (!ALLOWED_RECEIPT_TYPES.has((file.type || '').toLowerCase())){ toast(`Skipping ${file.name}: unsupported type`, true); continue; }
    const id = randId();
    const thumbDataUrl = await makeThumbDataUrl(file);
    await cachePutReceipt(id, file);
    arr.push({ id, name: file.name, type: file.type, size: file.size, added: Date.now(), thumbDataUrl, cached: true, status: 'cached' });
  }
  const existing = await getReceipts(orderNo);
  const merged = (existing?.files || []).concat(arr).sort((a,b)=> (b.added||0)-(a.added||0)).slice(0, LIMITS.MAX_RECEIPTS_PER_TRIP);
  await putReceipts(orderNo, merged);
  await enforceReceiptCacheLimit();
}

// ---- UI: Expenses ----
let expCursor = null;
let expSearchTerm = '';
async function renderExpenses(reset=false){
  const list = $('#expenseList');
  if (reset){ expCursor = null; showSkeleton(list); }
  const res = await listExpenses({cursor: expCursor, search: expSearchTerm});
  expCursor = res.nextCursor;
  if (reset) list.innerHTML = '';
  if (!res.items.length && reset){
    const empty = renderEmptyState('💰', 'No expenses yet', 'Track fuel, tolls, insurance, repairs — everything gets categorized for tax time. Takes 5 seconds.', '＋ Add Expense', ()=> openExpenseForm());
    list.innerHTML = '';
    list.appendChild(empty);
  }
  else { res.items.forEach(e => list.appendChild(expenseRow(e))); staggerItems(list); }
  $('#btnExpMore').disabled = !expCursor;
  await computeKPIs();
  await refreshStorageHealth('');
}

function expenseRow(e){
  const d = document.createElement('div'); d.className = 'item';
  d.innerHTML = `<div class="left"><div class="v">${escapeHtml(e.category||'Expense')}</div><div class="sub">${escapeHtml([e.date, e.notes].filter(Boolean).join(' • '))}</div></div>
    <div class="right"><div class="v">${fmtMoney(e.amount||0)}</div><div class="split"><button class="btn sm" data-act="edit">Edit</button><button class="btn sm danger" data-act="del">Del</button></div></div>`;
  $('[data-act="edit"]', d).addEventListener('click', ()=> openExpenseForm(e));
  $('[data-act="del"]', d).addEventListener('click', async ()=>{
    const mode = await getSetting('uiMode','simple');
    if (mode !== 'pro'){ toast('Delete is Pro-only (prevents accidents)', true); return; }
    if (!confirm('Delete this expense?')) return;
    await deleteExpense(e.id); invalidateKPICache(); toast('Deleted'); await renderExpenses(true);
  });
  return d;
}

// ---- UI: Fuel (P1-3 NEW) ----
let fuelCursor = null;
async function renderFuel(reset=false){
  const list = $('#fuelList');
  if (reset){ fuelCursor = null; showSkeleton(list); }
  const res = await listFuel({cursor: fuelCursor});
  fuelCursor = res.nextCursor;
  if (reset) list.innerHTML = '';
  if (!res.items.length && reset){
    const empty = renderEmptyState('⛽', 'No fuel entries yet', 'Log each fill-up with state and gallons. Fuel tracking powers cost analysis and mileage estimates.', '＋ Add Fuel', ()=> openFuelForm());
    list.innerHTML = '';
    list.appendChild(empty);
  }
  else { res.items.forEach(f => list.appendChild(fuelRow(f))); staggerItems(list); }
  $('#btnFuelMore').disabled = !fuelCursor;

  // IFTA summary
  const allFuel = await dumpStore('fuel');
  const byState = {};
  for (const f of allFuel){
    const st = (f.state || 'N/A').toUpperCase();
    if (!byState[st]) byState[st] = { gallons:0, amount:0 };
    byState[st].gallons += Number(f.gallons||0);
    byState[st].amount += Number(f.amount||0);
  }
  const box = $('#iftaSummary');
  box.innerHTML = '';
  const states = Object.entries(byState).sort((a,b)=> b[1].gallons - a[1].gallons);
  if (!states.length) box.innerHTML = `<div class="muted" style="font-size:12px">Add fuel entries to see state-by-state breakdown.</div>`;
  else states.forEach(([st, d]) => {
    const ppg = d.gallons > 0 ? (d.amount/d.gallons).toFixed(3) : '0';
    const p = document.createElement('div'); p.className = 'pill';
    p.innerHTML = `<span class="muted">${escapeHtml(st)}</span> <b>${d.gallons.toFixed(1)} gal</b> <span class="muted">${fmtMoney(d.amount)} ($${ppg}/gal)</span>`;
    box.appendChild(p);
  });
}

function fuelRow(f){
  const d = document.createElement('div'); d.className = 'item';
  const ppg = f.gallons > 0 ? (f.amount/f.gallons).toFixed(3) : '—';
  d.innerHTML = `<div class="left"><div class="v">${escapeHtml(f.date||'')}${f.state?' • '+escapeHtml(f.state):''}</div>
    <div class="sub">${f.gallons.toFixed(1)} gal • $${ppg}/gal${f.notes?' • '+escapeHtml(f.notes):''}</div></div>
    <div class="right"><div class="v">${fmtMoney(f.amount||0)}</div>
    <div class="split"><button class="btn sm" data-act="edit">Edit</button><button class="btn sm danger" data-act="del">Del</button></div></div>`;
  $('[data-act="edit"]', d).addEventListener('click', ()=> openFuelForm(f));
  $('[data-act="del"]', d).addEventListener('click', async ()=>{
    const mode = await getSetting('uiMode','simple');
    if (mode !== 'pro'){ toast('Delete is Pro-only', true); return; }
    if (!confirm('Delete this fuel entry?')) return;
    await deleteFuel(f.id); invalidateKPICache(); toast('Deleted'); await renderFuel(true);
  });
  return d;
}

// ---- UI: AR ----
async function listUnpaidTrips(limit=200){
  const {stores} = tx('trips');
  const out = [];
  return new Promise((resolve,reject)=>{
    const req = stores.trips.index('created').openCursor(null,'prev');
    req.onerror = ()=> reject(req.error);
    req.onsuccess = (e)=>{
      const cur = e.target.result;
      if (!cur || out.length >= limit){ resolve(out); return; }
      if (!cur.value.isPaid) out.push(cur.value);
      cur.continue();
    };
  });
}
async function renderAR(){
  const list = $('#arList'); list.innerHTML = '';
  const items = await listUnpaidTrips(200);

  // Populate AR aging pills in Money header
  const today = new Date();
  let b0=0, b16=0, b31=0, b46=0;
  for (const t of items){
    const days = t.pickupDate ? Math.max(0, Math.floor((today - new Date(t.pickupDate)) / 86400000)) : 0;
    const pay = Number(t.pay || 0);
    if (days <= 15) b0 += pay;
    else if (days <= 30) b16 += pay;
    else if (days <= 45) b31 += pay;
    else b46 += pay;
  }
  const set = (id, v) => { const el = $(id); if (el) el.textContent = fmtMoney(v); };
  set('#ar0_15m', b0); set('#ar16_30m', b16); set('#ar31_45m', b31); set('#ar46pm', b46);

  if (!items.length){
    const empty = renderEmptyState('✅', 'All caught up!', 'No unpaid trips. When you log a trip, it starts as unpaid — come here to mark loads paid when the check clears.', '', null);
    list.appendChild(empty);
    await computeKPIs(); return;
  }
  items.forEach(t => {
    const d = document.createElement('div'); d.className = 'item';
    d.innerHTML = `<div class="left"><div class="v">${escapeHtml(t.orderNo)}</div><div class="sub">${escapeHtml([t.customer, t.pickupDate].filter(Boolean).join(' • '))}</div></div>
      <div class="right"><div class="v">${fmtMoney(t.pay||0)}</div><button class="btn primary sm">Mark Paid</button></div>`;
    $('button', d).addEventListener('click', async ()=>{
      haptic(20);
      t.isPaid = true; t.paidDate = isoDate(); await upsertTrip(t); invalidateKPICache(); toast('Marked paid'); await renderAR(); await computeKPIs();
    });
    list.appendChild(d);
  });
  staggerItems(list);
  await computeKPIs();
  await refreshStorageHealth('');
}

// ---- UI: Insights ----
async function renderInsights(){
  const uiMode = await getSetting('uiMode','simple');
  const vClass = await getSetting('vehicleClass', 'cargo_van');
  const vcEl = $('#vehicleClass');
  if (vcEl) vcEl.value = vClass;
  $('#uiMode').value = uiMode || 'simple';
  $('#perDiemRate').value = await getSetting('perDiemRate', '') || '';
  $('#brokerWindow').value = String(await getSetting('brokerWindow', 90) || 90);
  $('#weeklyGoal').value = await getSetting('weeklyGoal', '') || '';
  $('#iftaMode').value = await getSetting('iftaMode', 'off') || 'off';
  $('#vehicleMpg').value = await getSetting('vehicleMpg', '') || '';
  $('#fuelPrice').value = await getSetting('fuelPrice', '') || '';
  $('#opCostPerMile').value = await getSetting('opCostPerMile', '') || '';
  const hlEl = $('#settingsHomeLocation');
  if (hlEl) hlEl.value = await getSetting('homeLocation', '') || '';
  // DAT API settings
  const datEnabled = await getSetting('datApiEnabled', 'off') || 'off';
  const datEl = $('#datApiEnabled');
  if (datEl) datEl.value = datEnabled;
  const datUrlEl = $('#datApiBaseUrl');
  if (datUrlEl) datUrlEl.value = await getSetting('datApiBaseUrl', '') || '';
  const datFields = $('#datApiFields');
  if (datFields) datFields.style.display = datEnabled === 'on' ? '' : 'none';
  if (datEl) {
    datEl.addEventListener('change', ()=>{
      if (datFields) datFields.style.display = datEl.value === 'on' ? '' : 'none';
    });
  }
  // Canada settings
  const caEnabled = await getSetting('canadaEnabled', 'off') || 'off';
  const caEl = $('#canadaEnabled');
  if (caEl) caEl.value = caEnabled;
  const caFields = $('#canadaFields');
  if (caFields) caFields.style.display = caEnabled === 'on' ? '' : 'none';
  const cadRateEl = $('#cadUsdRate');
  if (cadRateEl) cadRateEl.value = await getSetting('cadUsdRate', '') || '';
  const borderCostEl = $('#borderAdminCost');
  if (borderCostEl) borderCostEl.value = await getSetting('borderAdminCost', '') || '';
  const caDocsEl = $('#canadaDocsReady');
  if (caDocsEl) caDocsEl.checked = !!(await getSetting('canadaDocsReady', false));
  if (caEl) {
    caEl.addEventListener('change', ()=>{
      if (caFields) caFields.style.display = caEl.value === 'on' ? '' : 'none';
    });
  }
  // Cloud Backup settings
  const cbUrl = $('#cloudBackupUrl');
  if (cbUrl) cbUrl.value = await getSetting('cloudBackupUrl', '') || '';
  const cbPass = $('#cloudBackupPass');
  if (cbPass) cbPass.value = await getSetting('cloudBackupPass', '') || '';
  const cbToken = $('#cloudBackupToken');
  if (cbToken) cbToken.value = await getSetting('cloudBackupToken', '') || '';
  _lastCloudSync = Number(await getSetting('lastCloudSync', 0) || 0);
  updateCloudStatus();
  $('#btnCloudPush')?.addEventListener('click', async ()=>{
    haptic(20);
    await cloudPushBackup(false);
  });
  $('#btnCloudPull')?.addEventListener('click', async ()=>{
    haptic(20);
    await cloudPullBackup();
  });
  invalidateKPICache();
  await computeKPIs();
  await refreshStorageHealth('');
}

// ---- More menu ----
const MORE_TILES = [
  { icon:'💰', title:'Expenses', sub:'Track fuel, tolls, repairs', hash:'#expenses' },
  { icon:'⛽', title:'Fuel Log', sub:'Fill-ups & cost tracking', hash:'#fuel' },
  { icon:'⚡', title:'Midwest Stack', sub:'Load filter & market board', hash:'#omega' },
  { icon:'📊', title:'Tax & Reports', sub:'Quick tax view, accountant export', hash:'#insights' },
  { icon:'📥', title:'Import Data', sub:'CSV, Excel, JSON, PDF, TXT', act:'import' },
  { icon:'💾', title:'Export & Backup', sub:'JSON export with checksum', act:'export' },
];

let _moreBound = false;
async function renderMore(){
  const grid = $('#moreMenu');
  if (!_moreBound){
    _moreBound = true;
    grid.innerHTML = '';
    for (const tile of MORE_TILES){
      const el = document.createElement('div');
      el.className = 'menu-tile';
      el.setAttribute('role', 'button');
      el.setAttribute('tabindex', '0');
      el.setAttribute('aria-label', tile.title);
      el.innerHTML = `<div class="ti">${escapeHtml(tile.icon)}</div><div class="tt">${escapeHtml(tile.title)}</div><div class="ts">${escapeHtml(tile.sub)}</div>`;
      const tileAction = ()=>{
        haptic(15);
        if (tile.hash) location.hash = tile.hash;
        else if (tile.act === 'import') openUniversalImport();
        else if (tile.act === 'export') exportJSON();
      };
      el.addEventListener('click', tileAction);
      el.addEventListener('keydown', (e)=>{ if (e.key === 'Enter' || e.key === ' '){ e.preventDefault(); tileAction(); } });
      grid.appendChild(el);
    }
    // Quick settings save
    $('#moreSaveSettings').addEventListener('click', async ()=>{
      await setSetting('weeklyGoal', Number($('#moreWeeklyGoal').value || 0));
      await setSetting('vehicleMpg', Number($('#moreVehicleMpg').value || 0));
      await setSetting('fuelPrice', Number($('#moreFuelPrice').value || 0));
      await setSetting('perDiemRate', Number($('#morePerDiem').value || 0));
      // Sync with full settings page
      $('#weeklyGoal').value = $('#moreWeeklyGoal').value;
      $('#vehicleMpg').value = $('#moreVehicleMpg').value;
      $('#fuelPrice').value = $('#moreFuelPrice').value;
      $('#perDiemRate').value = $('#morePerDiem').value;
      toast('Settings saved'); invalidateKPICache(); await computeKPIs();
    });
  }
  // Populate current values
  $('#moreWeeklyGoal').value = await getSetting('weeklyGoal', '') || '';
  $('#moreVehicleMpg').value = await getSetting('vehicleMpg', '') || '';
  $('#moreFuelPrice').value = await getSetting('fuelPrice', '') || '';
  $('#morePerDiem').value = await getSetting('perDiemRate', '') || '';
  $('#moreVersion').textContent = APP_VERSION;
}

// Storage health
async function countStore(name){ try{ const {stores} = tx(name); return (await idbReq(stores[name].count())) || 0; }catch{ return 0; } }

/** Onboarding: detect app state */
async function getOnboardState(){
  const [trips, exps, fuel] = await Promise.all([countStore('trips'), countStore('expenses'), countStore('fuel')]);
  return { trips, exps, fuel, isEmpty: trips === 0, isBeginner: trips > 0 && trips < 4, isActive: trips >= 4 };
}

function renderWelcomeCard(){
  return `<div class="card" style="text-align:center;padding:28px 20px">
    <div style="font-size:48px;margin-bottom:12px">🚐</div>
    <h2 style="margin:0 0 8px 0;font-size:20px">Welcome to Freight Logic</h2>
    <p class="muted" style="font-size:14px;line-height:1.5;margin-bottom:20px;max-width:340px;margin-left:auto;margin-right:auto">Your personal freight command center. Track loads, expenses, and fuel — see exactly where your money goes.</p>
    <div style="text-align:left;max-width:320px;margin:0 auto 20px auto">
      <div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:14px">
        <div style="font-size:20px;line-height:1">①</div>
        <div><div style="font-weight:700;font-size:13px">Log your first trip</div><div class="muted" style="font-size:12px">Tap the ＋ button below, then "＋ Trip"</div></div>
      </div>
      <div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:14px">
        <div style="font-size:20px;line-height:1">②</div>
        <div><div style="font-weight:700;font-size:13px">Add any expenses</div><div class="muted" style="font-size:12px">Fuel, tolls, insurance — anything you spend</div></div>
      </div>
      <div style="display:flex;gap:10px;align-items:flex-start">
        <div style="font-size:20px;line-height:1">③</div>
        <div><div style="font-weight:700;font-size:13px">Watch your dashboard light up</div><div class="muted" style="font-size:12px">RPM, profit scores, broker grades — all automatic</div></div>
      </div>
    </div>
    <button class="btn primary" id="welcomeAddTrip" style="font-size:15px;padding:12px 32px">＋ Add Your First Trip</button>
    <div class="muted" style="font-size:11px;margin-top:14px">Or tap 📸 Snap Load to scan a rate confirmation photo</div>
  </div>`;
}

function renderEmptyState(icon, title, subtitle, btnLabel, btnAction){
  const wrap = document.createElement('div');
  wrap.style.cssText = 'text-align:center;padding:40px 20px';
  wrap.innerHTML = `<div style="font-size:40px;margin-bottom:10px;opacity:.7">${icon}</div>
    <div style="font-weight:700;font-size:14px;margin-bottom:6px">${escapeHtml(title)}</div>
    <div class="muted" style="font-size:12px;margin-bottom:16px;max-width:280px;margin-left:auto;margin-right:auto">${escapeHtml(subtitle)}</div>
    ${btnLabel ? `<button class="btn primary emptyBtn">${escapeHtml(btnLabel)}</button>` : ''}`;
  if (btnLabel && btnAction){
    wrap.querySelector('.emptyBtn').addEventListener('click', ()=> { haptic(); btnAction(); });
  }
  return wrap;
}
async function storageHealthSnapshot(){
  return { trips: await countStore('trips'), expenses: await countStore('expenses'), fuel: await countStore('fuel'), receiptSets: await countStore('receipts'), receiptBlobs: await countStore('receiptBlobs') };
}
async function refreshStorageHealth(statusText=''){
  try{
    const snap = await storageHealthSnapshot();
    $('#stTrips').textContent = String(snap.trips);
    $('#stExpenses').textContent = String(snap.expenses);
    $('#stFuel').textContent = String(snap.fuel);
    $('#stReceiptSets').textContent = String(snap.receiptSets);
    $('#stReceiptBlobs').textContent = String(snap.receiptBlobs);
    $('#stStatus').textContent = statusText || 'OK';
  }catch(e){ console.error('[FL] Storage health error:', e); $('#stStatus').textContent = 'Error — check console for details'; }
}
async function analyzeReceiptBlobSizes(){
  const status = $('#stStatus'); status.textContent = 'Analyzing…';
  try{
    const all = await idbReq(tx('receiptBlobs').stores.receiptBlobs.getAll());
    let total = 0;
    for (const rec of (all||[])) total += (rec?.blob?.size || 0);
    status.textContent = `Receipt blobs: ${(all||[]).length} • Total ~${(total/1024/1024).toFixed(1)} MB`;
  }catch(e){ console.error('[FL] Receipt analysis error:', e); status.textContent = 'Analysis failed — check console for details'; }
}
async function clearReceiptCache(){
  try{
    if (hasCacheStorage()) await caches.delete(RECEIPT_CACHE);
    const {t:txn, stores} = tx('receiptBlobs','readwrite');
    stores.receiptBlobs.clear(); await waitTxn(txn);
    await refreshStorageHealth('Receipt cache cleared.');
  }catch(e){ $('#stStatus').textContent = 'Clear failed: ' + (e?.message || e); }
}
async function rebuildReceiptIndex(){
  const status = $('#stStatus'); status.textContent = 'Rebuilding…';
  try{
    const all = await getAllReceipts();
    const idsInMeta = new Set();
    for (const set of all){
      const files = Array.isArray(set.files) ? set.files : [];
      let changed = false;
      for (const f of files){ if (!f.id){ f.id = randId(); changed = true; } idsInMeta.add(f.id); }
      if (changed) await putReceipts(set.tripOrderNo, files);
    }
    const metas = await idbListReceiptBlobMeta();
    for (const m of metas) if (!idsInMeta.has(m.id)) await idbDeleteReceiptBlob(m.id);
    await refreshStorageHealth('Receipt index rebuilt.');
  }catch(e){ status.textContent = 'Rebuild failed: ' + (e?.message || e); }
}


// ═══════════════════════════════════════════════════════════════════════
// USA FREIGHT ENGINE v1.0 — Nationwide Cargo-Van Market Intelligence
// Two-layer architecture: National geography + Operator strategy profile
// ═══════════════════════════════════════════════════════════════════════

const USA_ZONES = {
  MIDWEST:     { label: 'Midwest',       anchors: ['chicago','indianapolis','columbus','detroit','cleveland'] },
  SOUTHEAST:   { label: 'Southeast',     anchors: ['atlanta','nashville','charlotte'] },
  TEXAS:       { label: 'Texas',         anchors: ['dallas'] },
  NORTHEAST:   { label: 'Northeast',     anchors: ['pittsburgh','harrisburg','allentown'] },
  MIDATLANTIC: { label: 'Mid-Atlantic',  anchors: ['newark','baltimore','richmond'] },
  PLAINS:      { label: 'Plains',        anchors: ['kansas city','omaha'] },
  MOUNTAIN:    { label: 'Mountain',      anchors: ['denver','salt lake city'] },
  WEST_COAST:  { label: 'West Coast',    anchors: ['los angeles','seattle','portland'] },
  FLORIDA:     { label: 'Florida',       anchors: [] },
  SOUTH_TEXAS: { label: 'South Texas',   anchors: [] },
};

const USA_MARKET_ROLES = { anchor: 18, support: 9, feeder: 2, transitional: -6, trap: -18 };

const USA_MARKETS = {
  // ── Midwest ──
  'chicago':       { zone:'MIDWEST', role:'anchor',       bias:'very_strong' },
  'indianapolis':  { zone:'MIDWEST', role:'anchor',       bias:'very_strong' },
  'columbus':      { zone:'MIDWEST', role:'anchor',       bias:'strong' },
  'detroit':       { zone:'MIDWEST', role:'anchor',       bias:'strong' },
  'cleveland':     { zone:'MIDWEST', role:'anchor',       bias:'strong' },
  'louisville':    { zone:'MIDWEST', role:'support',      bias:'strong' },
  'cincinnati':    { zone:'MIDWEST', role:'support',      bias:'strong' },
  'dayton':        { zone:'MIDWEST', role:'support',      bias:'moderate' },
  'toledo':        { zone:'MIDWEST', role:'support',      bias:'moderate' },
  'st. louis':     { zone:'MIDWEST', role:'support',      bias:'moderate' },
  'grand rapids':  { zone:'MIDWEST', role:'feeder',       bias:'moderate' },
  'fort wayne':    { zone:'MIDWEST', role:'feeder',       bias:'moderate' },
  'evansville':    { zone:'MIDWEST', role:'feeder',       bias:'moderate' },
  // ── Southeast ──
  'atlanta':       { zone:'SOUTHEAST', role:'anchor',     bias:'strong' },
  'nashville':     { zone:'SOUTHEAST', role:'anchor',     bias:'strong' },
  'charlotte':     { zone:'SOUTHEAST', role:'anchor',     bias:'moderate' },
  'memphis':       { zone:'SOUTHEAST', role:'support',    bias:'moderate' },
  'knoxville':     { zone:'SOUTHEAST', role:'support',    bias:'moderate' },
  'greenville':    { zone:'SOUTHEAST', role:'support',    bias:'moderate' },
  'raleigh':       { zone:'SOUTHEAST', role:'support',    bias:'moderate' },
  'chattanooga':   { zone:'SOUTHEAST', role:'feeder',     bias:'moderate' },
  'savannah':      { zone:'SOUTHEAST', role:'feeder',     bias:'weak' },
  'jacksonville':  { zone:'SOUTHEAST', role:'transitional', bias:'weak' },
  // ── Texas ──
  'dallas':        { zone:'TEXAS', role:'anchor',         bias:'strong' },
  'houston':       { zone:'TEXAS', role:'support',        bias:'moderate', notes:'compression risk' },
  'austin':        { zone:'TEXAS', role:'support',        bias:'moderate' },
  'san antonio':   { zone:'TEXAS', role:'support',        bias:'moderate' },
  'fort worth':    { zone:'TEXAS', role:'support',        bias:'moderate' },
  // ── Northeast / Mid-Atlantic ──
  'pittsburgh':    { zone:'NORTHEAST', role:'anchor',     bias:'strong' },
  'harrisburg':    { zone:'NORTHEAST', role:'anchor',     bias:'strong' },
  'allentown':     { zone:'NORTHEAST', role:'anchor',     bias:'strong' },
  'newark':        { zone:'MIDATLANTIC', role:'anchor',   bias:'strong' },
  'baltimore':     { zone:'MIDATLANTIC', role:'anchor',   bias:'strong' },
  'richmond':      { zone:'MIDATLANTIC', role:'anchor',   bias:'moderate' },
  'philadelphia':  { zone:'MIDATLANTIC', role:'support',  bias:'moderate' },
  'norfolk':       { zone:'MIDATLANTIC', role:'feeder',   bias:'weak' },
  // ── Plains ──
  'kansas city':   { zone:'PLAINS', role:'transitional',  bias:'weak', notes:'feeder not anchor' },
  'omaha':         { zone:'PLAINS', role:'feeder',        bias:'weak' },
  'des moines':    { zone:'PLAINS', role:'feeder',        bias:'weak' },
  'minneapolis':   { zone:'PLAINS', role:'support',       bias:'moderate' },
  // ── Mountain ──
  'denver':        { zone:'MOUNTAIN', role:'transitional', bias:'weak' },
  'salt lake city':{ zone:'MOUNTAIN', role:'transitional', bias:'weak' },
  // ── West Coast ──
  'los angeles':   { zone:'WEST_COAST', role:'anchor',    bias:'moderate' },
  'seattle':       { zone:'WEST_COAST', role:'support',   bias:'moderate' },
  'portland':      { zone:'WEST_COAST', role:'support',   bias:'moderate' },
  'phoenix':       { zone:'WEST_COAST', role:'transitional', bias:'weak' },
  // ── TRAP MARKETS ──
  'miami':         { zone:'FLORIDA', role:'trap',         bias:'very_weak' },
  'fort lauderdale':{ zone:'FLORIDA', role:'trap',        bias:'very_weak' },
  'west palm beach':{ zone:'FLORIDA', role:'trap',        bias:'very_weak' },
  'orlando':       { zone:'FLORIDA', role:'transitional', bias:'weak' },
  'tampa':         { zone:'FLORIDA', role:'transitional', bias:'weak' },
  'laredo':        { zone:'SOUTH_TEXAS', role:'trap',     bias:'very_weak' },
  'mcallen':       { zone:'SOUTH_TEXAS', role:'trap',     bias:'very_weak' },
  'brownsville':   { zone:'SOUTH_TEXAS', role:'trap',     bias:'very_weak' },
  'midland':       { zone:'SOUTH_TEXAS', role:'trap',     bias:'very_weak' },
  'odessa':        { zone:'SOUTH_TEXAS', role:'trap',     bias:'very_weak' },
  'el paso':       { zone:'SOUTH_TEXAS', role:'trap',     bias:'very_weak' },
  'duluth':        { zone:'PLAINS', role:'trap',          bias:'very_weak' },
  'marquette':     { zone:'MIDWEST', role:'trap',         bias:'very_weak' },
  'portland me':   { zone:'NORTHEAST', role:'trap',       bias:'very_weak' },
  'bangor':        { zone:'NORTHEAST', role:'trap',       bias:'very_weak' },
  'burlington vt': { zone:'NORTHEAST', role:'trap',       bias:'very_weak' },
  'spokane':       { zone:'MOUNTAIN', role:'trap',        bias:'very_weak' },
};

const USA_CORRIDORS = [
  { id:'mw_mw',    name:'Midwest ↔ Midwest',         orZones:['MIDWEST'], deZones:['MIDWEST'],               laneClass:'favorable',     bonus: 15 },
  { id:'mw_se',    name:'Midwest → Southeast',        orZones:['MIDWEST'], deZones:['SOUTHEAST'],             laneClass:'favorable',     bonus: 10 },
  { id:'se_mw',    name:'Southeast → Midwest',        orZones:['SOUTHEAST'], deZones:['MIDWEST'],             laneClass:'favorable',     bonus: 12 },
  { id:'mw_ne',    name:'Midwest → Northeast',        orZones:['MIDWEST'], deZones:['NORTHEAST','MIDATLANTIC'], laneClass:'favorable',   bonus: 10 },
  { id:'ne_mw',    name:'Northeast → Midwest',        orZones:['NORTHEAST','MIDATLANTIC'], deZones:['MIDWEST'], laneClass:'favorable',   bonus: 12 },
  { id:'tx_mw',    name:'Texas → Midwest',            orZones:['TEXAS'], deZones:['MIDWEST'],                 laneClass:'favorable',     bonus: 10 },
  { id:'mw_tx',    name:'Midwest → Texas',            orZones:['MIDWEST'], deZones:['TEXAS'],                 laneClass:'neutral',       bonus: 0 },
  { id:'se_fl',    name:'Southeast → Florida',        orZones:['SOUTHEAST'], deZones:['FLORIDA'],             laneClass:'risky',         bonus: -12 },
  { id:'any_fl',   name:'Any → Deep Florida',         orZones:['MIDWEST','NORTHEAST','TEXAS','PLAINS'], deZones:['FLORIDA'], laneClass:'risky', bonus: -15 },
  { id:'stx_int',  name:'South Texas internal',       orZones:['SOUTH_TEXAS','TEXAS'], deZones:['SOUTH_TEXAS'], laneClass:'risky',       bonus: -18 },
  { id:'mw_wc',    name:'Midwest → West Coast',       orZones:['MIDWEST'], deZones:['WEST_COAST'],            laneClass:'premium_only',  bonus: -8 },
  { id:'wc_mw',    name:'West Coast → Midwest',       orZones:['WEST_COAST'], deZones:['MIDWEST'],            laneClass:'favorable',     bonus: 8 },
  { id:'mtn_any',  name:'Mountain corridors',         orZones:['MOUNTAIN'], deZones:['MOUNTAIN','PLAINS','WEST_COAST'], laneClass:'neutral', bonus: -5 },
  { id:'se_se',    name:'Southeast ↔ Southeast',      orZones:['SOUTHEAST'], deZones:['SOUTHEAST'],           laneClass:'neutral',       bonus: 4 },
  { id:'ne_ne',    name:'Northeast ↔ Northeast',      orZones:['NORTHEAST','MIDATLANTIC'], deZones:['NORTHEAST','MIDATLANTIC'], laneClass:'neutral', bonus: 4 },
  { id:'tx_tx',    name:'Texas ↔ Texas (core)',       orZones:['TEXAS'], deZones:['TEXAS'],                   laneClass:'neutral',       bonus: 2 },
];

const USA_MODES = {
  HARVEST:       { label:'Harvest',       rpmFloor:1.60, deadheadCap:80,  desc:'In density — maximize yield',         trapMult:1.4, transitionalMult:1.3 },
  REPOSITION:    { label:'Reposition',    rpmFloor:1.45, deadheadCap:120, desc:'Move toward target density',           trapMult:1.1, transitionalMult:0.8 },
  ESCAPE:        { label:'Escape',        rpmFloor:1.40, deadheadCap:150, desc:'Exit oversupplied region',             trapMult:0.9, transitionalMult:0.7 },
  FLOOR_PROTECT: { label:'Floor Protect', rpmFloor:1.50, deadheadCap:100, desc:'Late-week revenue stabilization',      trapMult:1.2, transitionalMult:1.0 },
};

const USA_PROFILES = {
  MIDWEST_STACK: {
    label: 'Midwest Stack',
    homeZone: 'MIDWEST',
    preferredZones: ['MIDWEST'],
    secondaryZones: ['SOUTHEAST','NORTHEAST','MIDATLANTIC','TEXAS'],
    avoidZones: ['MOUNTAIN'],
    trapPenaltyMultiplier: 1.25,
    outOfPreferredZonePenalty: 10,
    returnToHomeBonus: 12,
  },
};

// ════════════════════════════════════════════════════════════════
// CANADA ENGINE — North America Cross-Border Intelligence v1
// Extends the USA engine with country-aware scoring.
// Exchange rate: Bank of Canada / FRED. Border data: BTS / CBSA.
// ════════════════════════════════════════════════════════════════

const CA = Object.freeze({
  /** Default CAD→USD conversion. User-adjustable in settings. */
  DEFAULT_CAD_USD: 0.735,   // ~1 CAD = $0.735 USD (March 2026, FRED DEXCAUS ~1.36)
  BORDER_ADMIN_COST_DEFAULT: 50,  // USD, user-adjustable, covers tolls + customs broker fee avg
});

const CA_ZONES = {
  ON_CORE:    { label: 'Ontario Core',     country: 'CA', province: 'ON', anchors: ['toronto','mississauga','brampton'] },
  QC_CORE:    { label: 'Quebec Core',      country: 'CA', province: 'QC', anchors: ['montreal'] },
  PRAIRIE_CA: { label: 'Prairie Canada',   country: 'CA', province: 'MB', anchors: ['winnipeg'] },
  ALBERTA:    { label: 'Alberta Corridor', country: 'CA', province: 'AB', anchors: ['calgary','edmonton'] },
  BC_LOWER:   { label: 'BC Lower Mainland',country: 'CA', province: 'BC', anchors: ['vancouver'] },
  ATLANTIC_CA:{ label: 'Atlantic Canada',  country: 'CA', province: 'NB', anchors: [] },
};

const CA_MARKETS = {
  // ── Ontario Core ──
  'toronto':      { zone:'ON_CORE', role:'anchor',       country:'CA', province:'ON', bias:'very_strong' },
  'mississauga':  { zone:'ON_CORE', role:'anchor',       country:'CA', province:'ON', bias:'very_strong' },
  'brampton':     { zone:'ON_CORE', role:'anchor',       country:'CA', province:'ON', bias:'strong' },
  'hamilton':     { zone:'ON_CORE', role:'support',      country:'CA', province:'ON', bias:'strong' },
  'london on':    { zone:'ON_CORE', role:'support',      country:'CA', province:'ON', bias:'moderate' },
  'kitchener':    { zone:'ON_CORE', role:'support',      country:'CA', province:'ON', bias:'moderate' },
  'cambridge':    { zone:'ON_CORE', role:'support',      country:'CA', province:'ON', bias:'moderate' },
  'windsor on':   { zone:'ON_CORE', role:'transitional', country:'CA', province:'ON', bias:'moderate' },
  'oshawa':       { zone:'ON_CORE', role:'support',      country:'CA', province:'ON', bias:'moderate' },
  'ottawa':       { zone:'ON_CORE', role:'support',      country:'CA', province:'ON', bias:'moderate' },
  // ── Quebec Core ──
  'montreal':     { zone:'QC_CORE', role:'anchor',       country:'CA', province:'QC', bias:'strong' },
  'laval':        { zone:'QC_CORE', role:'support',      country:'CA', province:'QC', bias:'moderate' },
  'drummondville':{ zone:'QC_CORE', role:'feeder',       country:'CA', province:'QC', bias:'weak' },
  'quebec city':  { zone:'QC_CORE', role:'support',      country:'CA', province:'QC', bias:'moderate' },
  // ── Prairie Canada ──
  'winnipeg':     { zone:'PRAIRIE_CA', role:'transitional',country:'CA', province:'MB', bias:'weak' },
  'regina':       { zone:'PRAIRIE_CA', role:'feeder',     country:'CA', province:'SK', bias:'very_weak' },
  'saskatoon':    { zone:'PRAIRIE_CA', role:'feeder',     country:'CA', province:'SK', bias:'very_weak' },
  // ── Alberta Corridor ──
  'calgary':      { zone:'ALBERTA', role:'support',       country:'CA', province:'AB', bias:'moderate' },
  'edmonton':     { zone:'ALBERTA', role:'support',       country:'CA', province:'AB', bias:'moderate' },
  'red deer':     { zone:'ALBERTA', role:'feeder',        country:'CA', province:'AB', bias:'weak' },
  // ── BC Lower Mainland ──
  'vancouver':    { zone:'BC_LOWER', role:'anchor',       country:'CA', province:'BC', bias:'strong' },
  'surrey':       { zone:'BC_LOWER', role:'support',      country:'CA', province:'BC', bias:'moderate' },
  'burnaby':      { zone:'BC_LOWER', role:'support',      country:'CA', province:'BC', bias:'moderate' },
  'richmond bc':  { zone:'BC_LOWER', role:'support',      country:'CA', province:'BC', bias:'moderate' },
  'abbotsford':   { zone:'BC_LOWER', role:'feeder',       country:'CA', province:'BC', bias:'weak' },
  // ── Atlantic Canada ──
  'moncton':      { zone:'ATLANTIC_CA', role:'transitional',country:'CA', province:'NB', bias:'weak' },
  'halifax':      { zone:'ATLANTIC_CA', role:'transitional',country:'CA', province:'NS', bias:'weak' },
};

/** Border gateways — scored by commercial truck volume, efficiency, and expedite suitability.
 *  Source: BTS Border Crossing Data 2025, CBSA service standards 2025–2026. */
const CA_GATEWAYS = {
  'detroit_windsor':    { name:'Detroit ↔ Windsor',        usCity:'detroit',    caCity:'windsor on', friction:'low',    volume:'very_high', expediteFit:'excellent', notes:'Ambassador Bridge + Gordie Howe (2026). #1 US-CA truck crossing by value.' },
  'port_huron_sarnia':  { name:'Port Huron ↔ Sarnia',      usCity:'port huron', caCity:'sarnia',     friction:'low',    volume:'high',      expediteFit:'good',      notes:'Blue Water Bridge. Growing +17% YoY. Good alt to Detroit congestion.' },
  'buffalo_fort_erie':  { name:'Buffalo ↔ Fort Erie',      usCity:'buffalo',    caCity:'fort erie',  friction:'moderate',volume:'high',      expediteFit:'good',      notes:'Peace Bridge. Gateway to GTA from Northeast.' },
  'champlain_montreal': { name:'Champlain ↔ Lacolle',      usCity:'champlain',  caCity:'montreal',   friction:'moderate',volume:'high',      expediteFit:'good',      notes:'I-87 corridor into Quebec. Primary Montreal gateway.' },
  'pembina_emerson':    { name:'Pembina ↔ Emerson',        usCity:'pembina',    caCity:'winnipeg',   friction:'moderate',volume:'moderate',  expediteFit:'fair',      notes:'Prairie gateway. Lower volume, longer waits possible.' },
  'blaine_vancouver':   { name:'Blaine ↔ Pacific Hwy',     usCity:'blaine',     caCity:'vancouver',  friction:'moderate',volume:'moderate',  expediteFit:'fair',      notes:'Pacific crossing into BC. Seasonal congestion.' },
};

const CA_FRICTION_SCORES = { low: 0, moderate: -5, high: -12, severe: -20 };
const CA_VOLUME_SCORES = { very_high: 6, high: 3, moderate: 0, low: -4 };

/** Cross-border corridors (US→CA and CA→US) */
const CA_CORRIDORS = [
  { id:'mw_on',    name:'Midwest → Ontario Core',       orZones:['MIDWEST'],                 deZones:['ON_CORE'],    laneClass:'favorable',     bonus: 10, crossBorder: true },
  { id:'on_mw',    name:'Ontario Core → Midwest',       orZones:['ON_CORE'],                 deZones:['MIDWEST'],    laneClass:'favorable',     bonus: 12, crossBorder: true },
  { id:'ne_qc',    name:'Northeast → Quebec',           orZones:['NORTHEAST','MIDATLANTIC'], deZones:['QC_CORE'],    laneClass:'favorable',     bonus: 8,  crossBorder: true },
  { id:'qc_ne',    name:'Quebec → Northeast',           orZones:['QC_CORE'],                 deZones:['NORTHEAST','MIDATLANTIC','MIDWEST'], laneClass:'favorable', bonus: 10, crossBorder: true },
  { id:'on_on',    name:'Ontario ↔ Ontario',            orZones:['ON_CORE'],                 deZones:['ON_CORE'],    laneClass:'favorable',     bonus: 8,  crossBorder: false },
  { id:'mw_qc',    name:'Midwest → Quebec (long)',      orZones:['MIDWEST'],                 deZones:['QC_CORE'],    laneClass:'neutral',       bonus: 0,  crossBorder: true },
  { id:'pl_pr',    name:'Plains → Prairie Canada',      orZones:['PLAINS'],                  deZones:['PRAIRIE_CA'], laneClass:'risky',         bonus: -8, crossBorder: true },
  { id:'wc_bc',    name:'West Coast → BC',              orZones:['WEST_COAST'],              deZones:['BC_LOWER'],   laneClass:'neutral',       bonus: 2,  crossBorder: true },
  { id:'any_atl',  name:'Any → Atlantic Canada',        orZones:['MIDWEST','NORTHEAST','MIDATLANTIC','SOUTHEAST'], deZones:['ATLANTIC_CA'], laneClass:'risky', bonus: -12, crossBorder: true },
  { id:'on_qc',    name:'Ontario → Quebec',             orZones:['ON_CORE'],                 deZones:['QC_CORE'],    laneClass:'neutral',       bonus: 4,  crossBorder: false },
  { id:'any_ab',   name:'Any → Alberta (long-haul)',    orZones:['MIDWEST','PLAINS','MOUNTAIN'], deZones:['ALBERTA'],laneClass:'premium_only',  bonus: -10, crossBorder: true },
];

/** Normalize Canadian city names */
function caNormCity(s){
  return (s || '').trim().toLowerCase()
    .replace(/,?\s*(on|qc|bc|ab|mb|sk|nb|ns|pe|nl|nt|yt|nu|ont|que|canada)\s*$/i, '')
    .replace(/[.,;]/g, '').replace(/\s+/g, ' ').trim();
}

/** Lookup a city — check Canada first, then USA. Returns { city, ...data, country } */
function naLookupMarket(city){
  const norm = caNormCity(city);
  // Direct match in Canada
  if (CA_MARKETS[norm]) return { city: norm, ...CA_MARKETS[norm] };
  // Fuzzy match in Canada
  for (const [key, data] of Object.entries(CA_MARKETS)){
    if (norm.includes(key) || key.includes(norm)) return { city: key, ...data };
  }
  // Fall through to USA
  const usNorm = usaNormCity(city);
  if (USA_MARKETS[usNorm]) return { city: usNorm, ...USA_MARKETS[usNorm], country: 'US' };
  for (const [key, data] of Object.entries(USA_MARKETS)){
    if (usNorm.includes(key) || key.includes(usNorm)) return { city: key, ...data, country: 'US' };
  }
  return null;
}

/** Find best gateway for a cross-border lane */
function caFindGateway(origMarket, destMarket){
  if (!origMarket || !destMarket) return null;
  const origCA = origMarket.country === 'CA';
  const destCA = destMarket.country === 'CA';
  if (origCA === destCA) return null; // Not cross-border
  // Find closest gateway by matching cities
  const usMarket = origCA ? destMarket : origMarket;
  const caMarket = origCA ? origMarket : destMarket;
  // Try direct gateway match
  for (const [id, gw] of Object.entries(CA_GATEWAYS)){
    const gwUsNorm = usaNormCity(gw.usCity);
    const gwCaNorm = caNormCity(gw.caCity);
    // Match if origin/dest is a gateway city or in same zone
    if (usMarket.city === gwUsNorm || caMarket.city === gwCaNorm) return { id, ...gw };
  }
  // Zone-based fallback: find best gateway for the destination zone
  const zoneGateways = {
    'ON_CORE':     'detroit_windsor',
    'QC_CORE':     'champlain_montreal',
    'PRAIRIE_CA':  'pembina_emerson',
    'BC_LOWER':    'blaine_vancouver',
    'ATLANTIC_CA': 'champlain_montreal',
    'ALBERTA':     'pembina_emerson',
  };
  const targetZone = destCA ? destMarket.zone : origMarket.zone;
  const gwId = zoneGateways[targetZone];
  if (gwId && CA_GATEWAYS[gwId]) return { id: gwId, ...CA_GATEWAYS[gwId] };
  return null;
}

/** Find corridor — checks both USA and Canada corridors */
function naFindCorridor(origZone, destZone){
  if (!origZone || !destZone) return null;
  // Check Canada corridors first
  for (const c of CA_CORRIDORS){
    if (c.orZones.includes(origZone) && c.deZones.includes(destZone)) return c;
  }
  // Fall back to USA corridors
  for (const c of USA_CORRIDORS){
    if (c.orZones.includes(origZone) && c.deZones.includes(destZone)) return c;
  }
  return null;
}

/** Cross-border scoring module. Returns adjustment object to add to base score.
 *  Only applies when one end is CA and the other is US. */
function caScoreCrossBorder(origMarket, destMarket, revenue, revenueCurrency, gateway){
  const result = { isCrossBorder: false, adjustments: [], totalAdj: 0, normalizedRevenue: revenue, gateway: null, frictionLevel: null };
  if (!origMarket || !destMarket) return result;
  const origCA = origMarket.country === 'CA';
  const destCA = destMarket.country === 'CA';
  if (!origCA && !destCA) return result; // Domestic US
  if (origCA && destCA){ result.isCrossBorder = false; return result; } // Domestic CA

  result.isCrossBorder = true;
  result.gateway = gateway;

  // 1. Currency normalization
  if (revenueCurrency === 'CAD'){
    const rate = CA.DEFAULT_CAD_USD;
    result.normalizedRevenue = roundCents(revenue * rate);
    result.adjustments.push({ label: 'Currency (CAD→USD)', impact: 0, detail: `CAD $${revenue.toFixed(0)} → USD $${result.normalizedRevenue.toFixed(0)} (@${rate})` });
  }

  // 2. Gateway friction
  if (gateway){
    const frictionAdj = CA_FRICTION_SCORES[gateway.friction] || 0;
    const volumeAdj = CA_VOLUME_SCORES[gateway.volume] || 0;
    result.frictionLevel = gateway.friction;
    result.totalAdj += frictionAdj + volumeAdj;
    result.adjustments.push({ label: 'Border friction', impact: frictionAdj, detail: `${gateway.name} — ${gateway.friction} friction` });
    result.adjustments.push({ label: 'Crossing volume', impact: volumeAdj, detail: `${gateway.volume} commercial volume` });
  } else {
    result.totalAdj -= 8;
    result.adjustments.push({ label: 'Unknown gateway', impact: -8, detail: 'No known gateway — elevated risk' });
  }

  // 3. Documentation / customs complexity
  result.totalAdj -= 3;
  result.adjustments.push({ label: 'Customs/docs overhead', impact: -3, detail: 'Cross-border paperwork + possible delay' });

  // 4. Admin cost deduction (informational — already affects profitability)
  result.adjustments.push({ label: 'Estimated border cost', impact: 0, detail: `~$${CA.BORDER_ADMIN_COST_DEFAULT} (tolls, broker, customs)` });

  // 5. Return-to-US corridor strength (for loads going into Canada)
  if (destCA){
    const reloadStrength = destMarket.bias || 'weak';
    const reloadMap = { very_strong: 5, strong: 2, moderate: 0, weak: -5, very_weak: -10 };
    const reloadAdj = reloadMap[reloadStrength] || -5;
    result.totalAdj += reloadAdj;
    result.adjustments.push({ label: 'CA reload strength', impact: reloadAdj, detail: `${destMarket.city} reload: ${reloadStrength}` });
  }

  return result;
}

// ── USA Engine: Market Lookup (original — kept for backward compatibility) ──
function usaNormCity(s){
  return (s || '').trim().toLowerCase()
    .replace(/,?\s*(al|ak|az|ar|ca|co|ct|de|fl|ga|hi|id|il|in|ia|ks|ky|la|me|md|ma|mi|mn|ms|mo|mt|ne|nv|nh|nj|nm|ny|nc|nd|oh|ok|or|pa|ri|sc|sd|tn|tx|ut|vt|va|wa|wv|wi|wy)\.?$/i, '')
    .replace(/[.,;]/g, '').replace(/\s+/g, ' ').trim();
}

function usaLookupMarket(city){
  if (!city) return null;
  const norm = usaNormCity(city);
  // Direct match
  if (USA_MARKETS[norm]) return { city: norm, ...USA_MARKETS[norm] };
  // Partial match — check if any market key is contained in or contains the input
  for (const [key, data] of Object.entries(USA_MARKETS)){
    if (norm.includes(key) || key.includes(norm)) return { city: key, ...data };
  }
  return null;
}

function usaLookupZone(city){
  const mkt = usaLookupMarket(city);
  return mkt ? mkt.zone : null;
}

function usaFindCorridor(origZone, destZone){
  if (!origZone || !destZone) return null;
  // Find most specific corridor match
  for (const c of USA_CORRIDORS){
    if (c.orZones.includes(origZone) && c.deZones.includes(destZone)) return c;
  }
  return null;
}

// ── North America Engine: Score a Load ──
function usaScoreLoad(opts){
  const { origin, dest, trueRPM, deadMi, loadedMi, mode, profileId, revenue, revenueCurrency } = opts;
  const profile = USA_PROFILES[profileId || 'MIDWEST_STACK'];
  const modeConf = USA_MODES[mode || 'HARVEST'];
  const origMarket = naLookupMarket(origin) || usaLookupMarket(origin);
  const destMarket = naLookupMarket(dest) || usaLookupMarket(dest);
  const origZone = origMarket?.zone || null;
  const destZone = destMarket?.zone || null;
  const corridor = naFindCorridor(origZone, destZone) || usaFindCorridor(origZone, destZone);
  const totalMi = (loadedMi || 0) + (deadMi || 0);

  // Cross-border detection
  const gateway = caFindGateway(origMarket, destMarket);
  const crossBorder = caScoreCrossBorder(origMarket, destMarket, revenue || 0, revenueCurrency || 'USD', gateway);
  // If currency was CAD, use normalized revenue for RPM
  const effectiveRPM = crossBorder.isCrossBorder && revenueCurrency === 'CAD' && totalMi > 0
    ? roundCents(crossBorder.normalizedRevenue / totalMi) : trueRPM;

  const bullets = [];
  let score = 50; // base

  // 1. Economics — True RPM
  let econScore = 0;
  if (trueRPM >= 2.00)      econScore = 28;
  else if (trueRPM >= 1.75)  econScore = 22;
  else if (trueRPM >= 1.60)  econScore = 16;
  else if (trueRPM >= 1.50)  econScore = 10;
  else if (trueRPM >= 1.40)  econScore = 2;
  else                        econScore = -20;
  score += econScore;
  bullets.push({ icon: trueRPM >= 1.50 ? '✓' : '✕', text: `True RPM $${trueRPM.toFixed(2)} — ${trueRPM >= 1.60 ? 'strong' : trueRPM >= 1.50 ? 'acceptable' : trueRPM >= 1.40 ? 'marginal' : 'below floor'}` });

  // 2. Deadhead
  let dhScore = 0;
  if (deadMi <= 35)          dhScore = 8;
  else if (deadMi <= 75)     dhScore = 4;
  else if (deadMi <= 120)    dhScore = -4;
  else                        dhScore = -12;
  if (deadMi > modeConf.deadheadCap) dhScore -= 6;
  score += dhScore;
  if (deadMi > 0) bullets.push({ icon: deadMi <= 75 ? '✓' : '✕', text: `${deadMi} deadhead miles${deadMi > modeConf.deadheadCap ? ' — exceeds ' + modeConf.label + ' cap (' + modeConf.deadheadCap + ')' : ''}` });

  // 3. Destination market role
  let roleScore = 0;
  if (destMarket){
    roleScore = USA_MARKET_ROLES[destMarket.role] || 0;
    if (destMarket.role === 'trap') roleScore = Math.round(roleScore * (profile?.trapPenaltyMultiplier || 1) * (modeConf.trapMult || 1));
    if (destMarket.role === 'transitional') roleScore = Math.round(roleScore * (modeConf.transitionalMult || 1));
    score += roleScore;
    const roleIcon = ['anchor','support'].includes(destMarket.role) ? '✓' : destMarket.role === 'trap' ? '✕' : '–';
    bullets.push({ icon: roleIcon, text: `Destination: ${escapeHtml(destMarket.city)} — ${destMarket.role} market (${USA_ZONES[destMarket.zone]?.label || destMarket.zone})` });
  } else if (dest) {
    score -= 5;
    bullets.push({ icon: '–', text: `Destination "${escapeHtml(dest)}" not in market database` });
  }

  if (origMarket) {
    bullets.push({ icon: '–', text: `Origin: ${escapeHtml(origMarket.city)} — ${origMarket.role} (${USA_ZONES[origMarket.zone]?.label || origMarket.zone})` });
  }

  // 4. Corridor
  let corrScore = 0;
  if (corridor){
    corrScore = corridor.bonus;
    score += corrScore;
    const corrIcon = corridor.bonus > 0 ? '✓' : corridor.bonus < -5 ? '✕' : '–';
    bullets.push({ icon: corrIcon, text: `Corridor: ${escapeHtml(corridor.name)} (${corridor.laneClass}${corridor.bonus > 0 ? ', +' + corridor.bonus : corridor.bonus < 0 ? ', ' + corridor.bonus : ''})` });
  } else if (origZone && destZone) {
    bullets.push({ icon: '–', text: `No specific corridor rule for ${USA_ZONES[origZone]?.label || origZone} → ${USA_ZONES[destZone]?.label || destZone}` });
  }

  // 5. Profile preferred-zone bias
  if (destZone && profile){
    if (profile.preferredZones.includes(destZone)){
      score += profile.returnToHomeBonus;
      bullets.push({ icon: '✓', text: `Destination in preferred zone (${USA_ZONES[destZone]?.label})` });
    } else if (profile.secondaryZones.includes(destZone)){
      // Small penalty for secondary
      score -= Math.round(profile.outOfPreferredZonePenalty * 0.4);
      bullets.push({ icon: '–', text: `Destination in secondary zone (${USA_ZONES[destZone]?.label})` });
    } else if (profile.avoidZones.includes(destZone)){
      score -= profile.outOfPreferredZonePenalty;
      bullets.push({ icon: '✕', text: `Destination in avoid zone (${USA_ZONES[destZone]?.label})` });
    } else {
      score -= profile.outOfPreferredZonePenalty;
      bullets.push({ icon: '–', text: `Destination outside preferred zones` });
    }
  }

  // 6. Mode RPM floor
  if (trueRPM < modeConf.rpmFloor){
    const floorPenalty = Math.round((modeConf.rpmFloor - trueRPM) * 40);
    score -= floorPenalty;
    bullets.push({ icon: '✕', text: `Below ${modeConf.label} RPM floor ($${modeConf.rpmFloor.toFixed(2)})` });
  }

  // ── Cross-border adjustments ──
  if (crossBorder.isCrossBorder){
    score += crossBorder.totalAdj;
    for (const adj of crossBorder.adjustments){
      if (adj.impact !== 0){
        const icon = adj.impact > 0 ? '✓' : '✕';
        bullets.push({ icon, text: `🇨🇦 ${adj.label}: ${adj.detail}` });
      } else if (adj.detail){
        bullets.push({ icon: '–', text: `🇨🇦 ${adj.label}: ${adj.detail}` });
      }
    }
    if (crossBorder.gateway){
      bullets.push({ icon: '–', text: `🛂 Gateway: ${crossBorder.gateway.name} — ${crossBorder.gateway.notes || ''}` });
    }
  }

  // Clamp
  score = Math.max(0, Math.min(100, score));

  // Verdict
  let usaGrade, usaVerdict, usaColor;
  if (score >= 80)      { usaGrade = 'A'; usaVerdict = 'ACCEPT';    usaColor = 'var(--good)'; }
  else if (score >= 68) { usaGrade = 'B'; usaVerdict = 'ACCEPT';    usaColor = '#58a6ff'; }
  else if (score >= 56) { usaGrade = 'C'; usaVerdict = 'STRATEGIC'; usaColor = 'var(--warn)'; }
  else if (score >= 45) { usaGrade = 'D'; usaVerdict = 'CAUTION';   usaColor = '#ff8c42'; }
  else                  { usaGrade = 'F'; usaVerdict = 'REJECT';    usaColor = 'var(--bad)'; }

  return {
    score, usaGrade, usaVerdict, usaColor,
    origMarket, destMarket, origZone, destZone,
    corridor, mode: mode || 'HARVEST', profileId: profileId || 'MIDWEST_STACK',
    modeConf, profile,
    econScore, dhScore, roleScore, corrScore,
    bullets, crossBorder,
  };
}


// ---- Ω Calculator (P2-4: saves last inputs) ----
/* ═══════════════════════════════════════════════════════════════
   MIDWEST STACK — Sustainable Density Operator Engine v3
   90-second load filter, market board, reposition triggers
   ═══════════════════════════════════════════════════════════════ */

const MW = {
  mpg: 16.1,
  fuelBaseline: 2.89,
  weekTarget: { low: 3800, high: 4200 },
  monWed: { low: 2200, high: 2600 },
  thuFri: { low: 1200, high: 1600 },
  surgeFloor: 3000,
  stabilizeFloor: 2000,
  hardRejectRPM: 1.40,
  // Strategic floor — ONLY when replacing deadhead / going home / escaping slow market
  strategicFloorRPM: 1.25,
  longHaulMinRPM: 1.45,
  surgeMinRPM: 1.70,
  tier1: ['chicago','indianapolis','cleveland','columbus','detroit'],
  tier2: ['nashville','louisville','st. louis','st louis','stl'],
  avoid: ['deep southeast','rural southeast','deep texas','far northeast'],
  rpmTiers: [
    { min: 0,    max: 1.24, label: 'Reject',            color: 'var(--bad)',  verdict: 'REJECT' },
    { min: 1.25, max: 1.39, label: 'Strategic Only',    color: 'var(--warn)', verdict: 'STRATEGIC' },
    { min: 1.40, max: 1.49, label: 'Minimum Acceptable', color: '#ff8c42',    verdict: 'ACCEPT' },
    { min: 1.50, max: 1.59, label: 'Professional',   color: 'var(--text)', verdict: 'ACCEPT' },
    { min: 1.60, max: 1.74, label: 'Strong',         color: 'var(--good)', verdict: 'ACCEPT' },
    { min: 1.75, max: 1.99, label: 'Very Strong',    color: 'var(--good)', verdict: 'ACCEPT' },
    { min: 2.00, max: 99,   label: 'Premium',        color: 'var(--accent-text)', verdict: 'ACCEPT' }
  ]
};

function mwClassifyRPM(rpm){
  for (let i = MW.rpmTiers.length - 1; i >= 0; i--){
    if (rpm >= MW.rpmTiers[i].min) return MW.rpmTiers[i];
  }
  return MW.rpmTiers[0];
}

function mwNormCity(s){
  return (s || '').trim().toLowerCase().replace(/[^a-z\s.]/g,'');
}

function mwGeoCheck(origin, dest){
  const o = mwNormCity(origin), d = mwNormCity(dest);
  const oT1 = MW.tier1.some(c => o.includes(c));
  const dT1 = MW.tier1.some(c => d.includes(c));
  const oT2 = MW.tier2.some(c => o.includes(c));
  const dT2 = MW.tier2.some(c => d.includes(c));
  const destDensity = dT1 ? 'Tier 1' : dT2 ? 'Tier 2' : 'Out of Density';
  const origDensity = oT1 ? 'Tier 1' : oT2 ? 'Tier 2' : 'Out of Density';
  const intoDensity = dT1 || dT2;
  return { origDensity, destDensity, intoDensity, dT1, dT2, oT1, oT2 };
}

function mwFuelCost(totalMiles){
  return roundCents((totalMiles / MW.mpg) * MW.fuelBaseline);
}


async function mwIsGoingHome(dest) {
  const home = await getSetting('homeLocation', '');
  if (!home) return false;
  const homeParts = home.toLowerCase().split(',').map(s => s.trim());
  const destLower = dest.toLowerCase();
  return homeParts.some(part => destLower.includes(part) && part.length > 2);
}

async function mwEvaluateLoad(){
  const origin = ($('#mwOrigin')?.value || '').trim();
  const dest = ($('#mwDest')?.value || '').trim();
  const loadedMi = Math.max(0, numVal('mwLoadedMi', 0));
  const deadMi = Math.max(0, numVal('mwDeadMi', 0));
  const revenue = Math.max(0, numVal('mwRevenue', 0));
  const dayOfWeek = $('#mwDayOfWeek')?.value || 'mon';
  const fatigue = Math.min(10, Math.max(0, numVal('mwFatigue', 0)));
  const weeklyGross = Math.max(0, numVal('mwWeeklyGross', 0));
  const strategicEnabled = !!$('#mwStrategic')?.checked;
  const loadNotes = ($('#mwLoadNotes')?.value || '').trim();
  const urgency = detectUrgency(loadNotes);
  const strategicReason = ($('#mwStrategicReason')?.value || '').trim();

  const out = $('#mwEvalOutput');
  if (!out) return;
  if (!loadedMi || !revenue){ out.innerHTML = '<div class="muted" style="font-size:13px">Enter loaded miles and revenue.</div>'; return; }
  if (strategicEnabled && !strategicReason){
    toast('Select a Strategic Reason (home / slow market / replace deadhead).', true);
    return;
  }

  // Save inputs
  setSetting('mwLastInputs', { origin, dest, loadedMi, deadMi, revenue, dayOfWeek, fatigue, weeklyGross, strategicEnabled, strategicReason }).catch(()=>{});

  // ── Auto-detect "going home" and suggest strategic mode ──
  const goingHome = dest ? await mwIsGoingHome(dest) : false;
  if (goingHome && !strategicEnabled){
    const mwStratEl = $('#mwStrategic');
    const mwReasonEl = $('#mwStrategicReason');
    if (mwStratEl && mwReasonEl){
      mwStratEl.checked = true;
      mwReasonEl.value = 'home';
      toast('Going home detected — strategic $1.25 floor enabled');
    }
  }
  // Re-read after possible auto-toggle
  const effectiveStrategic = goingHome || strategicEnabled;
  const effectiveReason = goingHome && !strategicEnabled ? 'home' : strategicReason;

  // ── Core calculations ──
  const totalMi = loadedMi + deadMi;
  const trueRPM = totalMi > 0 ? roundCents(revenue / totalMi) : 0;
  const loadedRPM = loadedMi > 0 ? roundCents(revenue / loadedMi) : 0;
  const fuel = mwFuelCost(totalMi);
  const netAfterFuel = roundCents(revenue - fuel);
  const tier = mwClassifyRPM(trueRPM);
  const geo = mwGeoCheck(origin, dest);
  const deadheadPct = totalMi > 0 ? roundCents((deadMi / totalMi) * 100) : 0;

  // Floor logic
  // Normal floor is MW.hardRejectRPM. Strategic floor is only allowed when explicitly enabled.
  const floorRPM = effectiveStrategic ? MW.strategicFloorRPM : MW.hardRejectRPM;

  // ── Operating cost (v14.5.0) ──
  const opCPM = Number(await getSetting('opCostPerMile', 0) || 0);
  const operatingCost = roundCents(totalMi * opCPM);
  const totalCost = roundCents(fuel + operatingCost);
  const operationalProfit = netAfterFuel; // Revenue - Fuel
  const trueProfit = roundCents(revenue - totalCost); // Revenue - (Fuel + Operating)
  const profitMarginPct = revenue > 0 ? roundCents((trueProfit / revenue) * 100) : 0;
  const breakEvenRPM = totalMi > 0 ? roundCents(totalCost / totalMi) : 0;

  // ── Efficiency metrics ──
  const profitPerMile = totalMi > 0 ? roundCents(trueProfit / totalMi) : 0;
  const estHours = totalMi > 0 ? Math.max(1, Math.round(totalMi / 50)) : 1; // ~50mph avg
  const profitPerHour = roundCents(trueProfit / estHours);
  const fuelPerMile = totalMi > 0 ? roundCents(fuel / totalMi) : 0;

  const isMonWed = ['mon','tue','wed'].includes(dayOfWeek);
  const isThuFri = ['thu','fri'].includes(dayOfWeek);

  // ════════════════════════════════════════════════════
  // FREIGHT INTELLIGENCE — Multi-factor decision engine
  // ════════════════════════════════════════════════════
  const steps = [];
  let verdict = tier.verdict;
  let verdictReason = '';

  // STEP 1: Geography
  if (geo.intoDensity){
    steps.push({ pass: true, label: 'Geography', detail: `→ ${geo.destDensity} density (${escapeHtml(dest)})` });
  } else if (origin && dest){
    steps.push({ pass: false, label: 'Geography', detail: 'Out of density — rate must be strong' });
    if (trueRPM < 1.60){ verdict = 'REJECT'; verdictReason = 'Out of density + RPM below Strong'; }
  } else {
    steps.push({ pass: null, label: 'Geography', detail: 'No origin/dest — skipping geo check' });
  }

  // STEP 2: True RPM
  const rpmPass = trueRPM >= floorRPM;
  steps.push({ pass: rpmPass, label: 'True RPM', detail: `$${trueRPM.toFixed(2)} — ${tier.label}` });
  if (trueRPM < floorRPM){
    verdict = 'REJECT';
    verdictReason = `Under $${floorRPM.toFixed(2)} floor`;
  }
  // Long-haul minimum: allow strategic exception ONLY for "going home" or "replacing deadhead".
  if (totalMi > 250 && trueRPM < MW.longHaulMinRPM){
    const allowLongHaulStrategic = effectiveStrategic && (effectiveReason === 'home' || effectiveReason === 'replace');
    if (!allowLongHaulStrategic){
      verdict = 'REJECT';
      verdictReason = `Long haul under $${MW.longHaulMinRPM}`;
    }
  }

  // If strategic floor is enabled and we are between strategic and normal floors, mark explicitly.
  if (effectiveStrategic && trueRPM >= MW.strategicFloorRPM && trueRPM < MW.hardRejectRPM && verdict !== 'REJECT'){
    verdict = 'STRATEGIC';
    const reasonLabel = (effectiveReason === 'home') ? 'Going home' : (effectiveReason === 'slow') ? 'Escaping slow market' : (effectiveReason === 'replace') ? 'Replacing deadhead' : 'Strategic mode';
    verdictReason = verdictReason || `${reasonLabel} — strategic floor active`;
  }

  // STEP 3: Profit margin
  const marginPass = opCPM > 0 ? profitMarginPct >= 25 : (revenue > 0 ? ((netAfterFuel / revenue) * 100) >= 30 : false);
  steps.push({ pass: marginPass, label: 'Profit Margin', detail: opCPM > 0 ? `${profitMarginPct.toFixed(0)}% true margin (after all costs)` : `${revenue > 0 ? ((netAfterFuel / revenue) * 100).toFixed(0) : 0}% margin (fuel only — set op cost in settings for full analysis)` });
  if (opCPM > 0 && profitMarginPct < 10){ verdict = 'REJECT'; verdictReason = 'True profit margin below 10%'; }
  else if (!opCPM && revenue > 0 && ((netAfterFuel / revenue) * 100) < 20){ verdict = 'REJECT'; verdictReason = 'Fuel margin below 20%'; }

  // STEP 4: Deadhead
  const dhPass = deadheadPct <= 20;
  steps.push({ pass: dhPass, label: 'Deadhead', detail: `${deadheadPct.toFixed(1)}% empty${deadheadPct > 30 ? ' — excessive' : deadheadPct > 20 ? ' — elevated' : ''}` });
  if (deadheadPct > 35 && trueRPM < 1.60){ verdict = 'REJECT'; verdictReason = 'High deadhead + weak RPM'; }

  // STEP 5: Weekly position
  let weekNote = '';
  if (weeklyGross > 0){
    const projected = weeklyGross + revenue;
    const target = MW.weekTarget.high;
    if (weeklyGross < MW.stabilizeFloor && isMonWed){
      weekNote = `Below $${MW.stabilizeFloor.toLocaleString()} by mid-week — STABILIZE`;
      if (verdict === 'ACCEPT' && trueRPM < 1.50){ verdict = 'STRATEGIC'; verdictReason = 'Below floor mid-week — take if positions into density'; }
      steps.push({ pass: false, label: 'Weekly Position', detail: weekNote });
    } else if (weeklyGross >= MW.surgeFloor && isMonWed){
      weekNote = `Above $${MW.surgeFloor.toLocaleString()} by mid-week — controlled push allowed`;
      steps.push({ pass: true, label: 'Weekly Position', detail: weekNote });
    } else {
      const pct = Math.min(100, Math.round((weeklyGross / target) * 100));
      weekNote = `$${weeklyGross.toLocaleString()} / $${target.toLocaleString()} target (${pct}%)`;
      steps.push({ pass: pct >= 50, label: 'Weekly Position', detail: weekNote });
    }
  } else {
    steps.push({ pass: null, label: 'Weekly Position', detail: 'No weekly gross entered' });
  }

  // STEP 6: Fatigue
  if (fatigue > 0){
    const fatigueOk = fatigue <= 6;
    steps.push({ pass: fatigueOk, label: 'Fatigue', detail: `Level ${fatigue}/10${fatigue >= 7 ? ' — DO NOT SIGN TIRED' : fatigue >= 5 ? ' — elevated' : ''}` });
    if (fatigue >= 8){ verdict = 'REJECT'; verdictReason = 'Fatigue too high — rest first'; }
  }

  // Strategic positioning check
  if (verdict === 'STRATEGIC'){
    if (geo.intoDensity && trueRPM >= 1.40){ verdictReason = verdictReason || 'Strategic — positions into density'; }
    else if (!geo.intoDensity){ verdict = 'REJECT'; verdictReason = verdictReason || 'Strategic RPM but out of density'; }
  }

  // Reposition suggestion
  let repoSuggestion = '';
  if (verdict === 'REJECT' && !geo.intoDensity){
    repoSuggestion = 'Consider repositioning toward: Indianapolis, Chicago, Cleveland, or St. Louis corridor.';
  }

  // ════════════════════════════════════════════════════
  // DECISION GRADE (A–F based on True RPM)
  // A–E are displayed as the visible scale; <E is Reject
  // ════════════════════════════════════════════════════
  let grade, gradeLabel, gradeColor, gradeEmoji;
  if (trueRPM >= 1.75){ grade = 'A'; gradeLabel = 'STRONG LOAD'; gradeColor = 'var(--good)'; gradeEmoji = '🟢'; }
  else if (trueRPM >= 1.60){ grade = 'B'; gradeLabel = 'GOOD LOAD'; gradeColor = '#58a6ff'; gradeEmoji = '🔵'; }
  else if (trueRPM >= 1.50){ grade = 'C'; gradeLabel = 'PROFESSIONAL'; gradeColor = 'var(--warn)'; gradeEmoji = '🟡'; }
  else if (trueRPM >= 1.40){ grade = 'D'; gradeLabel = 'MINIMUM ACCEPTABLE'; gradeColor = '#ff8c42'; gradeEmoji = '🟠'; }
  else if (trueRPM >= 1.25){ grade = 'E'; gradeLabel = 'STRATEGIC ONLY'; gradeColor = 'var(--warn)'; gradeEmoji = '🟡'; }
  else { grade = 'F'; gradeLabel = 'REJECT'; gradeColor = 'var(--bad)'; gradeEmoji = '🔴'; }

  // Override display verdict with intelligence engine result
  const verdictColors = { ACCEPT: 'var(--good)', REJECT: 'var(--bad)', STRATEGIC: 'var(--warn)' };
  const verdictLabels = { ACCEPT: 'ACCEPT', REJECT: 'PASS', STRATEGIC: 'STRATEGIC ONLY' };

  // ── USA Engine integration ──
  const usaMode = $('#mwModeSelector')?.value || 'HARVEST';
  const revenueCurrency = $('#mwCurrency')?.value || 'USD';
  const usaResult = usaScoreLoad({
    origin, dest, trueRPM, deadMi, loadedMi,
    mode: usaMode, profileId: 'MIDWEST_STACK',
    revenue, revenueCurrency,
  });

  // ── Collect decision data for render ──
  // Generate bid range
  const isCrossBorder = !!(usaResult?.crossBorder?.isCrossBorder);
  const bidRange = generateBidRange(totalMi, { urgencyBoost: urgency.boost, crossBorder: isCrossBorder });

  const _decision = {
    trueRPM, loadedRPM, totalMi, loadedMi, deadMi, deadheadPct, revenue,
    tier, grade, gradeLabel, gradeColor, gradeEmoji,
    verdict, verdictReason, verdictColors, verdictLabels, steps,
    fuel, netAfterFuel, operatingCost, totalCost, operationalProfit,
    trueProfit, profitMarginPct, breakEvenRPM,
    profitPerMile, profitPerHour, fuelPerMile, estHours, opCPM,
    weeklyGross, repoSuggestion, geo, fatigue, origin, dest,
    floorRPM, effectiveStrategic, effectiveReason,
    usaResult, urgency, bidRange,
  };
  _mwRenderDecision(out, _decision);
  mwRenderWeekStructure(weeklyGross);
}

function _mwRenderDecision(out, d){
  const {trueRPM, loadedRPM, totalMi, loadedMi, deadMi, deadheadPct, revenue,
    tier, grade, gradeLabel, gradeColor, gradeEmoji,
    verdict, verdictReason, verdictColors, verdictLabels, steps,
    fuel, netAfterFuel, operatingCost, totalCost, operationalProfit,
    trueProfit, profitMarginPct, breakEvenRPM,
    profitPerMile, profitPerHour, fuelPerMile, estHours, opCPM,
    weeklyGross, repoSuggestion, geo, fatigue, origin, dest,
    floorRPM, effectiveStrategic, effectiveReason, usaResult, urgency, bidRange} = d;
  let html = '';


  // ── 1. DECISION BANNER ──
  const ladderRow = (g, label, rng) => {
    const active = g === grade;
    return `<div style="display:flex;align-items:center;gap:10px;padding:6px 8px;border-radius:8px;${active ? `background:${gradeColor}18;border:1px solid ${gradeColor}55` : 'border:1px solid transparent'}">
      <div style="width:22px;height:22px;border-radius:7px;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-weight:800;color:${active ? gradeColor : 'var(--text-tertiary)'};${active ? `background:${gradeColor}1a` : 'background:var(--surface-2)'}">${g}</div>
      <div style="flex:1;min-width:0">
        <div style="font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:${active ? gradeColor : 'var(--text-secondary)'}">${label}</div>
        <div style="font-size:10px;color:var(--text-tertiary)">${rng}</div>
      </div>
      ${active ? `<div style="font-size:10px;font-weight:700;color:${gradeColor}">CURRENT</div>` : ''}
    </div>`;
  };

  html += `<div style="text-align:center;padding:16px 0;border-bottom:2px solid ${gradeColor}40;margin-bottom:14px">
    <div style="font-size:14px;font-weight:600;color:${gradeColor};letter-spacing:1px;text-transform:uppercase">${gradeEmoji} ${escapeHtml(gradeLabel)}</div>
    <div style="font-size:48px;font-weight:800;color:${gradeColor};font-family:var(--font-mono);line-height:1.1;margin:4px 0">${grade}</div>
    <div style="font-size:13px;color:var(--text-secondary)">True RPM: <b style="color:${tier.color}">$${trueRPM.toFixed(2)}</b> • ${tier.label}</div>
    <div style="margin:10px auto 0;max-width:360px;text-align:left;display:grid;gap:6px">
      ${ladderRow('A','STRONG LOAD','≥ $1.75')}
      ${ladderRow('B','GOOD LOAD','$1.60–$1.74')}
      ${ladderRow('C','PROFESSIONAL','$1.50–$1.59')}
      ${ladderRow('D','MINIMUM ACCEPTABLE','$1.40–$1.49')}
      ${ladderRow('E','STRATEGIC ONLY','$1.25–$1.39')}
      <div style="font-size:10px;color:var(--text-tertiary);padding:0 8px">Below E: <b style="color:var(--bad)">REJECT</b></div>
    </div>
    ${verdictReason ? `<div style="font-size:11px;color:var(--text-tertiary);margin-top:4px">${escapeHtml(verdictReason)}</div>` : ''}
  </div>`;

  // ── 2. WEEKLY IMPACT BOX ──
  if (weeklyGross > 0){
    const target = MW.weekTarget.high;
    const projected = weeklyGross + revenue;
    const remaining = Math.max(0, target - projected);
    const pctBefore = Math.min(100, Math.round((weeklyGross / target) * 100));
    const pctAfter = Math.min(100, Math.round((projected / target) * 100));
    html += `<div style="background:var(--surface-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:12px;margin-bottom:12px">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:600;margin-bottom:8px">Weekly Impact</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;font-size:12px;margin-bottom:10px">
        <div><span class="muted">Weekly Target:</span></div><div style="text-align:right;font-weight:600">${fmtMoney(target)}</div>
        <div><span class="muted">Current Week:</span></div><div style="text-align:right">${fmtMoney(weeklyGross)}</div>
        <div><span class="muted">This Load:</span></div><div style="text-align:right;color:var(--good);font-weight:600">+${fmtMoney(revenue)}</div>
        <div style="border-top:1px solid var(--border-subtle);padding-top:4px"><b>Projected:</b></div><div style="text-align:right;border-top:1px solid var(--border-subtle);padding-top:4px;font-weight:700;font-size:13px;color:${projected >= target ? 'var(--good)' : 'var(--text)'}">${fmtMoney(projected)}</div>
        <div><span class="muted">Remaining:</span></div><div style="text-align:right;color:${remaining > 0 ? 'var(--warn)' : 'var(--good)'}">${ remaining > 0 ? fmtMoney(remaining) : '✓ Target hit!'}</div>
      </div>
      <div style="height:8px;border-radius:4px;background:var(--surface-2);overflow:hidden;position:relative">
        <div style="position:absolute;height:100%;width:${pctBefore}%;border-radius:4px;background:var(--accent);opacity:.4"></div>
        <div style="position:absolute;height:100%;width:${pctAfter}%;border-radius:4px;background:${projected >= target ? 'var(--good)' : 'var(--accent)'};transition:width .5s"></div>
      </div>
      <div style="font-size:10px;color:var(--text-tertiary);margin-top:4px;display:flex;justify-content:space-between"><span>Before: ${pctBefore}%</span><span>After: ${pctAfter}%</span></div>
    </div>`;
  }

  // ── 3. PROFIT GAUGE ──
  const gaugeMax = revenue || 1;
  const profitVal = opCPM > 0 ? trueProfit : netAfterFuel;
  const profitPct = Math.max(0, Math.min(100, (profitVal / gaugeMax) * 100));
  let gaugeColor = profitPct >= 50 ? 'var(--good)' : profitPct >= 35 ? '#58a6ff' : profitPct >= 20 ? 'var(--warn)' : 'var(--bad)';
  html += `<div style="background:var(--surface-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:12px;margin-bottom:12px">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:600;margin-bottom:8px">Profit Gauge</div>
    <div style="height:32px;border-radius:6px;background:var(--surface-2);overflow:hidden;position:relative">
      <div style="position:absolute;height:100%;width:${profitPct}%;border-radius:6px;background:${gaugeColor};transition:width .5s;display:flex;align-items:center;justify-content:center">
        ${profitPct > 25 ? `<span style="font-size:13px;font-weight:700;color:#fff;text-shadow:0 1px 3px rgba(0,0,0,.4)">${fmtMoney(profitVal)}</span>` : ''}
      </div>
      ${profitPct <= 25 ? `<span style="position:absolute;right:8px;top:50%;transform:translateY(-50%);font-size:12px;font-weight:600;color:var(--text-secondary)">${fmtMoney(profitVal)}</span>` : ''}
    </div>
    <div style="font-size:10px;color:var(--text-tertiary);margin-top:4px">${opCPM > 0 ? 'True Profit (after all costs)' : 'Operational Profit (fuel only — set op cost/mi in settings)'}</div>
  </div>`;

  // ── 4. DECISION METRICS ──
  html += `<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:12px">
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:8px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:18px;font-weight:600;color:${tier.color}">$${trueRPM.toFixed(2)}</div>
      <div style="font-size:10px;color:var(--text-tertiary)">True RPM</div>
    </div>
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:8px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:18px;font-weight:600;color:${breakEvenRPM > 0 && trueRPM > breakEvenRPM ? 'var(--good)' : 'var(--bad)'}">$${breakEvenRPM.toFixed(2)}</div>
      <div style="font-size:10px;color:var(--text-tertiary)">Break-Even</div>
    </div>
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:8px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:18px;font-weight:600">${totalMi}</div>
      <div style="font-size:10px;color:var(--text-tertiary)">Total Miles</div>
    </div>
  </div>`;

  // ── 4b. SMART BID ENGINE (Negotiation Intelligence) ──
  // Goal: give 3 numbers the driver can say on the phone.
  // Method: compute revenue required to hit the next RPM ladder step, bounded by break-even + buffer.
  const roundTo25 = (x)=> Math.round((Number(x)||0)/25)*25;
  const nextStepRPM = (trueRPM >= 1.75) ? 1.90 : (trueRPM >= 1.60) ? 1.75 : (trueRPM >= 1.50) ? 1.60 : (trueRPM >= 1.40) ? 1.50 : 1.40;
  const bufferRPM = breakEvenRPM > 0 ? (breakEvenRPM + 0.20) : 0;
  const strongRPM = Math.max(nextStepRPM, bufferRPM);
  const premiumRPM = strongRPM + 0.10;
  const strongAsk = roundTo25(strongRPM * totalMi);
  const premiumAsk = roundTo25(premiumRPM * totalMi);
  const quickAccept = roundTo25(revenue);

  // If the current offer is already above strong, keep strong = current (avoid asking down)
  const strongFinal = Math.max(strongAsk, quickAccept);
  const premiumFinal = Math.max(premiumAsk, strongFinal + 50);

  html += `<div style="background:var(--surface-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:12px;margin-bottom:12px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:700">Smart Bid Engine</div>
      <div class="muted" style="font-size:10px">Negotiation targets</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px">
      <div style="padding:10px;border-radius:12px;border:1px solid var(--border-subtle);background:rgba(255,255,255,0.02);text-align:center">
        <div style="font-size:10px;color:var(--text-tertiary);letter-spacing:.6px;text-transform:uppercase;font-weight:700">Premium Ask</div>
        <div style="font-family:var(--font-mono);font-size:18px;font-weight:800;color:var(--good)">${fmtMoney(premiumFinal)}</div>
        <div class="muted" style="font-size:10px">Aim: ~${premiumRPM.toFixed(2)} RPM</div>
      </div>
      <div style="padding:10px;border-radius:12px;border:1px solid var(--border-subtle);background:rgba(255,255,255,0.02);text-align:center">
        <div style="font-size:10px;color:var(--text-tertiary);letter-spacing:.6px;text-transform:uppercase;font-weight:700">Strong Target</div>
        <div style="font-family:var(--font-mono);font-size:18px;font-weight:800;color:#58a6ff">${fmtMoney(strongFinal)}</div>
        <div class="muted" style="font-size:10px">Min buffer above break-even</div>
      </div>
      <div style="padding:10px;border-radius:12px;border:1px solid var(--border-subtle);background:rgba(255,255,255,0.02);text-align:center">
        <div style="font-size:10px;color:var(--text-tertiary);letter-spacing:.6px;text-transform:uppercase;font-weight:700">Quick Accept</div>
        <div style="font-family:var(--font-mono);font-size:18px;font-weight:800;color:var(--text)">${fmtMoney(quickAccept)}</div>
        <div class="muted" style="font-size:10px">If they won’t move</div>
      </div>
    </div>
    <div class="muted" style="font-size:11px;margin-top:8px;line-height:1.35">
      Script: “I can run it for <b>${fmtMoney(strongFinal)}</b>. If you need it covered now, I can do <b>${fmtMoney(quickAccept)}</b>. If it’s tight / same-day, I’m at <b>${fmtMoney(premiumFinal)}</b>.”
    </div>
  </div>`;

  // ── 5. DUAL PROFIT SUMMARY ──
  html += `<div style="background:var(--surface-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:12px;margin-bottom:12px">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:600;margin-bottom:8px">Profit Summary</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div style="text-align:center;padding:10px;border-radius:var(--r-sm);background:var(--good-muted);border:1px solid var(--good-border)">
        <div style="font-family:var(--font-mono);font-size:20px;font-weight:700;color:var(--good)">${fmtMoney(operationalProfit)}</div>
        <div style="font-size:10px;color:var(--text-secondary);margin-top:2px">Operational Profit</div>
        <div style="font-size:9px;color:var(--text-tertiary)">Revenue − Fuel</div>
      </div>
      <div style="text-align:center;padding:10px;border-radius:var(--r-sm);background:${trueProfit >= 0 ? 'var(--good-muted)' : 'var(--bad-muted)'};border:1px solid ${trueProfit >= 0 ? 'var(--good-border)' : 'var(--bad-border)'}">
        <div style="font-family:var(--font-mono);font-size:20px;font-weight:700;color:${trueProfit >= 0 ? 'var(--good)' : 'var(--bad)'}">${fmtMoney(trueProfit)}</div>
        <div style="font-size:10px;color:var(--text-secondary);margin-top:2px">True Profit</div>
        <div style="font-size:9px;color:var(--text-tertiary)">${opCPM > 0 ? 'Revenue − All Costs' : 'Set op cost/mi →'}</div>
      </div>
    </div>
  </div>`;

  // ── 6. COST BREAKDOWN ──
  html += `<div style="background:var(--surface-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:12px;margin-bottom:12px">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:600;margin-bottom:8px">Cost Breakdown</div>
    <div style="display:grid;grid-template-columns:1fr auto;gap:4px 12px;font-size:13px">
      <div class="muted">Revenue</div><div style="text-align:right;font-weight:600">${fmtMoney(revenue)}</div>
      <div class="muted">Fuel Cost</div><div style="text-align:right;color:var(--bad)">−${fmtMoney(fuel)}</div>
      ${opCPM > 0 ? `<div class="muted">Operating Cost (${totalMi}mi × $${opCPM.toFixed(2)})</div><div style="text-align:right;color:var(--bad)">−${fmtMoney(operatingCost)}</div>` : ''}
      <div style="border-top:1px solid var(--border-subtle);padding-top:4px;font-weight:700">Total Cost</div>
      <div style="text-align:right;border-top:1px solid var(--border-subtle);padding-top:4px;font-weight:700;color:var(--bad)">−${fmtMoney(totalCost)}</div>
      <div style="font-weight:700;color:${trueProfit >= 0 ? 'var(--good)' : 'var(--bad)'}">Net Profit</div>
      <div style="text-align:right;font-weight:700;font-size:15px;color:${trueProfit >= 0 ? 'var(--good)' : 'var(--bad)'}">${fmtMoney(trueProfit)}</div>
    </div>
  </div>`;

  // ── 7. EFFICIENCY METRICS ──
  html += `<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:14px">
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:8px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:14px;font-weight:500">$${profitPerMile.toFixed(2)}</div>
      <div style="font-size:10px;color:var(--text-tertiary)">Profit/Mile</div>
    </div>
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:8px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:14px;font-weight:500">$${profitPerHour.toFixed(0)}</div>
      <div style="font-size:10px;color:var(--text-tertiary)">Profit/Hour</div>
    </div>
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:8px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:14px;font-weight:500">$${fuelPerMile.toFixed(2)}</div>
      <div style="font-size:10px;color:var(--text-tertiary)">Fuel/Mile</div>
    </div>
  </div>`;

  // ── 8. FREIGHT INTELLIGENCE FILTER ──
  html += '<div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:600;margin-bottom:8px">Freight Intelligence</div>';
  steps.forEach(s => {
    const icon = s.pass === true ? '✓' : s.pass === false ? '✕' : '–';
    const c = s.pass === true ? 'var(--good)' : s.pass === false ? 'var(--bad)' : 'var(--text-tertiary)';
    html += `<div style="display:flex;gap:10px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
      <div style="color:${c};font-weight:700;font-size:14px;width:18px;flex-shrink:0">${icon}</div>
      <div><div style="font-weight:600;font-size:13px">${escapeHtml(s.label)}</div><div style="font-size:12px;color:var(--text-secondary)">${escapeHtml(s.detail)}</div></div>
    </div>`;
  });

  // Final intelligence verdict
  html += `<div style="text-align:center;margin-top:14px;padding:12px;border-radius:var(--r-sm);background:${verdictColors[verdict]}15;border:1px solid ${verdictColors[verdict]}40">
    <div style="font-size:16px;font-weight:800;color:${verdictColors[verdict]};font-family:var(--font-mono)">${verdict === 'ACCEPT' ? (trueRPM >= 1.75 ? 'STRONG LOAD' : trueRPM >= 1.60 ? 'GOOD LOAD' : 'ACCEPT') : verdictLabels[verdict]}</div>
    ${verdictReason ? `<div style="font-size:11px;color:var(--text-secondary);margin-top:2px">${escapeHtml(verdictReason)}</div>` : ''}
  </div>`;

  if (repoSuggestion){
    html += `<div style="margin-top:10px;padding:10px;border-radius:var(--r-sm);background:var(--warn-muted);border:1px solid var(--warn-border);font-size:12px;color:var(--warn)">${escapeHtml(repoSuggestion)}</div>`;
  }

  // ── USA Engine Intelligence Panel ──
  if (usaResult){
    const u = usaResult;
    html += `<div style="margin-top:14px;border-top:2px solid ${u.usaColor}40;padding-top:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:600">USA Engine • ${escapeHtml(u.modeConf.label)} Mode</div>
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-family:var(--font-mono);font-size:22px;font-weight:800;color:${u.usaColor}">${u.usaGrade}</span>
          <span style="font-size:12px;font-weight:700;color:${u.usaColor}">${escapeHtml(u.usaVerdict)}</span>
          <span style="font-family:var(--font-mono);font-size:12px;color:var(--text-tertiary)">${u.score}/100</span>
        </div>
      </div>`;

    // Score breakdown bar
    const barSegments = [
      { label: 'Econ', val: u.econScore, max: 28 },
      { label: 'DH', val: u.dhScore, max: 8 },
      { label: 'Role', val: u.roleScore, max: 18 },
      { label: 'Corr', val: u.corrScore, max: 15 },
    ];
    html += `<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:4px;margin-bottom:12px">`;
    for (const seg of barSegments){
      const pct = seg.max > 0 ? Math.max(0, Math.min(100, ((seg.val + Math.abs(seg.max)) / (Math.abs(seg.max)*2)) * 100)) : 50;
      const segColor = seg.val > 0 ? 'var(--good)' : seg.val < 0 ? 'var(--bad)' : 'var(--text-tertiary)';
      html += `<div style="text-align:center">
        <div style="font-size:10px;color:var(--text-tertiary);margin-bottom:2px">${seg.label}</div>
        <div style="height:4px;border-radius:2px;background:var(--surface-2);overflow:hidden"><div style="height:100%;width:${pct}%;border-radius:2px;background:${segColor}"></div></div>
        <div style="font-size:10px;font-weight:600;color:${segColor};margin-top:2px">${seg.val > 0 ? '+' : ''}${seg.val}</div>
      </div>`;
    }
    html += `</div>`;

    // Bullet explanations
    for (const b of u.bullets){
      const ic = b.icon === '✓' ? 'var(--good)' : b.icon === '✕' ? 'var(--bad)' : 'var(--text-tertiary)';
      html += `<div style="display:flex;gap:8px;align-items:flex-start;padding:4px 0;font-size:12px">
        <div style="color:${ic};font-weight:700;width:14px;flex-shrink:0">${b.icon}</div>
        <div style="color:var(--text-secondary)">${escapeHtml(b.text)}</div>
      </div>`;
    }
    html += `</div>`;
  }

  // ── Urgency Detection ──
  if (urgency && urgency.isUrgent){
    html += `<div style="margin-top:12px;padding:10px 12px;border-radius:10px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.25)">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:20px">⚡</span>
        <div>
          <div style="font-size:13px;font-weight:700;color:var(--warn)">Urgency Detected: ${escapeHtml(urgency.matches.join(' • '))}</div>
          <div class="muted" style="font-size:11px">Bid range adjusted +$${urgency.boost.toFixed(2)}/mi — urgent freight supports premium pricing</div>
        </div>
      </div>
    </div>`;
  }

  // ── Bid Range ──
  if (bidRange){
    html += bidRangeHTML(bidRange);
  }

  // "Book as Trip" button — pre-fill trip wizard with evaluated load data
  html += `<div style="margin-top:14px;border-top:1px solid var(--border);padding-top:12px">
    <button class="btn primary" id="mwBookTrip" style="width:100%">＋ Book as Trip</button>
    <div class="muted" style="font-size:11px;margin-top:6px;text-align:center">Pre-fills a new trip with this load's data</div>
  </div>`;

  out.innerHTML = html;

  // Wire up book-as-trip
  const bookBtn = $('#mwBookTrip', out);
  if (bookBtn){
    bookBtn.addEventListener('click', ()=>{
      haptic(15);
      openTripWizard({
        orderNo: '',
        customer: '',
        origin: origin || '',
        destination: dest || '',
        loadedMiles: loadedMi || 0,
        emptyMiles: deadMi || 0,
        pay: revenue || 0,
        pickupDate: isoDate(),
        notes: `MW Stack: ${grade || ''} (USA ${usaResult?.score || 0}/100) — True RPM $${trueRPM.toFixed(2)}`,
      });
    });
  }
}


function mwRenderWeekStructure(weeklyGross){
  const gross = weeklyGross || 0;
  const pct = Math.min(100, Math.round((gross / MW.weekTarget.high) * 100));
  const bar = $('#mwWeekBar');
  const label = $('#mwWeekLabel');
  const grossEl = $('#mwWeekGross');
  const rpmEl = $('#mwWeekRPM');
  const nafEl = $('#mwWeekNAF');

  if (bar) bar.style.width = pct + '%';
  if (bar){
    bar.style.background = gross >= MW.weekTarget.low ? 'var(--good)' :
      gross >= MW.stabilizeFloor ? 'var(--accent)' : 'var(--bad)';
  }
  if (label){
    if (gross >= MW.weekTarget.low) label.textContent = `On target — $${gross.toLocaleString()} / $${MW.weekTarget.high.toLocaleString()}`;
    else if (gross >= MW.stabilizeFloor) label.textContent = `Building — $${gross.toLocaleString()} / $${MW.weekTarget.low.toLocaleString()} floor`;
    else if (gross > 0) label.textContent = `Below floor — stabilize into density`;
    else label.textContent = `Target: $${MW.weekTarget.low.toLocaleString()}–$${MW.weekTarget.high.toLocaleString()}/week`;
  }
  if (grossEl) grossEl.textContent = gross > 0 ? fmtMoney(gross) : '—';
  if (rpmEl) rpmEl.textContent = '—'; // computed from trips if available
  if (nafEl) nafEl.textContent = '—';
}

function mwRepoSignal(){
  const compression = numVal('mbCompression', 0);
  const rpmLow = numVal('mbRpmLow', 0);
  const rpmHigh = numVal('mbRpmHigh', 0);
  const location = ($('#mbLocation')?.value || '').trim();
  const out = $('#mbRepoSignal');
  if (!out) return;

  if (!compression && !rpmHigh){ out.innerHTML = '<div class="muted" style="font-size:13px">Enter compression + RPM data to get a reposition recommendation.</div>'; return; }

  const geo = mwGeoCheck(location, '');
  const inT1 = geo.oT1;
  const bestVisible = Math.max(rpmLow, rpmHigh);
  const shouldRepo = compression >= 70 && bestVisible < 1.50 && !inT1;

  let html = '';
  if (shouldRepo){
    html = `<div style="padding:10px;border-radius:var(--r-sm);background:var(--warn-muted);border:1px solid var(--warn-border)">
      <div style="font-weight:700;color:var(--warn);font-size:14px">⚠ Reposition Signal</div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:4px">Compression ${compression}/100 with no visible 1.50+ RPM. Move toward Chicago, Indianapolis, St. Louis corridor, or Cleveland.</div>
    </div>`;
  } else if (compression >= 70){
    html = `<div style="padding:10px;border-radius:var(--r-sm);background:var(--surface-0);border:1px solid var(--border)">
      <div style="font-weight:600;font-size:13px">Compressed market (${compression}/100)</div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:4px">${inT1 ? 'Already in Tier 1 — hold and wait for reload.' : `Best visible RPM: $${bestVisible.toFixed(2)} — monitor for 60–90 min before repositioning.`}</div>
    </div>`;
  } else {
    html = `<div style="padding:10px;border-radius:var(--r-sm);background:var(--good-muted);border:1px solid var(--good-border)">
      <div style="font-weight:600;font-size:13px;color:var(--good)">Market OK</div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:4px">Compression ${compression || '—'}/100 • Best visible: $${bestVisible ? bestVisible.toFixed(2) : '—'}</div>
    </div>`;
  }
  out.innerHTML = html;
}

// Tomorrow Signal — lightweight forecast based on your last market-board observations.
// This does NOT require any external API (works offline). It becomes more accurate with more logs.
async function mwRenderTomorrowSignal(){
  const box = $('#mbTomorrowSignal');
  if (!box) return;
  try{
    const {stores} = tx('marketBoard');
    const all = (await idbReq(stores.marketBoard.getAll())) || [];
    if (!all.length){ box.innerHTML = `<div class="muted" style="font-size:12px">Tomorrow Signal will appear after you log a few market observations.</div>`; return; }
    all.sort((a,b)=> (b.date||'').localeCompare(a.date||''));
    const recent = all.slice(0, 6);
    const cur = recent[0];
    const prev = recent[1];
    const volScore = v => v === 'heavy' ? 3 : v === 'moderate' ? 2 : 1;
    const curVol = volScore(cur.volume);
    const prevVol = prev ? volScore(prev.volume) : curVol;
    const volTrend = curVol - prevVol;

    const hi = Number(cur.rpmHigh || 0);
    const lo = Number(cur.rpmLow || 0);
    const compression = Number(cur.compression || 0);

    // Market status heuristic
    let status = 'BALANCED';
    let color = 'var(--accent)';
    if (curVol === 3 && hi >= 1.60 && compression <= 55){ status = 'HOT'; color = 'var(--good)'; }
    else if (curVol === 1 || hi && hi < 1.45 || compression >= 70){ status = 'SLOW'; color = 'var(--warn)'; }
    if (compression >= 80 && (cur.direction === 'S' || cur.densityDir === 'out')){ status = 'TRAP'; color = 'var(--bad)'; }

    // Tomorrow guess = today status adjusted by trend
    let tStatus = status;
    if (volTrend >= 1 && status === 'BALANCED') tStatus = 'HOT';
    if (volTrend <= -1 && status === 'BALANCED') tStatus = 'SLOW';
    if (status === 'HOT' && volTrend <= -1) tStatus = 'BALANCED';
    if (status === 'SLOW' && volTrend >= 1) tStatus = 'BALANCED';

    const trendLabel = volTrend >= 1 ? '↑ volume rising' : volTrend <= -1 ? '↓ volume falling' : '→ steady';
    const rec = (tStatus === 'HOT')
      ? 'Push within density corridors. Protect your floor, raise your ask.'
      : (tStatus === 'SLOW')
        ? 'Use Strategic Floor only for home/reposition. Favor short corridor moves.'
        : (tStatus === 'TRAP')
          ? 'Avoid. Reposition toward Midwest density (STL / IND / CHI corridor).'
          : 'Normal discipline. Take B+ loads that improve position.';

    const loc = escapeHtml(cur.location || 'Current market');
    box.innerHTML = `
      <div style="background:var(--surface-0);border:1px solid var(--border);border-radius:var(--r-sm);padding:10px">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
          <div>
            <div style="font-size:11px;letter-spacing:.8px;text-transform:uppercase;color:var(--text-tertiary);font-weight:700">Tomorrow Signal</div>
            <div style="font-size:13px;font-weight:700;margin-top:2px">${loc}: <span style="color:${color}">${tStatus}</span></div>
            <div class="muted" style="font-size:11px;margin-top:2px">Based on last market logs • ${trendLabel}</div>
          </div>
          <div style="text-align:right">
            <div style="font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)">${lo ? '$'+lo.toFixed(2) : '—'}–${hi ? '$'+hi.toFixed(2) : '—'}</div>
            <div style="font-size:10px;color:var(--text-tertiary)">Visible RPM range</div>
          </div>
        </div>
        <div style="margin-top:8px;font-size:11px;color:var(--text-secondary)">${escapeHtml(rec)}</div>
      </div>
    `;
  }catch(e){
    box.innerHTML = `<div class="muted" style="font-size:12px">Tomorrow Signal error.</div>`;
  }
}

async function mwSaveMarketEntry(){
  const entry = {
    id: crypto.randomUUID?.() || Date.now().toString(36) + Math.random().toString(36).slice(2,8),
    date: new Date().toISOString(),
    dayOfWeek: new Date().toLocaleDateString('en-US', { weekday:'long' }),
    location: ($('#mbLocation')?.value || '').trim(),
    volume: $('#mbVolume')?.value || 'moderate',
    direction: $('#mbDirection')?.value || 'mixed',
    densityDir: $('#mbDensityDir')?.value || 'into-t1',
    rpmLow: numVal('mbRpmLow', 0),
    rpmHigh: numVal('mbRpmHigh', 0),
    compression: numVal('mbCompression', 0),
    reload: numVal('mbReload', 0),
    deadRisk: numVal('mbDeadRisk', 0),
    notes: ($('#mbNotes')?.value || '').trim()
  };
  if (!entry.location){ toast('Enter a location', true); return; }
  try {
    const {t:txn, stores} = tx('marketBoard','readwrite');
    stores.marketBoard.put(entry);
    await waitTxn(txn);
    toast('Market entry saved');
    // Clear form
    ['mbLocation','mbRpmLow','mbRpmHigh','mbCompression','mbReload','mbDeadRisk','mbNotes'].forEach(id => { const el=$('#'+id); if(el) el.value=''; });
    $('#mbVolume').value='moderate'; $('#mbDirection').value='mixed'; $('#mbDensityDir').value='into-t1';
    await mwRenderBoardLog();
    await mwRenderTomorrowSignal();
  } catch(err){ console.error('[FL] Save error:', err); toast('Save failed. Please try again.', true); }
}

async function mwRenderBoardLog(){
  const box = $('#mbLogList');
  if (!box) return;
  try {
    const {stores} = tx('marketBoard');
    const all = (await idbReq(stores.marketBoard.getAll())) || [];
    all.sort((a,b) => (b.date||'').localeCompare(a.date||''));
    const recent = all.slice(0, 10);
    if (!recent.length){ box.innerHTML = '<div class="muted" style="font-size:12px">No market entries yet.</div>'; return; }
    box.innerHTML = '';
    recent.forEach(e => {
      const el = document.createElement('div'); el.className = 'item';
      const d = new Date(e.date);
      const dateStr = d.toLocaleDateString('en-US', { month:'short', day:'numeric' });
      const timeStr = d.toLocaleTimeString('en-US', { hour:'numeric', minute:'2-digit' });
      el.innerHTML = `<div class="left">
        <div class="v">${escapeHtml(e.location)}</div>
        <div class="sub">${dateStr} ${timeStr} • Vol: ${e.volume} • Compression: ${e.compression || '—'}/100</div>
        <div class="k">RPM: $${e.rpmLow ? e.rpmLow.toFixed(2) : '—'}–$${e.rpmHigh ? e.rpmHigh.toFixed(2) : '—'} • Reload: ${e.reload || '—'}%${e.notes ? ' • ' + escapeHtml(e.notes.slice(0,40)) : ''}</div>
      </div>`;
      box.appendChild(el);
    });
    staggerItems(box);
  } catch{ box.innerHTML = '<div class="muted" style="font-size:12px">Error loading entries.</div>'; }
}

let mwBound = false;

function mwBindTabs(){
  const tabs = document.querySelectorAll('#mwTabs .btn');
  const panels = { eval: $('#mwTabEval'), omega: $('#mwTabOmega'), board: $('#mwTabBoard') };

  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.dataset.mwtab;
      tabs.forEach(b => b.classList.remove('act'));
      btn.classList.add('act');
      Object.entries(panels).forEach(([k,p]) => {
        if (p) p.style.display = k === t ? '' : 'none';
      });
      setSetting('mwLastTab', t).catch(()=>{});
    });
  });
}

async function mwInit(){
  if (mwBound) return;
  mwBound = true;

  // Tab switching
  mwBindTabs();

  // Restore last tab
  const lastTab = await getSetting('mwLastTab', 'eval');
  // T5-FIX: Guard against selector injection — only allow known tab values
  const validTabs = new Set(['eval', 'omega', 'board']);
  const safeTab = validTabs.has(lastTab) ? lastTab : 'eval';
  const tabBtn = document.querySelector(`#mwTabs [data-mwtab="${safeTab}"]`);
  if (tabBtn) tabBtn.click();

  // Load evaluator
  $('#mwEvalBtn')?.addEventListener('click', mwEvaluateLoad);

  // Mode selector persistence
  const modeEl = $('#mwModeSelector');
  if (modeEl){
    const savedMode = await getSetting('mwMode', 'HARVEST');
    if (['HARVEST','REPOSITION','ESCAPE','FLOOR_PROTECT'].includes(savedMode)) modeEl.value = savedMode;
    modeEl.addEventListener('change', ()=> setSetting('mwMode', modeEl.value).catch(()=>{}));
  }

  // Strategic floor toggle
  $('#mwStrategic')?.addEventListener('change', () => {
    const on = !!$('#mwStrategic')?.checked;
    const sel = $('#mwStrategicReason');
    if (sel){ sel.disabled = !on; if (!on) sel.value = ''; }
  });
  $('#mwEvalReset')?.addEventListener('click', () => {
    ['mwOrigin','mwDest','mwLoadedMi','mwDeadMi','mwRevenue','mwFatigue','mwWeeklyGross','mwLoadNotes'].forEach(id => { const el=$('#'+id); if(el) el.value=''; });
    $('#mwDayOfWeek').value='mon';
    const cur = $('#mwCurrency'); if (cur) cur.value='USD';
    const st = $('#mwStrategic'); if (st) st.checked = false;
    const sr = $('#mwStrategicReason'); if (sr){ sr.value=''; sr.disabled = true; }
    $('#mwEvalOutput').innerHTML = '<div class="muted" style="font-size:13px;line-height:1.8">Enter a load to run the 90-second filter.<br><br><span style="font-size:11px;color:var(--text-tertiary)">Geography → True RPM → Fuel → Weekly Position → Fatigue</span></div>';
    mwRenderWeekStructure(0);
    setSetting('mwLastInputs', null).catch(()=>{});
  });

  // Restore last eval inputs
  const last = await getSetting('mwLastInputs', null);
  if (last && typeof last === 'object'){
    if (last.origin) $('#mwOrigin').value = last.origin;
    if (last.dest) $('#mwDest').value = last.dest;
    if (last.loadedMi) $('#mwLoadedMi').value = last.loadedMi;
    if (last.deadMi) $('#mwDeadMi').value = last.deadMi;
    if (last.revenue) $('#mwRevenue').value = last.revenue;
    if (last.dayOfWeek) $('#mwDayOfWeek').value = last.dayOfWeek;
    if (last.fatigue) $('#mwFatigue').value = last.fatigue;
    if (last.weeklyGross) $('#mwWeeklyGross').value = last.weeklyGross;
    if (last.strategicEnabled){
      const st = $('#mwStrategic'); if (st) st.checked = true;
      const sr = $('#mwStrategicReason'); if (sr){ sr.disabled = false; sr.value = last.strategicReason || ''; }
    }
  }

  // Market board
  $('#mbSaveBtn')?.addEventListener('click', mwSaveMarketEntry);
  $('#mbClearBtn')?.addEventListener('click', () => {
    ['mbLocation','mbRpmLow','mbRpmHigh','mbCompression','mbReload','mbDeadRisk','mbNotes'].forEach(id => { const el=$('#'+id); if(el) el.value=''; });
    mwRepoSignal();
  });
  // Live reposition signal
  ['mbCompression','mbRpmLow','mbRpmHigh','mbLocation'].forEach(id => {
    $('#'+id)?.addEventListener('input', mwRepoSignal);
  });

  // Auto-set day of week
  const dayMap = ['sun','mon','tue','wed','thu','fri','sat'];
  const today = dayMap[new Date().getDay()];
  if (!last?.dayOfWeek) $('#mwDayOfWeek').value = today;

  await mwRenderBoardLog();
  await mwRenderTomorrowSignal();
}

let omegaBound = false;

function omegaTierForMiles(m){
  if (m <= 180) return 0; if (m <= 350) return 1; if (m <= 600) return 2; if (m <= 900) return 3; return 4;
}
const OMEGA_TIERS = [
  { name:'Ultra-Short (≤180)', premium:{min:2.30,max:null}, ideal:{min:2.05,max:2.29}, strong:{min:1.85,max:2.04}, floor:{min:1.65,max:1.84}, under:{min:1.50,max:1.64}, underCond:'≤20 empty & Tier-1 drop only' },
  { name:'Short (181–350)', premium:{min:1.90,max:null}, ideal:{min:1.65,max:1.89}, strong:{min:1.50,max:1.64}, floor:{min:1.38,max:1.49}, under:{min:1.28,max:1.37}, underCond:'Tier-1 corridor only' },
  { name:'Mid (351–600)', premium:{min:1.60,max:null}, ideal:{min:1.45,max:1.59}, strong:{min:1.35,max:1.44}, floor:{min:1.28,max:1.34}, under:{min:1.20,max:1.27}, underCond:'home reposition or Tier-1 hub only' },
  { name:'Long (601–900)', premium:{min:1.52,max:null}, ideal:{min:1.40,max:1.51}, strong:{min:1.32,max:1.39}, floor:{min:1.26,max:1.31}, under:{min:1.18,max:1.25}, underCond:'hub-to-hub only' },
  { name:'Ultra-Long (901+)', premium:{min:1.48,max:null}, ideal:{min:1.38,max:1.47}, strong:{min:1.30,max:1.37}, floor:{min:1.24,max:1.29}, under:{min:1.18,max:1.23}, underCond:'deadhead replacement only' }
];

function omegaFormatMoneyRange(miles, rpmRange){
  const min$ = Math.round(miles * rpmRange.min);
  if (rpmRange.max == null) return `${fmtMoney(min$)} (${rpmRange.min.toFixed(2)} RPM)`;
  return `${fmtMoney(min$)}–${fmtMoney(Math.round(miles * rpmRange.max))} (${rpmRange.min.toFixed(2)}–${rpmRange.max.toFixed(2)} RPM)`;
}
function omegaShiftOneTierLower(t){
  return { name: t.name + ' (Erosion)', premium:{...t.ideal}, ideal:{...t.strong}, strong:{...t.floor},
    floor:{...t.under}, under:{min:Math.max(0,t.under.min-0.05), max:t.under.max==null?null:Math.max(0,t.under.max-0.05)}, underCond:t.underCond };
}
function omegaApplyAdder(r, add){
  return { min:+(r.min+add).toFixed(2), max:r.max==null?null:+(r.max+add).toFixed(2) };
}

const OMEGA_DEFAULT = 'Premium Win: $___ (___ RPM)\nIdeal Target: $___ (___ RPM)\nStrong Accept: $___ (___ RPM)\nFloor Accept: $___ (___ RPM)\nStrategic Under-Floor: $___ (___ RPM – conditional only)';

function omegaCompute(){
  const miles = Math.max(0, numVal('omMiles', 0));
  const empty = Math.max(0, numVal('omEmpty', 0));
  const dropTier = Number($('#omDropTier').value || 1);
  const delayPct = Math.max(0, numVal('omDelayPct', 0));
  const overnight = $('#omOvernight').checked;
  const over250 = $('#om250').checked;
  const risk = $('#omRisk').value;
  const day3Gross = Math.max(0, numVal('omDay3Gross', 0));
  const erosionOk = $('#omErosionOk').checked;

  // P2-4: save inputs
  setSetting('omegaLastInputs', { miles, empty, dropTier, delayPct, overnight, over250, risk, day3Gross, erosionOk }).catch(()=>{});

  if (!miles || miles <= 0){ $('#omOutput').textContent = OMEGA_DEFAULT; toast('Enter all-in miles.'); return; }

  let tierIndex = omegaTierForMiles(miles);
  if (delayPct >= 15) tierIndex = Math.min(4, tierIndex + 1);
  let tier = OMEGA_TIERS[tierIndex];
  if (erosionOk && day3Gross > 0 && day3Gross < 2000) tier = omegaShiftOneTierLower(tier);

  let add = 0;
  if (dropTier === 3) add += 0.10;
  let trapLine = '';
  if (risk === 'mod') add += 0.05;
  if (risk === 'winter') add += 0.10;
  if (risk === 'ice') add += 0.15;
  if (risk === 'closure') trapLine = 'Trap: Major closure risk — PASS unless Premium Win';
  else if (overnight || over250 || add > 0){
    trapLine = add > 0 ? `Trap: Risk adder applied (+${add.toFixed(2)} RPM)` : 'Trap: Risk protocol required (weather/511/metro check)';
  }

  const p = omegaApplyAdder(tier.premium, add);
  const i = omegaApplyAdder(tier.ideal, add);
  const s = omegaApplyAdder(tier.strong, add);
  const f = omegaApplyAdder(tier.floor, add);
  const u = omegaApplyAdder(tier.under, add);

  let underCond = tier.underCond || '';
  if (tierIndex === 0){
    underCond = (empty > 20 || dropTier !== 1)
      ? 'conditional only (does NOT qualify: requires ≤20 empty & Tier-1 drop)'
      : 'conditional only (qualifies: ≤20 empty & Tier-1 drop)';
  } else underCond = `conditional only (${underCond})`;

  const lines = [
    `Premium Win: ${omegaFormatMoneyRange(miles, p)}`,
    `Ideal Target: ${omegaFormatMoneyRange(miles, i)}`,
    `Strong Accept: ${omegaFormatMoneyRange(miles, s)}`,
    `Floor Accept: ${omegaFormatMoneyRange(miles, f)}`,
    `Strategic Under-Floor: ${omegaFormatMoneyRange(miles, u)} – ${underCond}`
  ];
  if (trapLine) lines.push('', trapLine);
  $('#omOutput').textContent = lines.join('\n');
}

async function renderOmega(){
  await mwInit();
  if (!omegaBound){
    omegaBound = true;
    $('#omCalcBtn').addEventListener('click', omegaCompute);
    $('#omResetBtn').addEventListener('click', () => {
      ['omMiles','omEmpty','omDelayPct','omDay3Gross'].forEach(id => { const el = $('#'+id); if (el) el.value=''; });
      $('#omDropTier').value='1'; $('#omRisk').value='none';
      $('#omOvernight').checked=false; $('#om250').checked=false; $('#omErosionOk').checked=false;
      $('#omOutput').textContent = OMEGA_DEFAULT;
      setSetting('omegaLastInputs', null).catch(()=>{});
    });
    // P2-4: restore last inputs
    const last = await getSetting('omegaLastInputs', null);
    if (last && typeof last === 'object'){
      if (last.miles) $('#omMiles').value = last.miles;
      if (last.empty) $('#omEmpty').value = last.empty;
      if (last.dropTier) $('#omDropTier').value = last.dropTier;
      if (last.delayPct) $('#omDelayPct').value = last.delayPct;
      if (last.overnight) $('#omOvernight').checked = true;
      if (last.over250) $('#om250').checked = true;
      if (last.risk) $('#omRisk').value = last.risk;
      if (last.day3Gross) $('#omDay3Gross').value = last.day3Gross;
      if (last.erosionOk) $('#omErosionOk').checked = true;
    }
    $('#omOutput').textContent = OMEGA_DEFAULT;
  }
  // Render top lanes
  await renderTopLanes();
}

async function renderTopLanes(){
  const box = $('#laneList');
  if (!box) return;
  try{
    const { trips } = await _getTripsAndExps();
    const lanes = computeLaneStats(trips);
    box.innerHTML = '';
    const top = lanes.slice(0, 10);
    if (!top.length){
      box.innerHTML = `<div class="muted" style="font-size:12px">Add trips with origin + destination to see lane intelligence.</div>`;
      return;
    }
    top.forEach(lane => {
      const el = document.createElement('div'); el.className = 'item'; el.style.cursor = 'pointer';
      const trendIcon = lane.trend > 0 ? '📈' : lane.trend < 0 ? '📉' : '➡️';
      const trendColor = lane.trend > 0 ? 'var(--good)' : lane.trend < 0 ? 'var(--bad)' : 'var(--muted)';
      const repeatBadge = lane.repeatRate !== null && lane.repeats > 0 ? ` • <span style="color:#58a6ff">↻ ${lane.repeatRate}% repeat</span>` : '';
      el.innerHTML = `<div class="left">
        <div class="v">${escapeHtml(lane.display)}</div>
        <div class="sub">${lane.trips} run${lane.trips>1?'s':''} • $${lane.avgRpm} avg RPM • $${lane.minRpm}–$${lane.maxRpm} range</div>
        <div class="k"><span style="color:${trendColor}">${trendIcon} ${lane.trendLabel}</span>${repeatBadge}${lane.daysSinceLast !== null ? ` • Last: ${lane.daysSinceLast}d ago` : ''}</div>
      </div><div class="right"><div class="v">${fmtMoney(lane.avgPay)}</div><div class="sub">avg/load</div></div>`;
      el.addEventListener('click', ()=> { haptic(10); openLaneBreakdown(lane, trips); });
      box.appendChild(el);
    });
    staggerItems(box);
  }catch{ box.innerHTML = `<div class="muted" style="font-size:12px">Error loading lane data.</div>`; }
}

function openLaneBreakdown(lane, allTrips){
  const body = document.createElement('div');
  body.style.padding = '0';

  const header = document.createElement('div');
  header.style.cssText = 'text-align:center;padding:14px 0';
  const trendColor = lane.trend > 0 ? 'var(--good)' : lane.trend < 0 ? 'var(--bad)' : 'var(--muted)';
  header.innerHTML = `
    <div style="font-size:16px;font-weight:800;margin-bottom:4px">${escapeHtml(lane.display)}</div>
    <div style="font-size:36px;font-weight:900;color:var(--accent);line-height:1.1">$${lane.avgRpm} <span style="font-size:16px;color:var(--muted)">avg RPM</span></div>
    <div style="margin-top:8px;font-size:14px;font-weight:700;color:${trendColor}">${lane.trend > 0 ? '📈' : lane.trend < 0 ? '📉' : '➡️'} ${lane.trendLabel}</div>`;
  body.appendChild(header);

  const stats = document.createElement('div');
  stats.className = 'row';
  stats.style.cssText = 'margin:0 0 14px;justify-content:center';
  stats.innerHTML = `
    <div class="pill"><span class="muted">Runs</span> <b>${lane.trips}</b></div>
    <div class="pill"><span class="muted">RPM range</span> <b>$${lane.minRpm}–$${lane.maxRpm}</b></div>
    <div class="pill"><span class="muted">Avg pay</span> <b>${fmtMoney(lane.avgPay)}</b></div>
    <div class="pill"><span class="muted">Total rev</span> <b>${fmtMoney(lane.totalPay)}</b></div>
    <div class="pill"><span class="muted">Total miles</span> <b>${fmtNum(lane.totalMiles)}</b></div>
    ${lane.volatility > 0 ? `<div class="pill"><span class="muted">Volatility</span> <b>±$${lane.volatility.toFixed(2)}</b></div>` : ''}
    ${lane.repeatRate !== null ? `<div class="pill"><span class="muted">Would repeat</span> <b style="color:#58a6ff">${lane.repeatRate}%</b></div>` : ''}
    ${lane.daysSinceLast !== null ? `<div class="pill"><span class="muted">Last run</span> <b>${lane.daysSinceLast}d ago</b></div>` : ''}`;
  body.appendChild(stats);

  // RPM history list (most recent first)
  if (lane.rpms && lane.rpms.length > 0){
    const card = document.createElement('div');
    card.className = 'card';
    const sorted = [...lane.rpms].sort((a,b)=> (b.date||'').localeCompare(a.date||''));
    let rows = '';
    sorted.forEach((r, i) => {
      const bg = r.rpm >= lane.avgRpm ? 'rgba(107,255,149,.06)' : 'rgba(255,107,107,.06)';
      rows += `<div style="display:flex;justify-content:space-between;padding:6px 8px;border-radius:8px;margin-bottom:4px;background:${bg}">
        <span style="font-size:12px">${escapeHtml(r.date || '—')}</span>
        <span style="font-size:12px;font-weight:700">$${r.rpm.toFixed(2)} RPM • ${fmtMoney(r.pay)}</span></div>`;
    });
    card.innerHTML = `<h3>Run History (${sorted.length})</h3>${rows}`;
    body.appendChild(card);
  }

  openModal(`Lane • ${escapeHtml(lane.display)}`, body);
}

// ---- Forms ----
function openQuickAddSheet(){
  haptic(20);
  const fab = $('#fab'); fab.classList.add('open');
  const wrap = document.createElement('div'); wrap.className = 'card'; wrap.style.cssText='border:0;box-shadow:none;background:transparent';
  wrap.innerHTML = `<div class="btn-row"><button class="btn primary" id="qaTrip">＋ Trip</button><button class="btn" id="qaExpense">＋ Expense</button><button class="btn" id="qaFuel">＋ Fuel</button><button class="btn" id="qaCompare">⚖️ Compare</button></div>
    <div style="margin-top:10px"><button class="btn primary" id="qaSnapLoad" style="width:100%;background:var(--accent2,#e67e22)">📸 Snap Load — OCR from Photo</button></div>
    <div class="muted" style="font-size:12px;margin-top:10px">Trip is Order # + Pay + Miles. Everything else is optional.</div>`;
  $('#qaTrip', wrap).addEventListener('click', ()=> { haptic(); closeModal(); openTripWizard(); });
  $('#qaExpense', wrap).addEventListener('click', ()=> { haptic(); closeModal(); openExpenseForm(); });
  $('#qaFuel', wrap).addEventListener('click', ()=> { haptic(); closeModal(); openFuelForm(); });
  $('#qaCompare', wrap).addEventListener('click', ()=> { haptic(); closeModal(); openLoadCompare(); });
  $('#qaSnapLoad', wrap).addEventListener('click', ()=> { haptic(); closeModal(); openSnapLoad(); });
  const origClose = closeModal;
  const _close = closeModal;
  openModal('Quick Add', wrap);
  // Reset FAB on close
  const obs = new MutationObserver(()=> { if ($('#modal').style.display === 'none'){ fab.classList.remove('open'); obs.disconnect(); } });
  obs.observe($('#modal'), {attributes:true, attributeFilter:['style']});
}

// ── Snap Load: OCR-powered load entry ──────────────────────────────
let _tesseractReady = false;
let _tesseractWorker = null;

async function loadTesseract(){
  if (_tesseractReady && _tesseractWorker) return _tesseractWorker;
  if (typeof Tesseract === 'undefined'){
    await loadScriptWithFallback([
      './vendor/tesseract.min.js',
      'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js',
    ], () => {
      if (typeof Tesseract === 'undefined' || typeof Tesseract.createWorker !== 'function'){
        throw new Error('Tesseract loaded but createWorker missing — possible CDN tampering');
      }
    }, 'Failed to load OCR engine. Add local vendor files or connect to the internet.');
  }
  try {
    _tesseractWorker = await Tesseract.createWorker('eng', 1, {
      workerPath: './vendor/worker.min.js',
      corePath: './vendor/tesseract-core-simd-lstm.wasm.js',
    });
  } catch (_localErr){
    _tesseractWorker = await Tesseract.createWorker('eng', 1, {
      workerPath: 'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/worker.min.js',
      corePath: 'https://cdn.jsdelivr.net/npm/tesseract.js-core@5.1.0/tesseract-core-simd-lstm.wasm.js',
    });
  }
  _tesseractReady = true;
  return _tesseractWorker;
}

function parseLoadText(text){
  // T5-FIX: Cap OCR text length to prevent regex DoS on adversarial images
  const safeText = String(text || '').slice(0, 10000);
  const result = { orderNo:'', customer:'', origin:'', destination:'', pay:0, loadedMiles:0, deadheadMiles:0, pickupDate:'', deliveryDate:'', weight:0, notes:'' };
  const lines = safeText.split('\n').map(l => l.trim()).filter(Boolean);
  const full = lines.join(' ');

  // ── Order / Reference / Load / Confirmation number ──
  const orderPats = [
    /(?:order|load|ref(?:erence)?|confirmation|conf|bol|pro)\s*#?\s*:?\s*([A-Z0-9][A-Z0-9\-]{2,20})/i,
    /\b([A-Z]{2,4}[\-]?\d{4,10})\b/,
    /#\s*([A-Z0-9\-]{3,15})/i,
  ];
  for (const p of orderPats){
    const m = full.match(p);
    if (m){ result.orderNo = m[1].replace(/[^A-Za-z0-9\-]/g,'').slice(0,20); break; }
  }

  // ── Dollar amounts → largest is likely the line haul rate ──
  const moneyMatches = [];
  const moneyRe = /\$\s*([\d,]+\.?\d{0,2})/g;
  let mm;
  while ((mm = moneyRe.exec(full)) !== null){
    const val = parseFloat(mm[1].replace(/,/g,''));
    if (val > 0 && val < 100000) moneyMatches.push(val);
  }
  // Also check "rate: 2500" or "total: 2500.00" patterns without $
  const rateRe = /(?:rate|total|line\s*haul|all[\s\-]*in)\s*:?\s*\$?\s*([\d,]+\.?\d{0,2})/gi;
  while ((mm = rateRe.exec(full)) !== null){
    const val = parseFloat(mm[1].replace(/,/g,''));
    if (val > 100 && val < 100000) moneyMatches.push(val);
  }
  if (moneyMatches.length) result.pay = Math.max(...moneyMatches);

  // ── Miles ──
  const milesPats = [
    /(\d[\d,]{0,6})\s*(?:total\s*)?(?:miles|mi\b)/i,
    /(?:miles|distance|mileage)\s*:?\s*(\d[\d,]{0,6})/i,
  ];
  for (const p of milesPats){
    const m = full.match(p);
    if (m){ result.loadedMiles = parseInt(m[1].replace(/,/g,''), 10); break; }
  }

  // ── Deadhead / Distance (Load board specific) ──
  // Prefer explicit "Deadhead" and "Distance" fields when present (e.g., Trucker Path Truckloads)
  const dhm = full.match(/deadhead\s*:?\s*(\d[\d,]{0,6})\s*(?:miles|mi\b)/i);
  if (dhm) result.deadheadMiles = parseInt(dhm[1].replace(/,/g,''), 10) || 0;

  const distm = full.match(/distance\s*:?\s*(\d[\d,]{0,6})\s*(?:miles|mi\b)/i);
  if (distm){
    const dist = parseInt(distm[1].replace(/,/g,''), 10) || 0;
    if (dist > 0) result.loadedMiles = dist; // treat as loaded miles for evaluator
  }

  // ── City, State pairs (shipper/origin → consignee/destination) ──
  const cityStatePat = /([A-Z][a-zA-Z\s\.]{1,25}),?\s*([A-Z]{2})\b/g;
  const cities = [];
  let cs;
  while ((cs = cityStatePat.exec(full)) !== null){
    const city = cs[1].trim();
    const state = cs[2].toUpperCase();
    // Filter out noise by requiring known US state abbreviations
    if (/^(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)$/.test(state)){
      cities.push(`${city}, ${state}`);
    }
  }
  if (cities.length >= 2){ result.origin = cities[0]; result.destination = cities[cities.length - 1]; }
  else if (cities.length === 1) result.origin = cities[0];

  // ── Shipper / consignee as origin/destination labels ──
  // T5-FIX: Use [^\n] instead of . to prevent catastrophic backtracking on adversarial OCR text
  const shipperMatch = full.match(/(?:shipper|pick\s*up|origin)\s*:?\s*([^\n]{5,40}?)(?:\n|,\s*[A-Z]{2}|$)/i);
  const consigneeMatch = full.match(/(?:consignee|deliver(?:y)?|destination|drop)\s*:?\s*([^\n]{5,40}?)(?:\n|,\s*[A-Z]{2}|$)/i);
  if (!result.origin && shipperMatch) result.origin = shipperMatch[1].trim().slice(0,60);
  if (!result.destination && consigneeMatch) result.destination = consigneeMatch[1].trim().slice(0,60);

  // ── Customer / Broker ──
  const brokerPats = [
    /(?:broker|carrier|customer|company|brokerage)\s*:?\s*(.{3,50})/i,
    /(?:dispatched\s+(?:by|from)|booked\s+(?:by|with))\s*:?\s*(.{3,50})/i,
  ];
  for (const p of brokerPats){
    const m = full.match(p);
    if (m){ result.customer = m[1].trim().replace(/[^A-Za-z0-9\s&.\-']/g,'').slice(0,80); break; }
  }

  // ── Dates ──
  const datePats = [
    /(?:pick\s*up|ship|pu)\s*(?:date)?\s*:?\s*(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})/i,
    /(?:deliver(?:y)?|drop|del)\s*(?:date)?\s*:?\s*(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})/i,
  ];
  const parseDateStr = (s) => {
    const parts = s.split(/[\/-]/);
    if (parts.length !== 3) return '';
    let [m, d, y] = parts.map(Number);
    if (y < 100) y += 2000;
    if (m > 12){ [m, d] = [d, m]; }
    if (m < 1 || m > 12 || d < 1 || d > 31 || y < 2020 || y > 2030) return '';
    return `${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
  };
  const puMatch = full.match(datePats[0]);
  const delMatch = full.match(datePats[1]);
  if (puMatch) result.pickupDate = parseDateStr(puMatch[1]);
  if (delMatch) result.deliveryDate = parseDateStr(delMatch[1]);

  // ── Weight ──
  const weightMatch = full.match(/(\d[\d,]{0,7})\s*(?:lbs?|pounds?|#)/i) || full.match(/(?:weight)\s*:?\s*(\d[\d,]{0,7})/i);
  if (weightMatch) result.weight = parseInt(weightMatch[1].replace(/,/g,''), 10);

  // Stuff confidence and raw into notes
  const parsed = [];
  if (result.orderNo) parsed.push(`Order: ${result.orderNo}`);
  if (result.pay) parsed.push(`Pay: $${result.pay}`);
  if (result.loadedMiles) parsed.push(`Miles: ${result.loadedMiles}`);
  if (result.origin) parsed.push(`From: ${result.origin}`);
  if (result.destination) parsed.push(`To: ${result.destination}`);
  if (result.weight) parsed.push(`Weight: ${result.weight} lbs`);
  result._summary = parsed.join(' • ') || 'Could not extract structured data';
  result._rawText = text.slice(0, 2000);

  return result;
}


/** Parse multiple load cards from OCR or pasted text (best-effort).
 *  Supports Trucker Path Truckloads-style listings with Deadhead / Distance / Price.
 */
function parseLoadListFromText(text){
  const safeText = String(text || '').slice(0, 15000);
  const full = safeText.replace(/\s+/g,' ').trim();
  const loads = [];
  // Pattern: ORIGIN (City, ST) DEST (City, ST) ... Deadhead X mi ... Distance Y mi ... Price $Z
  const reCard = /([A-Z][a-zA-Z\.\s]{1,25}),\s*([A-Z]{2})\s+([A-Z][a-zA-Z\.\s]{1,25}),\s*([A-Z]{2})[\s\S]{0,220}?(?:deadhead\s*:?\s*(\d[\d,]{0,6})\s*(?:mi|miles))[\s\S]{0,220}?(?:distance\s*:?\s*(\d[\d,]{0,6})\s*(?:mi|miles))[\s\S]{0,220}?(?:price\s*:?\s*\$?\s*(\d[\d,]{0,8}))?/gi;
  let m;
  while ((m = reCard.exec(safeText)) !== null){
    const origin = `${m[1].trim()}, ${m[2].toUpperCase()}`;
    const destination = `${m[3].trim()}, ${m[4].toUpperCase()}`;
    const deadheadMiles = parseInt(String(m[5]||'0').replace(/,/g,''),10)||0;
    const loadedMiles = parseInt(String(m[6]||'0').replace(/,/g,''),10)||0;
    const pay = m[7] ? (parseInt(String(m[7]).replace(/,/g,''),10)||0) : 0;
    if (!origin || !destination || loadedMiles<=0) continue;
    loads.push({ origin, destination, deadheadMiles, loadedMiles, pay });
  }
  // De-dup similar cards
  const uniq = [];
  const seen = new Set();
  for (const l of loads){
    const k = `${l.origin}|${l.destination}|${l.loadedMiles}|${l.deadheadMiles}|${l.pay}`;
    if (seen.has(k)) continue;
    seen.add(k); uniq.push(l);
  }
  return uniq;
}

function openSnapLoad(preFile){
  const body = document.createElement('div');
  body.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <div class="muted" style="font-size:12px;margin-bottom:10px">Take a photo or select a screenshot of a rate confirmation, load board posting, or dispatch sheet. OCR will extract the details.</div>
    <div class="btn-row" style="margin-bottom:12px">
      <button class="btn primary" id="snapCamera">📷 Camera</button>
      <button class="btn" id="snapFile">📁 Choose File</button>
    
    <div style="margin:10px 0 6px;font-size:12px" class="muted">Or paste a load listing / dispatch text (or import a CSV of loads):</div>
    <textarea id="snapPaste" placeholder="Paste load text here (example: Origin Pryor, OK Destination Tolleson, AZ Deadhead 36 mi Distance 1161 mi Price $2400)" style="width:100%;min-height:90px;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.03);color:var(--text);font-size:12px;line-height:1.35;margin-bottom:8px"></textarea>
    <div class="btn-row" style="margin-bottom:12px">
      <button class="btn" id="snapParsePaste">🧠 Analyze Paste</button>
      <button class="btn" id="snapCsvBtn">📄 Import CSV</button>
    </div>
    <input type="file" id="snapCsvInput" accept=".csv,text/csv" style="display:none" />
</div>
    <input type="file" id="snapInput" accept="image/*" style="display:none" />
    <input type="file" id="snapCameraInput" accept="image/*" capture="environment" style="display:none" />
    <div id="snapPreview" style="display:none;margin-bottom:12px">
      <img id="snapImg" style="max-width:100%;max-height:300px;border-radius:8px;border:1px solid rgba(255,255,255,0.1)" />
    </div>
    <div id="snapStatus" style="display:none;font-size:12px" class="muted"></div>
    <div id="snapResults" style="display:none">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">📋 Extracted Data</div>
      <div id="snapParsed" style="font-size:12px;padding:10px;border-radius:6px;background:rgba(255,255,255,0.04);margin-bottom:8px"></div>
      <div id="snapLoadList" style="display:none;margin-top:10px"></div>
      <div class="muted" style="font-size:11px;margin-bottom:12px">You can edit everything in the trip form. OCR isn't perfect — always verify.</div>
      <div class="btn-row">
        <button class="btn primary" id="snapAccept">✓ Send to Load Evaluator</button>
        <button class="btn" id="snapRetry">↻ Try Another</button>
      </div>
      <details style="margin-top:12px"><summary class="muted" style="font-size:11px;cursor:pointer">Raw OCR text</summary>
        <pre id="snapRawText" style="font-size:10px;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all;padding:8px;background:rgba(0,0,0,0.2);border-radius:4px;margin-top:6px"></pre>
      </details>
    </div>
  </div>`;

  let _parsedData = null;

  function renderSingleParsed(p){
    const parsed = $('#snapParsed', body);
    const fields = [];
    if (p.orderNo) fields.push(`<b>Order #:</b> ${escapeHtml(p.orderNo)}`);
    if (p.customer) fields.push(`<b>Customer:</b> ${escapeHtml(p.customer)}`);
    if (p.origin) fields.push(`<b>Origin:</b> ${escapeHtml(p.origin)}`);
    if (p.destination) fields.push(`<b>Destination:</b> ${escapeHtml(p.destination)}`);
    if (p.pay) fields.push(`<b>Pay:</b> $${Number(p.pay||0).toLocaleString()}`);
    if (p.loadedMiles) fields.push(`<b>Distance:</b> ${Number(p.loadedMiles||0).toLocaleString()} mi`);
    if (p.deadheadMiles) fields.push(`<b>Deadhead:</b> ${Number(p.deadheadMiles||0).toLocaleString()} mi`);
    if (p.pickupDate) fields.push(`<b>Pickup:</b> ${escapeHtml(p.pickupDate)}`);
    if (p.deliveryDate) fields.push(`<b>Delivery:</b> ${escapeHtml(p.deliveryDate)}`);
    parsed.innerHTML = fields.length ? fields.join('<br>') : '<span class="muted">No structured fields detected.</span>';
    const listEl = $('#snapLoadList', body); if (listEl) listEl.style.display = 'none';
  }

  function renderLoadList(loads){
    // Rank by True RPM (pay / total miles)
    const ranked = loads.map(l => {
      const total = Math.max(1, (l.loadedMiles||0) + (l.deadheadMiles||0));
      const rpm = (l.pay||0) / total;
      const tier = mwClassifyRPM(rpm);
      return { ...l, totalMiles: total, trueRPM: rpm, tier };
    }).sort((a,b)=> (b.trueRPM - a.trueRPM));

    // Summary
    const parsed = $('#snapParsed', body);
    parsed.innerHTML = `<b>Found:</b> ${ranked.length} loads<br><b>Top True RPM:</b> ${ranked[0] ? ranked[0].trueRPM.toFixed(2) : '—'}`;

    const listEl = $('#snapLoadList', body);
    if (!listEl) return;
    listEl.style.display = 'block';

    const rows = ranked.slice(0, 12).map((l,i)=> {
      const grade = l.trueRPM >= 1.75 ? 'A' : (l.trueRPM >= 1.60 ? 'B' : (l.trueRPM >= 1.50 ? 'C' : (l.trueRPM >= 1.40 ? 'D' : (l.trueRPM >= 1.25 ? 'E' : 'F'))));
      const verdict = l.tier?.verdict || '';
      return `<div style="display:flex;gap:10px;align-items:center;padding:10px;border:1px solid var(--border);border-radius:12px;margin-top:8px;background:rgba(255,255,255,0.02)">
        <div style="min-width:34px;text-align:center;font-weight:800">${i+1}</div>
        <div style="flex:1">
          <div style="font-weight:700;font-size:13px">${escapeHtml(l.origin)} → ${escapeHtml(l.destination)}</div>
          <div class="muted" style="font-size:11px;margin-top:2px">
            ${l.loadedMiles||0} mi + ${l.deadheadMiles||0} dh • ${fmtMoney(l.pay||0)} • True RPM ${l.trueRPM.toFixed(2)} • Grade ${grade} (${escapeHtml(verdict)})
          </div>
        </div>
        <button class="btn primary" data-sendload="${i}">Use</button>
      </div>`;
    }).join('');

    listEl.innerHTML = `<div style="font-size:13px;font-weight:700;margin-top:6px">🏁 Ranked Loads (Top 12)</div>${rows}<div class="muted" style="font-size:11px;margin-top:8px">Tap “Use” to send the selected load into the Midwest Evaluator.</div>`;

    // Wire "Use" buttons via event delegation
    listEl.querySelectorAll('[data-sendload]').forEach(btn => {
      btn.addEventListener('click', ()=> {
        const idx = Number(btn.getAttribute('data-sendload'));
        const chosen = ranked[idx];
        if (!chosen) return;
        _parsedData = { ...chosen };
        haptic(15);
        closeModal();
        location.hash = '#omega';
        setTimeout(() => {
          $('#mwOrigin').value = chosen.origin || '';
          $('#mwDest').value = chosen.destination || '';
          $('#mwLoadedMi').value = String(chosen.loadedMiles || 0);
          $('#mwDeadMi').value = String(chosen.deadheadMiles || 0);
          $('#mwRevenue').value = String(chosen.pay || 0);
          try { mwEvaluateLoad(); } catch(e) {}
          toast('Loaded into Midwest Evaluator');
        }, 60);
      });
    });
  }

  function parseLoadsCSV(csvText){
    const text = String(csvText||'').slice(0, 2_000_000);
    const lines = text.split(/\r?\n/).filter(l=>l.trim().length);
    if (!lines.length) return [];
    const split = (line) => {
      // naive CSV split supporting quoted fields
      const out=[]; let cur=''; let q=false;
      for (let i=0;i<line.length;i++){
        const ch=line[i];
        if (ch==='"'){ q=!q; continue; }
        if (ch===',' && !q){ out.push(cur.trim()); cur=''; continue; }
        cur+=ch;
      }
      out.push(cur.trim());
      return out;
    };
    const header = split(lines[0]).map(h=>h.toLowerCase());
    const idx = (k)=> header.indexOf(k);
    const iOrigin = idx('origin'); const iDest = idx('destination'); 
    const iDead = idx('deadhead'); const iDist = idx('distance'); const iPay = idx('price')>=0?idx('price'):idx('pay');
    const loads=[];
    for (let r=1;r<lines.length;r++){
      const cols = split(lines[r]);
      const origin = cols[iOrigin] || '';
      const destination = cols[iDest] || '';
      const deadheadMiles = parseInt((cols[iDead]||'0').replace(/[^\d]/g,''),10)||0;
      const loadedMiles = parseInt((cols[iDist]||'0').replace(/[^\d]/g,''),10)||0;
      const pay = parseFloat((cols[iPay]||'0').replace(/[^\d.]/g,''))||0;
      if (!origin || !destination || loadedMiles<=0) continue;
      loads.push({ origin, destination, deadheadMiles, loadedMiles, pay });
    }
    return loads;
  }

  const csvInput = $('#snapCsvInput', body);
  csvInput?.addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try{
      const txt = await file.text();
      const loads = parseLoadsCSV(txt);
      if (!loads.length){ toast('No loads found in CSV', true); return; }
      _parsedData = { _loads: loads, _confidence: 0 };
      $('#snapResults', body).style.display = 'block';
      $('#snapStatus', body).style.display = 'none';
      renderLoadList(loads);
      toast(`Imported ${loads.length} loads`);
    }catch(err){ console.error('[FL] CSV import error:', err); toast('CSV import failed. Check file format.', true); }
    e.target.value = '';
  });

  const fileInput = $('#snapInput', body);
  const cameraInput = $('#snapCameraInput', body);

  async function processImage(file){
    if (!file || !file.type.startsWith('image/')){ toast('Please select an image file', true); return; }
    if (file.size > 10 * 1024 * 1024){ toast('Image too large (max 10MB)', true); return; }

    // Show preview
    const url = URL.createObjectURL(file);
    const img = $('#snapImg', body);
    img.src = url;
    $('#snapPreview', body).style.display = 'block';
    $('#snapResults', body).style.display = 'none';

    const status = $('#snapStatus', body);
    status.style.display = 'block';
    status.innerHTML = '<div style="font-size:13px">⏳ Loading OCR engine...</div><div class="muted" style="font-size:11px">First time may take a moment to download (~11MB)</div>';

    try {
      const worker = await loadTesseract();
      status.innerHTML = '<div style="font-size:13px">🔍 Scanning image...</div>';

      const { data } = await worker.recognize(file);
      const text = data.text || '';
      const confidence = data.confidence || 0;

      if (!text.trim()){
        status.innerHTML = '<div style="font-size:13px;color:var(--danger)">No text detected. Try a clearer photo with better lighting.</div>';
        return;
      }

      const list = parseLoadListFromText(text);
      _parsedData = list.length ? { _loads: list } : parseLoadText(text);
      _parsedData._confidence = confidence;
      if (list.length) { renderLoadList(list); } else { renderSingleParsed(_parsedData); }

      status.style.display = 'none';
      $('#snapResults', body).style.display = 'block';

      // Build parsed results display (single-load only)
      if (!(_parsedData && _parsedData._loads && _parsedData._loads.length)){
      const parsed = $('#snapParsed', body);
      const fields = [];
      if (_parsedData.orderNo) fields.push(`<b>Order #:</b> ${escapeHtml(_parsedData.orderNo)}`);
      if (_parsedData.customer) fields.push(`<b>Customer:</b> ${escapeHtml(_parsedData.customer)}`);
      if (_parsedData.origin) fields.push(`<b>Origin:</b> ${escapeHtml(_parsedData.origin)}`);
      if (_parsedData.destination) fields.push(`<b>Destination:</b> ${escapeHtml(_parsedData.destination)}`);
      if (_parsedData.pay) fields.push(`<b>Pay:</b> $${_parsedData.pay.toLocaleString()}`);
      if (_parsedData.loadedMiles) fields.push(`<b>Miles:</b> ${_parsedData.loadedMiles.toLocaleString()}`);
      if (_parsedData.weight) fields.push(`<b>Weight:</b> ${_parsedData.weight.toLocaleString()} lbs`);
      if (_parsedData.pickupDate) fields.push(`<b>Pickup:</b> ${_parsedData.pickupDate}`);
      if (_parsedData.deliveryDate) fields.push(`<b>Delivery:</b> ${_parsedData.deliveryDate}`);
      fields.push(`<span class="muted">Confidence: ${Math.round(confidence)}%</span>`);

      if (fields.length <= 1){
        parsed.innerHTML = '<div style="color:var(--warn)">Could not extract structured data. The image may not contain a load posting, or try a clearer photo.</div>';
      } else {
        parsed.innerHTML = fields.join('<br>');
      }

      // Raw text
            }

$('#snapRawText', body).textContent = text.slice(0, 3000);

    } catch(err){
      status.innerHTML = `<div style="color:var(--danger)">OCR failed: ${escapeHtml(String(err.message || err))}</div><div class="muted" style="font-size:11px;margin-top:4px">Make sure you're online for the first OCR scan (engine download). After that it works offline.</div>`;
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  $('#snapCamera', body).addEventListener('click', ()=> { haptic(); cameraInput.click(); });
  $('#snapFile', body).addEventListener('click', ()=> { haptic(); fileInput.click(); });
  fileInput.addEventListener('change', (e)=> { if (e.target.files[0]) processImage(e.target.files[0]); });
  cameraInput.addEventListener('change', (e)=> { if (e.target.files[0]) processImage(e.target.files[0]); });

  // If opened with a pre-selected file (e.g. PDF import), process immediately
  if (preFile && preFile.type === 'application/pdf'){
    // For PDFs, try to render first page as image, or just show message
    const status = $('#snapStatus', body);
    status.style.display = 'block';
    status.innerHTML = '<div style="font-size:13px">📄 PDF detected — extracting text via OCR...</div><div class="muted" style="font-size:11px">For best results, take a screenshot of the PDF and try Camera/File instead.</div>';
  } else if (preFile){
    processImage(preFile);
  }

  // Delegate — wait for buttons to exist in DOM before binding
  body.addEventListener('click', (e) => {
    if (e.target.id === 'snapAccept' && _parsedData){
      haptic();
      closeModal();

      // Prefer multi-load list if available (from paste/OCR)
      const loads = (_parsedData._loads && Array.isArray(_parsedData._loads) && _parsedData._loads.length) ? _parsedData._loads : null;
      const l0 = loads ? loads[0] : _parsedData;

      // Send to Midwest Stack Evaluator (Omega)
      location.hash = '#omega';
      setTimeout(() => {
        const o = $('#mwOrigin'); const d = $('#mwDest');
        const lm = $('#mwLoadedMi'); const dm = $('#mwDeadMi'); const rev = $('#mwRevenue');
        if (o) o.value = l0.origin || '';
        if (d) d.value = l0.destination || '';
        if (lm) lm.value = String(l0.loadedMiles || 0);
        if (dm) dm.value = String(l0.deadheadMiles || 0);
        if (rev) rev.value = String(l0.pay || 0);
        try { mwEvaluateLoad(); } catch(e) {}
        toast('Loaded into Midwest Evaluator');
      }, 60);
    }
    
    if (e.target.id === 'snapParsePaste'){
      haptic(15);
      const t = ($('#snapPaste', body)?.value || '').trim();
      if (!t){ toast('Paste some load text first', true); return; }
      const list = parseLoadListFromText(t);
      if (list.length){
        _parsedData = { _loads: list, _confidence: 0, origin:'', destination:'', pay:0, loadedMiles:0, deadheadMiles:0 };
        renderLoadList(list);
        $('#snapResults', body).style.display = 'block';
        $('#snapStatus', body).style.display = 'none';
        toast(`Parsed ${list.length} loads`);
      } else {
        // Fallback to single-load parser
        _parsedData = parseLoadText(t);
        renderSingleParsed(_parsedData);
        toast('Parsed 1 load');
      }
    }
    if (e.target.id === 'snapCsvBtn'){
      haptic(10);
      const inp = $('#snapCsvInput', body);
      if (inp) inp.click();
    }
if (e.target.id === 'snapRetry'){
      haptic();
      _parsedData = null;
      $('#snapPreview', body).style.display = 'none';
      $('#snapResults', body).style.display = 'none';
      $('#snapStatus', body).style.display = 'none';
    }
  });

  openModal('📸 Snap Load', body);
}

function openTripWizard(existing=null){
  // Snap Load: if _snapPrefill flag is set, treat as new trip with pre-filled data
  const isSnapPrefill = existing && existing._snapPrefill;
  const mode = (existing && !isSnapPrefill) ? 'edit' : 'add';
  const trip = existing ? {...newTripTemplate(), ...existing} : newTripTemplate();
  if (isSnapPrefill) delete trip._snapPrefill;
  const body = document.createElement('div');
  const step1 = document.createElement('div');
  const step2 = document.createElement('div');

  if (isSnapPrefill){
    const banner = document.createElement('div');
    banner.style.cssText = 'padding:8px 12px;border-radius:6px;background:rgba(230,126,34,0.15);border:1px solid rgba(230,126,34,0.3);margin-bottom:12px;font-size:12px';
    banner.innerHTML = '📸 <b>Snap Load</b> — Pre-filled from OCR. <span class="muted">Verify all fields before saving.</span>';
    body.appendChild(banner);
  } else if (mode === 'add'){
    // First-trip helper: show guidance if user has few trips
    countStore('trips').then(cnt => {
      if (cnt < 3){
        const tip = document.createElement('div');
        tip.style.cssText = 'padding:8px 12px;border-radius:6px;background:rgba(88,166,255,.08);border:1px solid rgba(88,166,255,.2);margin-bottom:12px;font-size:12px';
        tip.innerHTML = cnt === 0
          ? '👋 <b>First trip!</b> Just need Order # and Pay to get started. Miles unlock RPM tracking and profit scoring.'
          : `💡 <b>Tip:</b> Add the broker name and origin/destination on step 2 — they power your Broker Grades and Lane Intel.`;
        body.insertBefore(tip, body.firstChild);
      }
    }).catch(()=>{});
  }

  step1.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <div class="muted" style="font-size:12px;margin-bottom:10px">Step 1/2 — Required</div>
    <label>Order # *</label><input id="f_orderNo" placeholder="e.g., 123456 — from your rate confirmation" ${mode==='edit'?'disabled':''} />
    <div class="grid2"><div><label>Pay $ *</label><input id="f_pay" type="number" step="0.01" placeholder="Total line haul pay" /></div>
      <div><label>Pickup date</label><input id="f_pickup" type="date" /></div></div>
    <div class="grid2"><div><label>Loaded miles</label><input id="f_loaded" type="number" step="1" placeholder="Miles with freight" /></div>
      <div><label>Empty miles</label><input id="f_empty" type="number" step="1" placeholder="Deadhead to pickup" /></div></div>
    <div class="btn-row" style="margin-top:12px"><button class="btn" id="toStep2">Next (optional)</button>
      <button class="btn primary" id="saveTrip">Save</button>
      ${mode==='edit'?'<button class="btn danger" id="delTrip">Delete</button>':''}</div>
    <div class="muted" id="tripHint" style="font-size:12px;margin-top:10px"></div></div>`;

  step2.style.display = 'none';
  step2.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <div class="muted" style="font-size:12px;margin-bottom:10px">Step 2/2 — Optional</div>
    <label>Customer</label><input id="f_customer" placeholder="Broker / shipper" />
    <div id="brokerIntelBox"></div>
    <div class="grid2"><div><label>Origin</label><input id="f_origin" placeholder="City, ST" /></div>
      <div><label>Destination</label><input id="f_dest" placeholder="City, ST" /></div></div>
    <div id="laneIntelBox"></div>
    <div id="stopsSection" style="margin-top:12px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <label style="margin:0;font-size:13px;font-weight:600">Stops</label>
        <button class="btn sm" id="addStopBtn" type="button" style="font-size:11px">＋ Add Stop</button>
      </div>
      <div id="stopsList"></div>
      <div class="muted" style="font-size:11px;margin-top:4px">Optional intermediate stops (pickup → stop → delivery)</div>
    </div>
    <div class="grid2"><div><label>Delivery date</label><input id="f_delivery" type="date" /></div>
      <div><label>Status</label><select id="f_paid"><option value="false">Unpaid</option><option value="true">Paid</option></select></div></div>
    <label>Notes</label><textarea id="f_notes" placeholder="Optional"></textarea>
    <div style="margin-top:10px"><label class="chk" style="font-size:14px"><input type="checkbox" id="f_runAgain" /> Would run this lane again</label><div class="muted" style="font-size:11px;margin-top:4px">Feeds your Lane Intelligence — helps identify your best corridors</div></div>
    <label style="margin-top:12px">Receipts</label>
    <div style="display:flex;gap:8px;align-items:center">
      <input id="f_receipts" type="file" accept="image/*,application/pdf" multiple style="flex:1" />
      <button class="btn sm" id="f_camera" type="button" style="font-size:12px">📷 Camera</button>
    </div>
    <div class="btn-row" style="margin-top:12px"><button class="btn" id="backStep1">Back</button><button class="btn primary" id="saveTrip2">Save</button></div></div>`;

  body.appendChild(step1); body.appendChild(step2);

  $('#f_orderNo', body).value = trip.orderNo || '';
  $('#f_pay', body).value = trip.pay || '';
  $('#f_pickup', body).value = trip.pickupDate || isoDate();
  $('#f_loaded', body).value = trip.loadedMiles || '';
  $('#f_empty', body).value = trip.emptyMiles || '';

  if (mode==='edit'){
    $('#f_customer', body).value = trip.customer || '';
    $('#f_origin', body).value = trip.origin || '';
    $('#f_dest', body).value = trip.destination || '';
    $('#f_delivery', body).value = trip.deliveryDate || trip.pickupDate || isoDate();
    $('#f_paid', body).value = String(!!trip.isPaid);
    $('#f_notes', body).value = trip.notes || '';
    $('#f_runAgain', body).checked = !!trip.wouldRunAgain;
  } else if (isSnapPrefill){
    // Snap Load OCR pre-fill — populate all fields but keep add mode
    $('#f_customer', body).value = trip.customer || '';
    $('#f_origin', body).value = trip.origin || '';
    $('#f_dest', body).value = trip.destination || '';
    $('#f_delivery', body).value = trip.deliveryDate || trip.pickupDate || isoDate();
    $('#f_paid', body).value = 'false';
    $('#f_notes', body).value = trip.notes || '';
  } else { $('#f_delivery', body).value = isoDate(); $('#f_paid', body).value = 'false'; }

  // v14.5.0: Multi-stop management
  function addStopRow(stopData=null){
    const stopsList = $('#stopsList', body);
    if (!stopsList) return;
    const count = $$('.stop-entry', body).length;
    if (count >= 10){ toast('Max 10 stops per trip', true); return; }
    const row = document.createElement('div');
    row.className = 'stop-entry';
    row.style.cssText = 'display:flex;gap:6px;align-items:center;margin-bottom:6px;padding:8px;border-radius:var(--r-sm);background:var(--surface-0);border:1px solid var(--border-subtle)';
    row.innerHTML = `<div style="flex:1;display:flex;flex-direction:column;gap:4px">
      <div style="display:flex;gap:6px">
        <input class="stop-city" placeholder="City, ST" style="flex:1;font-size:12px" />
        <select class="stop-type" style="width:80px;font-size:11px">
          <option value="stop">Stop</option><option value="pickup">Pickup</option><option value="delivery">Delivery</option>
        </select>
      </div>
      <div style="display:flex;gap:6px">
        <input class="stop-date" type="date" style="flex:1;font-size:11px" />
        <input class="stop-notes" placeholder="Notes" style="flex:1;font-size:11px" />
      </div>
    </div>
    <button class="btn sm stop-remove" type="button" style="color:var(--bad);font-size:14px;padding:4px 8px">✕</button>`;
    if (stopData){
      $('.stop-city', row).value = stopData.city || '';
      $('.stop-type', row).value = stopData.type || 'stop';
      $('.stop-date', row).value = stopData.date || '';
      $('.stop-notes', row).value = stopData.notes || '';
    }
    $('.stop-remove', row).addEventListener('click', ()=> { row.remove(); });
    stopsList.appendChild(row);
  }
  $('#addStopBtn', body)?.addEventListener('click', ()=> { haptic(10); addStopRow(); });
  // Populate existing stops
  if (trip.stops && trip.stops.length){
    for (const s of trip.stops) addStopRow(s);
  }

  // v14.5.0: Camera button opens receipt camera
  $('#f_camera', body)?.addEventListener('click', ()=> { haptic(15); openReceiptCamera(trip.orderNo || 'new'); });

  async function validateStep1(){
    const orderNo = normOrderNo($('#f_orderNo', body).value);
    const pay = Number($('#f_pay', body).value || 0);
    const hint = $('#tripHint', body);
    if (!orderNo){ hint.textContent = 'Order # is required.'; return false; }
    if (!(pay > 0)){ hint.textContent = 'Pay must be > 0.'; return false; }
    if (mode==='add' && await tripExists(orderNo)){ hint.textContent = 'Order # already exists.'; return false; }
    hint.textContent = 'Looks good.'; return true;
  }
  async function collectTrip(stepNo){
    trip.orderNo = normOrderNo($('#f_orderNo', body).value);
    trip.pay = Number($('#f_pay', body).value || 0);
    trip.pickupDate = $('#f_pickup', body).value || isoDate();
    trip.loadedMiles = Math.max(0, Number($('#f_loaded', body).value || 0));
    trip.emptyMiles = Math.max(0, Number($('#f_empty', body).value || 0));
    if (stepNo >= 2){
      trip.customer = clampStr($('#f_customer', body).value, 80);
      trip.origin = clampStr($('#f_origin', body).value, 60);
      trip.destination = clampStr($('#f_dest', body).value, 60);
      trip.deliveryDate = $('#f_delivery', body).value || trip.pickupDate;
      trip.isPaid = ($('#f_paid', body).value === 'true');
      trip.notes = clampStr($('#f_notes', body).value, 500);
      trip.wouldRunAgain = $('#f_runAgain', body).checked ? true : null;
      // v14.5.0: collect stops
      const stopEls = $$('.stop-entry', body);
      trip.stops = [];
      for (const el of stopEls){
        const city = clampStr($('.stop-city', el)?.value || '', 60);
        if (!city) continue;
        trip.stops.push({
          city,
          date: $('.stop-date', el)?.value || '',
          type: $('.stop-type', el)?.value || 'stop',
          notes: clampStr($('.stop-notes', el)?.value || '', 200),
        });
      }
    }
  }
  async function save(stepNo){
    if (!(await validateStep1())){ toast('Fix required fields', true); return; }
    await collectTrip(stepNo);
    const saved = await upsertTrip(trip);
    if (stepNo >= 2){
      const f = $('#f_receipts', body).files;
      // Combine file picker + camera captures
      const allFiles = [];
      if (f && f.length) for (const file of f) allFiles.push(file);
      if (_cameraReceiptFiles.length) { allFiles.push(..._cameraReceiptFiles); _cameraReceiptFiles = []; }
      if (allFiles.length) await saveNewReceipts(saved.orderNo, allFiles);
    }
    invalidateKPICache();
    // First-trip celebration
    const tripCount = await countStore('trips');
    if (mode === 'add' && tripCount === 1){
      closeModal();
      setTimeout(()=> {
        toast('🎉 First trip logged! Your dashboard is live.');
        // Remove FAB pulse
        $('#fab').classList.remove('pulse');
        const hint = $('#fabHint');
        if (hint) hint.style.display = 'none';
      }, 300);
      await renderTrips(true); await renderHome();
      return;
    }
    // Compute and show Load Decision Score
    try{
      const { trips: allT, exps: allE } = await _getTripsAndExps();
      const fc = { mpg: Number(await getSetting('vehicleMpg', 0) || 0), pricePerGal: Number(await getSetting('fuelPrice', 0) || 0) };
      const score = computeLoadScore(saved, allT, allE, fc);
      closeModal();
      setTimeout(()=> showScoreFlash(saved, score), 400);
    }catch{
      toast(mode==='add' ? 'Trip saved' : 'Trip updated');
      closeModal();
    }
    await renderTrips(true); await renderHome();
  }

  // Live score preview — debounced
  const liveScoreEl = document.createElement('div');
  liveScoreEl.id = 'liveScore';
  step1.querySelector('.card').appendChild(liveScoreEl);
  let _lsTimer = null;
  async function updateLiveScore(){
    const pay = Number($('#f_pay', body).value || 0);
    const loaded = Number($('#f_loaded', body).value || 0);
    const empty = Number($('#f_empty', body).value || 0);
    if (pay <= 0 || (loaded + empty) <= 0){ liveScoreEl.innerHTML = ''; return; }
    const preview = { ...trip, pay, loadedMiles: loaded, emptyMiles: empty,
      customer: mode==='edit' ? trip.customer : ($('#f_customer', body)?.value || ''),
      orderNo: normOrderNo($('#f_orderNo', body).value) || 'preview' };
    try{
      const { trips: allT, exps: allE } = await _getTripsAndExps();
      renderLiveScore(liveScoreEl, preview, allT, allE);
    }catch{ liveScoreEl.innerHTML = ''; }
  }
  function debounceLiveScore(){
    clearTimeout(_lsTimer);
    _lsTimer = setTimeout(updateLiveScore, 300);
  }
  ['f_pay','f_loaded','f_empty'].forEach(id => {
    const el = $(`#${id}`, body);
    if (el){ el.addEventListener('input', debounceLiveScore); }
  });

  $('#toStep2', body).addEventListener('click', async ()=>{
    if (!(await validateStep1())){ toast('Fix required fields first', true); return; }
    step1.style.display = 'none'; step2.style.display = '';
    // Auto-populate intel if editing
    updateBrokerIntel(); updateLaneIntel();
  });
  $('#backStep1', body).addEventListener('click', ()=>{ step2.style.display = 'none'; step1.style.display = ''; });
  $('#saveTrip', body).addEventListener('click', ()=> save(1));
  $('#saveTrip2', body).addEventListener('click', ()=> save(2));

  // Lane + Broker intelligence in step 2 (debounced)
  let _biTimer = null, _liTimer = null;
  async function updateBrokerIntel(){
    const box = $('#brokerIntelBox', body);
    if (!box) return;
    const cust = ($('#f_customer', body)?.value || '').trim();
    if (!cust){ box.innerHTML = ''; return; }
    try{
      const { trips: allT } = await _getTripsAndExps();
      box.innerHTML = brokerIntelHTML(cust, allT);
    }catch{ box.innerHTML = ''; }
  }
  async function updateLaneIntel(){
    const box = $('#laneIntelBox', body);
    if (!box) return;
    const orig = ($('#f_origin', body)?.value || '').trim();
    const dest = ($('#f_dest', body)?.value || '').trim();
    if (!orig || !dest){ box.innerHTML = ''; return; }
    try{
      const { trips: allT } = await _getTripsAndExps();
      const intel = computeLaneIntel(orig, dest, allT);
      box.innerHTML = intel ? laneIntelHTML(intel) : `<div style="padding:8px 0"><span class="muted" style="font-size:12px">New lane — no history</span></div>`;
    }catch{ box.innerHTML = ''; }
  }
  const custEl = $('#f_customer', body);
  if (custEl){
    custEl.addEventListener('input', ()=>{ clearTimeout(_biTimer); _biTimer = setTimeout(updateBrokerIntel, 400); });
    attachAutoComplete(custEl, async (val) => {
      const { trips: allT } = await _getTripsAndExps();
      const brokers = computeBrokerStats(allT, isoDate(), 0);
      const q = val.toLowerCase();
      return brokers.filter(b => b.name.toLowerCase().includes(q)).slice(0, 6).map(b => ({
        label: b.name, value: b.name,
        sub: `${b.trips} load${b.trips>1?'s':''} • $${b.avgRpm.toFixed(2)} RPM • ${fmtMoney(b.pay)} total`
      }));
    }, () => { clearTimeout(_biTimer); _biTimer = setTimeout(updateBrokerIntel, 200); }, body);
  }
  const origEl = $('#f_origin', body);
  const destEl = $('#f_dest', body);
  if (origEl){
    origEl.addEventListener('input', ()=>{ clearTimeout(_liTimer); _liTimer = setTimeout(updateLaneIntel, 400); });
    attachAutoComplete(origEl, async (val) => {
      const { trips: allT } = await _getTripsAndExps();
      const cities = new Map();
      for (const t of allT){
        for (const c of [t.origin, t.destination]){
          if (!c) continue;
          const key = c.toLowerCase().trim();
          if (key.includes(val.toLowerCase()) && !cities.has(key)){
            cities.set(key, c.trim());
          }
        }
      }
      return [...cities.values()].slice(0, 6).map(c => ({ label: c, value: c }));
    }, () => { clearTimeout(_liTimer); _liTimer = setTimeout(updateLaneIntel, 200); }, body);
  }
  if (destEl){
    destEl.addEventListener('input', ()=>{ clearTimeout(_liTimer); _liTimer = setTimeout(updateLaneIntel, 400); });
    attachAutoComplete(destEl, async (val) => {
      const { trips: allT } = await _getTripsAndExps();
      const cities = new Map();
      for (const t of allT){
        for (const c of [t.origin, t.destination]){
          if (!c) continue;
          const key = c.toLowerCase().trim();
          if (key.includes(val.toLowerCase()) && !cities.has(key)){
            cities.set(key, c.trim());
          }
        }
      }
      return [...cities.values()].slice(0, 6).map(c => ({ label: c, value: c }));
    }, () => { clearTimeout(_liTimer); _liTimer = setTimeout(updateLaneIntel, 200); }, body);
  }

  if (mode==='edit'){
    const delBtn = $('#delTrip', body);
    if (delBtn) delBtn.addEventListener('click', async ()=>{
      const ui = await getSetting('uiMode','simple');
      if (ui !== 'pro'){ toast('Delete is Pro-only', true); return; }
      if (!confirm('Delete this trip and its receipts?')) return;
      try{ const rec = await getReceipts(trip.orderNo);
        for (const f of (rec?.files||[])) try{ await cacheDeleteReceipt(f.id); }catch(e){ console.warn("[FL]", e); } }catch(e){ console.warn("[FL]", e); }
      await deleteTrip(trip.orderNo); invalidateKPICache();
      toast('Trip deleted'); closeModal(); await renderTrips(true); await renderHome();
    });
  }
  openModal(mode==='add' ? 'Add Trip' : `Edit Trip • ${trip.orderNo}`, body);
}

// P1-6: expense form with category autocomplete
function openExpenseForm(existing=null){
  const mode = existing ? 'edit' : 'add';
  const e = existing ? {...existing} : { date:isoDate(), amount:0, category:'', notes:'', type:'expense' };
  const body = document.createElement('div');
  body.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <label>Date</label><input id="f_date" type="date" />
    <label>Amount $</label><input id="f_amt" type="number" step="0.01" placeholder="0.00" />
    <label>Category</label><input id="f_cat" list="catList" placeholder="e.g., Fuel, Tolls..." />
    <label>Notes</label><input id="f_notes" placeholder="Optional" />
    <div class="btn-row" style="margin-top:12px"><button class="btn primary" id="f_save">Save</button>
      ${mode==='edit'?'<button class="btn danger" id="f_del">Delete</button>':''}</div>
    <div class="muted" id="f_hint" style="font-size:12px;margin-top:10px"></div></div>`;
  $('#f_date', body).value = e.date || isoDate();
  $('#f_amt', body).value = e.amount || '';
  $('#f_cat', body).value = e.category || '';
  $('#f_notes', body).value = e.notes || '';

  function validate(){ const hint = $('#f_hint', body); const amt = Number($('#f_amt', body).value||0);
    if (!(amt > 0)){ hint.textContent = 'Amount must be > 0.'; return false; } hint.textContent = ''; return true; }

  $('#f_save', body).addEventListener('click', async ()=>{
    if (!validate()){ toast('Fix required fields', true); return; }
    const obj = { id: e.id, date: $('#f_date', body).value || isoDate(), amount: Number($('#f_amt', body).value||0),
      category: clampStr($('#f_cat', body).value, 60), notes: clampStr($('#f_notes', body).value, 300), type:'expense', created: e.created };
    if (mode==='add') await addExpense(obj); else await updateExpense(obj);
    invalidateKPICache(); toast(mode==='add'?'Expense saved':'Expense updated');
    closeModal(); await renderExpenses(true); await renderHome();
  });
  if (mode==='edit'){
    const delBtn = $('#f_del', body);
    if (delBtn) delBtn.addEventListener('click', async ()=>{
      const ui = await getSetting('uiMode','simple');
      if (ui !== 'pro'){ toast('Delete is Pro-only', true); return; }
      if (!confirm('Delete this expense?')) return;
      await deleteExpense(e.id); invalidateKPICache();
      toast('Deleted'); closeModal(); await renderExpenses(true); await renderHome();
    });
  }
  openModal(mode==='add' ? 'Add Expense' : 'Edit Expense', body); validate();
  // First-expense guidance
  if (mode === 'add'){
    countStore('expenses').then(cnt => {
      if (cnt === 0){
        const tip = document.createElement('div');
        tip.style.cssText = 'padding:8px 12px;border-radius:6px;background:rgba(88,166,255,.08);border:1px solid rgba(88,166,255,.2);margin-bottom:12px;font-size:12px';
        tip.innerHTML = '💡 <b>Tip:</b> Pick a category from the dropdown (Fuel, Tolls, Insurance, etc.) — your tax export groups them automatically.';
        body.insertBefore(tip, body.firstChild);
      }
    }).catch(()=>{});
  }
}

// P1-3: fuel form with edit support
function openFuelForm(existing=null){
  const mode = existing ? 'edit' : 'add';
  const f = existing || { date:isoDate(), gallons:0, amount:0, state:'', notes:'' };
  const body = document.createElement('div');
  body.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <label>Date</label><input id="f_date" type="date" />
    <div class="grid2"><div><label>Gallons</label><input id="f_gal" type="number" step="0.01" placeholder="0" /></div>
      <div><label>Total $</label><input id="f_amt" type="number" step="0.01" placeholder="0.00" /></div></div>
    <div class="grid2"><div><label>State</label><input id="f_state" placeholder="IL, IN, OH..." /></div>
      <div><label>Notes</label><input id="f_notes" placeholder="Optional" /></div></div>
    <div class="btn-row" style="margin-top:12px"><button class="btn primary" id="f_save">Save</button>
      ${mode==='edit'?'<button class="btn danger" id="f_del">Delete</button>':''}</div></div>`;
  $('#f_date', body).value = f.date || isoDate();
  $('#f_gal', body).value = f.gallons || '';
  $('#f_amt', body).value = f.amount || '';
  $('#f_state', body).value = f.state || '';
  $('#f_notes', body).value = f.notes || '';

  // State autocomplete from fuel history
  const stateEl = $('#f_state', body);
  if (stateEl){
    attachAutoComplete(stateEl, async (val) => {
      const allF = await dumpStore('fuel');
      const states = new Map();
      for (const r of allF){
        if (!r.state) continue;
        const s = r.state.toUpperCase().trim();
        if (s.includes(val.toUpperCase()) && !states.has(s)){
          const cnt = allF.filter(x => (x.state||'').toUpperCase().trim() === s).length;
          states.set(s, cnt);
        }
      }
      return [...states.entries()].sort((a,b) => b[1] - a[1]).slice(0, 6).map(([s, cnt]) => ({
        label: s, value: s, sub: `${cnt} fill-up${cnt>1?'s':''}`
      }));
    }, null, body);
  }

  $('#f_save', body).addEventListener('click', async ()=>{
    const obj = { id: f.id, date: $('#f_date', body).value || isoDate(),
      gallons: Number($('#f_gal', body).value || 0), amount: Number($('#f_amt', body).value || 0),
      state: clampStr($('#f_state', body).value, 20).toUpperCase(), notes: clampStr($('#f_notes', body).value, 200) };
    try{
      if (mode==='add') await addFuel(obj); else await updateFuel(obj);
      toast('Fuel saved'); closeModal();
      if (views.fuel.style.display !== 'none') await renderFuel(true);
      invalidateKPICache(); await computeKPIs();
    }catch(err){ console.error('[FL] Operation error:', err); toast('Operation failed. Please try again.', true); }
  });
  if (mode==='edit'){
    const delBtn = $('#f_del', body);
    if (delBtn) delBtn.addEventListener('click', async ()=>{
      const ui = await getSetting('uiMode','simple');
      if (ui !== 'pro'){ toast('Delete is Pro-only', true); return; }
      if (!confirm('Delete this fuel entry?')) return;
      await deleteFuel(f.id); invalidateKPICache(); toast('Deleted'); closeModal(); await renderFuel(true);
    });
  }
  openModal(mode==='add' ? 'Add Fuel' : 'Edit Fuel', body);
}

// ---- Weekly Reflection ----
async function openWeeklyReflection(){
  const body = document.createElement('div');
  const now = new Date();
  const weekStart = startOfWeek(now).toISOString().slice(0,10);

  // Get this week's stats
  const { trips, exps } = await _getTripsAndExps();
  const wk0 = startOfWeek(now).getTime();
  let wkGross = 0, wkExp = 0, wkLoaded = 0, wkAll = 0, wkTrips = 0;
  for (const t of trips){
    const dt = t.pickupDate || t.deliveryDate;
    if (dt && new Date(dt).getTime() >= wk0){
      wkGross += Number(t.pay || 0);
      wkLoaded += Number(t.loadedMiles || 0);
      wkAll += Number(t.loadedMiles || 0) + Number(t.emptyMiles || 0);
      wkTrips++;
    }
  }
  for (const e of exps){
    if (e.date && new Date(e.date).getTime() >= wk0) wkExp += Number(e.amount || 0);
  }
  const wkNet = wkGross - wkExp;
  const wkRpm = wkAll > 0 ? wkGross / wkAll : 0;
  const wkDh = wkAll > 0 ? ((wkAll - wkLoaded) / wkAll * 100) : 0;

  body.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <div style="text-align:center;margin-bottom:16px">
      <div style="font-size:14px;font-weight:700;color:var(--muted)">WEEK OF ${escapeHtml(weekStart)}</div>
      <div style="font-size:32px;font-weight:900;color:${wkNet>=3800?'var(--good)':wkNet>=2000?'var(--accent)':'var(--bad)'};margin-top:4px">${fmtMoney(wkNet)} net</div>
    </div>
    <div class="row" style="margin-bottom:16px;justify-content:center">
      <div class="pill"><span class="muted">Gross</span> <b>${fmtMoney(wkGross)}</b></div>
      <div class="pill"><span class="muted">RPM</span> <b>$${wkRpm.toFixed(2)}</b></div>
      <div class="pill"><span class="muted">Loads</span> <b>${wkTrips}</b></div>
      <div class="pill"><span class="muted">DH%</span> <b>${wkDh.toFixed(0)}%</b></div>
    </div>
    <label>Rate your week (1-10)</label>
    <div style="display:flex;gap:4px;margin-bottom:14px" id="ratingRow">${
      [1,2,3,4,5,6,7,8,9,10].map(n => `<button class="btn sm" data-rating="${n}" style="min-width:32px;padding:6px">${n}</button>`).join('')
    }</div>
    <input type="hidden" id="rf_rating" value="" />
    <label class="chk" style="font-size:14px;margin-bottom:14px"><input type="checkbox" id="rf_structured" /> Was the week structured?</label>
    <label>Wins</label><input id="rf_wins" placeholder="Best load, new broker, hit target..." />
    <label>Mistakes</label><input id="rf_mistakes" placeholder="Bad load, waited too long, fatigue..." />
    <label>Lessons</label><input id="rf_lessons" placeholder="What to do differently next week" />
    <div class="btn-row" style="margin-top:14px"><button class="btn primary" id="rf_save">Save Reflection</button></div>
  </div>`;

  // Rating buttons
  body.querySelectorAll('[data-rating]').forEach(btn => {
    btn.addEventListener('click', ()=>{
      body.querySelectorAll('[data-rating]').forEach(b => { b.style.background = ''; b.style.color = ''; });
      btn.style.background = 'var(--accent)';
      btn.style.color = '#0b1220';
      body.querySelector('#rf_rating').value = btn.dataset.rating;
      haptic(10);
    });
  });

  body.querySelector('#rf_save').addEventListener('click', async ()=>{
    const rating = Number(body.querySelector('#rf_rating').value || 0);
    if (!rating){ toast('Tap a number to rate your week', true); return; }
    const reflection = {
      week: weekStart,
      rating,
      structured: body.querySelector('#rf_structured').checked,
      wins: clampStr(body.querySelector('#rf_wins').value, 300),
      mistakes: clampStr(body.querySelector('#rf_mistakes').value, 300),
      lessons: clampStr(body.querySelector('#rf_lessons').value, 300),
      stats: { gross: wkGross, net: wkNet, rpm: +wkRpm.toFixed(2), trips: wkTrips, deadhead: +wkDh.toFixed(1) },
      saved: Date.now()
    };
    await setSetting('weeklyReflection', reflection);
    toast('Week reflection saved');
    haptic(25);
    closeModal();
    await renderHome();
  });

  openModal('📋 Weekly Reflection', body);
}

// ---- Buttons ----
addManagedListener($('#fab'), 'click', ()=>{
  // Dismiss onboarding pulse
  $('#fab').classList.remove('pulse');
  const hint = $('#fabHint');
  if (hint) hint.style.display = 'none';
  openQuickAddSheet();
});
addManagedListener($('#fab'), 'keydown', (e)=>{
  if (e.key === 'Enter' || e.key === ' '){ e.preventDefault(); $('#fab').click(); }
});
addManagedListener($('#btnQuickTrip'), 'click', ()=> openTripWizard());
addManagedListener($('#btnQuickExpense'), 'click', ()=> openExpenseForm());
addManagedListener($('#btnAddExp2'), 'click', ()=> openExpenseForm());
addManagedListener($('#btnQuickFuel'), 'click', ()=> openFuelForm());

addManagedListener($('#btnTripMore'), 'click', ()=> renderTrips(false));
addManagedListener($('#btnExpMore'), 'click', ()=> renderExpenses(false));
addManagedListener($('#btnFuelMore'), 'click', ()=> renderFuel(false));
addManagedListener($('#btnAddFuel2'), 'click', ()=> openFuelForm());

addManagedListener($('#tripSearch'), 'input', (e)=>{
  tripSearchTerm = e.target.value || '';
  clearTimeout(renderTrips._tm); renderTrips._tm = setTimeout(()=> renderTrips(true), 250);
});
addManagedListener($('#expSearch'), 'input', (e)=>{
  expSearchTerm = e.target.value || '';
  clearTimeout(renderExpenses._tm); renderExpenses._tm = setTimeout(()=> renderExpenses(true), 250);
});

// P1-1: Trip filter with date range
addManagedListener($('#btnTripFilter'), 'click', async ()=>{
  const body = document.createElement('div');
  body.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <label>Show</label><select id="flt_paid"><option value="all">All</option><option value="unpaid">Unpaid only</option><option value="paid">Paid only</option></select>
    <div class="grid2"><div><label>From date</label><input id="flt_from" type="date" /></div><div><label>To date</label><input id="flt_to" type="date" /></div></div>
    <div class="btn-row" style="margin-top:12px"><button class="btn primary" id="flt_apply">Apply</button><button class="btn" id="flt_clear">Clear</button></div></div>`;
  $('#flt_from', body).value = tripFilterDateFrom || '';
  $('#flt_to', body).value = tripFilterDateTo || '';
  $('#flt_apply', body).addEventListener('click', async ()=>{
    const v = $('#flt_paid', body).value;
    tripFilterDateFrom = $('#flt_from', body).value || '';
    tripFilterDateTo = $('#flt_to', body).value || '';
    closeModal();
    const res = await listTrips({cursor:null, search: tripSearchTerm, dateFrom: tripFilterDateFrom, dateTo: tripFilterDateTo});
    const list = $('#tripList'); list.innerHTML = '';
    let items = res.items;
    if (v === 'unpaid') items = items.filter(x => !x.isPaid);
    if (v === 'paid') items = items.filter(x => !!x.isPaid);
    items.forEach(t => list.appendChild(tripRow(t)));
    $('#btnTripMore').disabled = true;
  });
  $('#flt_clear', body).addEventListener('click', async ()=>{
    tripFilterDateFrom = ''; tripFilterDateTo = '';
    closeModal(); await renderTrips(true);
  });
  openModal('Trip Filter', body);
});

// Export/Import wiring
addManagedListener($('#btnTripExport'), 'click', exportJSON);
addManagedListener($('#btnExpExport'), 'click', exportJSON);
addManagedListener($('#btnTripExportCSV'), 'click', exportTripsCSV);
addManagedListener($('#btnExpExportCSV'), 'click', exportExpensesCSV);
addManagedListener($('#btnFuelExportCSV'), 'click', exportFuelCSV);
addManagedListener($('#btnFuelImport'), 'click', async ()=>{
  const f = await pickFile(IMPORT_ACCEPT); if (!f) return;
  await importFile(f); invalidateKPICache(); await renderFuel(true); await renderHome();
});

function pickFile(accept){
  return new Promise((resolve)=>{
    const i = document.createElement('input'); i.type = 'file'; i.accept = accept || '*';
    let resolved = false;
    const done = (file)=>{ if (resolved) return; resolved = true; window.removeEventListener('focus', onFocus); resolve(file); };
    i.onchange = ()=> done(i.files?.[0] || null);
    // Handle cancel: when focus returns and no file was picked, resolve null
    // T5-FIX: iOS Safari fires focus before onchange — use 1200ms guard + resolved flag
    const onFocus = ()=>{ setTimeout(()=>{ if (!resolved && !i.files?.length) done(null); }, 1200); };
    window.addEventListener('focus', onFocus);
    i.click();
  });
}
const IMPORT_ACCEPT = '.json,.csv,.tsv,.xlsx,.xls,.txt,.pdf';
addManagedListener($('#btnTripImport'), 'click', async ()=>{
  const f = await pickFile(IMPORT_ACCEPT); if (!f) return;
  await importFile(f); invalidateKPICache(); await renderTrips(true); await renderHome();
});
addManagedListener($('#btnExpImport'), 'click', async ()=>{
  const f = await pickFile(IMPORT_ACCEPT); if (!f) return;
  await importFile(f); invalidateKPICache(); await renderExpenses(true); await renderHome();
});

// Tax period tabs
$$('#taxPeriodTabs .btn').forEach(btn => {
  addManagedListener(btn, 'click', async ()=>{
    $$('#taxPeriodTabs .btn').forEach(b => b.classList.remove('act'));
    btn.classList.add('act');
    _taxPeriod = btn.dataset.period || 'week';
    invalidateKPICache(); await computeKPIs();
  });
});

// Settings
addManagedListener($('#btnSaveSettings'), 'click', async ()=>{
  await setSetting('vehicleClass', $('#vehicleClass')?.value || 'cargo_van');
  await setSetting('uiMode', $('#uiMode').value);
  await setSetting('perDiemRate', Number($('#perDiemRate').value || 0));
  await setSetting('brokerWindow', Number($('#brokerWindow').value || 90));
  await setSetting('weeklyGoal', Number($('#weeklyGoal').value || 0));
  await setSetting('iftaMode', $('#iftaMode').value || 'on');
  await setSetting('vehicleMpg', Number($('#vehicleMpg').value || 0));
  await setSetting('fuelPrice', Number($('#fuelPrice').value || 0));
  await setSetting('opCostPerMile', Number($('#opCostPerMile').value || 0));
  const hlInput = $('#settingsHomeLocation');
  if (hlInput) await setSetting('homeLocation', (hlInput.value || '').trim());
  // DAT API settings
  const datEnabled = $('#datApiEnabled')?.value || 'off';
  await setSetting('datApiEnabled', datEnabled);
  const datUrl = $('#datApiBaseUrl')?.value || '';
  if (datUrl) await setSetting('datApiBaseUrl', clampStr(datUrl, 200));
  // Cloud Backup settings
  const cbUrlVal = ($('#cloudBackupUrl')?.value || '').trim();
  if (cbUrlVal) await setSetting('cloudBackupUrl', clampStr(cbUrlVal, 200));
  const cbPassVal = ($('#cloudBackupPass')?.value || '').trim();
  if (cbPassVal) await setSetting('cloudBackupPass', cbPassVal);
  const cbTokenVal = ($('#cloudBackupToken')?.value || '').trim();
  if (cbTokenVal) await setSetting('cloudBackupToken', cbTokenVal);
  // Canada settings
  const caEnabled = $('#canadaEnabled')?.value || 'off';
  await setSetting('canadaEnabled', caEnabled);
  if (caEnabled === 'on'){
    const cadRate = Number($('#cadUsdRate')?.value || 0);
    if (cadRate > 0) await setSetting('cadUsdRate', cadRate);
    const borderCost = Number($('#borderAdminCost')?.value || 0);
    if (borderCost >= 0) await setSetting('borderAdminCost', borderCost);
    await setSetting('canadaDocsReady', !!$('#canadaDocsReady')?.checked);
  }
  toast('Saved settings'); invalidateKPICache(); await computeKPIs(); await refreshStorageHealth('');
});
addManagedListener($('#btnHardReset'), 'click', async ()=>{
  if ((await getSetting('uiMode','simple')) !== 'pro'){ toast('Hard reset is Pro-only', true); return; }
  if (!confirm('Hard reset will delete all local data on this device. Continue?')) return;
  indexedDB.deleteDatabase(DB_NAME);
  toast('Database deleted. Reloading...'); setTimeout(()=> location.reload(), 1200);
});

// Storage health
addManagedListener($('#btnStorageRefresh'), 'click', async ()=> await refreshStorageHealth(''));
addManagedListener($('#btnStorageAnalyze'), 'click', async ()=> await analyzeReceiptBlobSizes());
addManagedListener($('#btnStorageRebuild'), 'click', async ()=> await rebuildReceiptIndex());
addManagedListener($('#btnStorageClearCache'), 'click', async ()=>{
  if (!confirm('Clear receipt cache? Thumbnails stay.')) return; await clearReceiptCache(); toast('Receipt cache cleared');
});
addManagedListener($('#btnWeeklyReport'), 'click', ()=> { haptic(20); generateWeeklyReport(); });
addManagedListener($('#btnLoadCompare'), 'click', ()=> { haptic(20); openLoadCompare(); });

// Accountant period tabs
let _acctPeriod = 'ytd';
$$('#acctPeriodTabs .btn').forEach(btn => {
  addManagedListener(btn, 'click', ()=>{
    $$('#acctPeriodTabs .btn').forEach(b => b.classList.remove('act'));
    btn.classList.add('act');
    _acctPeriod = btn.dataset.acct;
    haptic(8);
  });
});
addManagedListener($('#btnAccountantExport'), 'click', ()=> { haptic(20); generateAccountantPackage(_acctPeriod); });

// ====================================================================
//  WEEKLY PERFORMANCE REPORT — Canvas-rendered shareable image
// ====================================================================
async function generateWeeklyReport(){
  toast('Generating report...');
  try{
    const { trips, exps } = await _getTripsAndExps();
    const allFuel = await dumpStore('fuel');
    const now = new Date();
    const wk0 = startOfWeek(now).getTime();
    const d7 = now.getTime() - 7 * 86400000;
    const d14 = now.getTime() - 14 * 86400000;
    const d30 = now.getTime() - 30 * 86400000;
    const today = isoDate();
    const userGoal = Number(await getSetting('weeklyGoal', 0) || 0);

    // Compute weekly stats
    let wkGross = 0, wkExp = 0, wkTrips = 0;
    let wkLoaded = 0, wkAll = 0;
    let wkScoreSum = 0, wkScoreCnt = 0, wkAccept = 0;
    for (const t of trips){
      const dt = t.pickupDate || t.deliveryDate;
      if (!dt || new Date(dt).getTime() < wk0) continue;
      wkTrips++;
      wkGross += Number(t.pay || 0);
      const l = Number(t.loadedMiles||0), e = Number(t.emptyMiles||0);
      wkLoaded += l; wkAll += l + e;
      if (l + e > 0){
        try{
          const s = computeLoadScore(t, trips, exps);
          wkScoreSum += s.marginScore; wkScoreCnt++;
          if (s.verdict === 'PREMIUM WIN' || s.verdict === 'ACCEPT') wkAccept++;
        }catch(e){ console.warn("[FL]", e); }
      }
    }
    for (const e of exps){
      if (e.date && new Date(e.date).getTime() >= wk0) wkExp += Number(e.amount || 0);
    }
    const wkNet = wkGross - wkExp;
    const wkRpm = wkAll > 0 ? wkGross / wkAll : 0;
    const wkDh = wkAll > 0 ? ((wkAll - wkLoaded) / wkAll * 100) : 0;
    const wkAvgScore = wkScoreCnt > 0 ? Math.round(wkScoreSum / wkScoreCnt) : 0;
    const wkAccRate = wkScoreCnt > 0 ? Math.round((wkAccept / wkScoreCnt) * 100) : 0;

    // Top lane this week
    const wkTripsArr = trips.filter(t => {
      const dt = t.pickupDate || t.deliveryDate;
      return dt && new Date(dt).getTime() >= wk0;
    });
    const lanes = computeLaneStats(wkTripsArr);
    const topLane = lanes.length > 0 ? lanes[0] : null;

    // Top broker this week
    const brokers = computeBrokerStats(wkTripsArr, today, 0);
    const topBroker = brokers.length > 0 ? brokers.sort((a,b) => b.pay - a.pay)[0] : null;
    let topBrokerGrade = null;
    if (topBroker){
      const allBrokers = computeBrokerStats(trips, today, 0);
      const gMiles = allBrokers.reduce((s,b) => s + b.miles, 0);
      const gPay = allBrokers.reduce((s,b) => s + b.pay, 0);
      const gAvgRpm = gMiles > 0 ? gPay / gMiles : 0;
      topBrokerGrade = computeBrokerGrade(topBroker, gAvgRpm);
    }

    // Fuel this week
    let fuelGal = 0, fuelAmt = 0;
    for (const f of allFuel){
      if (f.date && new Date(f.date).getTime() >= wk0){
        fuelGal += Number(f.gallons || 0);
        fuelAmt += Number(f.amount || 0);
      }
    }
    const fuelPpg = fuelGal > 0 ? fuelAmt / fuelGal : 0;

    // Week date range
    const wkStart = new Date(wk0);
    const wkLabel = `Week of ${wkStart.toLocaleDateString('en-US', { month:'short', day:'numeric' })} — ${now.toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' })}`;

    // ── Render Canvas ──
    const W = 1080, H = 1920;
    const canvas = document.createElement('canvas');
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext('2d');

    // Background
    ctx.fillStyle = '#0a0a0f'; ctx.fillRect(0, 0, W, H);

    // Accent gradient header
    const grd = ctx.createLinearGradient(0, 0, W, 180);
    grd.addColorStop(0, '#6366f1'); grd.addColorStop(1, '#8b5cf6');
    ctx.fillStyle = grd; ctx.fillRect(0, 0, W, 180);

    // Title
    ctx.fillStyle = '#fff'; ctx.font = 'bold 48px -apple-system, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Weekly Performance Report', W/2, 70);
    ctx.font = '28px -apple-system, system-ui, sans-serif';
    ctx.fillStyle = 'rgba(255,255,255,.8)';
    ctx.fillText(wkLabel, W/2, 120);
    ctx.font = '22px -apple-system, system-ui, sans-serif';
    ctx.fillStyle = 'rgba(255,255,255,.5)';
    ctx.fillText(`Freight Logic • v${APP_VERSION}`, W/2, 160);

    // Helper: draw stat card
    let cardY = 220;
    function drawCard(label, value, sub, color='#fff'){
      ctx.fillStyle = '#13131a'; roundRect(ctx, 60, cardY, W-120, 120, 20); ctx.fill();
      ctx.textAlign = 'left';
      ctx.font = '24px -apple-system, system-ui, sans-serif'; ctx.fillStyle = '#888';
      ctx.fillText(label, 100, cardY + 42);
      ctx.textAlign = 'right';
      ctx.font = 'bold 44px -apple-system, system-ui, sans-serif'; ctx.fillStyle = color;
      ctx.fillText(value, W - 100, cardY + 48);
      if (sub){
        ctx.font = '20px -apple-system, system-ui, sans-serif'; ctx.fillStyle = '#666';
        ctx.textAlign = 'left';
        ctx.fillText(sub, 100, cardY + 86);
      }
      cardY += 140;
    }

    function drawDivider(text){
      ctx.textAlign = 'left';
      ctx.font = 'bold 22px -apple-system, system-ui, sans-serif'; ctx.fillStyle = '#6366f1';
      ctx.fillText(text, 80, cardY + 20);
      cardY += 40;
    }

    function roundRect(c, x, y, w, h, r){
      c.beginPath(); c.moveTo(x+r, y);
      c.lineTo(x+w-r, y); c.quadraticCurveTo(x+w, y, x+w, y+r);
      c.lineTo(x+w, y+h-r); c.quadraticCurveTo(x+w, y+h, x+w-r, y+h);
      c.lineTo(x+r, y+h); c.quadraticCurveTo(x, y+h, x, y+h-r);
      c.lineTo(x, y+r); c.quadraticCurveTo(x, y, x+r, y);
      c.closePath();
    }

    drawDivider('REVENUE');
    drawCard('Gross Revenue', fmtMoney(wkGross), `${wkTrips} load${wkTrips!==1?'s':''}`, '#6bff95');
    drawCard('Expenses', fmtMoney(wkExp), '', '#ff6b6b');
    drawCard('Net Profit', fmtMoney(wkNet), '', wkNet >= 0 ? '#6bff95' : '#ff6b6b');

    if (userGoal > 0){
      const pct = wkGross > 0 ? Math.round((wkGross / userGoal) * 100) : 0;
      drawCard('Goal Progress', `${pct}%`, `${fmtMoney(wkGross)} of ${fmtMoney(userGoal)} goal`, pct >= 100 ? '#6bff95' : '#ffb300');
    }

    drawDivider('EFFICIENCY');
    drawCard('Avg RPM', wkRpm > 0 ? `$${wkRpm.toFixed(2)}` : '—', `${fmtNum(wkAll)} total miles`);
    drawCard('Deadhead', wkAll > 0 ? `${wkDh.toFixed(1)}%` : '—', `${fmtNum(wkAll - wkLoaded)} empty of ${fmtNum(wkAll)} total`, wkDh <= 15 ? '#6bff95' : wkDh <= 25 ? '#ffb300' : '#ff6b6b');
    drawCard('Avg Load Score', wkScoreCnt > 0 ? `${wkAvgScore}/100` : '—', `Accept rate: ${wkAccRate}%`, wkAvgScore >= 60 ? '#6bff95' : wkAvgScore >= 40 ? '#ffb300' : '#ff6b6b');

    drawDivider('INTELLIGENCE');
    if (topLane){
      drawCard('Top Lane', topLane.display.length > 30 ? topLane.display.slice(0,30)+'…' : topLane.display, `$${topLane.avgRpm} avg RPM • ${topLane.trips} run${topLane.trips>1?'s':''}`, '#58a6ff');
    }
    if (topBroker && topBrokerGrade){
      drawCard(`Top Broker (${topBrokerGrade.grade})`, topBroker.name.length > 25 ? topBroker.name.slice(0,25)+'…' : topBroker.name, `$${topBroker.avgRpm.toFixed(2)} RPM • ${fmtMoney(topBroker.pay)} revenue`, topBrokerGrade.gradeColor);
    }
    if (fuelGal > 0){
      drawCard('Fuel', `$${fuelPpg.toFixed(3)}/gal`, `${fuelGal.toFixed(1)} gal • ${fmtMoney(fuelAmt)} total`);
    }

    // Footer
    const footY = Math.min(cardY + 30, H - 60);
    ctx.textAlign = 'center';
    ctx.font = '20px -apple-system, system-ui, sans-serif'; ctx.fillStyle = '#444';
    ctx.fillText('Generated by Freight Logic — freightlogic.app', W/2, footY);

    // Download
    canvas.toBlob(blob => {
      if (!blob){ toast('Failed to generate', true); return; }
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `FreightLogic_Weekly_${today}.png`;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      haptic(25);
      toast('Weekly report saved!');
    }, 'image/png');
  }catch(err){ toast('Report generation failed', true); }
}

// ====================================================================
//  LOAD COMPARE MODE — Side-by-side scoring of two loads
// ====================================================================
function openLoadCompare(){
  const body = document.createElement('div');
  body.style.padding = '0';

  // Two-column input form
  body.innerHTML = `
    <div class="muted" style="font-size:12px;margin-bottom:12px;padding:0 4px">Enter two loads to compare. We'll score both and recommend the better option.</div>
    <div class="grid2" style="gap:10px">
      <div class="card" style="margin:0">
        <div style="font-size:14px;font-weight:800;color:var(--accent);margin-bottom:8px">LOAD A</div>
        <label>Pay $</label><input id="cmpA_pay" type="number" step="0.01" placeholder="0.00" />
        <div class="grid2"><div><label>Loaded mi</label><input id="cmpA_loaded" type="number" placeholder="0" /></div>
          <div><label>Empty mi</label><input id="cmpA_empty" type="number" placeholder="0" /></div></div>
        <label>Customer</label><input id="cmpA_customer" placeholder="Broker name" />
        <div class="grid2"><div><label>Origin</label><input id="cmpA_origin" placeholder="City, ST" /></div>
          <div><label>Dest</label><input id="cmpA_dest" placeholder="City, ST" /></div></div>
      </div>
      <div class="card" style="margin:0">
        <div style="font-size:14px;font-weight:800;color:#ff6b6b;margin-bottom:8px">LOAD B</div>
        <label>Pay $</label><input id="cmpB_pay" type="number" step="0.01" placeholder="0.00" />
        <div class="grid2"><div><label>Loaded mi</label><input id="cmpB_loaded" type="number" placeholder="0" /></div>
          <div><label>Empty mi</label><input id="cmpB_empty" type="number" placeholder="0" /></div></div>
        <label>Customer</label><input id="cmpB_customer" placeholder="Broker name" />
        <div class="grid2"><div><label>Origin</label><input id="cmpB_origin" placeholder="City, ST" /></div>
          <div><label>Dest</label><input id="cmpB_dest" placeholder="City, ST" /></div></div>
      </div>
    </div>
    <div class="btn-row" style="margin-top:12px"><button class="btn primary" id="cmpRun">Compare Loads</button></div>
    <div id="cmpResult" style="margin-top:12px"></div>`;

  $('#cmpRun', body).addEventListener('click', async ()=>{
    const getVal = (id) => Number($(`#${id}`, body)?.value || 0);
    const getStr = (id) => ($(`#${id}`, body)?.value || '').trim();

    const loadA = {
      orderNo: 'CMP-A', pay: getVal('cmpA_pay'),
      loadedMiles: getVal('cmpA_loaded'), emptyMiles: getVal('cmpA_empty'),
      customer: getStr('cmpA_customer'), origin: getStr('cmpA_origin'), destination: getStr('cmpA_dest'),
      pickupDate: isoDate(), deliveryDate: isoDate(), isPaid: false, paidDate: null
    };
    const loadB = {
      orderNo: 'CMP-B', pay: getVal('cmpB_pay'),
      loadedMiles: getVal('cmpB_loaded'), emptyMiles: getVal('cmpB_empty'),
      customer: getStr('cmpB_customer'), origin: getStr('cmpB_origin'), destination: getStr('cmpB_dest'),
      pickupDate: isoDate(), deliveryDate: isoDate(), isPaid: false, paidDate: null
    };

    if (loadA.pay <= 0 || loadB.pay <= 0){ toast('Both loads need a pay amount', true); return; }
    const miA = loadA.loadedMiles + loadA.emptyMiles;
    const miB = loadB.loadedMiles + loadB.emptyMiles;
    if (miA <= 0 || miB <= 0){ toast('Both loads need miles', true); return; }

    haptic(15);
    const result = $('#cmpResult', body);
    result.innerHTML = '<div class="muted" style="text-align:center;padding:12px">Scoring...</div>';

    try{
      const { trips: allT, exps: allE } = await _getTripsAndExps();
      const fc = { mpg: Number(await getSetting('vehicleMpg', 0) || 0), pricePerGal: Number(await getSetting('fuelPrice', 0) || 0) };
      const scoreA = computeLoadScore(loadA, allT, allE, fc);
      const scoreB = computeLoadScore(loadB, allT, allE, fc);

      // Lane intel
      const laneA = computeLaneIntel(loadA.origin, loadA.destination, allT);
      const laneB = computeLaneIntel(loadB.origin, loadB.destination, allT);

      // Broker intel
      const brokerStats = computeBrokerStats(allT, isoDate(), 0);
      const gMiles = brokerStats.reduce((s,b) => s + b.miles, 0);
      const gPay = brokerStats.reduce((s,b) => s + b.pay, 0);
      const gAvgRpm = gMiles > 0 ? gPay / gMiles : 0;
      const brokerA = loadA.customer ? brokerStats.find(b => b.name === loadA.customer) : null;
      const brokerB = loadB.customer ? brokerStats.find(b => b.name === loadB.customer) : null;
      const gradeA = brokerA ? computeBrokerGrade(brokerA, gAvgRpm) : null;
      const gradeB = brokerB ? computeBrokerGrade(brokerB, gAvgRpm) : null;

      // Determine winner
      const netA = scoreA.marginScore - (scoreA.riskScore * 0.5);
      const netB = scoreB.marginScore - (scoreB.riskScore * 0.5);
      let winner, reason;
      if (netA > netB + 5){ winner = 'A'; reason = 'Load A has better risk-adjusted margin'; }
      else if (netB > netA + 5){ winner = 'B'; reason = 'Load B has better risk-adjusted margin'; }
      else {
        // Tiebreaker: prefer higher RPM
        const rpmA = miA > 0 ? loadA.pay / miA : 0;
        const rpmB = miB > 0 ? loadB.pay / miB : 0;
        if (rpmA > rpmB){ winner = 'A'; reason = 'Very close — Load A edges out on RPM'; }
        else if (rpmB > rpmA){ winner = 'B'; reason = 'Very close — Load B edges out on RPM'; }
        else { winner = 'TIE'; reason = 'Effectively identical — pick based on preference'; }
      }

      const winColor = winner === 'A' ? 'var(--accent)' : winner === 'B' ? '#ff6b6b' : 'var(--muted)';
      const winLabel = winner === 'TIE' ? 'Too close to call' : `Take Load ${winner}`;

      // Helper: stat row
      function statRow(label, valA, valB, higherIsBetter=true){
        const a = typeof valA === 'number' ? valA : 0;
        const b = typeof valB === 'number' ? valB : 0;
        const aWin = higherIsBetter ? a > b : a < b;
        const bWin = higherIsBetter ? b > a : b < a;
        const aStyle = aWin ? 'color:var(--good);font-weight:700' : '';
        const bStyle = bWin ? 'color:var(--good);font-weight:700' : '';
        const fA = typeof valA === 'string' ? valA : (typeof valA === 'number' && valA % 1 !== 0 ? valA.toFixed(2) : valA);
        const fB = typeof valB === 'string' ? valB : (typeof valB === 'number' && valB % 1 !== 0 ? valB.toFixed(2) : valB);
        return `<div style="display:grid;grid-template-columns:1fr auto 1fr;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04)">
          <div style="text-align:right;${aStyle}">${fA}</div>
          <div style="text-align:center;font-size:11px;color:var(--muted);min-width:80px">${label}</div>
          <div style="text-align:left;${bStyle}">${fB}</div>
        </div>`;
      }

      const rpmA = miA > 0 ? loadA.pay / miA : 0;
      const rpmB = miB > 0 ? loadB.pay / miB : 0;
      const dhA = miA > 0 ? (loadA.emptyMiles / miA * 100) : 0;
      const dhB = miB > 0 ? (loadB.emptyMiles / miB * 100) : 0;

      let html = `
        <div style="text-align:center;padding:14px 0;border-radius:14px;background:${winColor}10;border:1px solid ${winColor}30;margin-bottom:14px">
          <div style="font-size:28px;font-weight:900;color:${winColor}">${winLabel}</div>
          <div class="muted" style="font-size:13px;margin-top:4px">${reason}</div>
        </div>
        <div style="display:grid;grid-template-columns:1fr auto 1fr;gap:8px;padding:6px 0;margin-bottom:4px">
          <div style="text-align:right;font-weight:800;color:var(--accent)">LOAD A</div>
          <div></div>
          <div style="text-align:left;font-weight:800;color:#ff6b6b">LOAD B</div>
        </div>
        ${statRow('Verdict', scoreA.verdict, scoreB.verdict)}
        ${statRow('Margin', scoreA.marginScore, scoreB.marginScore)}
        ${statRow('Risk', scoreA.riskScore, scoreB.riskScore, false)}
        ${statRow('Pay', fmtMoney(loadA.pay), fmtMoney(loadB.pay))}
        ${statRow('RPM', '$'+rpmA.toFixed(2), '$'+rpmB.toFixed(2))}
        ${statRow('Miles', fmtNum(miA), fmtNum(miB))}
        ${statRow('Deadhead', dhA.toFixed(1)+'%', dhB.toFixed(1)+'%', false)}`;

      // Counter offers
      if (scoreA.counterOffer || scoreB.counterOffer){
        html += statRow('Counter', scoreA.counterOffer ? fmtMoney(scoreA.counterOffer) : '—', scoreB.counterOffer ? fmtMoney(scoreB.counterOffer) : '—');
      }

      // Broker grades
      if (gradeA || gradeB){
        html += statRow('Broker', gradeA ? `${gradeA.grade} (${gradeA.score}/100)` : 'New', gradeB ? `${gradeB.grade} (${gradeB.score}/100)` : 'New');
      }

      // Lane history
      if (laneA || laneB){
        html += statRow('Lane runs', laneA ? `${laneA.trips}x ($${laneA.avgRpm} avg)` : 'New', laneB ? `${laneB.trips}x ($${laneB.avgRpm} avg)` : 'New');
      }

      // Fuel estimates
      if (scoreA.fuelCost !== null || scoreB.fuelCost !== null){
        html += statRow('Fuel est', scoreA.fuelCost !== null ? fmtMoney(scoreA.fuelCost) : '—', scoreB.fuelCost !== null ? fmtMoney(scoreB.fuelCost) : '—', false);
        html += statRow('Net after fuel', scoreA.netAfterFuel !== null ? fmtMoney(scoreA.netAfterFuel) : '—', scoreB.netAfterFuel !== null ? fmtMoney(scoreB.netAfterFuel) : '—');
      }

      result.innerHTML = html;
      haptic(25);
    }catch(err){ result.innerHTML = `<div class="muted" style="color:var(--bad)">Error: ${escapeHtml(err.message)}</div>`; }
  });

  openModal('⚖️ Compare Loads', body);
}

// ====================================================================
//  EXPORT-TO-ACCOUNTANT — Quarterly/YTD tax package as CSV bundle
// ====================================================================
async function generateAccountantPackage(period='ytd'){
  toast('Generating accountant package...');
  try{
    const { trips, exps } = await _getTripsAndExps();
    const allFuel = await dumpStore('fuel');
    const now = new Date();
    const year = now.getFullYear();
    const perDiemRate = Number(await getSetting('perDiemRate', 0) || 0) || 80; // IRS CONUS rate effective Oct 1, 2024
    const iftaOn = (await getSetting('iftaMode', 'on')) !== 'off';

    // Date range based on period
    let startDate, endDate, label;
    if (period === 'q1'){ startDate = `${year}-01-01`; endDate = `${year}-03-31`; label = `Q1_${year}`; }
    else if (period === 'q2'){ startDate = `${year}-04-01`; endDate = `${year}-06-30`; label = `Q2_${year}`; }
    else if (period === 'q3'){ startDate = `${year}-07-01`; endDate = `${year}-09-30`; label = `Q3_${year}`; }
    else if (period === 'q4'){ startDate = `${year}-10-01`; endDate = `${year}-12-31`; label = `Q4_${year}`; }
    else { startDate = `${year}-01-01`; endDate = isoDate(); label = `YTD_${year}`; }

    const inRange = (d) => {
      if (!d) return false;
      return d >= startDate && d <= endDate;
    };

    // ── 1. INCOME (P&L) ──
    const periodTrips = trips.filter(t => inRange(t.pickupDate || t.deliveryDate));
    let grossRevenue = 0, totalLoadedMi = 0, totalAllMi = 0;
    const incomeRows = [['Date','Order #','Customer','Origin','Destination','Pay','Loaded Miles','Empty Miles','RPM','Status']];
    for (const t of periodTrips){
      const pay = Number(t.pay || 0);
      const loaded = Number(t.loadedMiles || 0);
      const empty = Number(t.emptyMiles || 0);
      const allMi = loaded + empty;
      grossRevenue += pay;
      totalLoadedMi += loaded;
      totalAllMi += allMi;
      incomeRows.push([
        t.pickupDate || t.deliveryDate || '', t.orderNo || '', t.customer || '',
        t.origin || '', t.destination || '', pay.toFixed(2),
        String(loaded), String(empty),
        allMi > 0 ? (pay / allMi).toFixed(2) : '0.00',
        t.isPaid ? 'Paid' : 'Unpaid'
      ]);
    }

    // ── 2. EXPENSES (categorized) ──
    const periodExps = exps.filter(e => inRange(e.date));
    let totalExpenses = 0;
    const catTotals = new Map();
    const expenseRows = [['Date','Category','Amount','Notes']];
    for (const e of periodExps){
      const amt = Number(e.amount || 0);
      totalExpenses += amt;
      const cat = e.category || 'Uncategorized';
      catTotals.set(cat, (catTotals.get(cat) || 0) + amt);
      expenseRows.push([e.date || '', cat, amt.toFixed(2), e.notes || '']);
    }

    // ── 3. IFTA FUEL REPORT (by state) ──
    const periodFuel = allFuel.filter(f => inRange(f.date));
    let totalGallons = 0, totalFuelCost = 0;
    const stateTotals = new Map();
    const fuelRows = [['Date','State','Gallons','Amount','Price/Gal']];
    for (const f of periodFuel){
      const gal = Number(f.gallons || 0);
      const amt = Number(f.amount || 0);
      const st = (f.state || 'Unknown').toUpperCase().trim();
      totalGallons += gal;
      totalFuelCost += amt;
      if (!stateTotals.has(st)) stateTotals.set(st, { gallons: 0, amount: 0 });
      const sr = stateTotals.get(st);
      sr.gallons += gal; sr.amount += amt;
      fuelRows.push([f.date || '', st, gal.toFixed(2), amt.toFixed(2), gal > 0 ? (amt / gal).toFixed(3) : '0.000']);
    }

    // IFTA summary by state
    const iftaSummaryRows = [['State','Gallons','Amount','Avg Price/Gal']];
    for (const [st, data] of [...stateTotals.entries()].sort((a,b) => b[1].gallons - a[1].gallons)){
      iftaSummaryRows.push([st, data.gallons.toFixed(2), data.amount.toFixed(2), data.gallons > 0 ? (data.amount / data.gallons).toFixed(3) : '0.000']);
    }
    iftaSummaryRows.push(['TOTAL', totalGallons.toFixed(2), totalFuelCost.toFixed(2), totalGallons > 0 ? (totalFuelCost / totalGallons).toFixed(3) : '0.000']);

    // ── 4. PER DIEM CALCULATION ──
    // Count unique days with trips
    const tripDays = new Set();
    for (const t of periodTrips){
      const d = t.pickupDate || t.deliveryDate;
      if (d) tripDays.add(d);
      if (t.deliveryDate && t.pickupDate && t.deliveryDate !== t.pickupDate){
        // Multi-day trip: count all days between
        const s = new Date(t.pickupDate);
        const e = new Date(t.deliveryDate);
        for (let dt = new Date(s); dt <= e; dt.setDate(dt.getDate() + 1)){
          tripDays.add(isoDate(dt));
        }
      }
    }
    const perDiemDays = tripDays.size;
    const perDiemGross = roundCents(perDiemDays * perDiemRate);
    // IRS Sec 274(n): DOT-regulated = 80%, non-DOT (cargo van) = 50%
    const acctVehicleClass = await getSetting('vehicleClass', 'cargo_van');
    const acctPerDiemPct = (acctVehicleClass === 'semi' || acctVehicleClass === 'box_truck_cdl') ? IRS.PER_DIEM_PCT_DOT : IRS.PER_DIEM_PCT_NON_DOT;
    const perDiemTotal = roundCents(perDiemGross * acctPerDiemPct);

    // ── 5. SUMMARY (P&L) ──
    const netIncome = roundCents(grossRevenue - totalExpenses);
    const seTax = roundCents(Math.max(0, (netIncome - perDiemTotal) * IRS.SE_RATE * IRS.SE_NET_FACTOR));
    const estimatedProfit = roundCents(netIncome - perDiemTotal - seTax);
    const avgRpm = totalAllMi > 0 ? grossRevenue / totalAllMi : 0;
    const deadhead = totalAllMi > 0 ? ((totalAllMi - totalLoadedMi) / totalAllMi * 100) : 0;

    const summaryRows = [
      ['PROFIT & LOSS SUMMARY', label],
      ['Period', `${startDate} to ${endDate}`],
      [''],
      ['REVENUE'],
      ['Gross Revenue', '$' + grossRevenue.toFixed(2)],
      ['Total Loads', String(periodTrips.length)],
      ['Avg RPM (all miles)', '$' + avgRpm.toFixed(2)],
      ['Total Loaded Miles', String(totalLoadedMi)],
      ['Total All Miles', String(totalAllMi)],
      ['Deadhead %', deadhead.toFixed(1) + '%'],
      [''],
      ['EXPENSES'],
      ['Total Expenses', '$' + totalExpenses.toFixed(2)],
      ...([...catTotals.entries()].sort((a,b) => b[1] - a[1]).map(([cat, amt]) => [`  ${cat}`, '$' + amt.toFixed(2)])),
      ...(iftaOn ? [
        [''],
        ['FUEL'],
        ['Total Fuel Cost', '$' + totalFuelCost.toFixed(2)],
        ['Total Gallons', totalGallons.toFixed(2)],
        ['Avg Price/Gallon', '$' + (totalGallons > 0 ? (totalFuelCost / totalGallons).toFixed(3) : '0.000')],
      ] : []),
      [''],
      ['DEDUCTIONS'],
      ['Per Diem Rate', '$' + perDiemRate.toFixed(2) + '/day'],
      ['Days on Road', String(perDiemDays)],
      ['Per Diem Gross', '$' + perDiemGross.toFixed(2)],
      ['Per Diem Deductible (' + Math.round(acctPerDiemPct * 100) + '% IRS Sec 274n)', '$' + perDiemTotal.toFixed(2)],
      [''],
      ['MILEAGE (IRS Standard Rate Method)'],
      ['IRS Business Mileage Rate 2026', '$' + IRS.MILEAGE_RATE_2026.toFixed(3) + '/mile'],
      ['IRS Business Mileage Rate 2025', '$' + IRS.MILEAGE_RATE_2025.toFixed(3) + '/mile'],
      ['Total Business Miles', String(Math.round(totalAllMi))],
      ['Mileage Deduction (2026 rate)', '$' + (totalAllMi * IRS.MILEAGE_RATE_2026).toFixed(2)],
      ['NOTE: Choose EITHER mileage OR actual expenses — not both.'],
      [''],
      ['BOTTOM LINE'],
      ['Net Income (Revenue - Expenses)', '$' + netIncome.toFixed(2)],
      ['Per Diem Deduction (' + Math.round(acctPerDiemPct * 100) + '%)', '-$' + perDiemTotal.toFixed(2)],
      ['Est. SE Tax (15.3%)', '-$' + seTax.toFixed(2)],
      ['Estimated Profit', '$' + estimatedProfit.toFixed(2)],
      [''],
      ['NOTE: This is an estimate only. Not tax advice.'],
      ['Generated by Freight Logic ' + APP_VERSION]
    ];

    // ── Build CSV files ──
    function toCSV(rows){
      return rows.map(r => r.map(c => {
        const s = csvSafeCell(c);
        return `"${s.replace(/"/g, '""')}"`;
      }).join(',')).join('\n');
    }

    const summaryCSV = toCSV(summaryRows);
    const incomeCSV = toCSV(incomeRows);
    const expenseCSV = toCSV(expenseRows);

    // ── Combine into single download (multi-section CSV) ──
    const sections = [
      '=== FREIGHT LOGIC ACCOUNTANT PACKAGE ===',
      '=== ' + label + ' ===',
      '',
      '--- P&L SUMMARY ---',
      summaryCSV,
      '',
      '',
      '--- INCOME DETAIL ---',
      incomeCSV,
      '',
      '',
      '--- EXPENSES BY CATEGORY ---',
      expenseCSV,
    ];
    if (iftaOn){
      const fuelCSV = toCSV(fuelRows);
      const iftaCSV = toCSV(iftaSummaryRows);
      sections.push('', '', '--- FUEL LOG ---', fuelCSV, '', '', '--- FUEL SUMMARY BY STATE ---', iftaCSV);
    }
    const combined = sections.join('\n');

    // Download
    const blob = new Blob([combined], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `FreightLogic_Accountant_${label}.csv`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    haptic(25);
    toast(`Accountant package exported: ${label}`);
    await setSetting('lastExportDate', Date.now());
  }catch(err){ console.error('[FL] Export error:', err); toast('Export failed. Please try again.', true); }
}

// ════════════════════════════════════════════════════════════════
// v14.5.0 FEATURE: RECEIPT CAMERA (getUserMedia + Canvas)
// Auto-crop, compress, preview, save
// ════════════════════════════════════════════════════════════════

async function openReceiptCamera(orderNo){
  const hasCamera = !!(navigator.mediaDevices?.getUserMedia);
  if (!hasCamera){
    toast('Camera not available — use file picker instead', true);
    return;
  }

  const body = document.createElement('div');
  body.innerHTML = `<div style="position:relative;width:100%;overflow:hidden;border-radius:var(--r-sm)">
    <video id="camVideo" autoplay playsinline muted style="width:100%;display:block;border-radius:var(--r-sm);background:#000"></video>
    <canvas id="camCanvas" style="display:none;width:100%;border-radius:var(--r-sm)"></canvas>
    <div id="camOverlay" style="position:absolute;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;pointer-events:none">
      <div style="width:85%;height:70%;border:2px dashed rgba(255,255,255,0.4);border-radius:12px"></div>
    </div>
  </div>
  <div id="camControls" style="display:flex;gap:8px;margin-top:12px;justify-content:center">
    <button class="btn" id="camFlip" style="font-size:18px" title="Flip camera">🔄</button>
    <button class="btn primary" id="camCapture" style="padding:12px 32px;font-size:15px">📷 Capture</button>
  </div>
  <div id="camPreview" style="display:none;margin-top:12px">
    <div style="font-weight:600;font-size:13px;margin-bottom:8px">Preview</div>
    <canvas id="camResult" style="width:100%;border-radius:var(--r-sm);border:1px solid var(--border)"></canvas>
    <div style="display:flex;gap:4px;margin-top:4px">
      <div class="pill" id="camSizeInfo"><span class="muted">Size</span> <b>—</b></div>
      <div class="pill" id="camDimInfo"><span class="muted">Dim</span> <b>—</b></div>
    </div>
    <div class="btn-row" style="margin-top:10px">
      <button class="btn" id="camRetake">Retake</button>
      <button class="btn primary" id="camSave">Save Receipt</button>
    </div>
  </div>
  <div class="muted" style="font-size:11px;margin-top:10px;text-align:center">Align receipt within the guide frame. Auto-compressed to save storage.</div>`;

  let stream = null;
  let facingMode = 'environment'; // rear camera default
  let capturedBlob = null;

  async function startCamera(){
    try{
      if (stream) stream.getTracks().forEach(t => t.stop());
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode, width: { ideal: 1920 }, height: { ideal: 1080 } },
        audio: false
      });
      const video = $('#camVideo', body);
      if (video){
        video.srcObject = stream;
        video.play().catch(()=>{});
      }
    } catch(err){
      console.error('[FL] Camera error:', err); toast('Camera access denied. Check permissions.', true);
    }
  }

  function stopCamera(){
    if (stream){ stream.getTracks().forEach(t => t.stop()); stream = null; }
    const video = $('#camVideo', body);
    if (video) video.srcObject = null;
  }

  // Capture frame from video to canvas
  function captureFrame(){
    const video = $('#camVideo', body);
    const canvas = $('#camCanvas', body);
    const result = $('#camResult', body);
    if (!video || !canvas || !result) return;

    // Get video dimensions
    const vw = video.videoWidth || 640;
    const vh = video.videoHeight || 480;

    // Crop to center 85% x 70% (matching the overlay guide)
    const cropX = Math.round(vw * 0.075);
    const cropY = Math.round(vh * 0.15);
    const cropW = Math.round(vw * 0.85);
    const cropH = Math.round(vh * 0.70);

    // Scale down if too large (max 1600px wide for storage efficiency)
    const maxW = 1600;
    const scale = Math.min(1, maxW / cropW);
    const outW = Math.round(cropW * scale);
    const outH = Math.round(cropH * scale);

    result.width = outW;
    result.height = outH;
    const ctx = result.getContext('2d', { alpha: false });

    // Draw cropped region
    ctx.drawImage(video, cropX, cropY, cropW, cropH, 0, 0, outW, outH);

    // Auto-enhance: slight contrast boost for receipt text
    try {
      const imgData = ctx.getImageData(0, 0, outW, outH);
      const data = imgData.data;
      // Simple auto-levels: find min/max brightness and stretch
      let minB = 255, maxB = 0;
      for (let i = 0; i < data.length; i += 4){
        const b = (data[i] + data[i+1] + data[i+2]) / 3;
        if (b < minB) minB = b;
        if (b > maxB) maxB = b;
      }
      const range = maxB - minB;
      if (range > 30 && range < 240){
        const factor = 220 / range;
        for (let i = 0; i < data.length; i += 4){
          data[i] = Math.min(255, Math.max(0, (data[i] - minB) * factor + 15));
          data[i+1] = Math.min(255, Math.max(0, (data[i+1] - minB) * factor + 15));
          data[i+2] = Math.min(255, Math.max(0, (data[i+2] - minB) * factor + 15));
        }
        ctx.putImageData(imgData, 0, 0);
      }
    } catch(e){ /* enhancement failed, raw frame is fine */ }

    // Convert to compressed JPEG blob
    result.toBlob((blob)=>{
      capturedBlob = blob;
      const sizeKB = blob ? Math.round(blob.size / 1024) : 0;
      $('#camSizeInfo', body).innerHTML = `<span class="muted">Size</span> <b>${sizeKB} KB</b>`;
      $('#camDimInfo', body).innerHTML = `<span class="muted">Dim</span> <b>${outW}×${outH}</b>`;
    }, 'image/jpeg', 0.82);

    // Show preview, hide video
    video.style.display = 'none';
    $('#camOverlay', body).style.display = 'none';
    $('#camControls', body).style.display = 'none';
    result.style.display = 'block';
    $('#camPreview', body).style.display = '';
    stopCamera();
  }

  // Capture button
  $('#camCapture', body)?.addEventListener('click', ()=> { haptic(25); captureFrame(); });

  // Flip camera
  $('#camFlip', body)?.addEventListener('click', ()=> {
    haptic(10);
    facingMode = facingMode === 'environment' ? 'user' : 'environment';
    startCamera();
  });

  // Retake
  $('#camRetake', body)?.addEventListener('click', ()=> {
    haptic(10);
    capturedBlob = null;
    const video = $('#camVideo', body);
    const result = $('#camResult', body);
    if (video) video.style.display = 'block';
    if (result) result.style.display = 'none';
    $('#camOverlay', body).style.display = '';
    $('#camControls', body).style.display = 'flex';
    $('#camPreview', body).style.display = 'none';
    startCamera();
  });

  // Save
  $('#camSave', body)?.addEventListener('click', async ()=> {
    if (!capturedBlob){ toast('No capture to save', true); return; }
    haptic(20);
    const file = new File([capturedBlob], `receipt-${Date.now()}.jpg`, { type: 'image/jpeg' });
    if (orderNo && orderNo !== 'new'){
      await saveNewReceipts(orderNo, [file]);
      toast('Receipt saved from camera');
    } else {
      // Store temporarily for the trip being created
      _cameraReceiptFiles = _cameraReceiptFiles || [];
      _cameraReceiptFiles.push(file);
      toast('Receipt captured — will save with trip');
    }
    closeModal();
  });

  openModal('📷 Receipt Camera', body);
  startCamera();

  // Clean up camera when modal closes
  const _origClose = closeModal;
  const obs = new MutationObserver(()=> {
    if ($('#modal').style.display === 'none'){ stopCamera(); obs.disconnect(); }
  });
  obs.observe($('#modal'), { attributes: true, attributeFilter: ['style'] });
}

// Temp storage for camera receipts captured before trip is saved
let _cameraReceiptFiles = [];

// ════════════════════════════════════════════════════════════════
// v14.4.0 FEATURE: WEEKLY TRENDS CHART (Canvas-based, no deps)
// ════════════════════════════════════════════════════════════════

async function renderWeeklyChart(){
  const canvas = $('#weeklyChart');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  const W = rect.width;
  const H = rect.height;

  // Gather last 7 days of revenue & expenses
  const { trips, exps } = await _getTripsAndExps();
  const today = new Date();
  const dayLabels = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const days = [];
  for (let i = 6; i >= 0; i--){
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const iso = isoDate(d);
    let rev = 0, exp = 0;
    for (const t of trips){
      const dt = t.pickupDate || t.deliveryDate;
      if (dt === iso) rev += Number(t.pay || 0);
    }
    for (const e of exps){
      if (e.date === iso) exp += Number(e.amount || 0);
    }
    days.push({ label: dayLabels[d.getDay()], date: iso.slice(5), rev, exp, net: rev - exp });
  }

  const maxVal = Math.max(1, ...days.map(d => Math.max(d.rev, d.exp)));
  const isDark = !document.documentElement.hasAttribute('data-theme') || document.documentElement.getAttribute('data-theme') === 'dark';
  const textColor = isDark ? '#a8a8bc' : '#555570';
  const revColor = isDark ? '#eba40f' : '#d48f00';
  const expColor = isDark ? 'rgba(248,113,113,0.6)' : 'rgba(220,38,38,0.5)';
  const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';

  // Clear
  ctx.clearRect(0, 0, W, H);

  // Chart area
  const padL = 6, padR = 6, padT = 18, padB = 24;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;
  const barW = (chartW / 7) * 0.35;
  const gap = chartW / 7;

  // Title
  ctx.font = '600 11px -apple-system, system-ui, sans-serif';
  ctx.fillStyle = textColor;
  ctx.textAlign = 'left';
  ctx.fillText('7-DAY REVENUE', padL, 13);

  // Max label
  ctx.textAlign = 'right';
  ctx.font = '500 10px ui-monospace, SF Mono, monospace';
  ctx.fillStyle = textColor;
  ctx.fillText('$' + Math.round(maxVal).toLocaleString(), W - padR, 13);

  // Grid lines
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 0.5;
  for (let i = 0; i <= 3; i++){
    const y = padT + (chartH * i / 3);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
  }

  // Bars + labels
  for (let i = 0; i < 7; i++){
    const d = days[i];
    const x = padL + gap * i + gap / 2;

    // Revenue bar
    const revH = maxVal > 0 ? (d.rev / maxVal) * chartH : 0;
    ctx.fillStyle = revColor;
    ctx.beginPath();
    const bx = x - barW;
    const by = padT + chartH - revH;
    const bh = revH;
    ctx.roundRect?.(bx, by, barW * 1.8, bh, [3, 3, 0, 0]);
    if (ctx.roundRect) ctx.fill();
    else { ctx.fillRect(bx, by, barW * 1.8, bh); }

    // Expense overlay (thin line at bottom of bar)
    if (d.exp > 0){
      const expH = Math.max(2, (d.exp / maxVal) * chartH);
      ctx.fillStyle = expColor;
      ctx.fillRect(bx, padT + chartH - expH, barW * 1.8, expH);
    }

    // Day label
    ctx.fillStyle = i === 6 ? revColor : textColor;
    ctx.font = i === 6 ? '700 10px -apple-system, system-ui, sans-serif' : '400 10px -apple-system, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(d.label, x, H - 4);

    // Value on top of bar (if non-zero)
    if (d.rev > 0){
      ctx.fillStyle = textColor;
      ctx.font = '500 9px ui-monospace, SF Mono, monospace';
      ctx.textAlign = 'center';
      const valY = by - 3;
      if (valY > padT) ctx.fillText('$' + Math.round(d.rev).toLocaleString(), x, valY);
    }
  }
}

// ════════════════════════════════════════════════════════════════
// v14.4.0 FEATURE: PAYMENT REMINDER NOTIFICATIONS
// ════════════════════════════════════════════════════════════════

async function checkOverduePayments(){
  try{
    const trips = await dumpStore('trips');
    const today = new Date();
    const overdueTrips = [];
    for (const t of trips){
      if (t.isPaid) continue;
      const dt = t.pickupDate || t.deliveryDate;
      if (!dt) continue;
      const pickupTs = new Date(dt).getTime();
      const daysSince = Math.floor((today.getTime() - pickupTs) / 86400000);
      if (daysSince >= 30){
        overdueTrips.push({ orderNo: t.orderNo, customer: t.customer || 'Unknown', pay: Number(t.pay || 0), days: daysSince });
      }
    }
    if (!overdueTrips.length) return;

    // Show in-app alert banner
    const banner = $('#overdueAlert');
    if (banner){
      const total = overdueTrips.reduce((s, t) => s + t.pay, 0);
      const worst = overdueTrips.sort((a, b) => b.days - a.days)[0];
      banner.style.display = '';
      banner.innerHTML = `<div style="display:flex;align-items:center;gap:10px">
        <div style="font-size:20px">⏰</div>
        <div style="flex:1">
          <div style="font-weight:700;font-size:13px;color:var(--bad)">${overdueTrips.length} Overdue Payment${overdueTrips.length > 1 ? 's' : ''}</div>
          <div class="muted" style="font-size:12px">${fmtMoney(total)} unpaid 30+ days. Worst: ${escapeHtml(worst.customer)} (${worst.days}d)</div>
        </div>
        <button class="btn" onclick="location.hash='#money'" style="white-space:nowrap">View</button>
      </div>`;
    }

    // Push notification (if permitted)
    if ('Notification' in window && Notification.permission === 'granted'){
      const lastNotify = await getSetting('lastOverdueNotify', 0);
      const now = Date.now();
      // Only notify once per 24h
      if (now - lastNotify > 86400000){
        const total = overdueTrips.reduce((s, t) => s + t.pay, 0);
        new Notification('Freight Logic — Overdue Payments', {
          body: `${overdueTrips.length} load${overdueTrips.length > 1 ? 's' : ''} unpaid 30+ days (${fmtMoney(total)}). Follow up!`,
          icon: 'icons/icon192.png',
          badge: 'icons/icon64.png',
          tag: 'overdue-payments'
        });
        await setSetting('lastOverdueNotify', now);
      }
    }
  } catch(e){ console.warn('[NOTIFY] overdue check failed:', e); }
}

async function requestNotificationPermission(){
  try{
    if (!('Notification' in window)) return;
    if (Notification.permission === 'default'){
      // Only ask after user has added at least 1 trip
      const cnt = await countStore('trips');
      if (cnt >= 1){
        const perm = await Notification.requestPermission();
        if (perm === 'granted') toast('Notifications enabled — we\'ll alert you about late payments');
      }
    }
  } catch(e){ console.warn("[FL]", e); }
}

// ════════════════════════════════════════════════════════════════
// v14.4.0 FEATURE: PWA INSTALL BANNER
// ════════════════════════════════════════════════════════════════

let _deferredInstallPrompt = null;

// Capture the install event before the browser shows its own prompt
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  _deferredInstallPrompt = e;
  // Show custom banner (only if not dismissed before)
  const dismissed = localStorage.getItem('fl_pwa_dismiss_v1');
  if (!dismissed) showInstallBanner();
});

function showInstallBanner(){
  const banner = $('#pwaInstallBanner');
  if (!banner) return;
  banner.style.display = 'block';

  $('#pwaInstallBtn')?.addEventListener('click', async () => {
    if (_deferredInstallPrompt){
      _deferredInstallPrompt.prompt();
      const choice = await _deferredInstallPrompt.userChoice;
      if (choice.outcome === 'accepted') toast('Freight Logic installed!');
      _deferredInstallPrompt = null;
      banner.style.display = 'none';
    }
  });

  $('#pwaInstallDismiss')?.addEventListener('click', () => {
    banner.style.display = 'none';
    localStorage.setItem('fl_pwa_dismiss_v1', '1');
  });
}

// Also detect if already installed (standalone mode)
window.addEventListener('appinstalled', () => {
  const banner = $('#pwaInstallBanner');
  if (banner) banner.style.display = 'none';
  _deferredInstallPrompt = null;
});

// ════════════════════════════════════════════════════════════════
// v14.4.0 FEATURE: DARK/LIGHT THEME TOGGLE
// ════════════════════════════════════════════════════════════════

function initTheme(){
  const saved = localStorage.getItem('fl_theme');
  if (saved === 'light'){
    document.documentElement.setAttribute('data-theme', 'light');
    updateThemeIcon('light');
    updateThemeColor('light');
  } else {
    document.documentElement.removeAttribute('data-theme');
    updateThemeIcon('dark');
  }
}
function toggleTheme(){
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  if (isLight){
    document.documentElement.removeAttribute('data-theme');
    localStorage.setItem('fl_theme', 'dark');
    updateThemeIcon('dark');
    updateThemeColor('dark');
  } else {
    document.documentElement.setAttribute('data-theme', 'light');
    localStorage.setItem('fl_theme', 'light');
    updateThemeIcon('light');
    updateThemeColor('light');
  }
  // Redraw chart with new theme colors
  renderWeeklyChart().catch(()=>{});
}
function updateThemeIcon(theme){
  const btn = $('#themeToggle');
  if (btn) btn.textContent = theme === 'light' ? '☀️' : '🌙';
}
function updateThemeColor(theme){
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = theme === 'light' ? '#f5f5f7' : '#141419';
}
// Init theme immediately (before DOM paint to avoid flash)
initTheme();
addManagedListener($('#themeToggle'), 'click', ()=>{ haptic(15); toggleTheme(); });


// ==================== DAT API INTEGRATION MODULE ====================
// Future integration with DAT Power / DAT API for:
// - Live market rate lookups by lane
// - Rate trending data for negotiation
// - Load board search and auto-evaluate
// - Broker credit scores from DAT directory
//
// API docs: https://developer.dat.com
// CSP already allows: https://power.dat.com https://api.dat.com
// Settings: datApiEnabled, datApiBaseUrl stored in IndexedDB
// ====================================================================

const DAT_DEFAULT_BASE = 'https://power.dat.com/api/v2';
const DAT_TIMEOUT_MS = 12000;

async function datIsEnabled(){
  return (await getSetting('datApiEnabled', 'off')) === 'on';
}

async function datGetConfig(){
  const enabled = await datIsEnabled();
  if (!enabled) return null;
  const baseUrl = (await getSetting('datApiBaseUrl', '')) || DAT_DEFAULT_BASE;
  return { baseUrl: clampStr(baseUrl, 200) };
}

/**
 * datFetch — authenticated request to DAT API
 * @param {string} endpoint - API path (e.g., '/rateView/lane')
 * @param {object} options - { method, body, token }
 * @returns {object|null} - parsed JSON response or null on failure
 *
 * NOTE: DAT API requires OAuth2 authentication. When you get your
 * credentials from DAT, the token flow will be:
 *   1. POST to /auth/token with client_id + client_secret
 *   2. Use the bearer token in subsequent requests
 *   3. Token refresh on 401
 *
 * This function is a ready-to-use shell. Fill in your auth flow
 * when you have DAT credentials.
 */
async function datFetch(endpoint, options = {}){
  const config = await datGetConfig();
  if (!config) return null;

  const url = config.baseUrl.replace(/\/+$/, '') + '/' + endpoint.replace(/^\/+/, '');
  const method = options.method || 'GET';

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DAT_TIMEOUT_MS);

    const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    // When you have your DAT token:
    // if (options.token) headers['Authorization'] = `Bearer ${options.token}`;

    const fetchOpts = { method, headers, signal: controller.signal };
    if (options.body && method !== 'GET') fetchOpts.body = JSON.stringify(options.body);

    const res = await fetch(url, fetchOpts);
    clearTimeout(timer);

    if (!res.ok) {
      console.warn(`[DAT] ${method} ${endpoint} → ${res.status}`);
      return null;
    }
    return await res.json();
  } catch(e) {
    if (e.name === 'AbortError') console.warn('[DAT] Request timed out:', endpoint);
    else console.warn('[DAT] Request failed:', e.message || e);
    return null;
  }
}

/**
 * datLookupLaneRate — Get market rate for a lane
 * Ready to call once you have DAT API credentials.
 *
 * Usage (future):
 *   const rate = await datLookupLaneRate('Indianapolis, IN', 'Chicago, IL');
 *   // rate = { avg: 2.45, low: 2.10, high: 2.80, samples: 128, ... }
 */
async function datLookupLaneRate(origin, dest, options = {}){
  if (!origin || !dest) return null;
  if (!(await datIsEnabled())) return null;

  const data = await datFetch('rateView/lane', {
    method: 'POST',
    body: {
      origin: { city: clampStr(origin, 60) },
      destination: { city: clampStr(dest, 60) },
      equipmentType: options.equipmentType || 'V',
      timePeriod: options.days || 15,
    },
    token: options.token,
  });

  if (!data) return null;
  return {
    avgRate: finiteNum(data.rate?.perMile?.average, 0),
    lowRate: finiteNum(data.rate?.perMile?.low, 0),
    highRate: finiteNum(data.rate?.perMile?.high, 0),
    samples: intNum(data.rate?.reportCount, 0),
    avgMiles: finiteNum(data.mileage?.average, 0),
    source: 'DAT',
    timestamp: Date.now(),
  };
}

/**
 * datEnrichMwEvaluator — Inject DAT market rate into Midwest Stack
 * Call this after mwEvaluateLoad to add market context.
 */
async function datEnrichMwEvaluator(origin, dest, trueRPM){
  const rate = await datLookupLaneRate(origin, dest);
  if (!rate || !rate.avgRate) return null;

  const vsMarket = trueRPM - rate.avgRate;
  const pctVsMarket = rate.avgRate > 0 ? ((vsMarket / rate.avgRate) * 100) : 0;

  return {
    ...rate,
    yourRPM: trueRPM,
    vsMarketDelta: roundCents(vsMarket),
    vsMarketPct: roundCents(pctVsMarket),
    verdict: vsMarket >= 0.10 ? 'ABOVE MARKET' : vsMarket >= -0.05 ? 'AT MARKET' : 'BELOW MARKET',
  };
}


// ==================== CLOUD BACKUP MODULE ====================
// Client-side encrypted sync to Cloudflare Worker (free tier).
// Data is encrypted with AES-256-GCM using your passphrase
// BEFORE it leaves your device. The server never sees plaintext.
// ==============================================================

const CLOUD_SYNC_DEBOUNCE = 30000; // 30s debounce after data change
let _cloudSyncTimer = null;
let _cloudSyncInProgress = false;
let _lastCloudSync = 0;

async function cloudIsEnabled(){
  const url = await getSetting('cloudBackupUrl', '');
  const pass = await getSetting('cloudBackupPass', '');
  const token = await getSetting('cloudBackupToken', '');
  return !!(url && pass && token);
}

async function cloudGetConfig(){
  const url = await getSetting('cloudBackupUrl', '');
  const pass = await getSetting('cloudBackupPass', '');
  const token = await getSetting('cloudBackupToken', '');
  if (!url || !pass || !token) return null;
  try { new URL(url); } catch { return null; }
  return { url: clampStr(url, 200), pass, token };
}

function cloudGetDeviceId(){
  let id = localStorage.getItem('fl_device_id');
  if (!id){
    id = 'dev_' + (crypto.randomUUID?.() || Math.random().toString(36).slice(2) + Date.now().toString(36));
    localStorage.setItem('fl_device_id', id);
  }
  return id;
}

// ── AES-256-GCM Encryption (Web Crypto API) ──
async function cloudEncrypt(plaintext, passphrase){
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Derive key from passphrase using PBKDF2
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));

  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
    salt: btoa(String.fromCharCode(...salt)),
  };
}

async function cloudDecrypt(encrypted, iv, salt, passphrase){
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
  const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
  const cipherBytes = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));

  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, cipherBytes);
  return dec.decode(plainBuffer);
}

// ── Push backup to cloud ──
async function cloudPushBackup(silent = true){
  if (_cloudSyncInProgress) return;
  const config = await cloudGetConfig();
  if (!config) return;

  _cloudSyncInProgress = true;
  try {
    const trips = await dumpStore('trips');
    const expenses = await dumpStore('expenses');
    const fuel = await dumpStore('fuel');
    const settings = await dumpStore('settings');
    const receipts = await dumpStore('receipts');

    const payload = JSON.stringify({
      meta: { app: 'FreightLogic', version: APP_VERSION, savedAt: new Date().toISOString(),
        counts: { trips: trips.length, expenses: expenses.length, fuel: fuel.length } },
      trips, expenses, fuel, settings, receipts,
    });

    const { encrypted, iv, salt } = await cloudEncrypt(payload, config.pass);
    const envelope = JSON.stringify({ encrypted, iv, salt });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);

    const res = await fetch(config.url.replace(/\/+$/, ''), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': cloudGetDeviceId(),
        'X-Backup-Token': config.token,
      },
      body: envelope,
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (res.ok) {
      _lastCloudSync = Date.now();
      await setSetting('lastCloudSync', _lastCloudSync);
      if (!silent) toast('☁️ Backup synced to cloud');
      updateCloudStatus();
    } else {
      const errBody = await res.json().catch(() => ({}));
      console.warn('[CLOUD] Push failed:', res.status, errBody.error || '');
      if (!silent) toast(res.status === 401 ? 'Cloud backup: bad token' : 'Cloud backup failed', true);
    }
  } catch(e) {
    if (e.name === 'AbortError') console.warn('[CLOUD] Push timed out');
    else console.warn('[CLOUD] Push error:', e.message || e);
    if (!silent) toast('Cloud backup failed — check connection', true);
  } finally {
    _cloudSyncInProgress = false;
  }
}

// ── Pull backup from cloud ──
async function cloudPullBackup(){
  const config = await cloudGetConfig();
  if (!config){ toast('Set cloud URL, passphrase, and token first', true); return; }

  try {
    toast('Fetching cloud backup...');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);

    // GET lists this device's backup keys
    const res = await fetch(config.url.replace(/\/+$/, ''), {
      method: 'GET',
      headers: {
        'X-Device-Id': cloudGetDeviceId(),
        'X-Backup-Token': config.token,
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      toast(res.status === 401 ? 'Cloud restore: bad token' : 'Cloud restore failed', true);
      return;
    }

    const listData = await res.json();
    const keys = listData.backups || [];
    if (!keys.length) {
      toast('No cloud backup found for this device', true);
      return;
    }

    // Fetch the latest backup value by key
    const latestKey = keys[keys.length - 1];
    toast('Downloading backup data...');
    const ctrl2 = new AbortController();
    const timer2 = setTimeout(() => ctrl2.abort(), 15000);
    const fetchUrl = config.url.replace(/\/+$/, '') + '?key=' + encodeURIComponent(latestKey);
    const dataRes = await fetch(fetchUrl, {
      method: 'GET',
      headers: {
        'X-Device-Id': cloudGetDeviceId(),
        'X-Backup-Token': config.token,
      },
      signal: ctrl2.signal,
    });
    clearTimeout(timer2);

    if (!dataRes.ok) {
      toast('Could not fetch backup data', true);
      return;
    }

    const raw = await dataRes.text();
    let encObj;
    try { encObj = JSON.parse(raw); } catch { toast('Backup data is corrupted', true); return; }

    if (!encObj.encrypted || !encObj.iv || !encObj.salt) {
      toast('Backup format invalid', true);
      return;
    }

    let plaintext;
    try {
      plaintext = await cloudDecrypt(encObj, config.pass);
    } catch(e) {
      toast('Wrong passphrase — cannot decrypt', true);
      return;
    }

    const parsed = JSON.parse(plaintext);
    if (!parsed.trips && !parsed.expenses) {
      toast('Backup is empty', true);
      return;
    }

    const counts = parsed.meta?.counts || {};
    const doRestore = confirm(
      `Restore cloud backup?\n\n` +
      `Saved: ${parsed.meta?.savedAt?.slice(0,16) || 'unknown'}\n` +
      `Trips: ${counts.trips || 0}\n` +
      `Expenses: ${counts.expenses || 0}\n` +
      `Fuel: ${counts.fuel || 0}\n\n` +
      `This will ADD to your existing data.`
    );
    if (!doRestore) return;

    const blob = new Blob([plaintext], { type: 'application/json' });
    const file = new File([blob], 'cloud-restore.json', { type: 'application/json' });
    await importJSON(file);
    toast('☁️ Cloud backup restored!');
    invalidateKPICache();
    await renderHome();

  } catch(e) {
    console.error('[CLOUD] Pull error:', e);
    toast('Cloud restore failed', true);
  }
}

// ── Check cloud status ──
async function cloudCheckStatus(){
  const config = await cloudGetConfig();
  if (!config) return null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(config.url.replace(/\/+$/, ''), {
      headers: { 'X-Device-Id': cloudGetDeviceId(), 'X-Backup-Token': config.token },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

function updateCloudStatus(){
  const el = $('#cloudSyncStatus');
  const indicator = $('#cloudIndicator');
  const ts = _lastCloudSync;
  if (ts > 0){
    const ago = Math.floor((Date.now() - ts) / 60000);
    const label = ago < 1 ? 'Synced just now' : ago < 60 ? `Synced ${ago}m ago` : `Synced ${Math.floor(ago/60)}h ago`;
    if (el) { el.textContent = label; el.style.color = 'var(--good)'; }
    if (indicator) { indicator.style.display = ''; indicator.textContent = '☁️'; indicator.title = label; indicator.style.opacity = '1'; }
  } else {
    if (el) { el.textContent = 'Not synced yet'; el.style.color = 'var(--muted)'; }
    if (indicator) { indicator.style.display = 'none'; }
  }
}

// ── Auto-sync trigger (debounced) ──
function cloudScheduleSync(){
  if (_cloudSyncTimer) clearTimeout(_cloudSyncTimer);
  _cloudSyncTimer = setTimeout(async () => {
    _cloudSyncTimer = null;
    if (await cloudIsEnabled()) await cloudPushBackup(true);
  }, CLOUD_SYNC_DEBOUNCE);
}


// ── v15.3.0: Emergency auto-backup on tab close/hide ──
let _lastAutoBackup = 0;
const AUTO_BACKUP_INTERVAL = 300000; // 5 min minimum between auto-backups
async function emergencyAutoBackup(){
  try{
    const now = Date.now();
    if (now - _lastAutoBackup < AUTO_BACKUP_INTERVAL) return;
    _lastAutoBackup = now;
    const trips = await dumpStore('trips');
    const expenses = await dumpStore('expenses');
    const fuel = await dumpStore('fuel');
    if (!trips.length && !expenses.length && !fuel.length) return;
    const snapshot = {
      meta: { app:'FreightLogic', version:APP_VERSION, autoBackup:true, savedAt:new Date().toISOString(),
              counts:{ trips:trips.length, expenses:expenses.length, fuel:fuel.length } },
      trips, expenses, fuel
    };
    let json = JSON.stringify(snapshot);
    // Full dump fits — save it
    if (json.length < 4_000_000){
      localStorage.setItem('fl_emergency_backup', json);
      localStorage.setItem('fl_emergency_backup_ts', String(now));
    } else {
      // Full dump too large — fallback: save most recent records to preserve current work
      const recentTrips = trips.sort((a,b) => (b.created||0) - (a.created||0)).slice(0, 20);
      const recentExps = expenses.sort((a,b) => (b.created||0) - (a.created||0)).slice(0, 50);
      const recentFuel = fuel.sort((a,b) => (b.created||0) - (a.created||0)).slice(0, 50);
      const partial = {
        meta: { app:'FreightLogic', version:APP_VERSION, autoBackup:true, partial:true, savedAt:new Date().toISOString(),
                counts:{ trips:recentTrips.length, expenses:recentExps.length, fuel:recentFuel.length },
                totalCounts:{ trips:trips.length, expenses:expenses.length, fuel:fuel.length } },
        trips: recentTrips, expenses: recentExps, fuel: recentFuel
      };
      const partialJson = JSON.stringify(partial);
      if (partialJson.length < 4_000_000){
        localStorage.setItem('fl_emergency_backup', partialJson);
        localStorage.setItem('fl_emergency_backup_ts', String(now));
      }
      // If even partial is too large, we can't help — cloud backup is the safety net
    }
  }catch(e){ console.warn('[FL] Auto-backup failed:', e); }
}
document.addEventListener('visibilitychange', ()=>{
  if (document.visibilityState === 'hidden'){
    emergencyAutoBackup();
    // Cloud sync on tab close (non-blocking)
    cloudPushBackup(true).catch(()=>{});
  }
});
window.addEventListener('beforeunload', ()=> emergencyAutoBackup());


// ── v15.3.0: Offline/Online indicator ──
function _updateOnlineStatus(){
  const isOff = !navigator.onLine;
  let banner = document.getElementById('offlineBanner');
  if (isOff && !banner){
    banner = document.createElement('div');
    banner.id = 'offlineBanner';
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9998;padding:6px 16px;background:#ff6b6b;color:#fff;font-size:12px;font-weight:600;text-align:center;letter-spacing:.5px';
    banner.textContent = 'OFFLINE — Data is saved locally. Some features require connection.';
    document.body.appendChild(banner);
  } else if (!isOff && banner){
    banner.remove();
  }
}
window.addEventListener('online', _updateOnlineStatus);
window.addEventListener('offline', _updateOnlineStatus);

// ---- Boot ----
(async () => {
  try{
    $('#appMeta').textContent = `Omega • v${APP_VERSION}`;
    db = await initDB();
    const uiMode = await getSetting('uiMode', null);
    if (!uiMode) await setSetting('uiMode','simple');
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('./service-worker.js').catch(()=>{});

    // Pull-to-refresh on list views
    setupPTR('tripsPTR', '#tripList', ()=> renderTrips(true));
    setupPTR('expPTR', '#expenseList', ()=> renderExpenses(true));
    setupPTR('fuelPTR', '#fuelList', ()=> renderFuel(true));

    await navigate();
    _updateOnlineStatus();
    setInterval(()=> computeQuickKPIs().catch(()=>{}), 60_000);

    // Onboarding: pulse FAB and show hint for new users
    const onb = await getOnboardState();
    if (onb.isEmpty){
      $('#fab').classList.add('pulse');
      const hint = $('#fabHint');
      if (hint) hint.style.display = '';
    }

    // v14.4.0: Deferred boot tasks (non-blocking)
    setTimeout(async ()=>{
      try{ await requestPersistentStorage(); }catch(e){ console.warn("[FL]", e); }
      try{ await requestNotificationPermission(); }catch(e){ console.warn("[FL]", e); }
      try{ await checkBackupReminder(); }catch(e){ console.warn("[FL]", e); }
      try{ await checkQuarterlyExportReminder(); }catch(e){ console.warn("[FL]", e); }
      // v15.3.0: Check for emergency backup recovery
      try{
        const emTs = Number(localStorage.getItem('fl_emergency_backup_ts') || 0);
        const onb = await getOnboardState();
        if (onb.isEmpty && emTs > 0){
          const age = Math.floor((Date.now() - emTs) / 86400000);
          if (age < 30){
            const doRecover = confirm('Found emergency backup from ' + age + ' day(s) ago with data. Recover it?');
            if (doRecover){
              const json = localStorage.getItem('fl_emergency_backup');
              if (json){
                const blob = new Blob([json], {type:'application/json'});
                const file = new File([blob], 'recovery.json', {type:'application/json'});
                await importJSON(file);
                toast('Emergency backup recovered!');
                localStorage.removeItem('fl_emergency_backup');
                localStorage.removeItem('fl_emergency_backup_ts');
                await renderHome();
              }
            }
          }
        }
      }catch(e){ console.warn('[FL] Recovery check failed:', e); }
      try{ showSafariWarning(); }catch(e){ console.warn("[FL]", e); }
      try{ await checkStorageQuota(); }catch(e){ console.warn("[FL]", e); }
    }, 2000);
  }catch(err){
    console.error(err);
    console.error('[FL] Startup error:', err); toast('App startup failed. Try refreshing.', true);
  }
})();
})();
