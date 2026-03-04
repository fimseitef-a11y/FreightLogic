(() => {
'use strict';

/** Freight Logic v14.1.0-clarity
 *  UX overhaul + universal import fix: CSV, Excel, JSON, PDF, TXT all working
 */

const APP_VERSION = '14.3.5-tier5';
const DB_NAME = 'XpediteOps_v1';
const DB_VERSION = 8;
const PAGE_SIZE = 50;

const LIMITS = Object.freeze({
  MAX_IMPORT_BYTES: 30 * 1024 * 1024,
  MAX_RECEIPT_BYTES: 6 * 1024 * 1024,
  MAX_RECEIPTS_PER_TRIP: 20,
  MAX_RECEIPT_CACHE: 40,
  THUMB_MAX_DIM: 320,
  THUMB_JPEG_QUALITY: 0.72,
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
  if (/^[=+\-@\t\r|%!]/.test(s)) s = '\t' + s;
  // Also neutralize DDE payloads
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
    window.open(url, '_blank', 'noopener');
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

  return { destroy(){ wrap.parentNode?.insertBefore(input, wrap); wrap.remove(); } };
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
function openModal(title, bodyEl){
  // T5-FIX: Cancel any pending close timer to prevent race condition
  // (closeModal sets a 350ms delayed nuke that would destroy this new modal)
  if (_modalCloseTimer){ clearTimeout(_modalCloseTimer); _modalCloseTimer = null; }
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
  requestAnimationFrame(()=>{ bd.classList.add('vis'); md.classList.add('open'); });
}
function closeModal(){
  if (_modalCloseTimer){ clearTimeout(_modalCloseTimer); _modalCloseTimer = null; }
  const bd = $('#backdrop');
  const md = $('#modal');
  bd.classList.remove('vis');
  md.classList.remove('open');
  _modalCloseTimer = setTimeout(()=>{ _modalCloseTimer = null; bd.style.display = 'none'; md.style.display = 'none'; $('#modalBody').innerHTML = ''; }, 350);
}
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
$('#modalClose').addEventListener('click', ()=>{ haptic(); closeModal(); });
$('#backdrop').addEventListener('click', closeModal);

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
      ensureStore('settings', { keyPath:'key' });
      ensureStore('receipts', { keyPath:'tripOrderNo' });
      ensureStore('receiptBlobs', { keyPath:'id' });
      if (!d.objectStoreNames.contains('auditLog')) {
        const a = d.createObjectStore('auditLog', { keyPath:'id' });
        a.createIndex('timestamp','timestamp',{unique:false});
        a.createIndex('entityId','entityId',{unique:false});
      }
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
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => {
      // iOS/Safari IndexedDB can occasionally corrupt; attempt a one-time self-heal.
      try{
        const key = 'fl_idb_recover_v1';
        if (!sessionStorage.getItem(key)){
          sessionStorage.setItem(key,'1');
          try{ indexedDB.deleteDatabase(DB_NAME); }catch{}
          toast('Database issue detected. Recovering…', true);
          setTimeout(()=> location.reload(), 600);
          return;
        }
      }catch{}
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
    notes:'', isPaid:false, paidDate:null, wouldRunAgain:null, created:Date.now(), updated:Date.now() };
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
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['trips','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.trips.get(t.orderNo)); }catch{}
  stores.trips.put(t);
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: t.orderNo, action: beforeData ? 'UPDATE_TRIP' : 'CREATE_TRIP', beforeData: beforeData || null, afterData: t, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(t); txn.onerror = ()=> reject(txn.error); });
}
async function deleteTrip(orderNo){
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['trips','receipts','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.trips.get(orderNo)); }catch{}
  stores.trips.delete(orderNo);
  try{ stores.receipts.delete(orderNo); }catch{}
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
  const {t:txn, stores} = tx(['expenses','auditLog'],'readwrite');
  const req = stores.expenses.add(e);
  return new Promise((resolve,reject)=>{
    req.onerror = ()=> reject(req.error);
    req.onsuccess = ()=>{
      e.id = req.result;
      try{ stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(e.id), action:'CREATE_EXPENSE', beforeData: null, afterData: e, source: 'user' }); }catch{}
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
  try{ beforeData = await idbReq(stores.expenses.get(e.id)); }catch{}
  stores.expenses.put(e);
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(e.id), action:'UPDATE_EXPENSE', beforeData, afterData: e, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(e); txn.onerror = ()=> reject(txn.error); });
}
async function deleteExpense(id){
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['expenses','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.expenses.get(Number(id))); }catch{}
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
  const {t:txn, stores} = tx(['fuel','auditLog'],'readwrite');
  const req = stores.fuel.add(x);
  return new Promise((resolve,reject)=>{
    req.onsuccess = ()=> { x.id = req.result; try{ stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(x.id), action:'CREATE_FUEL', beforeData: null, afterData: x, source: 'user' }); }catch{} };
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
  try{ beforeData = await idbReq(stores.fuel.get(x.id)); }catch{}
  stores.fuel.put(x);
  stores.auditLog?.put?.({ id: crypto.randomUUID?.() || String(Date.now())+Math.random(), timestamp: Date.now(), entityId: String(x.id), action:'UPDATE_FUEL', beforeData, afterData: x, source: 'user' });
  return new Promise((resolve,reject)=>{ txn.oncomplete = ()=> resolve(x); txn.onerror = ()=> reject(txn.error); });
}
async function deleteFuel(id){
  // TOCTOU-safe: read + write in single readwrite transaction
  const {t:txn, stores} = tx(['fuel','auditLog'],'readwrite');
  let beforeData = null;
  try{ beforeData = await idbReq(stores.fuel.get(Number(id))); }catch{}
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
    for (const e of all.slice(0, Math.max(0, all.length - max))){
      await idbDeleteReceiptBlob(e.id);
      const receiptsAll = await getAllReceipts();
      for (const r of receiptsAll){
        if (!r?.files?.length) continue;
        let changed = false;
        r.files = r.files.map(x=>{ if (x?.id === e.id && x.cached){ changed = true; return Object.assign({}, x, { cached:false }); } return x; });
        if (changed) await putReceipts(r.tripOrderNo, r.files);
      }
    }
  }catch{}
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
  const header = ['Order#','Customer','Pickup','Delivery','Origin','Destination','Pay','LoadedMiles','EmptyMiles','AllMiles','RPM','Paid','PaidDate','WouldRunAgain','Notes'];
  const rows = [header, ...trips.map(t => {
    const all = (Number(t.loadedMiles||0) + Number(t.emptyMiles||0));
    const rpm = all > 0 ? (Number(t.pay||0)/all).toFixed(2) : '0';
    return [t.orderNo, t.customer, t.pickupDate, t.deliveryDate, t.origin, t.destination, t.pay, t.loadedMiles, t.emptyMiles, all, rpm, t.isPaid?'Yes':'No', t.paidDate||'', t.wouldRunAgain?'Yes':'', t.notes];
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
      } catch {}
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
    const ALLOWED_SETTINGS_KEYS = new Set(['uiMode','perDiemRate','brokerWindow','weeklyGoal','iftaMode','omegaLastInputs','lastExportDate','vehicleMpg','fuelPrice','weeklyReflection','mwLastInputs','mwLastTab']);
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
    const putAll = (store, a) => (a||[]).forEach(x => { try{ store.put(x); }catch{} });
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
      return i >= 0 && i < row.length ? row[i] : '';
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
        }catch{}
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
        }catch{}
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
        }catch{}
      }
      await waitTxn(txn);
      toast(`Imported ${imported} fuel entr${imported!==1?'ies':'y'} from CSV`);
      invalidateKPICache();
      await renderFuel(true); await renderHome();
    }
  }catch(err){ toast('CSV import failed: ' + (err.message || 'Unknown error'), true); }
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
  } catch(err) { toast('Import failed: ' + (err.message || 'Unknown error'), true); }
}

// ---- XLSX Import (uses SheetJS from CDN — version-pinned + SRI-ready) ----
// SECURITY: Generate SRI hash via: curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A
// Then set s.integrity = 'sha384-<hash>';
async function loadSheetJS(){
  if (typeof XLSX !== 'undefined') return;
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js';
    s.crossOrigin = 'anonymous';
    // T5-SECURITY: Add SRI hash before production deployment. Generate with:
    //   curl -sL https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js | openssl dgst -sha384 -binary | openssl base64 -A
    //   Then set: s.integrity = 'sha384-<paste_hash_here>';
    s.onload = () => {
      // T5-FIX: Post-load validation — verify XLSX global hasn't been replaced with a proxy/trap
      if (typeof XLSX === 'undefined' || typeof XLSX.read !== 'function'){
        reject(new Error('SheetJS loaded but XLSX.read missing — possible CDN tampering'));
        return;
      }
      resolve();
    };
    s.onerror = () => reject(new Error('Failed to load SheetJS — CDN unavailable'));
    document.head.appendChild(s);
  });
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
  }catch(err){ toast('Excel import failed: ' + (err.message || 'Unknown error'), true); }
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
  }catch(err){ toast('TXT import failed: ' + (err.message || 'Unknown error'), true); }
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
function invalidateKPICache(){ _kpiCache.ts = 0; }

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
  } catch {}
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
  const perDiem = roundCents(perDiemFull * 0.80); // IRS Sec 274(n): 80% limit for DOT drivers
  const se = roundCents(Math.max(0, (net - perDiem) * 0.9235 * 0.153)); // IRS SE tax
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
function openBrokerScorecard(gradeObj, globalAvgRpm){
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

  openModal(`Scorecard • ${escapeHtml(b.name)}`, body);
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

function computeLoadScore(trip, allTrips, allExps, fuelConfig=null){
  const pay = Number(trip.pay || 0);
  const loaded = Number(trip.loadedMiles || 0);
  const empty = Number(trip.emptyMiles || 0);
  const allMi = loaded + empty;
  const rpm = allMi > 0 ? pay / allMi : 0;
  const trueRpm = loaded > 0 ? pay / loaded : 0; // loaded-only CPM
  const deadheadPct = allMi > 0 ? (empty / allMi) * 100 : 0;
  const customer = clampStr(trip.customer || '', 80);

  // ── Historical baselines (last 90 days) ──
  const now = Date.now();
  const d90 = now - 90 * 86400000;
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
  const histAvgRpm = histMiSum > 0 ? histRpmSum / histMiSum : 0;
  const histAvgDeadhead = histDhCount > 0 ? histDeadheadSum / histDhCount : 15;
  const histAvgPay = histCount > 0 ? histPaySum / histCount : 0;

  // Weekly expense average
  const d30 = now - 30 * 86400000;
  let exp30 = 0;
  for (const e of allExps){
    if (e.date && new Date(e.date).getTime() >= d30) exp30 += Number(e.amount || 0);
  }
  const dailyFixedCost = exp30 / 30 || 0; // daily avg cost

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
      try{ await refreshFn(); }catch{}
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
  if (!state.isEmpty) await renderCommandCenter();
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
      }catch{}
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
  }catch{}
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
  // Compute load score for badge (uses cached KPI data)
  let scoreBadge = '';
  if (miles > 0 && _kpiCache.trips){
    try {
      const score = computeLoadScore(t, _kpiCache.trips, _kpiCache.exps || []);
      scoreBadge = scoreBadgeHTML(score);
      d._loadScore = score;
    } catch{}
  }
  d.innerHTML = `
    <div class="left">
      <div class="split"><div class="v">${escapeHtml(t.orderNo||'')}</div>${tag}${runTag}${scoreBadge}</div>
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
      try{ await cacheDeleteReceipt(f.id); }catch{}
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
    const empty = renderEmptyState('⛽', 'No fuel entries yet', 'Log each fill-up with state and gallons. Your IFTA summary builds automatically — no spreadsheets needed.', '＋ Add Fuel', ()=> openFuelForm());
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
  $('#uiMode').value = uiMode || 'simple';
  $('#perDiemRate').value = await getSetting('perDiemRate', '') || '';
  $('#brokerWindow').value = String(await getSetting('brokerWindow', 90) || 90);
  $('#weeklyGoal').value = await getSetting('weeklyGoal', '') || '';
  $('#iftaMode').value = await getSetting('iftaMode', 'on') || 'on';
  $('#vehicleMpg').value = await getSetting('vehicleMpg', '') || '';
  $('#fuelPrice').value = await getSetting('fuelPrice', '') || '';
  invalidateKPICache();
  await computeKPIs();
  await refreshStorageHealth('');
}

// ---- More menu ----
const MORE_TILES = [
  { icon:'💰', title:'Expenses', sub:'Track fuel, tolls, repairs', hash:'#expenses' },
  { icon:'⛽', title:'Fuel Log', sub:'Fill-ups and IFTA', hash:'#fuel' },
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
      el.innerHTML = `<div class="ti">${escapeHtml(tile.icon)}</div><div class="tt">${escapeHtml(tile.title)}</div><div class="ts">${escapeHtml(tile.sub)}</div>`;
      el.addEventListener('click', ()=>{
        haptic(15);
        if (tile.hash) location.hash = tile.hash;
        else if (tile.act === 'import') openUniversalImport();
        else if (tile.act === 'export') exportJSON();
      });
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
    <div style="font-size:48px;margin-bottom:12px">🚛</div>
    <h2 style="margin:0 0 8px 0;font-size:20px">Welcome to Freight Logic</h2>
    <p class="muted" style="font-size:14px;line-height:1.5;margin-bottom:20px;max-width:340px;margin-left:auto;margin-right:auto">Your personal trucking command center. Track loads, expenses, and fuel — see exactly where your money goes.</p>
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
  }catch(e){ $('#stStatus').textContent = 'Error: ' + (e?.message || e); }
}
async function analyzeReceiptBlobSizes(){
  const status = $('#stStatus'); status.textContent = 'Analyzing…';
  try{
    const all = await idbReq(tx('receiptBlobs').stores.receiptBlobs.getAll());
    let total = 0;
    for (const rec of (all||[])) total += (rec?.blob?.size || 0);
    status.textContent = `Receipt blobs: ${(all||[]).length} • Total ~${(total/1024/1024).toFixed(1)} MB`;
  }catch(e){ status.textContent = 'Failed: ' + (e?.message || e); }
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
  longHaulMinRPM: 1.45,
  surgeMinRPM: 1.70,
  tier1: ['chicago','indianapolis','cleveland','columbus','detroit'],
  tier2: ['nashville','louisville','st. louis','st louis','stl'],
  avoid: ['deep southeast','rural southeast','deep texas','far northeast'],
  rpmTiers: [
    { min: 0,    max: 1.39, label: 'Reject',        color: 'var(--bad)',  verdict: 'REJECT' },
    { min: 1.40, max: 1.49, label: 'Strategic Only', color: 'var(--warn)', verdict: 'STRATEGIC' },
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

function mwEvaluateLoad(){
  const origin = ($('#mwOrigin')?.value || '').trim();
  const dest = ($('#mwDest')?.value || '').trim();
  const loadedMi = Math.max(0, numVal('mwLoadedMi', 0));
  const deadMi = Math.max(0, numVal('mwDeadMi', 0));
  const revenue = Math.max(0, numVal('mwRevenue', 0));
  const dayOfWeek = $('#mwDayOfWeek')?.value || 'mon';
  const fatigue = Math.min(10, Math.max(0, numVal('mwFatigue', 0)));
  const weeklyGross = Math.max(0, numVal('mwWeeklyGross', 0));

  const out = $('#mwEvalOutput');
  if (!out) return;
  if (!loadedMi || !revenue){ out.innerHTML = '<div class="muted" style="font-size:13px">Enter loaded miles and revenue.</div>'; return; }

  // Save inputs
  setSetting('mwLastInputs', { origin, dest, loadedMi, deadMi, revenue, dayOfWeek, fatigue, weeklyGross }).catch(()=>{});

  const totalMi = loadedMi + deadMi;
  const trueRPM = roundCents(revenue / totalMi);
  const loadedRPM = roundCents(revenue / loadedMi);
  const fuel = mwFuelCost(totalMi);
  const netAfterFuel = roundCents(revenue - fuel);
  const tier = mwClassifyRPM(trueRPM);
  const geo = mwGeoCheck(origin, dest);

  const isMonWed = ['mon','tue','wed'].includes(dayOfWeek);
  const isThuFri = ['thu','fri'].includes(dayOfWeek);

  // Build decision steps
  const steps = [];
  let verdict = tier.verdict;
  let verdictReason = '';

  // STEP 1: Geography
  if (geo.intoDensity){
    steps.push({ pass: true, label: 'Geography', detail: `→ ${geo.destDensity} density (${escapeHtml(dest)})` });
  } else if (origin && dest){
    steps.push({ pass: false, label: 'Geography', detail: `Out of density — rate must be strong` });
    if (trueRPM < 1.60){ verdict = 'REJECT'; verdictReason = 'Out of density + RPM below Strong'; }
  } else {
    steps.push({ pass: null, label: 'Geography', detail: 'No origin/dest — skipping geo check' });
  }

  // STEP 2: True RPM
  const rpmPass = trueRPM >= MW.hardRejectRPM;
  steps.push({ pass: rpmPass, label: 'True RPM', detail: `$${trueRPM.toFixed(2)} — ${tier.label}` });
  if (trueRPM < MW.hardRejectRPM){ verdict = 'REJECT'; verdictReason = `Under $${MW.hardRejectRPM} hard floor`; }
  if (totalMi > 250 && trueRPM < MW.longHaulMinRPM){ verdict = 'REJECT'; verdictReason = `Long haul under $${MW.longHaulMinRPM}`; }

  // STEP 3: Fuel check
  const marginPct = revenue > 0 ? roundCents(((revenue - fuel) / revenue) * 100) : 0;
  const fuelPass = marginPct >= 30;
  steps.push({ pass: fuelPass, label: 'Fuel Check', detail: `$${fuel.toFixed(0)} fuel • $${netAfterFuel.toFixed(0)} net • ${marginPct.toFixed(0)}% margin` });
  if (!fuelPass && marginPct < 20){ verdict = 'REJECT'; verdictReason = 'Fuel margin below 20%'; }

  // STEP 4: Weekly position
  let weekNote = '';
  if (weeklyGross > 0){
    if (weeklyGross < MW.stabilizeFloor && isMonWed){
      weekNote = `Below $${MW.stabilizeFloor.toLocaleString()} by mid-week — STABILIZE`;
      if (verdict === 'ACCEPT' && trueRPM < 1.50){ verdict = 'STRATEGIC'; verdictReason = 'Below floor mid-week — take if positions into density'; }
      steps.push({ pass: false, label: 'Weekly Position', detail: weekNote });
    } else if (weeklyGross >= MW.surgeFloor && isMonWed){
      weekNote = `Above $${MW.surgeFloor.toLocaleString()} by mid-week — controlled push allowed`;
      steps.push({ pass: true, label: 'Weekly Position', detail: weekNote });
    } else {
      const pct = Math.min(100, Math.round((weeklyGross / MW.weekTarget.high) * 100));
      weekNote = `$${weeklyGross.toLocaleString()} / $${MW.weekTarget.high.toLocaleString()} target (${pct}%)`;
      steps.push({ pass: pct >= 50, label: 'Weekly Position', detail: weekNote });
    }
  } else {
    steps.push({ pass: null, label: 'Weekly Position', detail: 'No weekly gross entered' });
  }

  // STEP 5: Fatigue
  if (fatigue > 0){
    const fatigueOk = fatigue <= 6;
    steps.push({ pass: fatigueOk, label: 'Fatigue', detail: `Level ${fatigue}/10${fatigue >= 7 ? ' — DO NOT SIGN TIRED' : fatigue >= 5 ? ' — elevated, confirm rate carefully' : ''}` });
    if (fatigue >= 8){ verdict = 'REJECT'; verdictReason = 'Fatigue too high — rest first'; }
  } else {
    steps.push({ pass: null, label: 'Fatigue', detail: 'Not entered' });
  }

  // Strategic: check if repositioning into density
  if (verdict === 'STRATEGIC'){
    if (geo.intoDensity && trueRPM >= 1.40){
      verdictReason = verdictReason || 'Strategic — positions into density';
    } else if (!geo.intoDensity){
      verdict = 'REJECT'; verdictReason = verdictReason || 'Strategic RPM but out of density';
    }
  }

  // Reposition suggestion
  let repoSuggestion = '';
  if (verdict === 'REJECT' && !geo.intoDensity){
    repoSuggestion = 'Consider repositioning toward: Indianapolis, Chicago, Cleveland, or St. Louis corridor.';
  }

  // Render
  const verdictColors = { ACCEPT: 'var(--good)', REJECT: 'var(--bad)', STRATEGIC: 'var(--warn)' };
  const verdictIcons = { ACCEPT: '✓', REJECT: '✕', STRATEGIC: '◐' };
  const verdictLabels = { ACCEPT: 'ACCEPT', REJECT: 'PASS', STRATEGIC: 'STRATEGIC ONLY' };

  let html = `<div style="text-align:center;padding:12px 0 16px;border-bottom:1px solid var(--border);margin-bottom:14px">
    <div style="font-size:32px;font-weight:700;color:${verdictColors[verdict]};font-family:var(--font-mono);letter-spacing:-1px">${verdictIcons[verdict]} ${verdictLabels[verdict]}</div>
    ${verdictReason ? `<div style="font-size:12px;color:var(--text-secondary);margin-top:4px">${escapeHtml(verdictReason)}</div>` : ''}
  </div>`;

  // Numbers
  html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:10px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:20px;font-weight:500;color:${tier.color}">$${trueRPM.toFixed(2)}</div>
      <div style="font-size:11px;color:var(--text-tertiary)">True RPM</div>
    </div>
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:10px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:20px;font-weight:500">$${netAfterFuel.toFixed(0)}</div>
      <div style="font-size:11px;color:var(--text-tertiary)">Net After Fuel</div>
    </div>
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:10px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:16px;font-weight:500">${totalMi}</div>
      <div style="font-size:11px;color:var(--text-tertiary)">Total Miles</div>
    </div>
    <div style="background:var(--surface-0);border:1px solid var(--border-subtle);border-radius:var(--r-sm);padding:10px;text-align:center">
      <div style="font-family:var(--font-mono);font-size:16px;font-weight:500">$${fuel.toFixed(0)}</div>
      <div style="font-size:11px;color:var(--text-tertiary)">Fuel Cost</div>
    </div>
  </div>`;

  // Filter steps
  html += '<div style="font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-tertiary);font-weight:600;margin-bottom:8px">90-Second Filter</div>';
  steps.forEach(s => {
    const icon = s.pass === true ? '✓' : s.pass === false ? '✕' : '–';
    const c = s.pass === true ? 'var(--good)' : s.pass === false ? 'var(--bad)' : 'var(--text-tertiary)';
    html += `<div style="display:flex;gap:10px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
      <div style="color:${c};font-weight:700;font-size:14px;width:18px;flex-shrink:0">${icon}</div>
      <div><div style="font-weight:600;font-size:13px">${s.label}</div><div style="font-size:12px;color:var(--text-secondary)">${s.detail}</div></div>
    </div>`;
  });

  if (repoSuggestion){
    html += `<div style="margin-top:12px;padding:10px;border-radius:var(--r-sm);background:var(--warn-muted);border:1px solid var(--warn-border);font-size:12px;color:var(--warn)">${repoSuggestion}</div>`;
  }

  out.innerHTML = html;

  // Update week structure bar
  mwRenderWeekStructure(weeklyGross);
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
  } catch(err){ toast('Save failed: ' + (err.message||''), true); }
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
  $('#mwEvalReset')?.addEventListener('click', () => {
    ['mwOrigin','mwDest','mwLoadedMi','mwDeadMi','mwRevenue','mwFatigue','mwWeeklyGross'].forEach(id => { const el=$('#'+id); if(el) el.value=''; });
    $('#mwDayOfWeek').value='mon';
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
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      // T5-SECURITY: Version-pinned + crossOrigin. Add SRI hash before production:
      //   curl -sL https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js | openssl dgst -sha384 -binary | openssl base64 -A
      //   Then set: s.integrity = 'sha384-<paste_hash_here>';
      s.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js';
      s.crossOrigin = 'anonymous';
      s.onload = () => {
        // T5-FIX: Post-load validation — verify Tesseract global is legitimate
        if (typeof Tesseract === 'undefined' || typeof Tesseract.createWorker !== 'function'){
          reject(new Error('Tesseract loaded but createWorker missing — possible CDN tampering'));
          return;
        }
        resolve();
      };
      s.onerror = () => reject(new Error('Failed to load OCR engine. Check your connection.'));
      document.head.appendChild(s);
    });
  }
  _tesseractWorker = await Tesseract.createWorker('eng', 1, {
    workerPath: 'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/worker.min.js',
    corePath: 'https://cdn.jsdelivr.net/npm/tesseract.js-core@5.1.0/tesseract-core-simd-lstm.wasm.js',
  });
  _tesseractReady = true;
  return _tesseractWorker;
}

function parseLoadText(text){
  // T5-FIX: Cap OCR text length to prevent regex DoS on adversarial images
  const safeText = String(text || '').slice(0, 10000);
  const result = { orderNo:'', customer:'', origin:'', destination:'', pay:0, loadedMiles:0, pickupDate:'', deliveryDate:'', weight:0, notes:'' };
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

function openSnapLoad(preFile){
  const body = document.createElement('div');
  body.innerHTML = `<div class="card" style="border:0;box-shadow:none;background:transparent;padding:0">
    <div class="muted" style="font-size:12px;margin-bottom:10px">Take a photo or select a screenshot of a rate confirmation, load board posting, or dispatch sheet. OCR will extract the details.</div>
    <div class="btn-row" style="margin-bottom:12px">
      <button class="btn primary" id="snapCamera">📷 Camera</button>
      <button class="btn" id="snapFile">📁 Choose File</button>
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
      <div class="muted" style="font-size:11px;margin-bottom:12px">You can edit everything in the trip form. OCR isn't perfect — always verify.</div>
      <div class="btn-row">
        <button class="btn primary" id="snapAccept">✓ Open in Trip Form</button>
        <button class="btn" id="snapRetry">↻ Try Another</button>
      </div>
      <details style="margin-top:12px"><summary class="muted" style="font-size:11px;cursor:pointer">Raw OCR text</summary>
        <pre id="snapRawText" style="font-size:10px;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all;padding:8px;background:rgba(0,0,0,0.2);border-radius:4px;margin-top:6px"></pre>
      </details>
    </div>
  </div>`;

  let _parsedData = null;

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

      _parsedData = parseLoadText(text);
      _parsedData._confidence = confidence;

      status.style.display = 'none';
      $('#snapResults', body).style.display = 'block';

      // Build parsed results display
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
      // Build trip-like object and pass to wizard for pre-fill
      const prefill = {
        orderNo: _parsedData.orderNo || '',
        customer: _parsedData.customer || '',
        origin: _parsedData.origin || '',
        destination: _parsedData.destination || '',
        pay: _parsedData.pay || 0,
        loadedMiles: _parsedData.loadedMiles || 0,
        pickupDate: _parsedData.pickupDate || isoDate(),
        deliveryDate: _parsedData.deliveryDate || _parsedData.pickupDate || isoDate(),
        notes: _parsedData.weight ? `Weight: ${_parsedData.weight} lbs | Snap Load OCR` : 'Snap Load OCR',
        isPaid: false,
      };
      // Feed through sanitizeTrip for validation
      try { Object.assign(prefill, sanitizeTrip(prefill)); } catch {}
      // Flag for wizard to treat as add-mode with pre-filled data
      prefill._snapPrefill = true;
      openTripWizard(prefill);
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
    <div class="grid2"><div><label>Delivery date</label><input id="f_delivery" type="date" /></div>
      <div><label>Status</label><select id="f_paid"><option value="false">Unpaid</option><option value="true">Paid</option></select></div></div>
    <label>Notes</label><textarea id="f_notes" placeholder="Optional"></textarea>
    <div style="margin-top:10px"><label class="chk" style="font-size:14px"><input type="checkbox" id="f_runAgain" /> Would run this lane again</label><div class="muted" style="font-size:11px;margin-top:4px">Feeds your Lane Intelligence — helps identify your best corridors</div></div>
    <label style="margin-top:12px">Receipts (optional)</label><input id="f_receipts" type="file" accept="image/*,application/pdf" multiple />
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
    }
  }
  async function save(stepNo){
    if (!(await validateStep1())){ toast('Fix required fields', true); return; }
    await collectTrip(stepNo);
    const saved = await upsertTrip(trip);
    if (stepNo >= 2){
      const f = $('#f_receipts', body).files;
      if (f && f.length) await saveNewReceipts(saved.orderNo, f);
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
        for (const f of (rec?.files||[])) try{ await cacheDeleteReceipt(f.id); }catch{} }catch{}
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
    }catch(err){ toast(err.message || 'Failed', true); }
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
$('#fab').addEventListener('click', ()=>{
  // Dismiss onboarding pulse
  $('#fab').classList.remove('pulse');
  const hint = $('#fabHint');
  if (hint) hint.style.display = 'none';
  openQuickAddSheet();
});
$('#btnQuickTrip').addEventListener('click', ()=> openTripWizard());
$('#btnQuickExpense').addEventListener('click', ()=> openExpenseForm());
$('#btnAddExp2')?.addEventListener('click', ()=> openExpenseForm());
$('#btnQuickFuel').addEventListener('click', ()=> openFuelForm());

$('#btnTripMore').addEventListener('click', ()=> renderTrips(false));
$('#btnExpMore').addEventListener('click', ()=> renderExpenses(false));
$('#btnFuelMore').addEventListener('click', ()=> renderFuel(false));
$('#btnAddFuel2').addEventListener('click', ()=> openFuelForm());

$('#tripSearch').addEventListener('input', (e)=>{
  tripSearchTerm = e.target.value || '';
  clearTimeout(renderTrips._tm); renderTrips._tm = setTimeout(()=> renderTrips(true), 250);
});
$('#expSearch').addEventListener('input', (e)=>{
  expSearchTerm = e.target.value || '';
  clearTimeout(renderExpenses._tm); renderExpenses._tm = setTimeout(()=> renderExpenses(true), 250);
});

// P1-1: Trip filter with date range
$('#btnTripFilter').addEventListener('click', async ()=>{
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
$('#btnTripExport').addEventListener('click', exportJSON);
$('#btnExpExport').addEventListener('click', exportJSON);
$('#btnTripExportCSV').addEventListener('click', exportTripsCSV);
$('#btnExpExportCSV').addEventListener('click', exportExpensesCSV);
$('#btnFuelExportCSV').addEventListener('click', exportFuelCSV);
$('#btnFuelImport').addEventListener('click', async ()=>{
  const f = await pickFile(IMPORT_ACCEPT); if (!f) return;
  await importFile(f); invalidateKPICache(); await renderFuel(true); await renderHome();
});

function pickFile(accept){
  return new Promise((resolve)=>{
    const i = document.createElement('input'); i.type = 'file'; i.accept = accept || '*';
    i.onchange = ()=> resolve(i.files?.[0] || null);
    // Handle cancel: when focus returns and no file was picked, resolve null
    const onFocus = ()=>{ setTimeout(()=>{ if (!i.files?.length) resolve(null); window.removeEventListener('focus', onFocus); }, 500); };
    window.addEventListener('focus', onFocus);
    i.click();
  });
}
const IMPORT_ACCEPT = '.json,.csv,.tsv,.xlsx,.xls,.txt,.pdf';
$('#btnTripImport').addEventListener('click', async ()=>{
  const f = await pickFile(IMPORT_ACCEPT); if (!f) return;
  await importFile(f); invalidateKPICache(); await renderTrips(true); await renderHome();
});
$('#btnExpImport').addEventListener('click', async ()=>{
  const f = await pickFile(IMPORT_ACCEPT); if (!f) return;
  await importFile(f); invalidateKPICache(); await renderExpenses(true); await renderHome();
});

// Tax period tabs
$$('#taxPeriodTabs .btn').forEach(btn => {
  btn.addEventListener('click', async ()=>{
    $$('#taxPeriodTabs .btn').forEach(b => b.classList.remove('act'));
    btn.classList.add('act');
    _taxPeriod = btn.dataset.period || 'week';
    invalidateKPICache(); await computeKPIs();
  });
});

// Settings
$('#btnSaveSettings').addEventListener('click', async ()=>{
  await setSetting('uiMode', $('#uiMode').value);
  await setSetting('perDiemRate', Number($('#perDiemRate').value || 0));
  await setSetting('brokerWindow', Number($('#brokerWindow').value || 90));
  await setSetting('weeklyGoal', Number($('#weeklyGoal').value || 0));
  await setSetting('iftaMode', $('#iftaMode').value || 'on');
  await setSetting('vehicleMpg', Number($('#vehicleMpg').value || 0));
  await setSetting('fuelPrice', Number($('#fuelPrice').value || 0));
  toast('Saved settings'); invalidateKPICache(); await computeKPIs(); await refreshStorageHealth('');
});
$('#btnHardReset').addEventListener('click', async ()=>{
  if ((await getSetting('uiMode','simple')) !== 'pro'){ toast('Hard reset is Pro-only', true); return; }
  if (!confirm('Hard reset will delete all local data on this device. Continue?')) return;
  indexedDB.deleteDatabase(DB_NAME);
  toast('Database deleted. Reloading...'); setTimeout(()=> location.reload(), 1200);
});

// Storage health
$('#btnStorageRefresh').addEventListener('click', async ()=> await refreshStorageHealth(''));
$('#btnStorageAnalyze').addEventListener('click', async ()=> await analyzeReceiptBlobSizes());
$('#btnStorageRebuild').addEventListener('click', async ()=> await rebuildReceiptIndex());
$('#btnStorageClearCache').addEventListener('click', async ()=>{
  if (!confirm('Clear receipt cache? Thumbnails stay.')) return; await clearReceiptCache(); toast('Receipt cache cleared');
});
$('#btnWeeklyReport').addEventListener('click', ()=> { haptic(20); generateWeeklyReport(); });
$('#btnLoadCompare').addEventListener('click', ()=> { haptic(20); openLoadCompare(); });

// Accountant period tabs
let _acctPeriod = 'ytd';
$$('#acctPeriodTabs .btn').forEach(btn => {
  btn.addEventListener('click', ()=>{
    $$('#acctPeriodTabs .btn').forEach(b => b.classList.remove('act'));
    btn.classList.add('act');
    _acctPeriod = btn.dataset.acct;
    haptic(8);
  });
});
$('#btnAccountantExport').addEventListener('click', ()=> { haptic(20); generateAccountantPackage(_acctPeriod); });

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
        }catch{}
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

      // Helper: verdict badge
      function vBadge(v){
        const c = v==='PREMIUM WIN'||v==='ACCEPT' ? 'rgba(107,255,149,.15)' : v==='NEGOTIATE' ? 'rgba(255,179,0,.15)' : 'rgba(255,107,107,.15)';
        const tc = v==='PREMIUM WIN'||v==='ACCEPT' ? '#6bff95' : v==='NEGOTIATE' ? '#ffb300' : '#ff6b6b';
        return `<span class="tag" style="background:${c};color:${tc};font-weight:700">${v}</span>`;
      }

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
    const perDiemRate = Number(await getSetting('perDiemRate', 0) || 0) || 69; // IRS default
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
    const perDiemTotal = roundCents(perDiemGross * 0.80); // IRS Sec 274(n): 80% limit for DOT drivers

    // ── 5. SUMMARY (P&L) ──
    const netIncome = roundCents(grossRevenue - totalExpenses);
    const seRate = 0.153; // 15.3% self-employment
    const seTax = roundCents(Math.max(0, (netIncome - perDiemTotal) * seRate * 0.9235)); // 92.35% of net
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
      ['Per Diem Deductible (80% IRS Sec 274n)', '$' + perDiemTotal.toFixed(2)],
      [''],
      ['BOTTOM LINE'],
      ['Net Income (Revenue - Expenses)', '$' + netIncome.toFixed(2)],
      ['Per Diem Deduction (80%)', '-$' + perDiemTotal.toFixed(2)],
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
      sections.push('', '', '--- FUEL LOG ---', fuelCSV, '', '', '--- IFTA FUEL SUMMARY BY STATE ---', iftaCSV);
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
  }catch(err){ toast('Export failed: ' + (err.message || err), true); }
}

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
    setInterval(()=> computeQuickKPIs().catch(()=>{}), 60_000);

    // Onboarding: pulse FAB and show hint for new users
    const onb = await getOnboardState();
    if (onb.isEmpty){
      $('#fab').classList.add('pulse');
      const hint = $('#fabHint');
      if (hint) hint.style.display = '';
    }
  }catch(err){
    console.error(err);
    toast(err.message || 'Startup failed', true);
  }
})();
})();
