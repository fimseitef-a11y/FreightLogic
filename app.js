(function() {
'use strict';

// ── Emergency cache cleanup for v9.7.x → v9.9.x migration ──
// Old single-file version cached inline JS; new split-file version breaks under stale SW.
// Force-unregister any SW that doesn't match current version, then reload once.
(async () => {
  try {
    if (!navigator.serviceWorker) return;
    const regs = await navigator.serviceWorker.getRegistrations();
    for (const reg of regs) {
      if (reg.active) {
        const mc = new MessageChannel();
        const versionPromise = new Promise(r => { mc.port1.onmessage = e => r(e.data?.version || ''); setTimeout(() => r('__TIMEOUT__'), 1500); });
        reg.active.postMessage({ type: 'GET_VERSION' }, [mc.port2]);
        const ver = await versionPromise;
        // Stale if: timed out (old SW doesn't handle GET_VERSION), or version doesn't match
        const isStale = ver === '__TIMEOUT__' || !ver || !ver.includes('10.1.1');
        if (isStale) {
          console.warn('[App] Stale SW detected:', ver || '(no response)', '— forcing update');
          await reg.unregister();
          if (!sessionStorage.getItem('xos-cache-cleared')) {
            sessionStorage.setItem('xos-cache-cleared', '1');
            const keys = await caches.keys();
            await Promise.all(keys.map(k => caches.delete(k)));
            location.reload();
            return;
          }
        }
      }
    }
  } catch (e) { console.warn('[App] Cache cleanup skipped:', e); }
})();


// ============================================================================
// v9.5.2 SECURITY & PERFORMANCE MODULES
// ============================================================================

// ─── LAYER 1: SANITIZATION MODULE ─────────────────────────────────────────
// ALL text/number/CSV sanitizers consolidated here. No scattered helpers.
const Sanitize = {
  /** HTML entity escaping — single authoritative function */
  html(str) {
    return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  },

  /** Non-negative money: parse, strip $/, clamp ≥ 0 */
  money(v) {
    const n = parseFloat(String(v ?? '0').replace(/[$, ]/g, ''));
    return isFinite(n) ? Math.max(0, n) : 0;
  },

  /** Non-negative miles: parse, clamp ≥ 0, 2 decimal places */
  miles(v) {
    const n = parseFloat(String(v ?? '0'));
    return isFinite(n) ? Math.max(0, Math.round(n * 100) / 100) : 0;
  },

  /** Safe float parse — NaN → 0 */
  float(val) {
    const n = parseFloat(String(val ?? ''));
    return isNaN(n) ? 0 : n;
  },

  /** Normalize order number: trim + uppercase + collapse whitespace */
  orderNo(raw) {
    return String(raw ?? '').trim().replace(/\s+/g, ' ').toUpperCase().substring(0, 100);
  },

  /** CSV cell: neutralize formula injection + RFC 4180 quoting */
  csvCell(val) {
    let s = String(val ?? '');
    if (/^[=+\-@\t\r\n]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  },

  /** Import string: trim, truncate, strip formula chars */
  importStr(v, maxLen = 500) {
    let s = String(v ?? '').trim().substring(0, maxLen);
    s = s.replace(/^[=+\-@\t\r\n]+/, '');
    return s;
  },

  /** Sanitize a trip record from DB (read-path defense) */
  tripRecord(t) {
    if (!t || typeof t !== 'object') return null;
    const str  = (v, max = 500) => String(v ?? '').substring(0, max);
    const num  = v => { const n = parseFloat(v); return isFinite(n) && n >= 0 ? n : 0; };
    const bool = v => v === true || v === 1 || v === 'true' || v === 'Yes';
    const dateStr = v => { const s = str(v, 20); return s.match(/^\d{4}-\d{2}-\d{2}$/) ? s : ''; };
    return {
      orderNo:       str(t.orderNo, 100),
      pickupDate:    dateStr(t.pickupDate),
      deliveryDate:  dateStr(t.deliveryDate),
      revenue:       num(t.revenue),
      loadedMiles:   num(t.loadedMiles),
      emptyMiles:    num(t.emptyMiles),
      origin:        str(t.origin),
      dest:          str(t.dest),
      perDiemAmount: num(t.perDiemAmount),
      perDiemDays:   num(t.perDiemDays),
      customer:      str(t.customer),
      notes:         str(t.notes, 1000),
      paid:          bool(t.paid),
      paidDate:      typeof t.paidDate === 'number' ? t.paidDate : (t.paidDate ? String(t.paidDate) : null),
      created:       typeof t.created === 'number' ? t.created : Date.now(),
      isActive:      (t.isActive !== false),
      deletedAt:     t.deletedAt ? String(t.deletedAt).substring(0, 40) : null,
      deletedReason: t.deletedReason ? String(t.deletedReason).substring(0, 40) : null
    };
  }
};

// Backward-compat aliases (used widely — keeps diff small)
const escapeHTML       = Sanitize.html;
const clampMoney       = Sanitize.money;
const clampMiles       = Sanitize.miles;
const safeFloat        = Sanitize.float;
const normalizeOrderNo = Sanitize.orderNo;
const sanitizeCSVCell  = Sanitize.csvCell;
const cleanImportString = Sanitize.importStr;
const sanitizeTripRecord = Sanitize.tripRecord;

// ─── LAYER 3: RENDER HELPERS ──────────────────────────────────────────────
// Reusable DOM builders — no innerHTML with user data
const Render = {
  /** Create element with optional class, text, style */
  el(tag, opts = {}) {
    const e = document.createElement(tag);
    if (opts.cls)   e.className = opts.cls;
    if (opts.text)  e.textContent = opts.text;
    if (opts.style) e.style.cssText = opts.style;
    return e;
  },

  /** Build a standard empty-state placeholder */
  emptyState(icon, message) {
    const wrapper = this.el('div', { style: 'text-align:center;padding:60px 20px;color:var(--text-tertiary);' });
    wrapper.appendChild(this.el('div', { text: icon, style: 'font-size:48px;opacity:0.3;' }));
    wrapper.appendChild(this.el('div', { text: message }));
    return wrapper;
  },

  /** Build a small empty-state (for panels) */
  emptyPanel(message) {
    return this.el('div', { text: message, style: 'text-align:center;padding:24px;color:var(--text-tertiary);' });
  },

  /** Clear a container safely */
  clear(el) {
    if (el) el.textContent = '';
  }
};

// ─── UTILITY: null-safe DOM selector ──────────────────────────────────────
// Returns a proxy that silently no-ops if element is missing (prevents init crashes)
const $ = id => document.getElementById(id);
const $safe = id => {
  const el = document.getElementById(id);
  if (el) return el;
  // Return inert proxy so .addEventListener, .value, .checked etc. don't throw
  return new Proxy({}, {
    get(_, prop) {
      if (prop === 'addEventListener') return () => {};
      if (prop === 'removeEventListener') return () => {};
      if (prop === 'classList') return { add(){}, remove(){}, toggle(){}, contains(){ return false; } };
      if (prop === 'style') return new Proxy({}, { set(){ return true; }, get(){ return ''; } });
      if (prop === 'value') return '';
      if (prop === 'checked') return false;
      if (prop === 'textContent') return '';
      if (prop === 'disabled') return false;
      if (prop === 'click') return () => {};
      return undefined;
    },
    set() { return true; }
  });
};

// Strict DOM getter for required elements (Blacksite hard-fail instead of silent no-op)
const $req = (id) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`[UI] Missing required element: #${id}`);
  return el;
};

// Startup self-test to prevent "dead UI" scenarios on iOS when IDs drift
function assertCriticalUI() {
  const requiredIds = [
    // Core screens / containers
    'tabs', 'main',
    // Common forms (must exist for basic function)
    'orderNo', 'pickupDate', 'deliveryDate',
  ];
  for (const id of requiredIds) $req(id);

  // Ensure nav tabs exist
  const navTabs = document.querySelectorAll('.nav-tab[data-tab]');
  if (!navTabs || navTabs.length < 3) {
    throw new Error('[UI] Navigation tabs not found or incomplete (.nav-tab[data-tab])');
  }

  // Ensure switchTab target panels exist for each nav
  navTabs.forEach(btn => {
    const tabId = btn.getAttribute('data-tab');
    if (!tabId) return;
    const panel = document.getElementById(tabId);
    if (!panel) throw new Error(`[UI] Missing tab panel for data-tab="${tabId}"`);
  });
}

// ─── UTILITY: Debounce (for search/filter throttling) ─────────────────────
function debounce(fn, ms = 150) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

function escapeHtml(str){return String(str??'').replace(/[&<>"']/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));}

const formatMoney = val => {
  const n = Number(val);
  const safe = Number.isFinite(n) ? n : 0;
  return '$' + safe.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
};
const getTodayStr = () => {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
};

// ─── ENCRYPTION MODULE (for PIN-protected data) ────────────────────────────
const CryptoModule = {

  init() {
    if (!window.crypto || !window.crypto.subtle) {
      console.warn('[Crypto] Web Crypto API not available');
      this.key = null;
      return false;
    }
    return true;
  },

  key: null,
  
  async deriveKey(pin) {
    if (!this.init()) return null;
    const enc = new TextEncoder();
    // Use per-device salt instead of static string (prevents rainbow table attacks)
    let saltHex = localStorage.getItem('cryptoSalt');
    if (!saltHex) {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      localStorage.setItem('cryptoSalt', saltHex);
    }
    const saltBytes = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(pin), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']
    );
    this.key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    return this.key;
  },
  
  async encrypt(plaintext) {
    if (!this.key) return plaintext;
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, enc.encode(String(plaintext)));
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return btoa(String.fromCharCode(...combined));
  },
  
  async decrypt(ciphertext) {
    if (!this.key || typeof ciphertext !== 'string') return ciphertext;
    try {
      const combined = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const data = combined.slice(12);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, data);
      return new TextDecoder().decode(plaintext);
    } catch (e) {
      return ciphertext;
    }
  }
};

// ─── PIN LOCK MODULE (SEC-01) ──────────────────────────────────────────────
const PINModule = {
  _initialized: false,
  _resolve: null,
  _failCount: 0,
  _lockoutUntil: 0,

  async init() {
    if (this._initialized) return;
    const pinScreen = $('pinScreen');
    const pinInput = $('pinInput');
    const pinError = $('pinError');
    if (!pinScreen || !pinInput) { this._initialized = true; return; }

    // Restore lockout state
    const lockStr = localStorage.getItem('pinLockout');
    if (lockStr) {
      const lockData = JSON.parse(lockStr);
      this._failCount = lockData.fails || 0;
      this._lockoutUntil = lockData.until || 0;
    }

    const hashPIN = async (pin) => {
      // Prefer slow KDF (PBKDF2) to reduce brute-force risk on copied local storage.
      if (!window.crypto || !crypto.subtle) return null;

      const enc = new TextEncoder();
      const pinStr = String(pin);

      // New (v10.1.1+) KDF metadata
      const kdfSaltHex = localStorage.getItem('pinKdfSalt');
      const kdfIterStr = localStorage.getItem('pinKdfIter');
      let iter = parseInt(kdfIterStr || '150000', 10);
      if (!isFinite(iter)) iter = 150000;
      iter = Math.max(100000, Math.min(300000, iter));

      const derive = async (saltHex) => {
        const saltBytes = new Uint8Array((saltHex.match(/.{1,2}/g) || []).map(h => parseInt(h, 16)));
        const keyMat = await crypto.subtle.importKey('raw', enc.encode(pinStr), { name: 'PBKDF2' }, false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits(
          { name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' },
          keyMat,
          256
        );
        return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
      };

      if (kdfSaltHex) {
        return derive(kdfSaltHex);
      }

      // Back-compat: v9.8.0+ salted fast-hash path
      const salt = localStorage.getItem('pinSalt');
      if (salt) {
        const buf = await crypto.subtle.digest('SHA-256', enc.encode(salt + ':' + pinStr));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
      }

      // Legacy unsalted fast-hash path (pre-v9.8.0)
      const buf = await crypto.subtle.digest('SHA-256', enc.encode(pinStr));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const calibratePinKdfIter = async (pinStr) => {
      // Calibrate PBKDF2 iterations to target ~250ms on this device (iOS performance varies).
      // Stored once; protects against "too slow" unlocks on older devices while keeping strong KDF.
      if (!window.crypto || !crypto.subtle) return 150000;
      if (localStorage.getItem('pinKdfIter')) {
        const v = parseInt(localStorage.getItem('pinKdfIter') || '150000', 10);
        return Math.max(100000, Math.min(300000, isFinite(v) ? v : 150000));
      }
      try {
        const enc = new TextEncoder();
        const saltBytes = crypto.getRandomValues(new Uint8Array(16));
        const keyMat = await crypto.subtle.importKey('raw', enc.encode(String(pinStr||'0000')), { name: 'PBKDF2' }, false, ['deriveBits']);
        const t0 = performance.now();
        await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: 50000, hash: 'SHA-256' }, keyMat, 256);
        const dt = Math.max(1, performance.now() - t0);
        // Linear extrapolation; cap range
        const targetMs = 250;
        const est = Math.round((targetMs / dt) * 50000);
        const iter = Math.max(100000, Math.min(300000, est));
        localStorage.setItem('pinKdfIter', String(iter));
        return iter;
      } catch (e) {
        localStorage.setItem('pinKdfIter', '150000');
        return 150000;
      }
    };

    // After successful verification, migrate legacy hash to PBKDF2 KDF
    const migratePINHash = async (pin) => {
      if (!window.crypto || !crypto.subtle) return;
      if (localStorage.getItem('pinKdfSalt')) return; // already migrated to KDF

      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      const iter = await calibratePinKdfIter(String(pin));

      localStorage.setItem('pinKdfSalt', saltHex);
      localStorage.setItem('pinKdfIter', String(iter));

      // Compute PBKDF2 hash
      const enc = new TextEncoder();
      const keyMat = await crypto.subtle.importKey('raw', enc.encode(String(pin)), { name: 'PBKDF2' }, false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' },
        keyMat,
        256
      );
      const newHash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
      localStorage.setItem('pinHash', newHash);

      // Keep old salt for one version for rollback compatibility, but future logic will prefer KDF.
      if (!localStorage.getItem('pinSalt')) {
        localStorage.setItem('pinSalt', saltHex);
      }
    };

    const verify = async () => {
      // Brute-force lockout check
      if (Date.now() < this._lockoutUntil) {
        const secsLeft = Math.ceil((this._lockoutUntil - Date.now()) / 1000);
        if (pinError) pinError.textContent = `🔒 Locked out. Try again in ${secsLeft}s`;
        pinInput.value = '';
        return;
      }

      const stored = localStorage.getItem('pinHash');
      const entered = String(pinInput.value || '');
      if (!stored) {
        // No PIN stored; fail open (but disable pinEnabled)
        localStorage.setItem('pinEnabled', 'false');
        pinScreen.classList.add('hidden');
        if (this._resolve) { const r=this._resolve; this._resolve=null; r(true); }
        return;
      }
      if (entered.length < 4) return;

      const hashHex = await hashPIN(entered);
      if (!hashHex) {
        // Crypto unavailable: do NOT silently bypass security. Offer explicit disable.
        const ok = confirm('Security module unavailable in this browser. Disable PIN lock to continue?');
        if (ok) {
          localStorage.setItem('pinEnabled', 'false');
          pinScreen.classList.add('hidden');
          showToast('⚠️ PIN disabled (crypto unavailable)', true);
          if (this._resolve) { const r=this._resolve; this._resolve=null; r(true); }
        } else {
          if (pinError) pinError.textContent = 'PIN cannot be verified here. Use Safari/modern browser.';
        }
        return;
      }

      if (hashHex === stored) {
        // Reset fail counter on success
        this._failCount = 0;
        this._lockoutUntil = 0;
        localStorage.removeItem('pinLockout');
        // Migrate unsalted hash → salted on first successful v9.8.0 login
        try { await migratePINHash(entered); } catch (_) {}
        pinScreen.classList.add('hidden');
        try { await CryptoModule.deriveKey(entered); } catch (_) {}
        if (this._resolve) { const r=this._resolve; this._resolve=null; r(true); }
      } else {
        this._failCount++;
        // Progressive lockout: 5 fails = 30s, 10 fails = 120s, 15+ = 300s
        let lockDuration = 0;
        if (this._failCount >= 15) lockDuration = 300000;
        else if (this._failCount >= 10) lockDuration = 120000;
        else if (this._failCount >= 5) lockDuration = 30000;

        if (lockDuration > 0) {
          this._lockoutUntil = Date.now() + lockDuration;
          localStorage.setItem('pinLockout', JSON.stringify({ fails: this._failCount, until: this._lockoutUntil }));
          const secs = Math.round(lockDuration / 1000);
          if (pinError) pinError.textContent = `🔒 Too many attempts. Locked for ${secs}s`;
        } else {
          const remaining = 5 - this._failCount;
          if (pinError) pinError.textContent = `❌ Incorrect PIN (${remaining} attempts left)`;
        }
        localStorage.setItem('pinLockout', JSON.stringify({ fails: this._failCount, until: this._lockoutUntil }));
        pinInput.value = '';
        setTimeout(() => { if (pinError && !this._lockoutUntil) pinError.textContent = ''; }, 3000);
      }
    };

    pinInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') verify(); });

    document.querySelectorAll('.pin-key').forEach(key => {
      key.addEventListener('click', () => {
        const k = key.dataset.key;
        if (k === 'clear') {
          pinInput.value = pinInput.value.slice(0, -1);
        } else if (k === 'enter') {
          verify();
        } else {
          if (pinInput.value.length < 6) {
            pinInput.value += k;
            if (pinInput.value.length >= 4) verify();
          }
        }
      });
    });

    this._initialized = true;
  },

  async checkPIN() {
    const pinEnabled = localStorage.getItem('pinEnabled');
    if (pinEnabled !== 'true') return true;

    await this.init();

    const pinScreen = $('pinScreen');
    const pinInput = $('pinInput');
    if (!pinScreen || !pinInput) return true;

    pinInput.value = '';
    const pinError = $('pinError');
    if (pinError) pinError.textContent = '';

    pinScreen.classList.remove('hidden');

    return new Promise((resolve) => { this._resolve = resolve; });
  },

  async setPIN(pin) {
    if (!pin || pin.length < 4) throw new Error('PIN must be at least 4 digits');
    if (!window.crypto || !crypto.subtle) throw new Error('Web Crypto API not available');
    // Ensure per-device salt exists
    let salt = localStorage.getItem('pinSalt');
    if (!salt) {
      salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
      localStorage.setItem('pinSalt', salt);
    }
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + ':' + pin));
    const hashHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem('pinHash', hashHex);
    localStorage.setItem('pinEnabled', 'true');
    await CryptoModule.deriveKey(pin);
  },
  
  disable() {
    localStorage.removeItem('pinHash');
    localStorage.setItem('pinEnabled', 'false');
    CryptoModule.key = null;
  }
};

// ─── AUDIT TRAIL MODULE (BLIND-01) ─────────────────────────────────────────
const AuditModule = {
  deviceId: null,
  
  async init() {
    this.deviceId = localStorage.getItem('deviceId');
    if (!this.deviceId) {
      this.deviceId = 'device-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
      localStorage.setItem('deviceId', this.deviceId);
    }
  },
  
  async log(action, entityType, entityId, changes) {
    const entry = {
      id: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      action,
      entityType,
      entityId,
      changes,
      deviceId: this.deviceId
    };
    
    try {
      await dbOp('auditLog', 'readwrite', s => s.add(entry));
    } catch (e) {
      console.error('[Audit] Failed to log:', e);
    }
  },
  
  async getHistory(entityType, entityId, limit = 50) {
    try {
      const all = await dbOp('auditLog', 'readonly', s => s.getAll());
      return all
        .filter(e => (!entityType || e.entityType === entityType) && (!entityId || e.entityId === entityId))
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, limit);
    } catch (e) {
      return [];
    }
  },
  
  formatEntry(entry) {
    const date = new Date(entry.timestamp).toLocaleString();
    const changes = Object.entries(entry.changes || {})
      .map(([field, change]) => `${field}: ${JSON.stringify(change.old)} → ${JSON.stringify(change.new)}`)
      .join(', ');
    return `[${date}] ${entry.action} ${entry.entityType} ${entry.entityId}: ${changes}`;
  }
};

// ─── PERFORMANCE: MEMOIZATION CACHE (CRIT-01) ─────────────────────────────
const MemoCache = {
  cache: new Map(),
  
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }
    return entry.value;
  },
  
  set(key, value, ttl = 300000) {
    this.cache.set(key, { value, timestamp: Date.now(), ttl });
  },
  
  invalidate(prefix) {
    for (const key of this.cache.keys()) {
      if (!prefix || key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }
};

// ─── GPS BATCHING (CRIT-04) ───────────────────────────────────────────────
const GPS_BATCH_SIZE = 100;
const GPS_BATCH_INTERVAL = 900000; // 15 min
let gpsLastBatchTime = 0;

async function saveGPSLogBatched(forceFlush = false) {
  if (!gpsTrackingData || !gpsTrackingData.logBuffer.length) return;
  
  const now = Date.now();
  const shouldFlush = forceFlush ||
                      gpsTrackingData.logBuffer.length >= GPS_BATCH_SIZE || 
                      (now - gpsLastBatchTime) >= GPS_BATCH_INTERVAL;
  
  if (shouldFlush) {
    try {
      await dbOp('gpsLogs', 'readwrite', s => s.add({
        orderNo: gpsTrackingData.orderNo,
        positions: gpsTrackingData.logBuffer.slice(),
        totalDistanceSoFar: gpsTrackingData.totalDistance,
        timestamp: now
      }));
      gpsTrackingData.logBuffer = [];
      gpsLastBatchTime = now;
    } catch (e) {
      console.error('[GPS] Batch save error:', e);
    }
  }
}

// ─── SERVICE WORKER UPDATE DETECTION (CRIT-05) ────────────────────────────
const UpdateModule = {
  init() {
    if (!navigator.serviceWorker) return;
    
    navigator.serviceWorker.addEventListener('message', event => {
      if (event.data?.type === 'SW_UPDATED') {
        this.showUpdateBanner();
      }
    });
    
    navigator.serviceWorker.ready.then(registration => {
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing;
        newWorker?.addEventListener('statechange', () => {
          if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
            this.showUpdateBanner();
          }
        });
      });
      
      setInterval(() => registration.update(), 3600000); // Check hourly
    });
  },
  
  showUpdateBanner() {
    const banner = $('updateBanner');
    if (!banner) return;
    banner.classList.add('visible');
    
    $('btnUpdateNow')?.addEventListener('click', () => {
      navigator.serviceWorker.getRegistration().then(reg => {
        reg?.waiting?.postMessage({ type: 'SKIP_WAITING' });
        setTimeout(() => location.reload(), 500);
      });
    });
  }
};



// ============================================================================
// PWA / SERVICE WORKER
// ============================================================================
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    // FIXED: register as generic name — rename file to service-worker.js at deploy
    navigator.serviceWorker.register('service-worker.js', { scope: './' })
      .then(reg => {
        console.log('[PWA] SW registered:', reg.scope);
        setInterval(() => reg.update(), 3600000);
      })
      .catch(err => console.warn('[PWA] SW registration failed:', err));
  });
}

let deferredPrompt;
const installPromptEl = document.getElementById('installPrompt');

window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  deferredPrompt = e;
  const dismissed = localStorage.getItem('installPromptDismissed');
  if (!dismissed || (Date.now() - parseInt(dismissed)) > 7 * 24 * 60 * 60 * 1000) {
    setTimeout(() => {
      if (!window.matchMedia('(display-mode: standalone)').matches) {
        installPromptEl && installPromptEl.classList.add('visible');
      }
    }, 10000);
  }
});

$safe('installBtn').addEventListener('click', async () => {
  if (!deferredPrompt) return;
  deferredPrompt.prompt();
  const { outcome } = await deferredPrompt.userChoice;
  if (outcome === 'accepted') console.log('[PWA] Installed');
  deferredPrompt = null;
  installPromptEl && installPromptEl.classList.remove('visible');
});

$safe('installClose').addEventListener('click', () => {
  installPromptEl && installPromptEl.classList.remove('visible');
  localStorage.setItem('installPromptDismissed', Date.now());
});

window.addEventListener('appinstalled', () => {
  installPromptEl && installPromptEl.classList.remove('visible');
  deferredPrompt = null;
});

if (window.matchMedia('(display-mode: standalone)').matches) {
  if (installPromptEl) installPromptEl.style.display = 'none';
}

// ============================================================================
// APP CONSTANTS & STATE
// ============================================================================
const DB_NAME    = 'XpediteOps_v1';
const DB_VERSION = 5;
const APP_VERSION = '10.2.1';
const PAGE_SIZE  = 50; // trips per page

let db;
let gpsWatchId         = null;
let gpsTrackingData    = null;

function getGPSOptions(timeout = 10000) {
  return {
    enableHighAccuracy: gpsHighAccuracy,
    timeout,
    maximumAge: gpsHighAccuracy ? 0 : 30000
  };
}
let currentExpenseType = 'fuel';
let deductionMethod    = 'standard';
let wakeLock           = null;
let pendingDelete      = null;
let lastSoftDeleted    = null; // {store,key,at,reason}
let gpsEnabled         = false;
let gpsHighAccuracy    = true;
let baselineMPGValue    = 18;
let mpgAlertPctValue    = 20;
let bulkMode           = false;
let selectedTrips      = new Set();
let currentFilters     = { customer: '', status: '', dateRange: '', search: '' };
let tempTripReceipts = []; let tempExpenseReceipts = []; let tempMealReceipts = []; let receiptsViewerContext = null;
let currentPage        = 1;
let irsMileageRate     = 0.70;
let perDiemRate        = 69;
let actualCPM          = 0.50; // Updated dynamically by refreshCommandCenter

// GPS safety limits (fix for phantom miles)
const GPS_MAX_SEGMENT_MI = 2.0;
const GPS_MAX_SPEED_MPH  = 120;
const GPS_MIN_ACCURACY_M = 50;
const GPS_STALE_MS       = 45000;

// Receipt limits
const RECEIPT_MAX_BYTES = 400 * 1024;
const RECEIPT_MAX_PX    = 1200;
const RECEIPT_RAW_MAX   = 10 * 1024 * 1024;

const STATE_TAX_RATES = {
  'AL':5.0,'AK':0,'AZ':4.5,'AR':5.5,'CA':9.3,'CO':4.4,'CT':5.5,'DE':6.6,'FL':0,'GA':5.75,
  'HI':8.25,'ID':5.8,'IL':4.95,'IN':3.23,'IA':6.0,'KS':5.7,'KY':4.5,'LA':4.25,'ME':7.15,
  'MD':5.75,'MA':5.0,'MI':4.25,'MN':6.8,'MS':5.0,'MO':4.95,'MT':6.5,'NE':6.84,'NV':0,
  'NH':0,'NJ':6.37,'NM':4.9,'NY':6.5,'NC':4.75,'ND':2.9,'OH':3.5,'OK':4.75,'OR':9.0,
  'PA':3.07,'RI':5.99,'SC':6.5,'SD':0,'TN':0,'TX':0,'UT':4.85,'VT':6.75,'VA':5.75,
  'WA':0,'WV':6.5,'WI':6.27,'WY':0
};

// ============================================================================
// INDEXEDDB
// ============================================================================
function initDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onblocked = () => {
      showToast('Close other Freight Logic tabs to continue upgrading', true);
      // Force reload after 3s if still blocked — don't leave in limbo
      setTimeout(() => location.reload(), 3000);
    };

    req.onupgradeneeded = e => {
      const d = e.target.result;
      const oldVersion = e.oldVersion;

      // Version-gated migrations
      if (oldVersion < 1) {
        const tripStore = d.createObjectStore('trips', { keyPath: 'orderNo' });
        tripStore.createIndex('pickupDate', 'pickupDate', { unique: false });
        tripStore.createIndex('created', 'created', { unique: false });
        tripStore.createIndex('customer', 'customer', { unique: false });

        ['fuel', 'expenses', 'gpsLogs'].forEach(name => {
          d.createObjectStore(name, { keyPath: 'id', autoIncrement: true });
        });
        d.createObjectStore('settings', { keyPath: 'key' });
      }


      if (oldVersion < 2) {
        if (!d.objectStoreNames.contains('receipts')) {
          d.createObjectStore('receipts', { keyPath: 'tripOrderNo' });
        }
      }

      if (oldVersion < 3) {
        if (!d.objectStoreNames.contains('auditLog')) {
          const auditStore = d.createObjectStore('auditLog', { keyPath: 'id' });
          auditStore.createIndex('timestamp', 'timestamp', { unique: false });
          auditStore.createIndex('entityId', 'entityId', { unique: false });
        }
      }
      // v4: receiptsV2 supports multiple receipts per trip and per expense
      if (oldVersion < 4) {
        if (!d.objectStoreNames.contains('receiptsV2')) {
          const r = d.createObjectStore('receiptsV2', { keyPath: 'receiptId', autoIncrement: true });
          r.createIndex('byTripOrderNo', 'tripOrderNo', { unique: false });
          r.createIndex('byExpenseId', 'expenseId', { unique: false });
          r.createIndex('byTimestamp', 'timestamp', { unique: false });
        }
      }
      // v5: receipt dedupe hash index
      if (oldVersion < 5) {
        const r = e.target.transaction.objectStore('receiptsV2');
        if (r && !Array.from(r.indexNames).includes('byHash')) {
          r.createIndex('byHash', 'receiptHash', { unique: true });
        }
      }

    };

    req.onsuccess = e => {
      db = e.target.result;
      window.__XPEDITE_OS_DB_READY__ = true;
      db.onversionchange = () => {
        db.close();
        showToast('Database updated — reloading...', true);
        setTimeout(() => location.reload(), 1500);
      };
      resolve();
    };

    req.onerror = e => {
      console.error('[DB] Open error:', e);
      reject(e.target.error);
    };
  });
}

// HARDENED: dbOp now attaches tx.onerror + tx.onabort to catch silent failures
const dbOp = (store, mode, fn) => new Promise((res, rej) => {
  try {
    const tx = db.transaction(store, mode);
    tx.onerror  = () => rej(tx.error);
    tx.onabort  = () => rej(new Error('Transaction aborted'));
    const s = tx.objectStore(store);
    const r = fn(s);
    r.onsuccess = () => res(r.result);
    r.onerror   = () => rej(r.error);
  } catch (e) { rej(e); }

});

// ─────────────────────────────────────────────────────────────────────────────
// SOFT DELETE (Safety)
// Records are never physically deleted by default. We mark isActive=false and
// set deletedAt. Old records without isActive are treated as active.
// ─────────────────────────────────────────────────────────────────────────────
const isActiveRecord = (r) => (r && r.isActive !== false);

async function softDeleteRecord(store, key, { reason = 'user' } = {}) {
  const now = new Date().toISOString();
  // Receipts use autoIncrement keys; trips use orderNo.
  const rec = await dbOp(store, 'readonly', s => s.get(key));
  if (!rec) return false;
  // Already inactive? idempotent
  if (rec.isActive === false) return true;

  rec.isActive = false;
  rec.deletedAt = now;
  rec.deletedReason = String(reason || 'user').substring(0, 40);
  // Preserve a timestamp for conflict sanity in the future
  if (!rec.updated) rec.updated = Date.now();
  rec.updated = Date.now();

  await dbOp(store, 'readwrite', s => s.put(rec));
  return true;
}

async function restoreSoftDeleted(store, key) {
  const rec = await dbOp(store, 'readonly', s => s.get(key));
  if (!rec) return false;
  rec.isActive = true;
  rec.deletedAt = null;
  rec.deletedReason = null;
  rec.updated = Date.now();
  await dbOp(store, 'readwrite', s => s.put(rec));
  return true;
}

async function restoreLastDeleted() {
  if (!lastSoftDeleted) { showToast('Nothing to restore'); return; }
  // Only allow restore within 10 minutes to avoid surprise resurrects
  if (Date.now() - lastSoftDeleted.at > 10 * 60 * 1000) {
    lastSoftDeleted = null;
    showToast('Restore window expired');
    return;
  }
  try {
    const ok = await restoreSoftDeleted(lastSoftDeleted.store, lastSoftDeleted.key);
    if (ok) {
      // Cascade restore attached receipts for parent records
      if (lastSoftDeleted.store === 'expenses' && ReceiptModule?.cascadeRestoreExpense) {
        try { await ReceiptModule.cascadeRestoreExpense(lastSoftDeleted.key); } catch {}
      }
      if (lastSoftDeleted.store === 'trips' && ReceiptModule?.cascadeRestoreTrip) {
        try { await ReceiptModule.cascadeRestoreTrip(lastSoftDeleted.key); } catch {}
      }
      showToast('✅ Restored last removed record');
    } else {
      showToast('Restore failed', true);
    }
  } catch (e) {
    showToast('Restore failed', true);
  }
  lastSoftDeleted = null;
  await checkStorageQuota();
  refreshUI();
}


// Settings KV helpers (stored in IndexedDB settings store; included in backups)
async function getSettingKV(key, fallback=null) {
  try { const row = await dbOp('settings','readonly', s => s.get(key)); return row ? row.value : fallback; } catch { return fallback; }
}
async function setSettingKV(key, value) {
  try { await dbOp('settings','readwrite', s => s.put({ key, value })); } catch {}
}

// Stable per-device id (used for backup filenames & metadata)
function getDeviceId() {
  let id = localStorage.getItem('xpedite_device_id');
  if (!id) {
    id = (crypto.randomUUID ? crypto.randomUUID() : ('dev_' + Math.random().toString(16).slice(2) + Date.now().toString(16)));
    localStorage.setItem('xpedite_device_id', id);
  }
  return id;
}

// ============================================================================
// STORAGE QUOTA MONITOR
// ============================================================================
async function checkStorageQuota() {
  if (!navigator.storage || !navigator.storage.estimate) return;
  try {
    const { usage, quota } = await navigator.storage.estimate();
    const pct = quota > 0 ? Math.round((usage / quota) * 100) : 0;
    const usedMB = (usage / 1024 / 1024).toFixed(1);
    const quotaMB = (quota / 1024 / 1024).toFixed(0);

    const bar = $('quotaBar');
    const fill = $('quotaFill');
    const label = $('quotaLabel');
    const pctEl = $('quotaPct');

    label.textContent = `Storage: ${usedMB}MB / ${quotaMB}MB`;
    fill.style.width = Math.min(pct, 100) + '%';
    pctEl.textContent = pct + '%';

    bar.classList.remove('warn', 'critical');
    if (pct >= 90) {
      bar.classList.add('visible', 'critical');
      fill.style.background = 'var(--accent-danger)';
    } else if (pct >= 70) {
      bar.classList.add('visible', 'warn');
      fill.style.background = 'var(--accent-warning)';
    } else if (pct >= 50) {
      bar.classList.add('visible');
      fill.style.background = 'var(--accent-success)';
    } else {
      bar.classList.remove('visible');
    }

    // Also update settings panel
    const ss = $('storageStatus');
    if (ss) {
      ss.textContent = '';
      const usageLine = document.createElement('div');
      usageLine.textContent = `Storage Used: ${usedMB}MB of ${quotaMB}MB (${pct}%)`;
      const statusLine = document.createElement('div');
      statusLine.style.color = pct >= 90 ? 'var(--accent-danger)' : pct >= 70 ? 'var(--accent-warning)' : 'var(--accent-success)';
      statusLine.textContent = pct >= 90 ? '⚠️ Critical — delete receipts or old data' : pct >= 70 ? '⚠️ Getting full' : '✅ OK';
      ss.appendChild(usageLine);
      ss.appendChild(statusLine);
    }
  } catch (e) {
    console.warn('[Quota] Could not estimate storage:', e);
  }
}

// ============================================================================
// CSV EXPORT SANITIZATION — handled by Sanitize.csvCell
// ============================================================================

// ============================================================================
// INTEGRATIONS (Deep Links) — safe encoding + fallbacks
// ============================================================================
function buildGoogleMapsURL(origin, dest) {
  const o = encodeURIComponent(origin);
  const d = encodeURIComponent(dest);
  return `https://www.google.com/maps/dir/?api=1&origin=${o}&destination=${d}`;
}

function openGoogleMaps() {
  const origin = $('origin').value.trim();
  const dest = $('dest').value.trim();
  if (!origin || !dest) return showToast('Enter origin and destination first', true);
  window.open(buildGoogleMapsURL(origin, dest), '_blank');
}

function openCoPilot() {
  const origin = $('origin').value.trim();
  const dest = $('dest').value.trim();
  if (!origin || !dest) return showToast('Enter origin and destination first', true);
  const d = encodeURIComponent(dest);
  const scheme = `copilot://navigate?destination=${d}`;
  const fallback = buildGoogleMapsURL(origin, dest);
  const t = setTimeout(() => window.open(fallback, '_blank'), 900);
  try { window.location.href = scheme; } catch (e) { clearTimeout(t); window.open(fallback, '_blank'); }
}

function openTruckerPath() {
  const origin = $('origin').value.trim();
  const dest = $('dest').value.trim();
  if (!origin || !dest) return showToast('Enter origin and destination first', true);
  const q = encodeURIComponent(`truck stop near ${dest}`);
  const scheme = `truckerpath://search?query=${q}`;
  const fallback = `https://www.google.com/maps/search/?api=1&query=${q}`;
  const t = setTimeout(() => window.open(fallback, '_blank'), 900);
  try { window.location.href = scheme; } catch (e) { clearTimeout(t); window.open(fallback, '_blank'); }
}

// ============================================================================
// ONBOARDING
// ============================================================================
function initOnboarding() {
  const flag = localStorage.getItem('xp_onboarded');
  if (flag === 'true') return;

  const welcome = $('welcomeModal');
  const setup = $('setupModal');
  if (!welcome || !setup) return;

  welcome.classList.add('active');

  const closeAll = () => { welcome.classList.remove('active'); setup.classList.remove('active'); };

  $safe('closeWelcomeModal').addEventListener('click', () => { localStorage.setItem('xp_onboarded', 'true'); closeAll(); });
  $safe('btnWelcomeContinue').addEventListener('click', () => {
    welcome.classList.remove('active');
    localStorage.setItem('xp_onboarded', 'true');
    setTimeout(() => { openSettings(); setup.classList.add('active'); }, 120);
  });

  $safe('closeSetupModal').addEventListener('click', () => setup.classList.remove('active'));
  $safe('btnSetupGoSettings').addEventListener('click', () => { setup.classList.remove('active'); openSettings(); });
}

// ============================================================================
// BACKUPS (AES-GCM + PBKDF2, atomic restore)
// ============================================================================
function b64FromBytes(bytes) { let s=''; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s); }
function bytesFromB64(b64) { const bin = atob(b64); const out = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out; }

async function promptForPINVerified() {
  if (localStorage.getItem('pinEnabled') !== 'true') throw new Error('PIN not enabled');
  const stored = localStorage.getItem('pinHash');
  const pin = prompt('Enter your PIN to continue:');
  if (!pin || pin.length < 4) throw new Error('PIN required');
  // Use salted hash if salt exists (v9.8.0+), fall back to legacy unsalted for migration
  const salt = localStorage.getItem('pinSalt');
  const toHash = salt ? (salt + ':' + pin) : pin;
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(toHash));
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
  if (hashHex !== stored) throw new Error('Incorrect PIN');
  return pin;
}

async function deriveBackupKey(pin, saltBytes, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), { name:'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name:'PBKDF2', salt: saltBytes, iterations, hash:'SHA-256' }, keyMaterial, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}

async function exportEncryptedBackup() {
  try {
    if (localStorage.getItem('backupEnabled') === 'false') return showToast('Encrypted backups are disabled in Settings', true);
    const pin = await promptForPINVerified();
    const includeReceipts = localStorage.getItem('backupIncludeReceipts') !== 'false';

    const payload = { schema:1, app:'FreightLogic', version:APP_VERSION, exportedAt:Date.now(), includeReceipts, counts:{}, data:{} };
    const stores = ['trips','fuel','expenses','gpsLogs','settings','auditLog'];
    for (const st of stores) { try { payload.data[st] = await dbOp(st,'readonly', s => s.getAll()); } catch { payload.data[st]=[]; } }
    if (includeReceipts) { try { payload.data.receiptsV2 = await dbOp('receiptsV2','readonly', s => s.getAll()); } catch { payload.data.receiptsV2=[]; } }
    else payload.data.receiptsV2 = [];

    // Counts snapshot for restore preview
    try {
      for (const k of Object.keys(payload.data)) payload.counts[k] = Array.isArray(payload.data[k]) ? payload.data[k].length : 0;
    } catch {}


    const plain = new TextEncoder().encode(JSON.stringify(payload));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const iter = 200000;
    const key = await deriveBackupKey(pin, salt, iter);
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plain);

    const wrapper = { v:2, app:'FreightLogic', appVersion:APP_VERSION, createdAt:new Date().toISOString(), deviceId:getDeviceId(), kdf:'PBKDF2', iter, salt:b64FromBytes(salt), iv:b64FromBytes(iv), ct:b64FromBytes(new Uint8Array(ct)) };
    const blob = new Blob([JSON.stringify(wrapper)], { type:'application/octet-stream' });
    const filename = `freight.latest.xosenc`;

    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);

    $('backupStatus').textContent = `Exported: ${filename}`;
    showToast('✅ Encrypted backup exported');
    recordBackupReminderNow();
  } catch (e) {
    showToast('Backup export failed: ' + e.message, true);
  }
}


async function exportSyncPackLatestAndHistory() {
  try {
    if (localStorage.getItem('backupEnabled') === 'false') return showToast('Encrypted backups are disabled in Settings', true);
    const pin = await promptForPINVerified();
    const includeReceipts = localStorage.getItem('backupIncludeReceipts') !== 'false';

    // Build payload (same as encrypted backup) with counts
    const payload = { schema:1, app:'FreightLogic', version:APP_VERSION, exportedAt:Date.now(), includeReceipts, counts:{}, data:{} };
    const stores = ['trips','fuel','expenses','gpsLogs','settings','auditLog'];
    for (const st of stores) { try { payload.data[st] = await dbOp(st,'readonly', s => s.getAll()); } catch { payload.data[st]=[]; } }
    if (includeReceipts) { try { payload.data.receiptsV2 = await dbOp('receiptsV2','readonly', s => s.getAll()); } catch { payload.data.receiptsV2=[]; } }
    else payload.data.receiptsV2 = [];
    try { for (const k of Object.keys(payload.data)) payload.counts[k] = Array.isArray(payload.data[k]) ? payload.data[k].length : 0; } catch {}

    const plain = new TextEncoder().encode(JSON.stringify(payload));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const iter = 250000;
    const key = await deriveBackupKey(pin, salt, iter);
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plain);

    const wrapper = { v:2, app:'FreightLogic', appVersion:APP_VERSION, createdAt:new Date().toISOString(), deviceId:getDeviceId(), kdf:'PBKDF2', iter, salt:b64FromBytes(salt), iv:b64FromBytes(iv), ct:b64FromBytes(new Uint8Array(ct)), counts: payload.counts };

    const blob = new Blob([JSON.stringify(wrapper)], { type:'application/octet-stream' });

    // Two downloads: latest + history snapshot
    const ts = new Date().toISOString().replace(/[:.]/g,'-');
    const device = getDeviceId().slice(0,8);
    const latestName = 'freight.latest.xosenc';
    const histName = `freight.${ts}.device-${device}.xosenc`;

    downloadBlob(blob, latestName);
    // slight delay so iOS doesn't collapse downloads into one
    setTimeout(() => downloadBlob(blob, histName), 350);

    // record local history metadata (for your own tracking)
    try {
      const meta = { name: histName, createdAt: Date.now(), device: device, counts: wrapper.counts || {} };
      const list = (await getSettingKV('syncBackupHistoryV1', [])) || [];
      list.unshift(meta);
      const capped = list.slice(0, 30);
      await setSettingKV('syncBackupHistoryV1', capped);
      renderBackupHistoryInline();
    } catch {}

    $('backupStatus').textContent = `Exported: ${latestName} + history`;
    showToast('✅ Sync Pack exported (latest + history)');
    recordBackupReminderNow();
  } catch (e) {
    showToast('Sync Pack export failed: ' + e.message, true);
  }
}

function downloadBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1200);
}


function openHtmlInNewTabOrSelf(html, suggestedFilename) {
  try {
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);

    // Try opening in a new tab/window first (preferred for print flows)
    const w = window.open(url, '_blank');
    if (w) {
      // Ensure URL revocation eventually
      setTimeout(() => { try { URL.revokeObjectURL(url); } catch (_) {} }, 60000);
      return { ok: true, mode: 'newtab' };
    }

    // Popup blocked: fall back to same-tab navigation (works on iOS Safari)
    window.location.href = url;
    setTimeout(() => { try { URL.revokeObjectURL(url); } catch (_) {} }, 60000);
    return { ok: true, mode: 'sametab' };
  } catch (e) {
    // As a last resort, offer as a download
    try {
      downloadBlob(new Blob([html], { type: 'text/html' }), suggestedFilename || 'export.html');
      return { ok: true, mode: 'download' };
    } catch (_) {
      return { ok: false, mode: 'failed' };
    }
  }
}



async function renderBackupHistoryInline() {
  const el = $('backupHistoryList');
  if (!el) return;
  const list = (await getSettingKV('syncBackupHistoryV1', [])) || [];

  // Clear safely
  while (el.firstChild) el.removeChild(el.firstChild);

  if (!list.length) {
    const d = document.createElement('div');
    d.style.cssText = 'color:var(--text-secondary); font-size:12px;';
    d.textContent = 'No local history yet.';
    el.appendChild(d);
    return;
  }

  const frag = document.createDocumentFragment();
  list.slice(0, 10).forEach(x => {
    const wrap = document.createElement('div');
    wrap.style.cssText = 'padding:6px 0; border-bottom:1px solid var(--border); font-size:12px;';

    const title = document.createElement('div');
    title.style.fontWeight = '700';
    title.textContent = String(x?.name || '');

    const meta = document.createElement('div');
    meta.style.cssText = 'color:var(--text-secondary);';
    const dt = new Date(x.createdAt).toLocaleString();
    const trips = (x.counts && typeof x.counts.trips !== 'undefined') ? x.counts.trips : '';
    meta.textContent = `Created: ${dt} • Trips: ${trips}`;

    wrap.appendChild(title);
    wrap.appendChild(meta);
    frag.appendChild(wrap);
  });

  el.appendChild(frag);
}


// Accountant packet (downloads CSVs + opens printable summary)
async function exportAccountantPacket() {
  try {
    const year = new Date().getFullYear();
    const trips = await dbOp('trips','readonly', s => s.getAll());
    let fuel      = await dbOp('fuel','readonly', s => s.getAll());
    let expenses  = await dbOp('expenses','readonly', s => s.getAll());
    const settingsRows = await dbOp('settings','readonly', s => s.getAll());

    const csv = (rows) => rows.map(r => r.map(sanitizeCSVCell).join(',')).join('\n');
    const tripRows = [['orderNo','pickupDate','deliveryDate','customer','revenue','loadedMiles','emptyMiles','paid','paidDate','notes']]
      .concat(trips.map(t => [t.orderNo,t.pickupDate||'',t.deliveryDate||'',t.customer||'',t.revenue||0,t.loadedMiles||0,t.emptyMiles||0,!!t.paid,t.paidDate||'',t.notes||'']));
    const fuelRows = [['id','date','vendor','state','gallons','amount','odometer','notes']]
      .concat(fuel.map(f => [f.id||'',f.date||'',f.vendor||'',f.state||'',f.gallons||0,f.amount||0,f.odometer||'',f.notes||'']));
    const expRows = [['id','date','category','amount','description','notes']]
      .concat(expenses.map(e => [e.id||'',e.date||'',e.category||'',e.amount||0,e.desc||e.description||'',e.notes||'']));

    downloadBlob(new Blob([csv(tripRows)], {type:'text/csv'}), `freight_logic_${year}_trips.csv`);
    setTimeout(()=>downloadBlob(new Blob([csv(fuelRows)], {type:'text/csv'}), `freight_logic_${year}_fuel.csv`), 250);
    setTimeout(()=>downloadBlob(new Blob([csv(expRows)], {type:'text/csv'}), `freight_logic_${year}_expenses.csv`), 500);

    // Print-friendly summary
    const totalRev = trips.reduce((a,t)=>a+(Number(t.revenue)||0),0);
    const totalFuel = fuel.reduce((a,f)=>a+(Number(f.amount)||0),0);
    const totalExp = expenses.reduce((a,e)=>a+(Number(e.amount)||0),0);
    const net = totalRev - (totalFuel + totalExp);
    const summaryHtml = `<!doctype html><html><head><meta charset="utf-8"><title>Freight Logic Accountant Packet</title>
      <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;padding:24px;}h1{font-size:20px}table{border-collapse:collapse;width:100%;margin-top:12px}td,th{border:1px solid #ccc;padding:8px;font-size:12px}</style>
      </head><body>
      <h1>Freight Logic Accountant Packet (${year})</h1>
      <p>Generated: ${new Date().toLocaleString()}</p>
      <table><tr><th>Total Revenue</th><th>Total Fuel</th><th>Total Expenses</th><th>Estimated Net</th></tr>
      <tr><td>$${totalRev.toFixed(2)}</td><td>$${totalFuel.toFixed(2)}</td><td>$${totalExp.toFixed(2)}</td><td>$${net.toFixed(2)}</td></tr></table>
      <h2 style="font-size:16px;margin-top:20px;">Notes</h2>
      <ul><li>CSV files downloaded: trips, fuel, expenses</li><li>All data remains local to your device.</li></ul>
      </body></html>`;
    const opened = openHtmlInNewTabOrSelf(summaryHtml, `freight_logic_${year}_accountant_packet.html`);
    if (!opened.ok) showToast('Export opened with fallback (popup blocked)', true);
    showToast('✅ Accountant packet exported');
  } catch (e) {
    showToast('Accountant packet export failed: ' + e.message, true);
  }
}

async function importEncryptedBackup(file) {
  try {
    if (!file) return;
    const pin = await promptForPINVerified();
    const text = await file.text();
    let wrapper; try { wrapper = JSON.parse(text); } catch { throw new Error('Invalid backup file'); }
    if (!wrapper || !(wrapper.v===1 || wrapper.v===2) || !wrapper.ct || !wrapper.salt || !wrapper.iv) throw new Error('Invalid backup format');

    const salt = bytesFromB64(wrapper.salt);
    const iv = bytesFromB64(wrapper.iv);
    const ct = bytesFromB64(wrapper.ct);
    const iter = Number(wrapper.iter) || 250000;
    const key = await deriveBackupKey(pin, salt, iter);

    let plainBuf;
    try { plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct); } catch { throw new Error('Wrong PIN or corrupted backup'); }
    let payload; try { payload = JSON.parse(new TextDecoder().decode(plainBuf)); } catch { throw new Error('Decrypted data invalid'); }
    if (!['XpediteOps','XpediteOS','FreightLogic'].includes(payload?.app) || !payload.data) throw new Error('Backup schema mismatch');

    const data = payload.data;
    const trips = Array.isArray(data.trips) ? data.trips : [];
    const fuel = Array.isArray(data.fuel) ? data.fuel : [];
    const expenses = Array.isArray(data.expenses) ? data.expenses : [];
    const gpsLogs = Array.isArray(data.gpsLogs) ? data.gpsLogs : [];
    const settings = Array.isArray(data.settings) ? data.settings : [];
    const auditLog = Array.isArray(data.auditLog) ? data.auditLog : [];
    const receiptsV2 = Array.isArray(data.receiptsV2) ? data.receiptsV2 : [];

    const stores = ['trips','fuel','expenses','gpsLogs','settings','auditLog','receiptsV2'];
    const tx = db.transaction(stores, 'readwrite');
    const tripStore = tx.objectStore('trips');
    const fuelStore = tx.objectStore('fuel');
    const expStore  = tx.objectStore('expenses');
    const gpsStore  = tx.objectStore('gpsLogs');
    const setStore  = tx.objectStore('settings');
    const audStore  = tx.objectStore('auditLog');
    const recStore  = tx.objectStore('receiptsV2');

    const existingTrips = await new Promise((res, rej) => { const r=tripStore.getAllKeys(); r.onsuccess=()=>res(new Set(r.result||[])); r.onerror=()=>rej(r.error); });
    let tripsAdded = 0, tripsSkipped = 0;
    trips.forEach(t => { const clean=sanitizeTripRecord(t); if (!clean?.orderNo) return; if (existingTrips.has(clean.orderNo)) { tripsSkipped++; return; } existingTrips.add(clean.orderNo); tripStore.add(clean); tripsAdded++; });

    // ── Fuel dedup (fingerprint: date + amount + gallons + location) ──
    const existingFuel = await new Promise((res, rej) => {
      const r = fuelStore.getAll();
      r.onsuccess = () => { const set = new Set(); (r.result||[]).forEach(f => set.add(`${f.date||''}|${safeFloat(f.amount)}|${safeFloat(f.gallons)}|${f.location||''}`)); res(set); };
      r.onerror = () => rej(r.error);
    });
    let fuelAdded = 0, fuelSkipped = 0;
    fuel.forEach(f => {
      const fp = `${f.date||''}|${safeFloat(f.amount)}|${safeFloat(f.gallons)}|${f.location||''}`;
      if (existingFuel.has(fp)) { fuelSkipped++; return; }
      existingFuel.add(fp);
      const clean = { ...f }; delete clean.id; // strip autoIncrement key to avoid collisions
      try { fuelStore.add(clean); fuelAdded++; } catch { fuelSkipped++; }
    });

    // ── Expenses dedup (fingerprint: date + amount + category + description) ──
    const existingExp = await new Promise((res, rej) => {
      const r = expStore.getAll();
      r.onsuccess = () => { const set = new Set(); (r.result||[]).forEach(e => set.add(`${e.date||''}|${safeFloat(e.amount)}|${e.category||''}|${e.desc||e.description||''}`)); res(set); };
      r.onerror = () => rej(r.error);
    });
    let expAdded = 0, expSkipped = 0;
    expenses.forEach(ex => {
      const fp = `${ex.date||''}|${safeFloat(ex.amount)}|${ex.category||''}|${ex.description||''}`;
      if (existingExp.has(fp)) { expSkipped++; return; }
      existingExp.add(fp);
      const clean = { ...ex }; delete clean.id;
      try { expStore.add(clean); expAdded++; } catch { expSkipped++; }
    });

    // ── GPS logs dedup (fingerprint: tripOrderNo + timestamp) ──
    const existingGPS = await new Promise((res, rej) => {
      const r = gpsStore.getAll();
      r.onsuccess = () => { const set = new Set(); (r.result||[]).forEach(g => set.add(`${g.tripOrderNo||''}|${g.timestamp||''}`)); res(set); };
      r.onerror = () => rej(r.error);
    });
    let gpsAdded = 0, gpsSkipped = 0;
    gpsLogs.forEach(g => {
      const fp = `${g.tripOrderNo||''}|${g.timestamp||''}`;
      if (existingGPS.has(fp)) { gpsSkipped++; return; }
      existingGPS.add(fp);
      const clean = { ...g }; delete clean.id;
      try { gpsStore.add(clean); gpsAdded++; } catch { gpsSkipped++; }
    });

    const existingSettings = await new Promise((res, rej) => { const r=setStore.getAllKeys(); r.onsuccess=()=>res(new Set(r.result||[])); r.onerror=()=>rej(r.error); });
    settings.forEach(s => { if (!s?.key) return; if (existingSettings.has(s.key)) return; existingSettings.add(s.key); setStore.add(s); });

    const existingAudit = await new Promise((res, rej) => { const r=audStore.getAllKeys(); r.onsuccess=()=>res(new Set(r.result||[])); r.onerror=()=>rej(r.error); });
    auditLog.forEach(a => { if (!a?.id) return; if (existingAudit.has(a.id)) return; existingAudit.add(a.id); audStore.add(a); });

    const existingReceiptFps = await new Promise((res, rej) => {
      const r = recStore.getAll();
      r.onsuccess = () => { const set=new Set(); (r.result||[]).forEach(x => set.add(`${x.tripOrderNo||''}|${x.expenseId||''}|${x.timestamp||''}|${x.size||''}`)); res(set); };
      r.onerror = () => rej(r.error);
    });
    receiptsV2.forEach(r => {
      if (!r) return;
      const fp = `${r.tripOrderNo||''}|${r.expenseId||''}|${r.timestamp||''}|${r.size||''}`;
      if (existingReceiptFps.has(fp)) return;
      existingReceiptFps.add(fp);
      const rec = { tripOrderNo:r.tripOrderNo||null, expenseId:r.expenseId??null, timestamp:r.timestamp||Date.now(), mime:r.mime||'image/jpeg', blob:r.blob, size:r.size||(r.blob?.size||0), width:r.width||0, height:r.height||0 };
      recStore.add(rec);
    });

    await new Promise((res, rej) => { tx.oncomplete=()=>res(true); tx.onerror=()=>rej(tx.error||new Error('Restore failed')); tx.onabort=()=>rej(tx.error||new Error('Restore aborted')); });

    // ── Import Summary Report ──
    const summaryParts = [];
    if (tripsAdded > 0 || tripsSkipped > 0)  summaryParts.push(`Trips: ${tripsAdded} added, ${tripsSkipped} skipped`);
    if (fuelAdded > 0 || fuelSkipped > 0)    summaryParts.push(`Fuel: ${fuelAdded} added, ${fuelSkipped} skipped`);
    if (expAdded > 0 || expSkipped > 0)      summaryParts.push(`Expenses: ${expAdded} added, ${expSkipped} skipped`);
    if (gpsAdded > 0 || gpsSkipped > 0)      summaryParts.push(`GPS: ${gpsAdded} added, ${gpsSkipped} skipped`);
    const totalAdded = tripsAdded + fuelAdded + expAdded + gpsAdded;
    const totalSkipped = tripsSkipped + fuelSkipped + expSkipped + gpsSkipped;
    const summaryText = summaryParts.length > 0 ? summaryParts.join('\n') : 'No new data found';

    showToast(`✅ Backup imported (${totalAdded} records added, ${totalSkipped} duplicates skipped)`);
    $('backupStatus').textContent = `Imported: ${file.name}`;

    // Show detailed summary in an alert for transparency
    if (summaryParts.length > 0) {
      setTimeout(() => alert('📋 Import Summary\n\n' + summaryText), 300);
    }
    await refreshReceiptCounts();
    refreshUI();
  } catch (e) {
    showToast('Backup import failed: ' + e.message, true);
  }
}

function recordBackupReminderNow() { localStorage.setItem('backupLastExport', String(Date.now())); }
function scheduleBackupReminder() { /* remind-on-open only */ }
function maybeShowBackupReminderOnOpen() {
  const mode = localStorage.getItem('backupReminder') || 'off';
  if (mode === 'off') return;
  const last = parseInt(localStorage.getItem('backupLastExport') || '0', 10);
  const now = Date.now();
  const day = 24*60*60*1000;
  const due = mode === 'daily' ? day : 7*day;
  if (!last || (now - last) >= due) showToast('Reminder: export an encrypted backup', false);
}

// ============================================================================
// RECEIPTS UI HELPERS
// ============================================================================
async function handleReceiptFilesForContext(context, files) {
  if (!files || !files.length) return;
  const statusEl = context === 'trip' ? $('tripReceiptStatus') : (context === 'expense' ? $('expenseReceiptStatus') : $('mealReceiptStatus'));
  try {
    statusEl.textContent = 'Processing...';
    const out = [];
    for (const f of files) {
      const { blob, width, height } = await ReceiptModule.imageToJPEGBlob(f, RECEIPT_MAX_PX, 0.7);
      const receiptHash = await ReceiptModule.hashBlob(blob);
      // temp-stage dedupe within current session
      const alreadyTemp = (context==='trip' ? tempTripReceipts : (context==='expense'?tempExpenseReceipts:tempMealReceipts)).some(r => r.receiptHash === receiptHash);
      if (alreadyTemp) continue;
      // saved dedupe
      try { const existing = await ReceiptModule.findByHash(receiptHash); if (existing) continue; } catch {}
      out.push({ blob, width, height, size: blob.size, receiptHash });
    }
    if (context === 'trip') tempTripReceipts.push(...out);
    else if (context === 'expense') tempExpenseReceipts.push(...out);
    else tempMealReceipts.push(...out);

    statusEl.textContent = `Ready: ${out.length} added`;
    await refreshReceiptCounts();
    showToast(`🧾 Added ${out.length} receipt(s)`);
    // Feature 4: Quick-entry prompt
    if (out.length > 0) promptReceiptAmount(context);
  } catch (e) {
    statusEl.textContent = '';
    showToast('Receipt error: ' + e.message, true);
  }
}

async function refreshReceiptCounts() {
  const orderNo = normalizeOrderNo($('orderNo')?.value || '');
  let tripCount = tempTripReceipts.length;
  if (orderNo) { try { const saved = await ReceiptModule.listByTrip(orderNo); tripCount += saved.length; } catch {} }
  if ($('tripReceiptsCount')) $('tripReceiptsCount').textContent = `(${tripCount})`;
  if ($('expenseReceiptsCount')) $('expenseReceiptsCount').textContent = `(${tempExpenseReceipts.length})`;
  if ($('mealReceiptsCount')) $('mealReceiptsCount').textContent = `(${tempMealReceipts.length})`;
}

function openReceiptsViewer(ctx) {
  receiptsViewerContext = { ...ctx, selectedReceiptId: null };
  renderReceiptsViewer().then(() => $('receiptsModal').classList.add('active'));
}

async function renderReceiptsViewer() {
  const grid = $('receiptsGrid');
  const empty = $('receiptsEmpty');
  const statsEl = $('receiptGalleryStats');
  if (!grid) return;
  grid.innerHTML = '';
  let list = [];
  const ctx = receiptsViewerContext || {};

  if (ctx.type === 'trip') {
    const orderNo = ctx.orderNo;
    if (orderNo) { try { list = await ReceiptModule.listByTrip(orderNo); } catch { list=[]; } }
    tempTripReceipts.forEach((t,i) => list.push({ receiptId:null, _temp:true, _tempIndex:i, blob:t.blob, timestamp:Date.now(), size:t.size, width:t.width, height:t.height }));
  } else if (ctx.type === 'expense') {
    tempExpenseReceipts.forEach((t,i) => list.push({ receiptId:null, _temp:true, _tempIndex:i, blob:t.blob, timestamp:Date.now(), size:t.size, width:t.width, height:t.height }));
  } else if (ctx.type === 'meal') {
    tempMealReceipts.forEach((t,i) => list.push({ receiptId:null, _temp:true, _tempIndex:i, blob:t.blob, timestamp:Date.now(), size:t.size, width:t.width, height:t.height }));
  }

  if (!list.length) { empty.style.display='block'; statsEl.style.display='none'; return; }
  empty.style.display='none';

  // Gallery stats
  if (statsEl) {
    const totalSize = list.reduce((sum, r) => sum + (r.size || r.blob?.size || 0), 0);
    statsEl.style.display = 'flex';
    statsEl.textContent = '';
    const addStat = (emoji, label, val) => {
      const d = document.createElement('span');
      d.className = 'receipt-gallery-stat';
      d.innerHTML = '';
      const strong = document.createElement('strong');
      strong.textContent = val;
      d.textContent = emoji + ' ';
      d.appendChild(strong);
      const lbl = document.createTextNode(' ' + label);
      d.appendChild(lbl);
      statsEl.appendChild(d);
    };
    addStat('🧾', 'receipts', list.length);
    addStat('💾', 'total', (totalSize / 1024).toFixed(0) + 'KB');
    const savedCount = list.filter(r => !r._temp).length;
    const unsavedCount = list.filter(r => r._temp).length;
    if (savedCount > 0) addStat('✅', 'saved', savedCount);
    if (unsavedCount > 0) addStat('🆕', 'unsaved', unsavedCount);
  }

  const frag = document.createDocumentFragment();
  for (const r of list) {
    const btn = document.createElement('button');
    btn.type='button';
    btn.style.cssText='padding:0;border:0;background:transparent;cursor:pointer;';
    const img = document.createElement('img');
    img.alt='Receipt';
    img.style.cssText='width:100%; height:100px; object-fit:cover; border-radius:10px; border:1px solid var(--border);';
    const url = URL.createObjectURL(r.blob);
    img.src = url;
    img.onload = () => setTimeout(() => URL.revokeObjectURL(url), 1000);
    img.onerror = () => setTimeout(() => URL.revokeObjectURL(url), 1000);
    btn.appendChild(img);
    btn.addEventListener('click', () => openReceiptFullscreen(r));
    frag.appendChild(btn);
  }
  grid.appendChild(frag);
}

function openReceiptFullscreen(r) {
  const imgEl = $('receiptFullscreenImg');
  const metaEl = $('receiptFullscreenMeta');

  // ── State for this receipt session ──
  const state = { rotation: 0, zoom: 1, panX: 0, panY: 0, brightness: 100, contrast: 100, blob: r.blob };
  window._receiptViewState = state;

  // ── Load image ──
  const url = URL.createObjectURL(r.blob);
  imgEl.src = url;
  imgEl.onload = () => setTimeout(() => URL.revokeObjectURL(url), 1500);
  imgEl.onerror = () => setTimeout(() => URL.revokeObjectURL(url), 1500);

  // Reset transforms
  applyReceiptTransform();

  // ── Metadata display ──
  const sizeKB = Math.round((r.size || r.blob.size || 0) / 1024);
  const dims = (r.width && r.height) ? `${r.width}×${r.height}` : '';
  const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '';
  metaEl.textContent = '';
  const parts = [sizeKB + 'KB', dims, ts].filter(Boolean);
  parts.forEach((p, i) => {
    const sp = document.createElement('span');
    sp.textContent = (i === 0 ? '📁 ' : i === 1 ? '📐 ' : '🕐 ') + p;
    metaEl.appendChild(sp);
  });

  // ── Enhance bar reset ──
  const enhBar = $('receiptEnhanceBar');
  if (enhBar) enhBar.style.display = 'none';
  const brSlider = $('receiptBrightness');
  const ctSlider = $('receiptContrast');
  if (brSlider) brSlider.value = 100;
  if (ctSlider) ctSlider.value = 100;
  const enhBtn = $('btnEnhanceToggle');
  if (enhBtn) enhBtn.classList.remove('active');

  // ── Delete handler ──
  const delBtn = $('btnDeleteReceipt');
  delBtn.onclick = async () => {
    try {
      if (r._temp) {
        if (receiptsViewerContext.type === 'trip') tempTripReceipts.splice(r._tempIndex, 1);
        if (receiptsViewerContext.type === 'expense') tempExpenseReceipts.splice(r._tempIndex, 1);
        if (receiptsViewerContext.type === 'meal') tempMealReceipts.splice(r._tempIndex, 1);
      } else if (r.receiptId != null) {
        await ReceiptModule.deleteById(r.receiptId);
      }
      $('receiptFullscreen').classList.remove('active');
      await refreshReceiptCounts();
      await renderReceiptsViewer();
      refreshUI();
      showToast('🗑️ Receipt deleted');
    } catch (e) { showToast('Delete failed', true); }
  };

  $('receiptFullscreen').classList.add('active');
}

// ── Receipt Transform Engine ──
function applyReceiptTransform() {
  const imgEl = $('receiptFullscreenImg');
  const s = window._receiptViewState;
  if (!imgEl || !s) return;
  imgEl.style.transform = `rotate(${s.rotation}deg) scale(${s.zoom}) translate(${s.panX}px, ${s.panY}px)`;
  imgEl.style.filter = `brightness(${s.brightness}%) contrast(${s.contrast}%)`;
}

// ── Receipt Toolbar Handlers (bound once at init) ──
function initReceiptToolbar() {
  // Rotation
  const rotLeft = $('btnRotateLeft');
  const rotRight = $('btnRotateRight');
  if (rotLeft) rotLeft.addEventListener('click', () => {
    const s = window._receiptViewState; if (!s) return;
    s.rotation = (s.rotation - 90) % 360;
    applyReceiptTransform();
  });
  if (rotRight) rotRight.addEventListener('click', () => {
    const s = window._receiptViewState; if (!s) return;
    s.rotation = (s.rotation + 90) % 360;
    applyReceiptTransform();
  });

  // Zoom
  const zoomIn = $('btnZoomIn');
  const zoomOut = $('btnZoomOut');
  const zoomReset = $('btnZoomReset');
  if (zoomIn) zoomIn.addEventListener('click', () => {
    const s = window._receiptViewState; if (!s) return;
    s.zoom = Math.min(s.zoom * 1.25, 5);
    applyReceiptTransform();
  });
  if (zoomOut) zoomOut.addEventListener('click', () => {
    const s = window._receiptViewState; if (!s) return;
    s.zoom = Math.max(s.zoom / 1.25, 0.25);
    applyReceiptTransform();
  });
  if (zoomReset) zoomReset.addEventListener('click', () => {
    const s = window._receiptViewState; if (!s) return;
    s.zoom = 1; s.panX = 0; s.panY = 0; s.rotation = 0;
    applyReceiptTransform();
  });

  // Pinch-to-zoom + pan on the zoom container
  const container = $('receiptZoomContainer');
  if (container) {
    let lastTouchDist = null;
    let lastTouchCenter = null;
    let isPanning = false;

    container.addEventListener('touchstart', (e) => {
      const s = window._receiptViewState; if (!s) return;
      if (e.touches.length === 2) {
        e.preventDefault();
        lastTouchDist = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
        lastTouchCenter = { x: (e.touches[0].clientX + e.touches[1].clientX) / 2, y: (e.touches[0].clientY + e.touches[1].clientY) / 2 };
      } else if (e.touches.length === 1 && s.zoom > 1) {
        isPanning = true;
        lastTouchCenter = { x: e.touches[0].clientX, y: e.touches[0].clientY };
      }
    }, { passive: false });

    container.addEventListener('touchmove', (e) => {
      const s = window._receiptViewState; if (!s) return;
      if (e.touches.length === 2 && lastTouchDist !== null) {
        e.preventDefault();
        const newDist = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
        const scale = newDist / lastTouchDist;
        s.zoom = Math.min(Math.max(s.zoom * scale, 0.25), 5);
        lastTouchDist = newDist;
        applyReceiptTransform();
      } else if (e.touches.length === 1 && isPanning && lastTouchCenter) {
        e.preventDefault();
        const dx = (e.touches[0].clientX - lastTouchCenter.x) / s.zoom;
        const dy = (e.touches[0].clientY - lastTouchCenter.y) / s.zoom;
        s.panX += dx;
        s.panY += dy;
        lastTouchCenter = { x: e.touches[0].clientX, y: e.touches[0].clientY };
        applyReceiptTransform();
      }
    }, { passive: false });

    container.addEventListener('touchend', () => { lastTouchDist = null; isPanning = false; lastTouchCenter = null; });

    // Mouse wheel zoom
    container.addEventListener('wheel', (e) => {
      const s = window._receiptViewState; if (!s) return;
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      s.zoom = Math.min(Math.max(s.zoom * factor, 0.25), 5);
      applyReceiptTransform();
    }, { passive: false });
  }

  // Enhancement toggle
  const enhBtn = $('btnEnhanceToggle');
  const enhBar = $('receiptEnhanceBar');
  if (enhBtn && enhBar) {
    enhBtn.addEventListener('click', () => {
      const visible = enhBar.style.display !== 'none';
      enhBar.style.display = visible ? 'none' : 'flex';
      enhBtn.classList.toggle('active', !visible);
    });
  }

  // Brightness / Contrast sliders
  const brSlider = $('receiptBrightness');
  const ctSlider = $('receiptContrast');
  if (brSlider) brSlider.addEventListener('input', () => {
    const s = window._receiptViewState; if (!s) return;
    s.brightness = parseInt(brSlider.value, 10);
    applyReceiptTransform();
  });
  if (ctSlider) ctSlider.addEventListener('input', () => {
    const s = window._receiptViewState; if (!s) return;
    s.contrast = parseInt(ctSlider.value, 10);
    applyReceiptTransform();
  });

  // Enhance reset
  const enhReset = $('btnEnhanceReset');
  if (enhReset) enhReset.addEventListener('click', () => {
    const s = window._receiptViewState; if (!s) return;
    s.brightness = 100; s.contrast = 100;
    if (brSlider) brSlider.value = 100;
    if (ctSlider) ctSlider.value = 100;
    applyReceiptTransform();
  });

  // Share
  const shareBtn = $('btnShareReceipt');
  if (shareBtn) shareBtn.addEventListener('click', async () => {
    const s = window._receiptViewState; if (!s || !s.blob) return;
    const file = new File([s.blob], 'receipt.' + (s.blob.type === 'image/png' ? 'png' : 'jpg'), { type: s.blob.type || 'image/jpeg' });
    if (navigator.share && navigator.canShare?.({ files: [file] })) {
      try {
        await navigator.share({ files: [file], title: 'Receipt', text: 'Shared from Freight Logic' });
      } catch (e) { if (e.name !== 'AbortError') showToast('Share failed', true); }
    } else {
      // Fallback: download
      const url = URL.createObjectURL(s.blob);
      const a = document.createElement('a');
      a.href = url; a.download = file.name; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 500);
      showToast('📥 Receipt downloaded');
    }
  });
}

// ============================================================================
// UI HELPERS
// ============================================================================
function switchTab(id) {
  document.querySelectorAll('.module').forEach(m => m.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  const module = $('m-' + id);
  const tab = document.querySelector(`[data-tab="${id}"]`);
  if (module) module.classList.add('active');
  if (tab) { tab.classList.add('active'); tab.setAttribute('aria-selected', 'true'); }

  // Avoid "dead UI" on iOS: tabs must work even if DB is still opening/blocked.
  if (!window.__XPEDITE_OS_DB_READY__) {
    // Defer heavy panels until DB is ready; keep navigation responsive.
    if (id === 'reports' || id === 'summary' || id === 'ar') {
      showToast('Loading data…');
      // Queue a retry: when DB becomes ready, refresh the panel the user landed on
      const retryInterval = setInterval(() => {
        if (window.__XPEDITE_OS_DB_READY__) {
          clearInterval(retryInterval);
          // Only refresh if user is still on this tab
          const activeTab = document.querySelector('.nav-tab.active');
          if (activeTab && activeTab.getAttribute('data-tab') === id) {
            if (id === 'summary' || id === 'reports') refreshSummary();
            if (id === 'ar') refreshARPanel();
          }
        }
      }, 500);
      // Safety: stop retrying after 30 seconds
      setTimeout(() => clearInterval(retryInterval), 30000);
    }
    return;
  }

  if (id === 'summary') refreshSummary();
  if (id === 'reports') refreshSummary();
  if (id === 'ar') refreshARPanel();
}


function showToast(msg, error = false) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('error', 'success');
  if (error) t.classList.add('error');
  else if (msg.includes('✅')) t.classList.add('success');
  t.classList.add('visible');
  setTimeout(() => t.classList.remove('visible'), 3000);
}

function openSettings() {
  
  // Ensure PIN status is reflected without overriding globals
  const pinToggle = $('pinEnabledToggle');
  const pinStatus = $('pinStatus');
  if (pinToggle) {
    const enabled = localStorage.getItem('pinEnabled') === 'true';
    pinToggle.checked = enabled;
    if (pinStatus) pinStatus.textContent = enabled ? '✅ PIN lock active' : 'PIN lock off';
  }
$('settingsModal').classList.add('active');
  loadHomeAddress();
  loadTaxSettings();
  loadBaselineMPG();
  loadAllRateSettings();
  checkStorageQuota();

  // Backups & Sync UI state
  if ($('backupEnabledToggle')) $('backupEnabledToggle').checked = (localStorage.getItem('backupEnabled') !== 'false');
  if ($('backupIncludeReceiptsToggle')) $('backupIncludeReceiptsToggle').checked = (localStorage.getItem('backupIncludeReceipts') !== 'false');
  if ($('backupReminderSelect')) $('backupReminderSelect').value = (localStorage.getItem('backupReminder') || 'off');
}
function closeSettings()     { $('settingsModal').classList.remove('active'); }
function closeGPSModal()     { $('gpsModal').classList.remove('active'); }
function closeDeleteModal()  { $('deleteModal').classList.remove('active'); pendingDelete = null; }

function selectExpenseType(type) {
  currentExpenseType = type;
  document.querySelectorAll('.expense-type-btn').forEach(b => b.classList.remove('active'));
  const btn = document.querySelector(`[data-expense-type="${type}"]`);
  if (btn) btn.classList.add('active');
  $('fuelForm').style.display    = type === 'fuel'    ? 'block' : 'none';
  $('expenseForm').style.display = type === 'expense' ? 'block' : 'none';
  $('mealForm').style.display    = type === 'meal'    ? 'block' : 'none';
}

// ============================================================================
// GPS — HARDENED FOR iOS LIFECYCLE
// ============================================================================
async function requestWakeLock() {
  if ('wakeLock' in navigator) {
    try {
      wakeLock = await navigator.wakeLock.request('screen');
      wakeLock.addEventListener('release', () => { wakeLock = null; });
      console.log('[GPS] Wake lock acquired');
    } catch (err) {
      console.warn('[GPS] Wake lock failed:', err.message);
    }
  }
}

async function releaseWakeLock() {
  if (wakeLock) {
    try { await wakeLock.release(); } catch (e) {}
    wakeLock = null;
  }
}

async function startGPSTracking() {
  if (!navigator.geolocation) return showToast('GPS not supported on this device', true);
  if (!$('orderNo').value.trim()) return showToast('Enter Order # first', true);
  $('gpsModal').classList.add('active');
}

async function requestGPSPermission() {
  closeGPSModal();
  try {
    await new Promise((resolve, reject) => {
      navigator.geolocation.getCurrentPosition(resolve, reject, getGPSOptions(5000));
    });
    beginGPSTracking();
  } catch (error) {
    showToast(
      error.code === error.PERMISSION_DENIED
        ? 'GPS denied. Enable in device Settings.'
        : 'GPS error: ' + error.message,
      true
    );
  }
}

async function beginGPSTracking() {
  gpsTrackingData = {
    orderNo:        $('orderNo').value.trim(),
    startTime:      Date.now(),
    totalDistance:  0,
    lastPosition:   null,
    pointCount:     0,
    logBuffer:      [],
    lastUpdateTime: Date.now(),
    stalePaused:    false,
    _stalenessTimer: null
  };

  $('gpsTrackingPanel').style.display = 'block';
  $('btnStartGPS').disabled = true;
  $('gpsModeBanner').style.display = 'block';
  $('loadedMiles').disabled = true;
  $('emptyMiles').disabled = true;
  $('activeTripID').textContent = escapeHTML(gpsTrackingData.orderNo);
  $('gpsIndicator').classList.remove('inactive');
  $('gpsIndicator').classList.add('tracking');
  $('gpsText').textContent = 'Tracking...';
  $('gpsStatusMsg').textContent = '';

  await requestWakeLock();

  // Staleness detector — iOS suspends GPS when screen locks
  const stalenessTimer = setInterval(() => {
    if (!gpsTrackingData) { clearInterval(stalenessTimer); return; }
    const elapsed = Date.now() - gpsTrackingData.lastUpdateTime;
    if (elapsed > GPS_STALE_MS && !gpsTrackingData.stalePaused) {
      gpsTrackingData.stalePaused = true;
      $('gpsText').textContent = '⚠️ Paused';
      $('gpsStatusMsg').textContent = '⚠️ GPS paused — screen may have locked. Miles may be incomplete.';
      showToast('⚠️ GPS paused — keep screen on for accuracy', true);
    } else if (elapsed < GPS_STALE_MS && gpsTrackingData.stalePaused) {
      gpsTrackingData.stalePaused = false;
      $('gpsText').textContent = 'Tracking...';
      $('gpsStatusMsg').textContent = '✅ GPS resumed';
      showToast('📍 GPS resumed');
    }
  }, 10000);

  gpsTrackingData._stalenessTimer = stalenessTimer;

  gpsWatchId = navigator.geolocation.watchPosition(
    position => {
      if (!gpsTrackingData) return; // guard against post-stop callbacks

      const pt = {
        lat:       position.coords.latitude,
        lng:       position.coords.longitude,
        timestamp: Date.now(),
        accuracy:  position.coords.accuracy
      };

      gpsTrackingData.lastUpdateTime = Date.now();

      if (gpsTrackingData.lastPosition) {
        const segmentDist = haversineDistance(
          gpsTrackingData.lastPosition.lat, gpsTrackingData.lastPosition.lng,
          pt.lat, pt.lng
        );
        const timeDiffHours = (pt.timestamp - gpsTrackingData.lastPosition.timestamp) / 3600000;
        const mph = timeDiffHours > 0 ? segmentDist / timeDiffHours : 0;

        // HARDENED: filter accuracy + segment distance cap + speed ceiling
        if (
          position.coords.accuracy < GPS_MIN_ACCURACY_M &&
          segmentDist > 0.01 &&
          segmentDist < GPS_MAX_SEGMENT_MI && // reject GPS re-acquisition jumps
          mph > 3 &&
          mph < GPS_MAX_SPEED_MPH              // reject physically impossible speeds
        ) {
          gpsTrackingData.totalDistance += segmentDist;
          gpsTrackingData.lastPosition = pt;
        }
      } else {
        gpsTrackingData.lastPosition = pt;
      }

      gpsTrackingData.pointCount++;
      updateGPSDisplay();

      gpsTrackingData.logBuffer.push(pt);
      saveGPSLogBatched(); // Batched in v9.5.2 - saves every 100 points or 15min
    },
    error => {
      console.warn('[GPS] Watch error:', error.code, error.message);
      if (gpsTrackingData) gpsTrackingData.lastUpdateTime = 0; // force stale detection
    },
    getGPSOptions()
  );

  showToast('📍 GPS tracking started');
}

function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 3959;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function updateGPSDisplay() {
  const miles    = Math.round(gpsTrackingData.totalDistance * 10) / 10;
  const duration = Math.floor((Date.now() - gpsTrackingData.startTime) / 60000);
  const hours    = Math.floor(duration / 60);
  const mins     = duration % 60;
  const avgSpeed = duration > 0 ? Math.round((gpsTrackingData.totalDistance / duration) * 60) : 0;
  $('gpsMiles').textContent = miles;
  $('gpsTime').textContent  = `${String(hours).padStart(2,'0')}:${String(mins).padStart(2,'0')}`;
  $('gpsSpeed').textContent = avgSpeed;
}

async function stopGPSTracking() {
  // HARDENED: always attempt clearWatch even if gpsWatchId seems stale
  if (gpsWatchId !== null) {
    try { navigator.geolocation.clearWatch(gpsWatchId); } catch (e) {}
    gpsWatchId = null;
  }

  if (gpsTrackingData) {
    // FIXED: force-flush remaining buffer before clearing state
    if (gpsTrackingData.logBuffer.length > 0) {
      try { await saveGPSLogBatched(true); } catch (e) {}
    }

    if (gpsTrackingData._stalenessTimer) {
      clearInterval(gpsTrackingData._stalenessTimer);
    }
  }

  await releaseWakeLock();

  const miles      = gpsTrackingData ? Math.round(gpsTrackingData.totalDistance) : 0;
  const wasPaused  = gpsTrackingData ? gpsTrackingData.stalePaused : false;

  // Reset UI regardless of state
  $('loadedMiles').value    = miles;
  $('loadedMiles').disabled = false;
  $('emptyMiles').disabled  = false;
  $('gpsTrackingPanel').style.display = 'none';
  $('btnStartGPS').disabled = false;
  $('gpsModeBanner').style.display = 'none';
  $('gpsIndicator').classList.remove('tracking');
  $('gpsIndicator').classList.add('inactive');
  $('gpsText').textContent = 'GPS Off';
  $('gpsStatusMsg').textContent = '';

  gpsTrackingData = null;

  if (wasPaused) {
    showToast(`⚠️ GPS was paused — ${miles} mi recorded. Verify before saving.`, true);
  } else {
    showToast(`✅ GPS stopped: ${miles} miles recorded`);
  }
}

// ============================================================================
// GPS LIFECYCLE: iOS visibility + page resume recovery
// ============================================================================
document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState === 'visible') {
    // Re-acquire wake lock if GPS is still running
    if (gpsWatchId !== null && !wakeLock) {
      await requestWakeLock();
    }
  } else {
    // Page hidden — iOS will suspend JS. Note the time for staleness tracking.
    if (gpsTrackingData) {
      // Don't clear the watch here — let the staleness detector handle the UI
      // Clearing and restarting watchPosition on resume is more reliable on some devices
      console.log('[GPS] Page hidden — tracking may be suspended by iOS');
    }
  }
});

// pageshow fires on back-navigation and PWA resume on iOS
window.addEventListener('pageshow', async (e) => {
  if (e.persisted && gpsWatchId !== null) {
    // Page was restored from bfcache — restart watch for freshness
    console.log('[GPS] pageshow (persisted) — restarting watch');
    try { navigator.geolocation.clearWatch(gpsWatchId); } catch (e) {}
    gpsWatchId = navigator.geolocation.watchPosition(
      position => {
        if (!gpsTrackingData) return;

        const pt = {
          lat:       position.coords.latitude,
          lng:       position.coords.longitude,
          timestamp: Date.now(),
          accuracy:  position.coords.accuracy
        };
        gpsTrackingData.lastUpdateTime = Date.now();

        if (gpsTrackingData.lastPosition) {
          const segmentDist = haversineDistance(
            gpsTrackingData.lastPosition.lat, gpsTrackingData.lastPosition.lng,
            pt.lat, pt.lng
          );
          const timeDiffHours = (pt.timestamp - gpsTrackingData.lastPosition.timestamp) / 3600000;
          const mph = timeDiffHours > 0 ? segmentDist / timeDiffHours : 0;

          if (
            position.coords.accuracy < GPS_MIN_ACCURACY_M &&
            segmentDist > 0.01 &&
            segmentDist < GPS_MAX_SEGMENT_MI &&
            mph > 3 &&
            mph < GPS_MAX_SPEED_MPH
          ) {
            gpsTrackingData.totalDistance += segmentDist;
            gpsTrackingData.lastPosition = pt;
          }
        } else {
          gpsTrackingData.lastPosition = pt;
        }

        gpsTrackingData.pointCount++;
        updateGPSDisplay();

        gpsTrackingData.logBuffer.push(pt);
        saveGPSLogBatched();
      },
      err => console.warn('[GPS] pageshow watch error:', err),
      getGPSOptions()
    );
  }
});

// ============================================================================
// PER DIEM — FIXED: same-day trips get 0 per diem
// ============================================================================
function calculatePerDiem(pickupDate, deliveryDate) {
  if (!pickupDate || !deliveryDate) return { days: 0, amount: 0 };

  const pickup   = new Date(pickupDate   + 'T00:00:00');
  const delivery = new Date(deliveryDate + 'T00:00:00');
  const daysDiff = Math.round((delivery.getTime() - pickup.getTime()) / 86400000);

  if (daysDiff < 0) return { days: 0, amount: 0 };

  // FIXED: same-day (daysDiff=0) = 0 per diem days
  // Only multi-day trips qualify under IRS transportation worker rules
  if (daysDiff === 0) return { days: 0, amount: 0 };

  const days   = daysDiff + 1;   // inclusive for multi-day: 1-night trip = 2 days
  const amount = days * perDiemRate;
  return { days, amount };
}

// ============================================================================
// RECEIPT HANDLING — with quota guard and magic-byte validation
// ============================================================================
// ============================================================================
// RECEIPTS v2 (multi-receipt, blob-based, memory-safe)
// ============================================================================
const ReceiptModule = (() => {
  const MAGIC = {
    jpg: [0xFF,0xD8,0xFF],
    png: [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A],
    webp: [0x52,0x49,0x46,0x46] // RIFF....WEBP checked later
  };

  function bytesStart(buf, sig) {
    if (buf.byteLength < sig.length) return false;
    const a = new Uint8Array(buf, 0, sig.length);
    for (let i=0;i<sig.length;i++) if (a[i] !== sig[i]) return false;
    return true;
  }

  async function validateMagic(file) {
    const head = await file.slice(0, 16).arrayBuffer();
    if (bytesStart(head, MAGIC.jpg)) return true;
    if (bytesStart(head, MAGIC.png)) return true;
    if (bytesStart(head, MAGIC.webp)) {
      const u = new Uint8Array(head);
      return (u[8]===0x57 && u[9]===0x45 && u[10]===0x42 && u[11]===0x50);
    }
    return false;
  }

  async function imageToJPEGBlob(file, maxPx=RECEIPT_MAX_PX, quality=0.7) {
    if (!file) throw new Error('No file');
    if (file.size > RECEIPT_RAW_MAX) throw new Error('Receipt too large (max 10MB)');
    const ok = await validateMagic(file);
    if (!ok) throw new Error('Unsupported image type (JPG/PNG/WEBP only)');

    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      await new Promise((resolve, reject) => {
        img.onload = () => resolve(true);
        img.onerror = () => reject(new Error('Could not decode image'));
        img.src = url;
      });

      const w = img.naturalWidth || img.width;
      const h = img.naturalHeight || img.height;
      if (!w || !h) throw new Error('Bad image dimensions');

      const scale = Math.min(1, maxPx / Math.max(w, h));
      const cw = Math.max(1, Math.round(w * scale));
      const ch = Math.max(1, Math.round(h * scale));

      const canvas = document.createElement('canvas');
      canvas.width = cw; canvas.height = ch;
      const ctx = canvas.getContext('2d', { alpha:false });
      ctx.drawImage(img, 0, 0, cw, ch);

      const blob = await new Promise((resolve, reject) => {
        canvas.toBlob(b => b ? resolve(b) : reject(new Error('Compression failed')), 'image/jpeg', quality);
      });

      return { blob, width: cw, height: ch };
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  
  async function sha256Hex(buf) {
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const u = new Uint8Array(hash);
    return Array.from(u).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  async function hashBlob(blob) {
    const ab = await blob.arrayBuffer();
    return sha256Hex(ab);
  }

  async function findByHash(receiptHash) {
    return new Promise((res, rej) => {
      const tx = db.transaction(['receiptsV2'], 'readonly');
      const idx = tx.objectStore('receiptsV2').index('byHash');
      const req = idx.get(IDBKeyRange.only(receiptHash));
      req.onsuccess = () => res(req.result || null);
      req.onerror = () => rej(req.error);
    });
  }
async function addReceipts(records) {
    if (!records || !records.length) return { added:0, skipped:0 };
    // Pre-filter duplicates by receiptHash to avoid tx abort on unique index
    const filtered = [];
    let skipped = 0;
    for (const r of records) {
      if (r.receiptHash) {
        try { const existing = await findByHash(r.receiptHash); if (existing) { skipped++; continue; } } catch {}
      }
      filtered.push(r);
    }
    if (!filtered.length) return { added:0, skipped };
    const tx = db.transaction(['receiptsV2'], 'readwrite');
    const store = tx.objectStore('receiptsV2');
    for (const r of filtered) store.add(r);
    return new Promise((res, rej) => {
      tx.oncomplete = () => res({ added: filtered.length, skipped });
      tx.onerror = () => rej(tx.error || new Error('Receipt tx failed'));
      tx.onabort = () => rej(tx.error || new Error('Receipt tx aborted'));
    });
  }

  async function listByTrip(orderNo) {
    return new Promise((res, rej) => {
      const tx = db.transaction(['receiptsV2'], 'readonly');
      const idx = tx.objectStore('receiptsV2').index('byTripOrderNo');
      const req = idx.getAll(IDBKeyRange.only(orderNo));
      req.onsuccess = () => res((req.result || []).filter(isActiveRecord));
      req.onerror = () => rej(req.error);
    });
  }

  async function listByExpense(expenseId) {
    return new Promise((res, rej) => {
      const tx = db.transaction(['receiptsV2'], 'readonly');
      const idx = tx.objectStore('receiptsV2').index('byExpenseId');
      const req = idx.getAll(IDBKeyRange.only(expenseId));
      req.onsuccess = () => res((req.result || []).filter(isActiveRecord));
      req.onerror = () => rej(req.error);
    });
  }

  async function deleteById(receiptId) {
    return softDeleteRecord('receiptsV2', receiptId, { reason: 'user' });
  }

  async function cascadeDeleteTrip(orderNo) {
    const list = await listByTrip(orderNo);
    if (!list.length) return;
    const tx = db.transaction(['receiptsV2'], 'readwrite');
    const s = tx.objectStore('receiptsV2');
    const now = new Date().toISOString();
    list.forEach(r => {
      const rec = Object.assign({}, r, { isActive: false, deletedAt: now, deletedReason: 'cascade', updated: Date.now() });
      // Ensure keyPath for autoIncrement is preserved as receiptId
      s.put(rec);
    });
    return new Promise((res, rej) => {
      tx.oncomplete = () => res(true);
      tx.onerror = () => rej(tx.error);
      tx.onabort = () => rej(tx.error);
    });
  }

  async function cascadeDeleteExpense(expenseId) {
    const list = await listByExpense(expenseId);
    if (!list.length) return;
    const tx = db.transaction(['receiptsV2'], 'readwrite');
    const s = tx.objectStore('receiptsV2');
    const now = new Date().toISOString();
    list.forEach(r => {
      const rec = Object.assign({}, r, { isActive: false, deletedAt: now, deletedReason: 'cascade', updated: Date.now() });
      s.put(rec);
    });
    return new Promise((res, rej) => {
      tx.oncomplete = () => res(true);
      tx.onerror = () => rej(tx.error);
      tx.onabort = () => rej(tx.error);
    });
  }

  

  async function cascadeRestoreTrip(tripId) {
    const list = await listByTrip(tripId);
    if (!list.length) return;
    const tx = db.transaction(['receiptsV2'], 'readwrite');
    const s = tx.objectStore('receiptsV2');
    list.forEach(r => {
      const rec = Object.assign({}, r, { isActive: true, deletedAt: null, deletedReason: null, updated: Date.now() });
      s.put(rec);
    });
    return new Promise((res, rej) => {
      tx.oncomplete = () => res(true);
      tx.onerror = () => rej(tx.error);
      tx.onabort = () => rej(tx.error);
    });
  }

  async function cascadeRestoreExpense(expenseId) {
    const list = await listByExpense(expenseId);
    if (!list.length) return;
    const tx = db.transaction(['receiptsV2'], 'readwrite');
    const s = tx.objectStore('receiptsV2');
    list.forEach(r => {
      const rec = Object.assign({}, r, { isActive: true, deletedAt: null, deletedReason: null, updated: Date.now() });
      s.put(rec);
    });
    return new Promise((res, rej) => {
      tx.oncomplete = () => res(true);
      tx.onerror = () => rej(tx.error);
      tx.onabort = () => rej(tx.error);
    });
  }
return {
    imageToJPEGBlob,
    hashBlob,
    findByHash,
    addReceipts,
    listByTrip,
    listByExpense,
    deleteById,
    cascadeDeleteTrip,
    cascadeDeleteExpense,
    cascadeRestoreTrip,
    cascadeRestoreExpense
  };
})();

// ============================================================================
// TRIP SAVE — hardened with normalization + clamping
// ============================================================================
async function saveTrip() {
  // Normalize order number first
  const rawOrderNo = $('orderNo').value;
  const orderNo = normalizeOrderNo(rawOrderNo);
  if (rawOrderNo !== rawOrderNo.trim().toUpperCase()) {
    $('orderNo').value = orderNo; // auto-correct the field
  }

  if (!orderNo) return showToast('Order # required', true);

  const pickupVal   = $('pickupDate').value   || getTodayStr();
  const deliveryVal = $('deliveryDate').value || pickupVal;

  if (new Date(deliveryVal) < new Date(pickupVal)) {
    showToast('Delivery cannot be before pickup', true);
    $('deliveryDate').classList.add('error');
    setTimeout(() => $('deliveryDate').classList.remove('error'), 3000);
    return;
  }

  const perDiem = calculatePerDiem(pickupVal, deliveryVal);

  // HARDENED: clampMoney + clampMiles on all numeric fields before write
  const revenue    = clampMoney($('revenue').value);
  const loadedMi   = clampMiles($('loadedMiles').value);
  const emptyMi    = clampMiles($('emptyMiles').value);

  if (revenue <= 0) return showToast('Revenue must be greater than $0', true);

  const data = {
    orderNo,
    customer:      $('customer').value.trim().substring(0, 200),
    origin:        $('origin').value.trim().substring(0, 200),
    dest:          $('dest').value.trim().substring(0, 200),
    loadedMiles:   loadedMi,
    emptyMiles:    emptyMi,
    revenue,
    pickupDate:    pickupVal,
    deliveryDate:  deliveryVal,
    perDiemDays:   perDiem.days,
    perDiemAmount: perDiem.amount,
    notes:         $('tripNotes').value.trim().substring(0, 500),
    paid:          $('tripPaid').checked,
    paidDate:      $('tripPaid').checked ? Date.now() : null,
    created:       Date.now()
  };

  try {
    const existing = await dbOp('trips', 'readonly', s => s.get(orderNo)).catch(() => null);
    if (existing) {
      if (!confirm(`Order # ${orderNo} already exists. Update it?`)) return;
      data.created = existing.created || data.created;
      await dbOp('trips', 'readwrite', s => s.put(data));
    } else {
      await dbOp('trips', 'readwrite', s => s.add(data));
    }
    // Save receipts v2 (many per trip)
    if (tempTripReceipts.length) {
      try {
        // optional storage estimate gate
        if (navigator.storage && navigator.storage.estimate) {
          const { usage, quota } = await navigator.storage.estimate();
          const pct = quota > 0 ? (usage / quota) : 0;
          if (pct > 0.92) throw new Error('quota');
        }

        const records = tempTripReceipts.map(r => ({
          tripOrderNo: orderNo,
          expenseId: null,
          timestamp: Date.now(),
          mime: 'image/jpeg',
          blob: r.blob,
          size: r.size,
          width: r.width,
          height: r.height
        }));
        await ReceiptModule.addReceipts(records);
        tempTripReceipts = [];
      } catch (qe) {
        if (String(qe?.message||'').includes('quota')) showToast('⚠️ Storage nearly full — receipts NOT saved. Trip was saved.', true);
        else showToast('⚠️ Receipt save failed — trip was saved', true);
      }
    }

    // AUDIT TRAIL: Log trip creation/update
    if (existing) {
      const changes = {};
      Object.keys(data).forEach(k => {
        if (existing[k] !== data[k]) {
          changes[k] = { old: existing[k], new: data[k] };
        }
      });
      if (Object.keys(changes).length > 0) {
        await AuditModule.log('update', 'trip', orderNo, changes);
      }
    } else {
      await AuditModule.log('create', 'trip', orderNo, { created: data });
    }

    clearTripForm();
    showToast('✅ Trip saved');
    await checkStorageQuota();
    refreshUI();
  } catch (e) {
    console.error('[Trip] Save error:', e);
    showToast('Error saving trip: ' + (e.message || 'unknown'), true);
  }
}

function clearTripForm() {
  ['orderNo','customer','origin','dest','loadedMiles','emptyMiles','revenue','tripNotes'].forEach(id => { const el=$(id); if (el) el.value=''; });
  if ($('tripPaid')) $('tripPaid').checked = false;
  tempTripReceipts = [];
  if ($('tripReceiptStatus')) $('tripReceiptStatus').textContent = '';
  refreshReceiptCounts();
}

// ============================================================================
// TRIP FILTERING & PAGINATION
// ============================================================================
async function updateCustomerAutocomplete() {
  const trips = await dbOp('trips', 'readonly', s => s.getAll());
  const customers = [...new Set(trips.map(t => t.customer).filter(c => c && c.trim()))].sort();

  const dl = $('customerList');
  if (!dl) return;

  // DOM-safe: build <datalist> options without innerHTML
  dl.textContent = '';
  const frag = document.createDocumentFragment();
  customers.forEach(c => {
    const opt = document.createElement('option');
    opt.value = String(c);
    frag.appendChild(opt);
  });
  dl.appendChild(frag);
}
function applyFilters() {
  currentFilters.search    = $('tripSearch').value.toLowerCase();
  currentFilters.customer  = $('filterCustomer').value;
  currentFilters.status    = $('filterStatus').value;
  currentFilters.dateRange = $('filterDateRange').value;
  currentPage = 1; // reset to page 1 on filter change
  refreshUI();
}
const debouncedApplyFilters = debounce(applyFilters, 200);

function filterTrips(trips) {
  let filtered = [...trips];

  if (currentFilters.search) {
    const s = currentFilters.search;
    filtered = filtered.filter(t =>
      (t.orderNo   && t.orderNo.toLowerCase().includes(s)) ||
      (t.customer  && t.customer.toLowerCase().includes(s)) ||
      (t.origin    && t.origin.toLowerCase().includes(s)) ||
      (t.dest      && t.dest.toLowerCase().includes(s))
    );
  }

  if (currentFilters.customer) {
    filtered = filtered.filter(t => t.customer === currentFilters.customer);
  }

  if (currentFilters.status === 'paid')   filtered = filtered.filter(t =>  t.paid);
  if (currentFilters.status === 'unpaid') filtered = filtered.filter(t => !t.paid);

  if (currentFilters.dateRange && currentFilters.dateRange !== '') {
    const today = new Date();
    let fromDate, toDate;

    if (currentFilters.dateRange === 'today') {
      fromDate = toDate = getTodayStr();
    } else if (currentFilters.dateRange === 'week') {
      // FIXED: use actual calendar week start (Sunday)
      const weekStart = new Date(today);
      weekStart.setDate(today.getDate() - today.getDay());
      weekStart.setHours(0, 0, 0, 0);
      fromDate = weekStart.toISOString().split('T')[0];
      toDate   = getTodayStr();
    } else if (currentFilters.dateRange === 'month') {
      // Calendar month start
      const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);
      fromDate = monthStart.toISOString().split('T')[0];
      toDate   = getTodayStr();
    } else if (currentFilters.dateRange === 'custom') {
      fromDate = $('filterDateFrom').value;
      toDate   = $('filterDateTo').value;
    }

    if (fromDate && toDate) {
      filtered = filtered.filter(t => {
        const d = t.pickupDate || '';
        return d >= fromDate && d <= toDate;
      });
    }
  }

  return filtered;
}

// ============================================================================
// BULK OPERATIONS — FIXED: capture count before clearing set
// ============================================================================
function toggleBulkMode() {
  bulkMode = !bulkMode;
  selectedTrips.clear();
  $('bulkOperationsBar').style.display = bulkMode ? 'block' : 'none';
  updateBulkCount();
  refreshUI();
}

function toggleTripSelection(orderNo) {
  if (selectedTrips.has(orderNo)) selectedTrips.delete(orderNo);
  else selectedTrips.add(orderNo);
  updateBulkCount();
}

async function selectAllTrips() {
  // FIXED: re-read filters from DOM before selecting
  applyFilters();
  const trips = await dbOp('trips', 'readonly', s => s.getAll());
  const filtered = filterTrips(trips);
  filtered.forEach(t => selectedTrips.add(t.orderNo));
  updateBulkCount();
  refreshUI();
}

function deselectAllTrips() {
  selectedTrips.clear();
  updateBulkCount();
  refreshUI();
}

function updateBulkCount() {
  $('bulkSelectionCount').textContent = `${selectedTrips.size} selected`;
}

async function bulkMarkPaid() {
  if (selectedTrips.size === 0) return showToast('No trips selected', true);
  const count = selectedTrips.size; // FIXED: capture BEFORE clearing
  if (!confirm(`Mark ${count} trip${count !== 1 ? 's' : ''} as paid?`)) return;
  try {
    for (const orderNo of selectedTrips) {
      const trip = await dbOp('trips', 'readonly', s => s.get(orderNo));
      if (trip) { trip.paid = true; trip.paidDate = trip.paidDate || Date.now(); await dbOp('trips', 'readwrite', s => s.put(trip)); }
    }
    selectedTrips.clear();
    showToast(`✅ ${count} trip${count !== 1 ? 's' : ''} marked as paid`);
    refreshUI();
  } catch (e) { showToast('Error updating trips', true); }
}

async function bulkMarkUnpaid() {
  if (selectedTrips.size === 0) return showToast('No trips selected', true);
  const count = selectedTrips.size; // FIXED: capture BEFORE clearing
  if (!confirm(`Mark ${count} trip${count !== 1 ? 's' : ''} as unpaid?`)) return;
  try {
    for (const orderNo of selectedTrips) {
      const trip = await dbOp('trips', 'readonly', s => s.get(orderNo));
      if (trip) { trip.paid = false; trip.paidDate = null; await dbOp('trips', 'readwrite', s => s.put(trip)); }
    }
    selectedTrips.clear();
    showToast(`✅ ${count} trip${count !== 1 ? 's' : ''} marked as unpaid`);
    refreshUI();
  } catch (e) { showToast('Error updating trips', true); }
}

async function duplicateLastTrip() {
  const trips = await dbOp('trips', 'readonly', s => s.getAll());
  if (!trips.length) return showToast('No previous trip', true);
  trips.sort((a, b) => (b.created || 0) - (a.created || 0));
  const last = trips[0];
  $('origin').value      = last.origin || '';
  $('dest').value        = last.dest   || '';
  $('loadedMiles').value = last.loadedMiles || '';
  $('emptyMiles').value  = last.emptyMiles  || '';
  $('pickupDate').value  = getTodayStr();
  $('deliveryDate').value = getTodayStr();
  showToast('📋 Last trip copied');
}

async function useLastDestination() {
  const trips = await dbOp('trips', 'readonly', s => s.getAll());
  if (!trips.length) return showToast('No previous trip', true);
  trips.sort((a, b) => (b.created || 0) - (a.created || 0));
  const last = trips[0];
  if (!last.dest) return showToast('Last trip has no destination', true);
  $('origin').value = last.dest;
  showToast('↻ Last destination → Origin');
}

function confirmDeleteRecord(store, key, label) {
  pendingDelete = { store, key };
  $('deleteModalText').textContent = `Delete this ${label}? This cannot be undone.`;
  $('deleteModal').classList.add('active');
}

async function executeDelete() {
  if (!pendingDelete) return;
  try {

    // AUDIT TRAIL: Log deletion
    await AuditModule.log('delete', pendingDelete.store, pendingDelete.key, {});

    await softDeleteRecord(pendingDelete.store, pendingDelete.key, { reason: 'user' });

    lastSoftDeleted = { store: pendingDelete.store, key: pendingDelete.key, at: Date.now(), reason: 'user' };

    // Cascade delete associated receipts when trip/expense is deleted
    try {
      if (pendingDelete.store === 'trips') await ReceiptModule.cascadeDeleteTrip(pendingDelete.key);
      if (pendingDelete.store === 'expenses') await ReceiptModule.cascadeDeleteExpense(pendingDelete.key);
    } catch (e) { /* ignore */ }

    showToast('✅ Record removed (can be restored)');
    await checkStorageQuota();
    refreshUI();
  } catch (e) {
    showToast('Error deleting record', true);
  }
  closeDeleteModal();
}

// ============================================================================
// FUEL / EXPENSE / MEAL SAVE
// ============================================================================
async function saveFuel() {
  const data = {
    amount:   clampMoney($('fuelAmount').value),
    gallons:  clampMiles($('fuelGallons').value),
    location: $('fuelLocation').value.trim().substring(0, 200),
    state:    ($('fuelState').value || '').substring(0, 2).toUpperCase(),
    date:     $('fuelDate').value || getTodayStr(),
    category: 'fuel'
  };
  if (data.amount <= 0) return showToast('Enter fuel amount', true);
  try {
    await dbOp('fuel', 'readwrite', s => s.add(data));
    $('fuelAmount').value = ''; $('fuelGallons').value = ''; $('fuelLocation').value = ''; $('fuelState').value = '';
    showToast('⛽ Fuel saved'); refreshUI();
  } catch (e) { showToast('Error saving fuel', true); }
}


// ============================================================================
// EXPENSE CATEGORY CONFIG (custom categories + simple auto-category rules)
// Stored in IndexedDB settings store so it survives backups/restores.
// ============================================================================
const DEFAULT_EXPENSE_CATEGORIES = [
  { key:'repairs',   label:'🔧 Repairs & Maintenance' },
  { key:'tolls',     label:'🛣️ Tolls / Scales / Permits' },
  { key:'supplies',  label:'📦 Supplies' },
  { key:'phone',     label:'📱 Phone / Internet' },
  { key:'insurance', label:'🛡️ Insurance' },
  { key:'licensing', label:'📋 Licensing / Fees' },
  { key:'parking',   label:'🅿️ Parking' },
  { key:'other',     label:'📌 Other' }
];

async function getExpenseCategoryConfig() {
  const cfg = (await getSettingKV('expenseCategoryConfigV1', null));
  if (cfg && cfg.categories && Array.isArray(cfg.categories)) return cfg;
  return { categories: [], rules: [] };
}

async function saveExpenseCategoryConfig(cfg) {
  await setSettingKV('expenseCategoryConfigV1', cfg);
}

function normalizeCategoryKey(s) {
  return String(s||'').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'').slice(0,40) || 'custom';
}

function allCategoriesMerged(defaults, custom) {
  const seen = new Set();
  const out = [];
  for (const c of defaults) { if (!seen.has(c.key)) { out.push(c); seen.add(c.key); } }
  for (const c of (custom||[])) { if (c && c.key && !seen.has(c.key)) { out.push(c); seen.add(c.key); } }
  return out;
}

async function refreshCategorySelects() {
  const cfg = await getExpenseCategoryConfig();
  const merged = allCategoriesMerged(DEFAULT_EXPENSE_CATEGORIES, cfg.categories);
  const selExpense = $('expenseCategory');
  const selRule = $('ruleCategory');
  if (selExpense) {
    const current = selExpense.value || 'other';
    // Build options safely (no innerHTML / attribute injection)
    selExpense.textContent = '';
    const fragE = document.createDocumentFragment();
    merged.forEach(c => {
      const opt = document.createElement('option');
      opt.value = String(c.key);
      opt.textContent = String(c.label || c.key);
      fragE.appendChild(opt);
    });
    selExpense.appendChild(fragE);
    if (merged.some(c => c.key === current)) selExpense.value = current;
  }
  if (selRule) {
    const cur = selRule.value || 'other';
    // Build options safely (no innerHTML / attribute injection)
    selRule.textContent = '';
    const fragR = document.createDocumentFragment();
    merged.forEach(c => {
      const opt = document.createElement('option');
      opt.value = String(c.key);
      opt.textContent = String(c.label || c.key);
      fragR.appendChild(opt);
    });
    selRule.appendChild(fragR);
    if (merged.some(c => c.key === cur)) selRule.value = cur;
  }
}


async function renderCategoryManager() {
  const cfg = await getExpenseCategoryConfig();
  const merged = allCategoriesMerged(DEFAULT_EXPENSE_CATEGORIES, cfg.categories);
  await refreshCategorySelects();

  const listEl = $('categoryList');
  if (listEl) {
    const custom = cfg.categories || [];
    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);

    if (!custom.length) {
      const d = document.createElement('div');
      d.style.cssText = 'color:var(--text-secondary);';
      d.textContent = 'No custom categories yet.';
      listEl.appendChild(d);
    } else {
      const frag = document.createDocumentFragment();
      custom.forEach((c, idx) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border);';

        const left = document.createElement('div');
        const b = document.createElement('b');
        b.textContent = String(c.label || c.key || '');
        const key = document.createElement('div');
        key.style.cssText = 'color:var(--text-secondary);';
        key.textContent = 'key: ' + String(c.key || '');
        left.appendChild(b);
        left.appendChild(key);

        const btn = document.createElement('button');
        btn.className = 'btn btn-danger';
        btn.setAttribute('data-cat-idx', String(idx));
        btn.style.cssText = 'padding:6px 10px; font-size:11px;';
        btn.textContent = 'Remove';

        row.appendChild(left);
        row.appendChild(btn);
        frag.appendChild(row);
      });
      listEl.appendChild(frag);
    }
  }

  const ruleEl = $('ruleList');
  if (ruleEl) {
    const rules = cfg.rules || [];
    while (ruleEl.firstChild) ruleEl.removeChild(ruleEl.firstChild);

    if (!rules.length) {
      const d = document.createElement('div');
      d.style.cssText = 'color:var(--text-secondary);';
      d.textContent = 'No rules yet.';
      ruleEl.appendChild(d);
    } else {
      const frag = document.createDocumentFragment();
      rules.forEach((r, idx) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border);';

        const left = document.createElement('div');

        const b = document.createElement('b');
        b.textContent = 'If contains:';
        left.appendChild(b);

        const txt = document.createTextNode(' "' + String(r.contains || '') + '" ');
        left.appendChild(txt);

        const to = document.createElement('div');
        to.style.cssText = 'color:var(--text-secondary);';
        const label = (merged.find(c => c.key === r.category) || {}).label || r.category;
        to.textContent = '→ ' + String(label || '');
        left.appendChild(to);

        const btn = document.createElement('button');
        btn.className = 'btn btn-danger';
        btn.setAttribute('data-rule-idx', String(idx));
        btn.style.cssText = 'padding:6px 10px; font-size:11px;';
        btn.textContent = 'Remove';

        row.appendChild(left);
        row.appendChild(btn);
        frag.appendChild(row);
      });
      ruleEl.appendChild(frag);
    }
  }
}


async function autoCategoryForDesc(desc) {
  const cfg = await getExpenseCategoryConfig();
  const rules = (cfg.rules || []).filter(r => r && r.contains && r.category);
  const d = String(desc||'').toLowerCase();
  for (const r of rules) {
    if (d.includes(String(r.contains).toLowerCase())) return r.category;
  }
  return null;
}

async function saveExpense() {
  const data = {
    category: $('expenseCategory').value,
    amount:   clampMoney($('expenseAmount').value),
    date:     $('expenseDate').value || getTodayStr(),
    desc:     $('expenseDesc').value.trim().substring(0, 200)
  };
  // Optional auto-category rules (only if category is 'other')
  if (data.category === 'other') {
    try { const auto = await autoCategoryForDesc(data.desc); if (auto) data.category = auto; } catch {}
  };
  if (data.amount <= 0) return showToast('Enter expense amount', true);

  // Recurring expense support
  const isRecurring = $('expenseRecurring')?.checked;
  if (isRecurring) {
    const freq = $('recurringFreq')?.value || 'monthly';
    data.recurringId = 'rec_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
    data.recurringFreq = freq;
    // Save recurring template
    try {
      const templates = (await getSettingKV('recurringTemplatesV1', [])) || [];
      templates.push({
        id: data.recurringId,
        category: data.category,
        amount: data.amount,
        desc: data.desc,
        freq: freq,
        lastGenerated: data.date,
        createdAt: Date.now(),
        active: true
      });
      await setSettingKV('recurringTemplatesV1', templates);
    } catch {}
  }

  try {
    const expenseId = await dbOp('expenses', 'readwrite', s => s.add(data));
    if (tempExpenseReceipts.length) {
      try {
        const records = tempExpenseReceipts.map(r => ({
          tripOrderNo: null,
          expenseId,
          timestamp: Date.now(),
          mime: 'image/jpeg',
          blob: r.blob,
          size: r.size,
          width: r.width,
          height: r.height
        }));
        await ReceiptModule.addReceipts(records);
        tempExpenseReceipts = [];
      } catch (qe) {
        showToast('⚠️ Receipt save failed — expense was saved', true);
      }
    }
    $('expenseAmount').value = ''; $('expenseDesc').value = '';
    if ($('expenseRecurring')) $('expenseRecurring').checked = false;
    if ($('recurringOptions')) $('recurringOptions').style.display = 'none';
    showToast(isRecurring ? '💰 Recurring expense saved' : '💰 Expense saved'); refreshUI();
  } catch (e) { showToast('Error saving expense', true); }
}

async function saveMeal() {
  const data = {
    category: 'meals',
    amount:   clampMoney($('mealAmount').value),
    date:     $('mealDate').value || getTodayStr(),
    desc:     $('mealLocation').value.trim().substring(0, 200)
  };
  if (data.amount <= 0) return showToast('Enter meal amount', true);
  try {
    const expenseId = await dbOp('expenses', 'readwrite', s => s.add(data));
    if (tempMealReceipts.length) {
      try {
        const records = tempMealReceipts.map(r => ({
          tripOrderNo: null,
          expenseId,
          timestamp: Date.now(),
          mime: 'image/jpeg',
          blob: r.blob,
          size: r.size,
          width: r.width,
          height: r.height
        }));
        await ReceiptModule.addReceipts(records);
        tempMealReceipts = [];
      } catch (qe) {
        showToast('⚠️ Receipt save failed — meal was saved', true);
      }
    }
    $('mealAmount').value = ''; $('mealLocation').value = '';
    showToast('🍔 Meal saved'); refreshUI();
  } catch (e) { showToast('Error saving meal', true); }
}

// ============================================================================
// RENDER: trip list with DocumentFragment (no innerHTML thrashing)
// ============================================================================
function renderTripCards(trips) {
  const container = $('tripList');
  container.innerHTML = '';

  if (!trips.length) {
    container.appendChild(Render.emptyState('📦', 'No trips found'));
    return;
  }

  const fragment = document.createDocumentFragment();
  const icons = { fuel:'⛽', repairs:'🔧', tolls:'🛣️', meals:'🍔', supplies:'📦', phone:'📱', insurance:'🛡️', licensing:'📋', parking:'🅿️', other:'📌' };

  trips.forEach(t => {
    const clean = sanitizeTripRecord(t);
    if (!clean) return;

    const totalMiles = clean.loadedMiles + clean.emptyMiles;
    const rpm = totalMiles > 0 ? (clean.revenue / totalMiles) : 0;

    const card = document.createElement('div');
    card.className = 'card';

    const inner = document.createElement('div');
    inner.style.flex = '1';

    // Header row
    const header = document.createElement('div');
    header.className = 'card-header';
    const title = document.createElement('div');
    title.className = 'card-title';
    title.textContent = clean.orderNo || 'No #';
    if (clean.customer) {
      const cust = document.createElement('span');
      cust.style.cssText = 'opacity:0.6; font-size:12px;';
      cust.textContent = ' • ' + clean.customer;
      title.appendChild(cust);
    }
    const amount = document.createElement('div');
    amount.className = 'card-amount text-success';
    amount.textContent = formatMoney(clean.revenue);
    header.appendChild(title);
    header.appendChild(amount);

    // Route meta
    const meta1 = document.createElement('div');
    meta1.className = 'card-meta';
    const routeSpan = document.createElement('span');
    routeSpan.textContent = (clean.origin || '?') + ' → ' + (clean.dest || '?');
    const dateSpan = document.createElement('span');
    dateSpan.textContent = clean.pickupDate;
    meta1.appendChild(routeSpan);
    meta1.appendChild(dateSpan);

    const meta2 = document.createElement('div');
    meta2.className = 'card-meta';
    const miSpan = document.createElement('span');
    miSpan.textContent = `${totalMiles} mi (${clean.loadedMiles}L / ${clean.emptyMiles}E)`;
    const rpmSpan = document.createElement('span');
    rpmSpan.style.cssText = 'color:var(--accent-success); font-weight:700;';
    rpmSpan.textContent = formatMoney(rpm) + '/mi';
    meta2.appendChild(miSpan);
    meta2.appendChild(rpmSpan);

    inner.appendChild(header);
    inner.appendChild(meta1);
    inner.appendChild(meta2);

    // Notes badge
    if (clean.notes) {
      const nb = document.createElement('div');
      nb.className = 'card-badge';
      nb.style.color = 'var(--text-secondary)';
      nb.textContent = '📝 ' + clean.notes;
      inner.appendChild(nb);
    }

    // Per diem badge
    if (clean.perDiemAmount > 0) {
      const pb = document.createElement('div');
      pb.className = 'card-badge';
      pb.style.color = 'var(--accent-primary)';
      pb.textContent = `💵 Per Diem: ${formatMoney(clean.perDiemAmount)} (${clean.perDiemDays} days)`;
      inner.appendChild(pb);
    }

    // MARGIN BADGE — uses actualCPM computed by refreshCommandCenter
    const marginPct = calculateTripMargin(clean, actualCPM);
    const marginBadge = getMarginBadge(marginPct);
    inner.appendChild(marginBadge);

    // Paid badge
    const paidBadge = document.createElement('div');
    paidBadge.className = 'card-badge';
    if (clean.paid) {
      paidBadge.style.cssText = 'background:rgba(105,240,174,0.2); color:var(--accent-success); border:1px solid var(--accent-success);';
      paidBadge.textContent = '✓ Paid';
    } else {
      paidBadge.style.cssText = 'background:rgba(255,167,38,0.1); color:var(--accent-warning); border:1px solid rgba(255,167,38,0.3);';
      paidBadge.textContent = '⏳ Unpaid';
    }
    inner.appendChild(paidBadge);

    // Actions row
    const actions = document.createElement('div');
    actions.className = 'card-actions';
    const delBtn = document.createElement('button');
    delBtn.className = 'card-action-btn delete';
    delBtn.textContent = '🗑️ Delete';
    delBtn.addEventListener('click', () => confirmDeleteRecord('trips', clean.orderNo, 'trip'));
    actions.appendChild(delBtn);

    // Quick-toggle paid/unpaid
    const paidToggle = document.createElement('button');
    paidToggle.type = 'button';
    paidToggle.className = 'card-action-btn';
    paidToggle.style.color = clean.paid ? 'var(--accent-warning)' : 'var(--accent-success)';
    paidToggle.style.borderColor = clean.paid ? 'rgba(255,167,38,0.3)' : 'rgba(105,240,174,0.3)';
    paidToggle.textContent = clean.paid ? '↩ Unpaid' : '✓ Paid';
    paidToggle.addEventListener('click', async () => {
      try {
        const trip = await dbOp('trips', 'readonly', s => s.get(clean.orderNo));
        if (trip) {
          trip.paid = !trip.paid;
          trip.paidDate = trip.paid ? (trip.paidDate || Date.now()) : null;
          await dbOp('trips', 'readwrite', s => s.put(trip));
          showToast(trip.paid ? '✓ Marked Paid' : '↩ Marked Unpaid');
          refreshUI();
        }
      } catch (e) { showToast('Error updating trip', true); }
    });
    actions.appendChild(paidToggle);
    inner.appendChild(actions);

    // Bulk checkbox
    if (bulkMode) {
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'trip-checkbox';
      cb.checked = selectedTrips.has(clean.orderNo);
      cb.addEventListener('change', () => toggleTripSelection(clean.orderNo));
      card.appendChild(cb);
    }

    card.appendChild(inner);
    fragment.appendChild(card);
  });

  container.appendChild(fragment);
}

// ============================================================================
// MAIN REFRESH
// ============================================================================
async function refreshUI() {
  
  // Cache invalidation on data changes
  try { MemoCache.invalidate('ar-'); } catch (_) {}
try {
    const rawTrips  = await dbOp('trips', 'readonly', s => s.getAll());
    let fuel      = await dbOp('fuel', 'readonly', s => s.getAll());
    let expenses  = await dbOp('expenses', 'readonly', s => s.getAll());
    const taxRateSetting = await dbOp('settings', 'readonly', s => s.get('incomeTaxRate'));
    const incomeTaxRate  = taxRateSetting ? safeFloat(taxRateSetting.value) : 22;

    // Baseline MPG settings (for anomaly display)
    try {
      const b = await dbOp('settings', 'readonly', s => s.get('baselineMPG'));
      const p = await dbOp('settings', 'readonly', s => s.get('mpgAlertPct'));
      baselineMPGValue = b && b.value != null ? safeFloat(b.value) : 18;
      mpgAlertPctValue = p && p.value != null ? safeFloat(p.value) : 20;
    } catch (_) {}

    const trips = rawTrips.filter(isActiveRecord).map(sanitizeTripRecord).filter(Boolean);

    const activeFuel = fuel.filter(isActiveRecord);
    const activeExpenses = expenses.filter(isActiveRecord);
    fuel = activeFuel;
    expenses = activeExpenses;

    // Update customer filter dropdown (DOM-safe)
    const customers = [...new Set(trips.map(t => t.customer).filter(c => c && c.trim()))].sort();
    const sel = $('filterCustomer');
    if (sel) {
      const curCust = sel.value;
      sel.textContent = '';
      const optAll = document.createElement('option');
      optAll.value = '';
      optAll.textContent = 'All Customers';
      sel.appendChild(optAll);

      const frag = document.createDocumentFragment();
      customers.forEach(c => {
        const opt = document.createElement('option');
        opt.value = String(c);
        opt.textContent = String(c);
        if (c === curCust) opt.selected = true;
        frag.appendChild(opt);
      });
      sel.appendChild(frag);
    }

    updateCustomerAutocomplete();

    // Sort
    trips.sort((a, b) => {
      const ad = a.pickupDate || '', bd = b.pickupDate || '';
      if (ad !== bd) return bd.localeCompare(ad);
      return (b.created || 0) - (a.created || 0);
    });

    const filteredTrips = filterTrips(trips);
    const totalPages    = Math.max(1, Math.ceil(filteredTrips.length / PAGE_SIZE));
    currentPage = Math.min(currentPage, totalPages);

    const pageTrips = filteredTrips.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

    // Render trip cards (DocumentFragment — no innerHTML thrashing)
    renderTripCards(pageTrips);

    // Pagination
    const pagEl = $('tripPagination');
    if (filteredTrips.length > PAGE_SIZE) {
      pagEl.style.display = 'flex';
      $('paginationInfo').textContent = `Page ${currentPage} of ${totalPages} (${filteredTrips.length} trips)`;
      $('btnPrevPage').disabled = currentPage <= 1;
      $('btnNextPage').disabled = currentPage >= totalPages;
    } else {
      pagEl.style.display = 'none';
    }

    // Expense list (DocumentFragment)
    const allExpenses = [];
    fuel.forEach(f => allExpenses.push({ type:'fuel', date:f.date, amount:f.amount, desc:f.location, gallons:f.gallons, id:f.id, store:'fuel' }));
    expenses.forEach(e => allExpenses.push({ type:e.category, date:e.date, amount:e.amount, desc:e.desc, id:e.id, store:'expenses' }));
    allExpenses.sort((a, b) => (b.date || '').localeCompare(a.date || ''));

    const expContainer = $('expenseList');
    expContainer.innerHTML = '';

    if (!allExpenses.length) {
      expContainer.appendChild(Render.emptyState('💸', 'No expenses yet'));
    } else {
      const expFrag = document.createDocumentFragment();
      const icons = { fuel:'⛽', repairs:'🔧', tolls:'🛣️', meals:'🍔', supplies:'📦', phone:'📱', insurance:'🛡️', licensing:'📋', parking:'🅿️', other:'📌' };

      allExpenses.slice(0, 20).forEach(e => {
        const card = document.createElement('div');
        card.className = 'card ' + (e.type === 'fuel' ? 'fuel' : 'expense');

        const inner = document.createElement('div');
        inner.style.flex = '1';

        const hdr = document.createElement('div');
        hdr.className = 'card-header';
        const ttl = document.createElement('div');
        ttl.className = 'card-title';
        ttl.textContent = (icons[e.type] || '💸') + ' ' + (e.type.charAt(0).toUpperCase() + e.type.slice(1));
        const amt = document.createElement('div');
        amt.className = 'card-amount';
        amt.style.color = e.type === 'fuel' ? 'var(--accent-primary)' : 'var(--accent-danger)';
        amt.textContent = formatMoney(e.amount);
        hdr.appendChild(ttl); hdr.appendChild(amt);

        const meta = document.createElement('div');
        meta.className = 'card-meta';
        const descS = document.createElement('span');
        descS.textContent = e.desc || '-';
        const dateS = document.createElement('span');
        dateS.textContent = e.date;
        meta.appendChild(descS); meta.appendChild(dateS);

        inner.appendChild(hdr); inner.appendChild(meta);

        if (e.gallons && e.gallons > 0) {
          const ppg = (e.amount / e.gallons).toFixed(2);
          const badge = document.createElement('div');
          badge.className = 'card-badge';
          badge.style.color = 'var(--accent-info)';
          badge.textContent = `${e.gallons} gal @ $${ppg}/gal`;
          inner.appendChild(badge);
        }

        const actions = document.createElement('div');
        actions.className = 'card-actions';
        const del = document.createElement('button');
        del.className = 'card-action-btn delete';
        del.textContent = '🗑️ Delete';
        const capturedStore = e.store, capturedId = e.id;
        del.addEventListener('click', () => confirmDeleteRecord(capturedStore, capturedId, e.type));
        actions.appendChild(del);
        inner.appendChild(actions);
        card.appendChild(inner);
        expFrag.appendChild(card);
      });

      expContainer.appendChild(expFrag);
    }

    await refreshCommandCenter(trips, fuel, expenses);

    // v10.1.1: Refresh dashboard
    try { await refreshDashboard(); } catch {}

  } catch (e) {
    console.error('[UI] Refresh error:', e);
  }
}

// ============================================================================
// ANALYTICS
// ============================================================================
function calculateAnalytics(trips, fuel, expenses, incomeTaxRate = 22) {
  let totalRev = 0, totalMiles = 0, totalPerDiem = 0, totalPerDiemDays = 0;
  trips.forEach(t => {
    totalRev        += safeFloat(t.revenue);
    totalMiles      += safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles);
    totalPerDiem    += safeFloat(t.perDiemAmount);
    totalPerDiemDays += safeFloat(t.perDiemDays);
  });

  const totalFuelCost  = fuel.reduce((s, f) => s + safeFloat(f.amount), 0);
  const totalGallons   = fuel.reduce((s, f) => s + safeFloat(f.gallons), 0);
  // FIXED: 50% for actual meal receipts (IRC §274(n)), not 80%
  const mealExpenses   = expenses.filter(e => e.category === 'meals').reduce((s, e) => s + safeFloat(e.amount), 0);
  const otherExpenses  = expenses.filter(e => e.category !== 'meals').reduce((s, e) => s + safeFloat(e.amount), 0);

  const avgMPG = totalGallons && totalMiles ? totalMiles / totalGallons : 0;
  const avgPPG = totalGallons ? totalFuelCost / totalGallons : 0;

  const mileageDeduction = totalMiles * irsMileageRate;
  // FIXED: 50% deduction for actual meal receipts
  const mealDeduction    = mealExpenses * 0.50;
  // Per diem at 80% for DOT workers (this is correct for the per diem method)
  const perDiemDeduction = totalPerDiem * 0.80;

  let vehicleDeduction, fuelDeductionUsed = 0, mileageDeductionUsed = 0;
  if (deductionMethod === 'standard') {
    vehicleDeduction     = mileageDeduction;
    mileageDeductionUsed = mileageDeduction;
  } else {
    vehicleDeduction  = totalFuelCost;
    fuelDeductionUsed = totalFuelCost;
  }

  const totalDeductions = vehicleDeduction + mealDeduction + perDiemDeduction + otherExpenses;
  const grossProfit     = totalRev - totalDeductions;

  const seTaxBase    = Math.max(0, grossProfit);
  const seTax        = seTaxBase * 0.9235 * 0.153;
  const taxableIncome = Math.max(0, grossProfit - (seTax * 0.5));
  const incomeTax    = taxableIncome * (safeFloat(incomeTaxRate) / 100);
  const totalTax     = seTax + incomeTax;

  return {
    totalRev, totalMiles, totalFuelCost, totalGallons, avgMPG, avgPPG,
    mileageDeduction: mileageDeductionUsed,
    mealDeduction, perDiemDeduction, otherExpenses,
    fuelDeduction: fuelDeductionUsed,
    totalDeductions, grossProfit, totalTax, totalPerDiemDays,
    seTax, incomeTax, isLoss: grossProfit <= 0
  };
}



// ============================================================================
// COMMAND CENTER
// ============================================================================
async function refreshCommandCenter(preTrips, preFuel, preExpenses) {
  try {
    const trips = preTrips || await dbOp('trips', 'readonly', s => s.getAll());
    const fuel = preFuel || await dbOp('fuel', 'readonly', s => s.getAll());
    const expenses = preExpenses || await dbOp('expenses', 'readonly', s => s.getAll());
    const taxSetting = await dbOp('settings', 'readonly', s => s.get('incomeTaxRate'));
    const taxRate = taxSetting ? safeFloat(taxSetting.value) : 22;
    
    const analytics = calculateAnalytics(trips, fuel, expenses, taxRate);
    
    // YTD Net Profit
    const profitCard = $('ccProfit');
    $('ccProfitVal').textContent = formatMoney(analytics.grossProfit);
    profitCard.classList.remove('cc-warn', 'cc-good');
    if (analytics.grossProfit < 0) {
      profitCard.classList.add('cc-warn');
      $('ccProfitSub').textContent = 'Operating at a loss';
    } else {
      profitCard.classList.add('cc-good');
      $('ccProfitSub').textContent = `+${((analytics.grossProfit / (analytics.totalRev || 1)) * 100).toFixed(1)}% margin`;
    }
    
    // Unpaid Revenue
    const unpaidTrips = trips.filter(t => !t.paid);
    const unpaidRev = unpaidTrips.reduce((s, t) => s + safeFloat(t.revenue), 0);
    const unpaidPct = analytics.totalRev > 0 ? (unpaidRev / analytics.totalRev) * 100 : 0;
    $('ccUnpaidVal').textContent = formatMoney(unpaidRev);
    $('ccUnpaidSub').textContent = `${unpaidTrips.length} trips (${unpaidPct.toFixed(0)}%)`;
    
    // 30-day RPM
    const today = new Date();
    const thirtyDaysAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
    const recentTrips = trips.filter(t => {
      const d = new Date(t.pickupDate + 'T00:00:00');
      return d >= thirtyDaysAgo;
    });
    let recentRev = 0, recentMiles = 0;
    recentTrips.forEach(t => {
      recentRev += safeFloat(t.revenue);
      recentMiles += safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles);
    });
    const rpm30 = recentMiles > 0 ? recentRev / recentMiles : 0;
    $('ccRPMVal').textContent = formatMoney(rpm30);
    $('ccRPMSub').textContent = `${recentTrips.length} trips, ${recentMiles.toFixed(0)} mi`;
    
    // Cost per Mile
    const totalFuel = fuel.reduce((s, f) => s + safeFloat(f.amount), 0);
    const totalExp = expenses.reduce((s, e) => s + safeFloat(e.amount), 0);
    const totalCosts = totalFuel + totalExp;
    const cpm = analytics.totalMiles > 0 ? totalCosts / analytics.totalMiles : 0;
    actualCPM = cpm > 0 ? cpm : 0.50; // Update module-level CPM for margin badges
    $('ccCPMVal').textContent = formatMoney(cpm);
    
    // Update header tone
    updateHeaderTone(unpaidPct, analytics.grossProfit);
    
  } catch (e) {
    console.error('[CommandCenter] Error:', e);
  }
}

function updateHeaderTone(unpaidPct, profit) {
  const header = $('appHeader');
  header.classList.remove('unpaid-alert', 'loss-alert');
  if (profit < 0) {
    header.classList.add('loss-alert');
  } else if (unpaidPct > 20) {
    header.classList.add('unpaid-alert');
  }
}

// ============================================================================
// A/R AGING
// ============================================================================
async function refreshARPanel() {
  // PERFORMANCE: Check cache first
  const cacheKey = 'ar-panel';
  const cached = MemoCache.get(cacheKey);
  if (cached) {
    renderARPanel(cached);
    return;
  }
  
  try {
    const trips = await dbOp('trips', 'readonly', s => s.getAll());
    const unpaidTrips = trips.filter(t => !t.paid);
    
    const data = {
      aging: calculateAgingBuckets(unpaidTrips),
      slowPayers: findSlowPayers(trips),
      unpaidTrips
    };
    
    MemoCache.set(cacheKey, data, 300000); // 5min cache
    renderARPanel(data);
    // v10.1.1: Refresh customer rate history when AR tab loads
    try { refreshCustomerRateHistory(); } catch {}
  } catch (e) {
    console.error('[AR] Error:', e);
  }
}

function renderARPanel(data) {
  const aging = data.aging;
    
    $('ar030Val').textContent = formatMoney(aging.bucket030.amount);
    $('ar030Count').textContent = `${aging.bucket030.count} trips`;
    
    $('ar3060Val').textContent = formatMoney(aging.bucket3060.amount);
    $('ar3060Count').textContent = `${aging.bucket3060.count} trips`;
    
    $('ar60Val').textContent = formatMoney(aging.bucket60.amount);
    $('ar60Count').textContent = `${aging.bucket60.count} trips`;
    
    $('arTotalVal').textContent = formatMoney(aging.total);
    
    // Slow payers
    const slowPayers = data.slowPayers;
    const spList = $('slowPayerList');
    spList.innerHTML = '';
    
    if (slowPayers.length === 0) {
      spList.appendChild(Render.emptyPanel('No slow payers identified'));
    } else {
      slowPayers.slice(0, 10).forEach(sp => {
        const div = document.createElement('div');
        div.className = 'slow-payer-item';
        
        const leftDiv = document.createElement('div');
        const nameDiv = document.createElement('div');
        nameDiv.className = 'slow-payer-name';
        nameDiv.textContent = sp.customer;
        const metaDiv = document.createElement('div');
        metaDiv.className = 'slow-payer-meta';
        metaDiv.textContent = `${sp.paidCount} paid trips • ${formatMoney(sp.totalRevenue)} total`;
        leftDiv.appendChild(nameDiv);
        leftDiv.appendChild(metaDiv);
        
        const rightDiv = document.createElement('div');
        rightDiv.className = 'slow-payer-days';
        rightDiv.textContent = `${sp.avgDays.toFixed(0)} days avg`;
        
        div.appendChild(leftDiv);
        div.appendChild(rightDiv);
        spList.appendChild(div);
      });
    }
    
    // Unpaid trip detail
    const arList = $('arTripList');
    arList.innerHTML = '';
    
    if (data.unpaidTrips.length === 0) {
      arList.appendChild(Render.emptyPanel('No unpaid trips'));
    } else {
      const sorted = data.unpaidTrips.map(t => {
        const age = Math.floor((Date.now() - new Date(t.pickupDate + 'T00:00:00').getTime()) / 86400000);
        return { ...t, age };
      }).sort((a, b) => b.age - a.age);
      
      sorted.slice(0, 20).forEach(t => {
        const div = document.createElement('div');
        div.className = 'customer-profit-item';
        let ageColor = 'var(--accent-success)';
        if (t.age > 60) ageColor = 'var(--accent-danger)';
        else if (t.age > 30) ageColor = 'var(--accent-warning)';
        
        const leftDiv = document.createElement('div');
        const nameDiv = document.createElement('div');
        nameDiv.className = 'customer-profit-name';
        nameDiv.textContent = t.orderNo;
        const statsDiv = document.createElement('div');
        statsDiv.className = 'customer-profit-stats';
        statsDiv.textContent = `${t.customer || 'Unknown'} • ${t.pickupDate}`;
        leftDiv.appendChild(nameDiv);
        leftDiv.appendChild(statsDiv);
        
        const rightDiv = document.createElement('div');
        rightDiv.style.textAlign = 'right';
        const ageDiv = document.createElement('div');
        ageDiv.style.cssText = `font-size:16px; font-weight:800; font-family:'Monaco',monospace; color:${ageColor};`;
        ageDiv.textContent = `${t.age} days`;
        const revDiv = document.createElement('div');
        revDiv.style.cssText = 'font-size:13px; color:var(--text-secondary);';
        revDiv.textContent = formatMoney(t.revenue);
        rightDiv.appendChild(ageDiv);
        rightDiv.appendChild(revDiv);
        
        div.appendChild(leftDiv);
        div.appendChild(rightDiv);
        arList.appendChild(div);
      });
    }
}


function calculateAgingBuckets(unpaidTrips) {
  const buckets = {
    bucket030: { count: 0, amount: 0 },
    bucket3060: { count: 0, amount: 0 },
    bucket60: { count: 0, amount: 0 },
    total: 0
  };
  
  unpaidTrips.forEach(t => {
    const age = Math.floor((Date.now() - new Date(t.pickupDate + 'T00:00:00').getTime()) / 86400000);
    const rev = safeFloat(t.revenue);
    
    if (age <= 30) {
      buckets.bucket030.count++;
      buckets.bucket030.amount += rev;
    } else if (age <= 60) {
      buckets.bucket3060.count++;
      buckets.bucket3060.amount += rev;
    } else {
      buckets.bucket60.count++;
      buckets.bucket60.amount += rev;
    }
    buckets.total += rev;
  });
  
  return buckets;
}

function findSlowPayers(trips) {
  const customerData = {};
  
  trips.filter(t => t.paid).forEach(t => {
    const cust = t.customer || 'Unknown';
    if (!customerData[cust]) {
      customerData[cust] = { totalDays: 0, paidCount: 0, totalRevenue: 0 };
    }
    
    const pickup = new Date(t.pickupDate + 'T00:00:00');
    // Use paidDate if available (v9.8.0+), otherwise estimate conservatively
    // using deliveryDate + 30 as a rough proxy for pre-v9.8.0 data
    let payDate;
    if (t.paidDate) {
      payDate = new Date(typeof t.paidDate === 'number' ? t.paidDate : t.paidDate + 'T00:00:00');
    } else if (t.deliveryDate) {
      payDate = new Date(t.deliveryDate + 'T00:00:00');
      payDate.setDate(payDate.getDate() + 30); // estimate: paid ~30 days after delivery
    } else {
      payDate = new Date(); // fallback
    }
    const daysToPayment = Math.max(0, Math.floor((payDate.getTime() - pickup.getTime()) / 86400000));
    
    customerData[cust].totalDays += daysToPayment;
    customerData[cust].paidCount++;
    customerData[cust].totalRevenue += safeFloat(t.revenue);
  });
  
  const slowPayers = Object.entries(customerData)
    .map(([customer, data]) => ({
      customer,
      avgDays: data.paidCount > 0 ? data.totalDays / data.paidCount : 0,
      paidCount: data.paidCount,
      totalRevenue: data.totalRevenue
    }))
    .filter(sp => sp.avgDays > 45 && sp.paidCount >= 3)
    .sort((a, b) => b.avgDays - a.avgDays);
  
  return slowPayers;
}

// ============================================================================
// LOAD SIMULATOR
// ============================================================================
async function runLoadSimulator() {
  const rate = safeFloat($('simRate').value);
  const loaded = safeFloat($('simLoaded').value);
  const deadhead = safeFloat($('simDeadhead').value);
  const mpg = safeFloat($('simMPG').value);
  const fuelPrice = safeFloat($('simFuelPrice').value);
  
  if (rate <= 0 || loaded <= 0 || mpg <= 0 || fuelPrice <= 0) {
    return showToast('Fill all fields with valid numbers', true);
  }
  
  const totalMiles = loaded + deadhead;
  const fuelCost = (totalMiles / mpg) * fuelPrice;
  const net = rate - fuelCost;
  const rpm = totalMiles > 0 ? rate / totalMiles : 0;
  if (totalMiles === 0) {
    showToast('Total miles cannot be zero', true);
    return;
  }
  const netMargin = (net / rate) * 100;
  
  $('simRevenue').textContent = formatMoney(rate);
  $('simFuelCost').textContent = formatMoney(fuelCost);
  $('simNet').textContent = formatMoney(net);
  $('simRPM').textContent = formatMoney(rpm);
  
  // Get break-even RPM if available
  let breakEvenRPM = 0;
  try {
    const be = await dbOp('settings', 'readonly', s => s.get('breakEvenRPM'));
    if (be && be.value) breakEvenRPM = safeFloat(be.value);
  } catch (e) {}
  
  const verdict = getSimulatorVerdict(netMargin, rpm, breakEvenRPM);
  const verdictEl = $('simVerdict');
  verdictEl.className = 'sim-verdict ' + verdict.css;
  verdictEl.innerHTML = '';
    const iconDiv = document.createElement('div');
    iconDiv.style.cssText = 'font-size:20px; margin-bottom:8px;';
    iconDiv.textContent = verdict.emoji;
    const titleDiv = document.createElement('div');
        const strong = document.createElement('strong');
    strong.textContent = String(verdict.title ?? '');
    titleDiv.textContent = '';
    titleDiv.appendChild(strong);
const msgDiv = document.createElement('div');
    msgDiv.style.cssText = 'font-size:12px; margin-top:6px; opacity:0.8;';
    msgDiv.textContent = verdict.message;
    verdictEl.appendChild(iconDiv);
    verdictEl.appendChild(titleDiv);
    verdictEl.appendChild(msgDiv);
  
  const fillEl = $('simMarginFill');
  fillEl.style.width = Math.min(netMargin, 100) + '%';
  fillEl.style.background = verdict.color;
  
  $('simResults').style.display = 'block';
}

function getSimulatorVerdict(netMargin, rpm, breakEvenRPM) {
  if (netMargin >= 30 && (breakEvenRPM === 0 || rpm >= breakEvenRPM * 1.2)) {
    return {
      css: 'accept',
      emoji: '✅',
      title: 'ACCEPT',
      message: `Strong ${netMargin.toFixed(0)}% margin with good safety cushion`,
      color: 'var(--accent-success)'
    };
  }
  
  if (netMargin >= 15 && (breakEvenRPM === 0 || rpm >= breakEvenRPM)) {
    return {
      css: 'caution',
      emoji: '⚠️',
      title: 'PROCEED WITH CAUTION',
      message: `Acceptable ${netMargin.toFixed(0)}% margin but tight. Watch for delays.`,
      color: 'var(--accent-warning)'
    };
  }
  
  return {
    css: 'reject',
    emoji: '🚫',
    title: 'REJECT',
    message: netMargin < 0 
      ? 'Loses money even before other expenses'
      : `Only ${netMargin.toFixed(0)}% margin after fuel — too thin`,
    color: 'var(--accent-danger)'
  };
}

// ============================================================================
// BREAK-EVEN CALCULATOR
// ============================================================================
async function calculateBreakEven() {
  const insurance = safeFloat($('beInsurance').value);
  const payment = safeFloat($('beTruckPayment').value);
  const otherFixed = safeFloat($('beOtherFixed').value);
  const avgMiles = safeFloat($('beAvgMiles').value);
  
  if (avgMiles <= 0) {
    return showToast('Enter average miles per month', true);
  }
  
  const totalFixed = insurance + payment + otherFixed;
  const breakEvenRPM = totalFixed / avgMiles;
  
  // Save for simulator reference
  try {
    await dbOp('settings', 'readwrite', s => s.put({ key: 'breakEvenRPM', value: breakEvenRPM }));
  } catch (e) {}
  
  // Get actual RPM
  let actualRPM = 0;
  const rpmEl = $('ccRPMVal');
  if (rpmEl && rpmEl.textContent) {
    actualRPM = safeFloat(rpmEl.textContent.replace(/[$,]/g, ''));
  }
  
  const resultDiv = $('breakEvenResult');
  resultDiv.style.display = 'block';
  
  const compClass = actualRPM >= breakEvenRPM ? 'be-ok' : 'be-warning';
  const icon = actualRPM >= breakEvenRPM ? '✅' : '⚠️';
  const msg = actualRPM >= breakEvenRPM 
    ? `You're ${formatMoney(actualRPM - breakEvenRPM)} above break-even. Good cushion.`
    : `You're ${formatMoney(breakEvenRPM - actualRPM)} below break-even. Need higher rates or lower costs.`;
  
  resultDiv.innerHTML = '';
  const container = document.createElement('div');
  container.className = 'breakeven-result';
  const titleEl = document.createElement('div');
  titleEl.style.cssText = 'font-size:12px; color:var(--text-tertiary); margin-bottom:8px;';
  titleEl.textContent = 'REQUIRED RPM TO BREAK EVEN';
  const valueEl = document.createElement('div');
  valueEl.className = 'be-rpm';
  valueEl.style.color = 'var(--accent-primary)';
  valueEl.textContent = formatMoney(breakEvenRPM);
  const compEl = document.createElement('div');
  compEl.className = 'be-comparison';
  compEl.textContent = `Fixed: ${formatMoney(totalFixed)}/mo ÷ ${avgMiles.toLocaleString()} mi`;
  container.appendChild(titleEl);
  container.appendChild(valueEl);
  container.appendChild(compEl);
  resultDiv.appendChild(container);

  if (actualRPM > 0) {
    const statusEl = document.createElement('div');
    statusEl.className = compClass;
    const statusIcon = document.createElement('span');
    statusIcon.textContent = icon + ' ';
    const statusStrong = document.createElement('strong');
    statusStrong.textContent = `Actual RPM (30d): ${formatMoney(actualRPM)}`;
    const statusBr = document.createElement('br');
    const statusMsg = document.createTextNode(msg);
    statusEl.appendChild(statusIcon);
    statusEl.appendChild(statusStrong);
    statusEl.appendChild(statusBr);
    statusEl.appendChild(statusMsg);
    resultDiv.appendChild(statusEl);
  }
  
  showToast(`Break-even RPM: ${formatMoney(breakEvenRPM)}`);
}

// ============================================================================
// MARGIN BADGES FOR TRIP CARDS
// ============================================================================
function calculateTripMargin(trip, cpm) {
  const rev = safeFloat(trip.revenue);
  const miles = safeFloat(trip.loadedMiles) + safeFloat(trip.emptyMiles);
  if (rev <= 0 || miles <= 0) return 0;
  
  const estimatedCost = miles * cpm;
  const net = rev - estimatedCost;
  return (net / rev) * 100;
}

function getMarginBadge(marginPct) {
  const badge = document.createElement('div');
  badge.className = 'margin-badge';
  
  if (marginPct >= 40) {
    badge.classList.add('margin-high');
    badge.textContent = '▲ High Margin';
  } else if (marginPct >= 25) {
    badge.classList.add('margin-avg');
    badge.textContent = '■ Average';
  } else {
    badge.classList.add('margin-low');
    badge.textContent = '▼ Low Margin';
  }
  
  return badge;
}

async function refreshSummary() {
  try {
    const trips      = await dbOp('trips', 'readonly', s => s.getAll());
    const fuel       = await dbOp('fuel', 'readonly', s => s.getAll());
    const expenses   = await dbOp('expenses', 'readonly', s => s.getAll());
    const taxSetting = await dbOp('settings', 'readonly', s => s.get('incomeTaxRate'));
    const taxRate    = taxSetting ? safeFloat(taxSetting.value) : 22;
    const a          = calculateAnalytics(trips, fuel, expenses, taxRate);

    $('summaryRevenue').textContent = formatMoney(a.totalRev);
    $('summaryMiles').textContent   = Math.round(a.totalMiles);
    $('summaryProfit').textContent  = formatMoney(a.grossProfit);
    $('summaryTax').textContent     = a.isLoss ? '$0.00' : formatMoney(a.totalTax);
    $('taxLossNotice').style.display = a.isLoss ? 'block' : 'none';
    $('summaryMPG').textContent     = a.avgMPG ? a.avgMPG.toFixed(1) : '-';
    // MPG anomaly vs baseline
    try {
      const deltaEl = $('summaryMPGDelta');
      if (deltaEl) {
        if (!a.avgMPG || !baselineMPGValue) { deltaEl.textContent = ''; }
        else {
          const pct = ((a.avgMPG - baselineMPGValue) / baselineMPGValue) * 100;
          const pctAbs = Math.abs(pct);
          const sign = pct >= 0 ? '+' : '-';
          const alert = (pct < 0 && pctAbs >= mpgAlertPctValue);
          deltaEl.textContent = `${sign}${pctAbs.toFixed(0)}% vs baseline (${baselineMPGValue.toFixed(1)} mpg)`;
          deltaEl.style.color = alert ? 'var(--accent-danger)' : 'var(--text-secondary)';
        }
      }
    } catch (_) {}
    $('summaryPPG').textContent     = a.avgPPG ? '$' + a.avgPPG.toFixed(2) : '$0.00';
    $('summaryGallons').textContent = Math.round(a.totalGallons);

    // Expense breakdown
    const cats = {};
    expenses.forEach(e => { if (!cats[e.category]) cats[e.category] = 0; cats[e.category] += safeFloat(e.amount); });
    cats['fuel'] = a.totalFuelCost;
    const catLabels = { fuel:'⛽ Fuel', repairs:'🔧 Repairs', tolls:'🛣️ Tolls', meals:'🍔 Meals', supplies:'📦 Supplies', phone:'📱 Phone', insurance:'🛡️ Insurance', licensing:'📋 Licensing', parking:'🅿️ Parking', other:'📌 Other' };

    const bd = $('expenseBreakdown');
    bd.innerHTML = '';
    Object.keys(cats).forEach(c => {
      const row = document.createElement('div');
      row.className = 'summary-row';
      const lbl = document.createElement('span');
      lbl.className = 'label';
      lbl.textContent = catLabels[c] || c;
      const val = document.createElement('span');
      val.className = 'value';
      val.textContent = formatMoney(cats[c]);
      row.appendChild(lbl); row.appendChild(val);
      bd.appendChild(row);
    });
    if (!Object.keys(cats).length) { bd.innerHTML = ''; const p = document.createElement('p'); p.style.cssText='text-align:center;opacity:0.5;'; p.textContent='No expenses'; bd.appendChild(p); }

    $('deductionMileage').textContent  = formatMoney(a.mileageDeduction);
    $('deductionFuel').textContent     = formatMoney(a.fuelDeduction);
    $('deductionMeals').textContent    = formatMoney(a.mealDeduction);
    $('deductionPerDiem').textContent  = formatMoney(a.perDiemDeduction);

    // Meals vs Per Diem double-dip warning
    const ddWarn = $('mealsPerDiemWarning');
    if (ddWarn) ddWarn.style.display = (a.mealDeduction > 0 && a.perDiemDeduction > 0) ? 'block' : 'none';
    $('deductionOther').textContent    = formatMoney(a.otherExpenses);
    $('deductionTotal').textContent    = formatMoney(a.totalDeductions);
    $('perDiemDaysTotal').textContent  = a.totalPerDiemDays;
    $('taxNetProfit').textContent      = formatMoney(a.grossProfit);
    $('taxSE').textContent             = formatMoney(a.seTax);
    $('taxIncome').textContent         = formatMoney(a.incomeTax);
    $('taxTotal').textContent          = formatMoney(a.totalTax);
    $('taxRateDisplay').textContent    = taxRate.toFixed(1);
  } catch (e) { console.error('[Summary] Error:', e); }
}

// ============================================================================
// REPORT GENERATION
// ============================================================================
function renderCustomerProfitReport(customers) {
  const container = document.createElement('div');
  customers.forEach(c => {
    const item = document.createElement('div');
    item.className = 'customer-profit-item';
    
    const left = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'customer-profit-name';
    name.textContent = c.customer;
    
    const stats = document.createElement('div');
    stats.className = 'customer-profit-stats';
    stats.textContent = `${c.trips} trips • ${c.avgMiles.toFixed(0)} avg mi`;
    
    left.appendChild(name);
    left.appendChild(stats);
    
    const right = document.createElement('div');
    right.className = 'customer-profit-rpm';
    right.textContent = formatMoney(c.rpm);
    
    item.appendChild(left);
    item.appendChild(right);
    container.appendChild(item);
  });
  return container;
}


async function generateReport() {
  const period = $('reportPeriod').value;
  const today  = new Date();
  let dateFrom, dateTo;

  if (period === 'week') {
    const ws = new Date(today); ws.setDate(today.getDate() - today.getDay()); ws.setHours(0,0,0,0);
    dateFrom = ws.toISOString().split('T')[0]; dateTo = getTodayStr();
  } else if (period === 'month') {
    dateFrom = new Date(today.getFullYear(), today.getMonth(), 1).toISOString().split('T')[0]; dateTo = getTodayStr();
  } else if (period === 'quarter') {
    const qMonth = Math.floor(today.getMonth() / 3) * 3;
    dateFrom = new Date(today.getFullYear(), qMonth, 1).toISOString().split('T')[0]; dateTo = getTodayStr();
  } else if (period === 'year') {
    const y = new Date(today); y.setFullYear(today.getFullYear() - 1);
    dateFrom = y.toISOString().split('T')[0]; dateTo = getTodayStr();
  } else if (period === 'ytd') {
    dateFrom = today.getFullYear() + '-01-01'; dateTo = getTodayStr();
  } else if (period === 'custom') {
    dateFrom = $('reportDateFrom').value; dateTo = $('reportDateTo').value;
    if (!dateFrom || !dateTo) return showToast('Select date range', true);
  } else {
    dateFrom = '1900-01-01'; dateTo = '2100-12-31';
  }

  // Update command center range label
  const rangeLabel = $('reportRangeText');
  if (rangeLabel) rangeLabel.textContent = `Period: ${dateFrom} → ${dateTo}`;


  const trips    = await dbOp('trips', 'readonly', s => s.getAll());
  const filtered = trips.filter(t => { const d = t.pickupDate || ''; return d >= dateFrom && d <= dateTo; });
  if (!filtered.length) { $('reportSummary').style.display = 'none'; $('reportCommandLayout').style.display = 'none'; return showToast('No trips in selected period', true); }

  let totalRevenue = 0, totalMiles = 0;
  filtered.forEach(t => { totalRevenue += safeFloat(t.revenue); totalMiles += safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles); });
  const avgRPM = totalMiles > 0 ? totalRevenue / totalMiles : 0;

  $('reportRevenue').textContent = formatMoney(totalRevenue);
  $('reportMiles').textContent   = totalMiles.toFixed(0) + ' mi';
  $('reportRPM').textContent     = formatMoney(avgRPM) + '/mi';
  $('reportTrips').textContent   = filtered.length;

  // Customer profitability
  const custData = {};
  filtered.forEach(t => {
    const c = t.customer || 'Unknown';
    if (!custData[c]) custData[c] = { revenue: 0, miles: 0, trips: 0 };
    custData[c].revenue += safeFloat(t.revenue);
    custData[c].miles   += safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles);
    custData[c].trips++;
  });
  const custArr = Object.entries(custData).map(([name, d]) => ({ name, ...d, rpm: d.miles > 0 ? d.revenue / d.miles : 0 }));
  custArr.sort((a, b) => b.rpm - a.rpm);

  const cpr = $('customerProfitReport');
  cpr.innerHTML = '';
  (custArr.length ? custArr : []).forEach(c => {
    const el = document.createElement('div');
    el.className = 'customer-profit-item';
    const left = document.createElement('div');
    const nm = document.createElement('div'); nm.className = 'customer-profit-name'; nm.textContent = c.name;
    const st = document.createElement('div'); st.className = 'customer-profit-stats';
    st.textContent = `${c.trips} trips • ${formatMoney(c.revenue)} • ${c.miles.toFixed(0)} mi`;
    left.appendChild(nm); left.appendChild(st);
    const rpm = document.createElement('div'); rpm.className = 'customer-profit-rpm'; rpm.textContent = formatMoney(c.rpm) + '/mi';
    el.appendChild(left); el.appendChild(rpm);
    cpr.appendChild(el);
  });
  if (!custArr.length) { cpr.innerHTML = ''; const div = document.createElement('div'); div.style.cssText='text-align:center;padding:20px;color:var(--text-tertiary);'; div.textContent='No customer data'; cpr.appendChild(div); }

  // Period breakdown
  const periodData = {};
  filtered.forEach(t => {
    const date = new Date(t.pickupDate + 'T00:00:00');
    let key = ['year','ytd','all'].includes(period)
      ? date.getFullYear() + '-' + String(date.getMonth() + 1).padStart(2, '0')
      : (() => { const ws = new Date(date); ws.setDate(date.getDate() - date.getDay()); return ws.toISOString().split('T')[0]; })();
    if (!periodData[key]) periodData[key] = { revenue: 0, miles: 0, trips: 0 };
    periodData[key].revenue += safeFloat(t.revenue);
    periodData[key].miles   += safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles);
    periodData[key].trips++;
  });
  const pArr = Object.entries(periodData).map(([k, d]) => ({ period: k, ...d, rpm: d.miles > 0 ? d.revenue / d.miles : 0 })).sort((a, b) => a.period.localeCompare(b.period));

  const pb = $('periodBreakdown');
  pb.innerHTML = '';
  pArr.forEach(p => {
    const el = document.createElement('div'); el.className = 'customer-profit-item';
    const left = document.createElement('div');
    const nm = document.createElement('div'); nm.className = 'customer-profit-name'; nm.textContent = p.period;
    const st = document.createElement('div'); st.className = 'customer-profit-stats';
    st.textContent = `${p.trips} trips • ${formatMoney(p.revenue)} • ${p.miles.toFixed(0)} mi`;
    left.appendChild(nm); left.appendChild(st);
    const rpm = document.createElement('div'); rpm.className = 'customer-profit-rpm'; rpm.textContent = formatMoney(p.rpm) + '/mi';
    el.appendChild(left); el.appendChild(rpm);
    pb.appendChild(el);
  });


  // Sidebar KPIs (non-blocking)
  try {
    const unpaidText = $('ccUnpaidVal')?.textContent || '—';
    const rpmText = $('reportRPM')?.textContent || '—';
    const tripsText = String(filtered.length);
    const arMeta = $('ccARMeta');
    if (arMeta) arMeta.textContent = `${filtered.length} trips in range`;
    const u = $('ccARUnpaid'); if (u) u.textContent = unpaidText;
    const t = $('ccARTrips');  if (t) t.textContent = tripsText;
    const r = $('ccARAvgRPM'); if (r) r.textContent = rpmText;

    const lr = $('ccLastReport');
    if (lr) lr.textContent = `${getTodayStr()} • ${dateFrom}→${dateTo}`;
  } catch (e) {}

  // Revenue sparkline using period breakdown (relative bars)
  const spark = $('reportSparkline');
  if (spark) {
    spark.textContent = '';
    const vals = pArr.map(p => p.revenue || 0);
    const maxV = Math.max(1, ...vals);
    const frag = document.createDocumentFragment();
    vals.forEach(v => {
      const b = document.createElement('div');
      b.className = 'cc-barcol' + (v >= maxV * 0.85 ? ' hi' : '');
      const h = Math.max(4, Math.round((v / maxV) * 46));
      b.style.height = h + 'px';
      frag.appendChild(b);
    });
    spark.appendChild(frag);
    const sm = $('sparkMeta');
    if (sm) sm.textContent = `Max period revenue: ${formatMoney(maxV)} • Bars show relative revenue`;
  }

  $('reportSummary').style.display = 'block'; $('reportCommandLayout').style.display = 'grid';
  showToast('📊 Report generated');
}


async function exportPDF() {
  if ($('reportSummary').style.display === 'none') return showToast('Generate a report first', true);

  const src = $('reportSummary');
  if (!src) return showToast('Nothing to export', true);

  // Primary path: popup window + print (best UX when allowed)
  const pw = window.open('', '_blank');
  if (pw) {
    pw.document.open();
    pw.document.write('<!DOCTYPE html><html><head><title>Freight Logic Report</title>' +
      '<style>body{font-family:Arial,sans-serif;padding:20px;} h1{color:#FFB300;} .customer-profit-item{padding:10px;margin:5px 0;border-bottom:1px solid #eee;} .stat-card{display:inline-block;margin:10px;padding:10px;border:1px solid #ccc;}</style>' +
      '</head><body></body></html>');
    pw.document.close();

    const body = pw.document.body;
    const h1 = pw.document.createElement('h1');
    h1.textContent = 'Freight Logic Report';
    body.appendChild(h1);

    const p = pw.document.createElement('p');
    p.textContent = 'Generated: ' + new Date().toLocaleDateString();
    body.appendChild(p);

    const cloned = src.cloneNode(true);
    cloned.style.display = 'block';
    body.appendChild(pw.document.importNode(cloned, true));

    setTimeout(() => {
      try { pw.focus(); pw.print(); } catch (_) {}
    }, 250);
    return;
  }

  // Fallback path: generate an HTML export and open it without popups (works on iOS).
  // User can then use Share → Print.
  const safeOuter = src.outerHTML; // reportSummary is built with DOM-safe renderers
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Freight Logic Report</title>
    <style>body{font-family:Arial,sans-serif;padding:20px;} h1{color:#FFB300;} .customer-profit-item{padding:10px;margin:5px 0;border-bottom:1px solid #eee;} .stat-card{display:inline-block;margin:10px;padding:10px;border:1px solid #ccc;}</style>
    </head><body><h1>Freight Logic Report</h1><p>Generated: ${new Date().toLocaleDateString()}</p>${safeOuter}</body></html>`;
  openHtmlInNewTabOrSelf(html, `freight_logic_report_${getTodayStr()}.html`);
  showToast('📄 Report opened (popup blocked). Use Share → Print.', true);
}



// ============================================================================
// CSV EXPORT — hardened injection neutralization
// ============================================================================
// CSV EXPORT — uses Sanitize.csvCell for injection defense

function exportCSV() {
  Promise.all([
    dbOp('trips', 'readonly', s => s.getAll()),
    dbOp('fuel', 'readonly', s => s.getAll()),
    dbOp('expenses', 'readonly', s => s.getAll())
  ]).then(([trips, fuel, expenses]) => {
    const rows = [['Type','Date','ID/Location/Desc','Amount','Meta1','Meta2','Meta3','Meta4','Meta5','Customer','Notes','Paid']];
    trips.forEach(t => rows.push(['Trip',t.pickupDate,t.orderNo,t.revenue,t.loadedMiles,t.emptyMiles,t.origin,t.dest,t.perDiemAmount||0,t.customer||'',t.notes||'',t.paid?'Yes':'No']));
    fuel.forEach(f => rows.push(['Fuel',f.date,f.location,f.amount,f.gallons,'','','','','','','']));
    expenses.forEach(e => rows.push(['Expense',e.date,e.desc,e.amount,e.category,'','','','','','','']));

    const csv      = rows.map(r => r.map(sanitizeCSVCell).join(',')).join('\n');
    const blob     = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const filename = `freight_logic_${getTodayStr()}.csv`;

    if (navigator.share && navigator.canShare && navigator.canShare({ files: [new File([blob], filename, { type: 'text/csv' })] })) {
      navigator.share({ files: [new File([blob], filename, { type: 'text/csv' })], title: 'Freight Logic Backup' })
        .then(() => showToast('✅ CSV shared'))
        .catch(() => downloadCSVFallback(blob, filename));
    } else {
      downloadCSVFallback(blob, filename);
    }
  }).catch(e => { console.error('[CSV] Export error:', e); showToast('Export failed', true); });
}

function downloadCSVFallback(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast('✅ CSV exported');
}

// ============================================================================
// CSV IMPORT — hardened: strip formula chars on inbound data
// ============================================================================
function parseCSV(csvText, { maxRows = 50000, maxChars = 10_000_000 } = {}) {
  if (typeof csvText !== 'string') throw new Error('CSV must be text');
  if (csvText.length > maxChars) throw new Error(`CSV file too large (max ${Math.round(maxChars / 1e6)}MB)`);
  const rows = [];
  let row = [], field = '', inQuotes = false, i = 0;
  while (i < csvText.length) {
    const c = csvText[i];
    if (inQuotes) {
      if (c === '"' && csvText[i + 1] === '"') { field += '"'; i += 2; continue; }
      if (c === '"') { inQuotes = false; i++; continue; }
      field += c; i++; continue;
    }
    if (c === '"') { inQuotes = true; i++; continue; }
    if (c === ',') { row.push(field); field = ''; i++; continue; }
    if (c === '\n' || c === '\r') {
      if (c === '\r' && csvText[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (!(row.length === 1 && row[0] === '' && rows.length === 0)) rows.push(row);
      row = []; i++;
      if (rows.length > maxRows) throw new Error(`CSV too many rows (max ${maxRows})`);
      continue;
    }
    field += c; i++;
  }
  row.push(field);
  if (!(row.length === 1 && row[0] === '')) rows.push(row);
  return rows;
}

// IMPORT: uses Sanitize.importStr for formula defense
function validateImportRow(type, row) {
  const num  = v => { const n = safeFloat(String(v ?? '0').replace(/[$, ]/g, '')); return isFinite(n) ? Math.max(0, n) : 0; };
  const date = v => { const s = cleanImportString(v, 20); return s.match(/^\d{4}-\d{2}-\d{2}$/) ? s : getTodayStr(); };

  if (type === 'trip') {
    if (row.length < 4) return null;
    const orderNo = normalizeOrderNo(cleanImportString(row[2], 100));
    if (!orderNo) return null;
    return {
      orderNo,
      pickupDate:    date(row[1]),
      revenue:       num(row[3]),
      loadedMiles:   num(row[4]),
      emptyMiles:    num(row[5]),
      origin:        cleanImportString(row[6]),
      dest:          cleanImportString(row[7]),
      perDiemAmount: num(row[8]),
      customer:      cleanImportString(row[9]),
      notes:         cleanImportString(row[10], 1000),
      paid:          cleanImportString(row[11]).toLowerCase() === 'yes',
      created:       Date.now()
    };
  }
  if (type === 'fuel') {
    if (row.length < 4) return null;
    return { date: date(row[1]), location: cleanImportString(row[2]), amount: num(row[3]), gallons: num(row[4]) };
  }
  if (type === 'expense') {
    if (row.length < 4) return null;
    return { date: date(row[1]), desc: cleanImportString(row[2]), amount: num(row[3]), category: cleanImportString(row[4]) || 'other' };
  }
  return null;
}


// ----------------------------------------------------------------------------
// Dispatchland / 3rd-party CSV Import (best-effort, defensive)
// - Detects common headers and maps to Freight Logic trip records
// - Normalizes dates (MM/DD/YYYY, YYYY-MM-DD, etc.) to YYYY-MM-DD
// - Never overwrites existing trips (orderNo uniqueness enforced)
// ----------------------------------------------------------------------------
function parseDateAny(v) {
  const s = String(v ?? '').trim();
  if (!s) return '';
  // already ISO
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  // MM/DD/YYYY or M/D/YY
  const m1 = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})/);
  if (m1) {
    const mm = String(m1[1]).padStart(2,'0');
    const dd = String(m1[2]).padStart(2,'0');
    let yy = m1[3];
    if (yy.length === 2) yy = (Number(yy) >= 70 ? '19' : '20') + yy;
    return `${yy}-${mm}-${dd}`;
  }
  // Try Date parse (locale-dependent; last resort)
  const d = new Date(s);
  if (!isNaN(d.getTime())) {
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth()+1).padStart(2,'0');
    const dd = String(d.getDate()).padStart(2,'0');
    return `${yyyy}-${mm}-${dd}`;
  }
  return '';
}

function normHeader(h) {
  return String(h || '').trim().toLowerCase().replace(/\s+/g,' ').replace(/[^a-z0-9 ]/g,'');
}

async function importDispatchlandCSV(lines, file) {
  try {
    const hdr = (lines[0] || []).map(normHeader);
    // Heuristic header detection
    const hasOrder = hdr.some(h => h.includes('order') || h.includes('load') || h.includes('trip'));
    const hasPickup = hdr.some(h => h.includes('pickup'));
    const hasDelivery = hdr.some(h => h.includes('delivery') || h.includes('drop'));
    const hasMiles = hdr.some(h => h.includes('miles'));
    const hasRevenue = hdr.some(h => h.includes('revenue') || h.includes('rate') || h.includes('pay') || h.includes('amount'));
    if (!(hasOrder && (hasPickup || hasDelivery) && (hasMiles || hasRevenue))) return false;

    const col = (nameParts) => {
      const idx = hdr.findIndex(h => nameParts.some(p => h.includes(p)));
      return idx >= 0 ? idx : -1;
    };

    const cOrder   = col(['order', 'load', 'trip']);
    const cCust    = col(['customer', 'shipper', 'broker', 'company']);
    const cPUCity  = col(['pickup city', 'pu city', 'origin city', 'from city', 'pickup']);
    const cPUState = col(['pickup state', 'pu state', 'origin state', 'from state']);
    const cDLCity  = col(['delivery city', 'drop city', 'dest city', 'to city', 'delivery']);
    const cDLState = col(['delivery state', 'drop state', 'dest state', 'to state']);
    const cPUDate  = col(['pickup date', 'pu date', 'pickup']);
    const cDLDate  = col(['delivery date', 'drop date', 'delivery']);
    const cMiles   = col(['loaded miles', 'miles loaded', 'miles']);
    const cEmpty   = col(['empty miles', 'deadhead']);
    const cRev     = col(['revenue', 'rate', 'gross', 'pay', 'amount']);

    const fname = (file && file.name) ? file.name : 'Dispatchland CSV';
    const rowsToImport = Math.max(0, lines.length - 1);
    if (!confirm(`Import ${rowsToImport} rows from ${fname}?\n\nThis will add TRIP records (best-effort mapping). It will NOT overwrite existing trips with the same Order #.`)) {
      $('fileImportCSV').value = '';
      return true; // handled
    }

    let added = 0, skipped = 0, invalid = 0;
    for (let i = 1; i < lines.length; i++) {
      const r = lines[i];
      if (!r || !r.length) continue;

      const orderRaw = cOrder >= 0 ? r[cOrder] : (r[0] || '');
      const orderNo = normalizeOrderNo(orderRaw);
      if (!orderNo) { invalid++; continue; }

      const trip = {
        orderNo,
        customer: cCust >= 0 ? String(r[cCust] || '').trim() : '',
        origin: '',
        destination: '',
        pickupDate: cPUDate >= 0 ? parseDateAny(r[cPUDate]) : '',
        deliveryDate: cDLDate >= 0 ? parseDateAny(r[cDLDate]) : '',
        loadedMiles: cMiles >= 0 ? Sanitize.miles(r[cMiles]) : 0,
        emptyMiles: cEmpty >= 0 ? Sanitize.miles(r[cEmpty]) : 0,
        revenue: cRev >= 0 ? Sanitize.money(r[cRev]) : 0,
        notes: `Imported from ${fname}`,
        paid: false,
        paidDate: null,
        created: Date.now(),
        isActive: true
      };

      // origin/destination heuristics if city/state exist
      const puCity = cPUCity >= 0 ? String(r[cPUCity] || '').trim() : '';
      const puState = cPUState >= 0 ? String(r[cPUState] || '').trim() : '';
      const dlCity = cDLCity >= 0 ? String(r[cDLCity] || '').trim() : '';
      const dlState = cDLState >= 0 ? String(r[cDLState] || '').trim() : '';
      if (puCity || puState) trip.origin = [puCity, puState].filter(Boolean).join(', ');
      if (dlCity || dlState) trip.destination = [dlCity, dlState].filter(Boolean).join(', ');

      const clean = sanitizeTripRecord(trip);
      if (!clean) { invalid++; continue; }

      try {
        await dbOp('trips', 'readwrite', s => s.add(clean));
        added++;
      } catch (err) {
        if (err && err.name === 'ConstraintError') skipped++;
        else if (err && (err.name === 'QuotaExceededError' || (err.message || '').includes('quota'))) {
          showToast(`⚠️ Storage full after ${added} trips. Free space and retry.`, true); break;
        } else invalid++;
      }
    }

    const msg = [`✅ Dispatchland import: ${added} trips added`];
    if (skipped) msg.push(`${skipped} skipped (duplicate Order #)`);
    if (invalid) msg.push(`${invalid} invalid`);
    showToast(msg.join(' • '));
    await checkStorageQuota();
    refreshUI();
    return true;
  } catch (e) {
    showToast('Dispatchland import failed', true);
    return true; // handled
  }
}

function importUnifiedCSV(file) {
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) { showToast('CSV too large (max 10MB)', true); return; }

  const reader = new FileReader();
  reader.onload = async e => {
    try {
      let lines;
      try { lines = parseCSV(e.target.result); }
      catch (pe) { showToast('CSV parse error: ' + pe.message, true); return; }

      if (lines.length < 2) { showToast('CSV appears empty', true); return; }

      const header = (lines[0] || []).map(h => String(h).trim().toLowerCase());
      if (!header[0] || !header.includes('type')) {
        // Attempt Dispatchland/3rd-party CSV import (best-effort, defensive)
        const ok = await importDispatchlandCSV(lines, file);
        if (!ok) {
          showToast('Unrecognized CSV format — expected Freight Logic export', true);
        }
        return;
      }

      const rowsToImport = Math.max(0, lines.length - 1);
      const fname = (file && file.name) ? file.name : 'CSV file';
      if (!confirm(`Import ${rowsToImport} rows from ${fname}?\n\nThis will add records to your database. Use an encrypted backup if you need a rollback.`)) {
        $('fileImportCSV').value = '';
        return;
      }

      let count = 0, skipped = 0, invalid = 0;
      for (let i = 1; i < lines.length; i++) {
        const row = lines[i];
        if (!row || !row.length) continue;
        const type = String(row[0] || '').trim().toLowerCase();
        if (!type) continue;

        const record = validateImportRow(type, row);
        if (!record) { invalid++; continue; }

        try {
          if (type === 'trip')    await dbOp('trips', 'readwrite', s => s.add(record));
          else if (type === 'fuel') await dbOp('fuel', 'readwrite', s => s.add(record));
          else if (type === 'expense') await dbOp('expenses', 'readwrite', s => s.add(record));
          count++;
        } catch (err) {
          if (err && err.name === 'ConstraintError') { skipped++; }
          else if (err && (err.name === 'QuotaExceededError' || (err.message || '').includes('quota'))) {
            showToast(`⚠️ Storage full after ${count} records. Free space and retry.`, true); break;
          } else { invalid++; }
        }
      }

      const parts = [`✅ Imported ${count} records`];
      if (skipped) parts.push(`${skipped} duplicates skipped`);
      if (invalid) parts.push(`${invalid} invalid rows skipped`);
      showToast(parts.join(' · '));
      refreshUI(); checkStorageQuota();
      $('fileImportCSV').value = '';
    } catch (e) {
      console.error('[Import] Error:', e);
      showToast('Import failed: ' + (e.message || 'unknown'), true);
    }
  };
  reader.onerror = () => showToast('Could not read file', true);
  reader.readAsText(file);
}

// ============================================================================
// SETTINGS
// ============================================================================
async function setDeductionMethod(method) {
  deductionMethod = method;
  $('toggleStdMileage').classList.toggle('active', method === 'standard');
  $('toggleActualExp').classList.toggle('active', method === 'actual');
  if (method === 'standard') {
    $('deductionMethodNote').textContent = `Using Standard Mileage: $${irsMileageRate.toFixed(2)} × total miles. Fuel costs are NOT separately deducted.`;
    $('deductionStdMileageRow').style.display = 'flex';
    $('deductionFuelRow').style.display = 'none';
  } else {
    $('deductionMethodNote').textContent = 'Using Actual Expense: Fuel costs deducted directly. Standard mileage NOT applied.';
    $('deductionStdMileageRow').style.display = 'none';
    $('deductionFuelRow').style.display = 'flex';
  }
  try { await dbOp('settings', 'readwrite', s => s.put({ key: 'deductionMethod', value: method })); } catch (e) {}
  refreshSummary();
}

function renderHomeAddressStatus(el, a, combined, fed, stateRate, prefixLabel) {
  if (!el) return;
  el.textContent = '';
  const line1 = document.createElement('div');
  line1.style.color = 'var(--accent-success)';
  line1.textContent = `${prefixLabel || '✅'} ${a.city}, ${a.state}`;
  const line2 = document.createElement('div');
  line2.style.color = 'var(--accent-info)';
  line2.textContent = `Tax: ${combined}% (${fed}% fed + ${stateRate}% state)`;
  el.appendChild(line1);
  el.appendChild(line2);
}

function renderTaxInfoDisplay(el, stateName, fed, sr) {
  if (!el) return;
  el.textContent = '';
  const row = (label, value) => {
    const d = document.createElement('div');
    d.style.marginBottom = '8px';
    const b = document.createElement('strong');
    b.textContent = label + ': ';
    d.appendChild(b);
    d.appendChild(document.createTextNode(String(value)));
    return d;
  };
  el.appendChild(row('State', stateName));
  el.appendChild(row('Federal', `${fed}%`));
  el.appendChild(row('State', `${sr}%`));
  const sep = document.createElement('div');
  sep.style.paddingTop = '8px';
  sep.style.borderTop = '1px solid var(--border)';
  const b = document.createElement('strong');
  b.textContent = 'Combined: ';
  sep.appendChild(b);
  sep.appendChild(document.createTextNode(`${fed + sr}%`));
  el.appendChild(sep);
}

async function saveHomeAddress() {
  const addr = {
    street: $('homeStreet').value.trim(), city: $('homeCity').value.trim(),
    state: $('homeState').value, zip: $('homeZip').value.trim()
  };
  if (!addr.city || !addr.state) return showToast('City and State required', true);
  try {
    await dbOp('settings', 'readwrite', s => s.put({ key: 'homeAddress', value: addr }));
    const stateRate = STATE_TAX_RATES[addr.state] || 0;
    const fed = safeFloat($('federalTaxBracket').value);
    const combined = fed + stateRate;
    await dbOp('settings', 'readwrite', s => s.put({ key: 'stateTaxRate', value: stateRate }));
    await dbOp('settings', 'readwrite', s => s.put({ key: 'incomeTaxRate', value: combined }));
          renderHomeAddressStatus($('homeAddressStatus'), addr, combined, fed, stateRate, '✅');
    $('homeAddressStatus').style.display = 'block';
    showToast(`🏠 Address saved · Tax: ${combined}%`);
    updateTaxInfoDisplay(); refreshUI();
  } catch (e) { showToast('Error saving address', true); }
}

async function loadHomeAddress() {
  try {
    const r = await dbOp('settings', 'readonly', s => s.get('homeAddress'));
    if (r && r.value) {
      const a = r.value;
      $('homeStreet').value = a.street || ''; $('homeCity').value = a.city || '';
      $('homeState').value = a.state || ''; $('homeZip').value = a.zip || '';
      if (a.city && a.state) {
        const sr = STATE_TAX_RATES[a.state] || 0;
        const fb = await dbOp('settings', 'readonly', s => s.get('federalTaxBracket'));
        const fed = fb ? fb.value : 22;
                renderHomeAddressStatus($('homeAddressStatus'), a, (fed + sr), fed, sr, 'Saved:');
        $('homeAddressStatus').style.display = 'block';
      }
    }
  } catch (e) { showToast('Error loading address', true); }
}

async function saveTaxSettings() {
  try {
    const fed = safeFloat($('federalTaxBracket').value);
    const ha = await dbOp('settings', 'readonly', s => s.get('homeAddress'));
    const sr = ha && ha.value && ha.value.state ? STATE_TAX_RATES[ha.value.state] || 0 : 0;
    const combined = fed + sr;
    await dbOp('settings', 'readwrite', s => s.put({ key: 'federalTaxBracket', value: fed }));
    await dbOp('settings', 'readwrite', s => s.put({ key: 'incomeTaxRate', value: combined }));
    updateTaxInfoDisplay(); refreshUI();
  } catch (e) { showToast('Error saving tax settings', true); }
}

async function loadTaxSettings() {
  try {
    const fb = await dbOp('settings', 'readonly', s => s.get('federalTaxBracket'));
    if (fb) $('federalTaxBracket').value = fb.value;
    updateTaxInfoDisplay();
  } catch (e) {}
}

async function updateTaxInfoDisplay() {
  try {
    const ha = await dbOp('settings', 'readonly', s => s.get('homeAddress'));
    const fed = safeFloat($('federalTaxBracket').value);
    let sr = 0, stateName = 'Not set';
    if (ha && ha.value && ha.value.state) { sr = STATE_TAX_RATES[ha.value.state] || 0; stateName = ha.value.state; }
        renderTaxInfoDisplay($('taxInfoDisplay'), stateName, fed, sr);
  } catch (e) {}
}

async function saveMileageRate() {
  const rate = safeFloat($('mileageRateSetting').value);
  if (rate <= 0 || rate > 5) return showToast('Invalid mileage rate', true);
  irsMileageRate = rate;
  await dbOp('settings', 'readwrite', s => s.put({ key: 'irsMileageRate', value: rate }));
  updateMileageRateLabels(); refreshSummary();
  showToast('Mileage rate saved');
}

async function savePerDiemSettings() {
  const rate = safeFloat($('perDiemRateSetting').value);
  if (rate <= 0 || rate > 500) return showToast('Invalid per diem rate', true);
  perDiemRate = rate;
  await dbOp('settings', 'readwrite', s => s.put({ key: 'perDiemRate', value: rate }));
  showToast('Per diem rate saved');
}

async function saveGPSEnabled(enabled) {
  gpsEnabled = enabled;
  await dbOp('settings', 'readwrite', s => s.put({ key: 'gpsEnabled', value: enabled }));
  updateGPSUI();
  showToast(enabled ? '📍 GPS enabled' : '📍 GPS disabled');
}

async function loadGPSEnabled() {
  try {
    const r = await dbOp('settings', 'readonly', s => s.get('gpsEnabled'));
    gpsEnabled = r && r.value === true;
    if ($('gpsEnabledToggle')) $('gpsEnabledToggle').checked = gpsEnabled;
    // Load high accuracy setting
    const ha = await dbOp('settings', 'readonly', s => s.get('gpsHighAccuracy'));
    gpsHighAccuracy = ha ? ha.value !== false : true; // default true
    if ($('gpsHighAccuracyToggle')) $('gpsHighAccuracyToggle').checked = gpsHighAccuracy;
    updateGPSUI();
  } catch (e) { gpsEnabled = false; }
}

async function saveGPSHighAccuracy(enabled) {
  gpsHighAccuracy = enabled;
  await dbOp('settings', 'readwrite', s => s.put({ key: 'gpsHighAccuracy', value: enabled }));
  showToast(enabled ? '📍 High accuracy mode on' : '📍 Battery saver mode on');
}

function updateGPSUI() {
  const ind = $('gpsIndicator'), txt = $('gpsText'), btn = $('btnStartGPS'), status = $('gpsToggleStatus');
  if (gpsEnabled && !gpsWatchId) { ind.classList.remove('inactive'); ind.classList.add('tracking'); txt.textContent = 'GPS On'; }
  else if (!gpsEnabled) { ind.classList.remove('tracking'); ind.classList.add('inactive'); txt.textContent = 'GPS Off'; }
  if (btn) btn.style.display = gpsEnabled ? 'block' : 'none';
  if (status) {
    status.textContent = gpsEnabled ? '✅ GPS enabled — Start Tracking button visible on Trips' : '⚪ GPS disabled — enter miles manually';
    status.style.color = gpsEnabled ? 'var(--accent-success)' : 'var(--text-tertiary)';
  }
}

// Baseline MPG setting (stored in IndexedDB settings; offline-first)
async function loadBaselineMPG() {
  try {
    const row = await dbOp('settings', 'readonly', s => s.get('baselineMPG'));
    const pct = await dbOp('settings', 'readonly', s => s.get('mpgAlertPct'));
    const baseline = row && row.value != null ? safeFloat(row.value) : 18.0; // sensible Transit baseline
    const alertPct = pct && pct.value != null ? safeFloat(pct.value) : 20;
    if ($('baselineMPG')) $('baselineMPG').value = baseline ? String(baseline) : '';
    if ($('mpgAlertPct')) $('mpgAlertPct').value = alertPct ? String(alertPct) : '20';
  } catch (_) {}
}

async function saveBaselineMPG() {
  try {
    const baseline = safeFloat($('baselineMPG')?.value);
    const alertPct = Math.min(60, Math.max(5, safeFloat($('mpgAlertPct')?.value || 20)));
    await dbOp('settings', 'readwrite', s => s.put({ key: 'baselineMPG', value: baseline || 0 }));
    await dbOp('settings', 'readwrite', s => s.put({ key: 'mpgAlertPct', value: alertPct || 20 }));
    showToast('✅ Baseline MPG saved');
    refreshUI();
  } catch (e) { showToast('Error saving baseline MPG', true); }
}

async function loadAllRateSettings() {
  try {
    const mr = await dbOp('settings', 'readonly', s => s.get('irsMileageRate'));
    if (mr && mr.value) { irsMileageRate = mr.value; $('mileageRateSetting').value = mr.value; }
    const pr = await dbOp('settings', 'readonly', s => s.get('perDiemRate'));
    if (pr && pr.value) { perDiemRate = pr.value; $('perDiemRateSetting').value = pr.value; }
    await loadGPSEnabled();
    updateMileageRateLabels();
  } catch (e) {}
}

function updateMileageRateLabels() {
  const r = irsMileageRate.toFixed(2);
  $('mileageRateLabel').textContent = r;
  document.querySelectorAll('.mileageRateInline').forEach(el => el.textContent = r);
}

function clearAllData() {
  if (!confirm('⚠️ DELETE ALL DATA?\n\nThis cannot be undone!')) return;
  if (prompt('Type YES to confirm:') !== 'YES') return showToast('Cancelled');
  if (db) db.close();
  indexedDB.deleteDatabase(DB_NAME);
  // Clear app data keys — especially PIN state to prevent bricked app on reload
  ['installPromptDismissed', 'pinHash', 'pinEnabled', 'pinLockout', 'pinSalt',
   'deviceId', 'backupLastExport', 'backupEnabled', 'backupReminder', 'backupIncludeReceipts',
   'cryptoSalt'].forEach(k => localStorage.removeItem(k));
  setTimeout(() => location.reload(), 500);
}

// ============================================================================
// FEATURE 1: IFTA FUEL TAX REPORT
// ============================================================================
function getIFTAQuarterDates(quarter, year) {
  const qMap = { Q1: [0, 2], Q2: [3, 5], Q3: [6, 8], Q4: [9, 11] };
  const [startMonth, endMonth] = qMap[quarter] || [0, 2];
  const from = new Date(year, startMonth, 1);
  const to = new Date(year, endMonth + 1, 0); // last day of end month
  return {
    from: from.toISOString().split('T')[0],
    to: to.toISOString().split('T')[0]
  };
}

function extractStateFromLocation(loc) {
  if (!loc) return '';
  const s = String(loc).trim().toUpperCase();
  // Match trailing 2-letter state code
  const m = s.match(/\b([A-Z]{2})\s*$/);
  if (m && STATE_TAX_RATES.hasOwnProperty(m[1])) return m[1];
  // Match "STATE" after comma
  const cm = s.match(/,\s*([A-Z]{2})\b/);
  if (cm && STATE_TAX_RATES.hasOwnProperty(cm[1])) return cm[1];
  return '';
}

async function generateIFTAReport() {
  try {
    const quarter = $('iftaQuarter').value;
    const year = parseInt($('iftaYear').value, 10);
    if (!quarter || !year) return showToast('Select quarter and year', true);

    const dates = getIFTAQuarterDates(quarter, year);
    const trips = (await dbOp('trips', 'readonly', s => s.getAll())).filter(t =>
      isActiveRecord(t) && t.pickupDate >= dates.from && t.pickupDate <= dates.to
    );
    const fuel = (await dbOp('fuel', 'readonly', s => s.getAll())).filter(f =>
      isActiveRecord(f) && f.date >= dates.from && f.date <= dates.to
    );

    // Gallons by state (from fuel entries)
    const fuelByState = {};
    let unassignedGal = 0;
    fuel.forEach(f => {
      const gal = safeFloat(f.gallons);
      const st = (f.state || extractStateFromLocation(f.location)).toUpperCase();
      if (st && st.length === 2) {
        if (!fuelByState[st]) fuelByState[st] = { gallons: 0, cost: 0 };
        fuelByState[st].gallons += gal;
        fuelByState[st].cost += safeFloat(f.amount);
      } else {
        unassignedGal += gal;
      }
    });

    // Miles by state (best-effort from trip origin/dest state codes)
    const milesByState = {};
    let totalMiles = 0;
    trips.forEach(t => {
      const miles = safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles);
      totalMiles += miles;
      const origState = extractStateFromLocation(t.origin);
      const destState = extractStateFromLocation(t.dest);
      // Split miles: if same state, all there; if different, split evenly
      if (origState && destState && origState === destState) {
        if (!milesByState[origState]) milesByState[origState] = 0;
        milesByState[origState] += miles;
      } else {
        if (origState) {
          if (!milesByState[origState]) milesByState[origState] = 0;
          milesByState[origState] += miles / 2;
        }
        if (destState) {
          if (!milesByState[destState]) milesByState[destState] = 0;
          milesByState[destState] += miles / 2;
        }
        if (!origState && !destState) {
          if (!milesByState['??']) milesByState['??'] = 0;
          milesByState['??'] += miles;
        }
      }
    });

    // Merge all states
    const allStates = new Set([...Object.keys(fuelByState), ...Object.keys(milesByState)]);
    const totalGallons = fuel.reduce((s, f) => s + safeFloat(f.gallons), 0);
    const avgMPG = totalGallons > 0 && totalMiles > 0 ? totalMiles / totalGallons : 0;

    // Build state rows
    const stateRows = [];
    allStates.forEach(st => {
      const miles = milesByState[st] || 0;
      const galPurchased = fuelByState[st]?.gallons || 0;
      const galConsumed = avgMPG > 0 ? miles / avgMPG : 0;
      const netGallons = galPurchased - galConsumed;
      stateRows.push({ state: st, miles, galPurchased, galConsumed, netGallons });
    });
    stateRows.sort((a, b) => a.state.localeCompare(b.state));

    // Store for CSV export
    window._lastIFTAData = { quarter, year, stateRows, totalMiles, totalGallons, avgMPG, unassignedGal };

    // Render
    $('iftaTotalMiles').textContent = Math.round(totalMiles).toLocaleString();
    $('iftaTotalGal').textContent = totalGallons.toFixed(1);
    $('iftaAvgMPG').textContent = avgMPG.toFixed(1);

    const tableEl = $('iftaStateTable');
    tableEl.innerHTML = '';
    if (!stateRows.length) {
      tableEl.appendChild(Render.emptyPanel('No data for this quarter. Add state to fuel entries and ensure trip origin/dest include state codes (e.g., "Dallas, TX").'));
    } else {
      const table = document.createElement('table');
      table.className = 'ifta-table';
      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      ['State','Miles','Gal Purchased','Gal Consumed','Net (±)'].forEach(h => { const th=document.createElement('th'); th.textContent=h; hr.appendChild(th); });
      thead.appendChild(hr);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      stateRows.forEach(r => {
        const tr = document.createElement('tr');
        const cls = r.netGallons >= 0 ? 'ifta-positive' : 'ifta-negative';

        const tdState = document.createElement('td');
        const strong = document.createElement('strong');
        strong.textContent = String(r.state || '').toUpperCase();
        tdState.appendChild(strong);

        const tdMiles = document.createElement('td');
        tdMiles.textContent = Math.round(r.miles || 0).toLocaleString();

        const tdPurchased = document.createElement('td');
        tdPurchased.textContent = Number(r.galPurchased || 0).toFixed(1);

        const tdConsumed = document.createElement('td');
        tdConsumed.textContent = Number(r.galConsumed || 0).toFixed(1);

        const tdNet = document.createElement('td');
        tdNet.className = cls;
        const net = Number(r.netGallons || 0);
        tdNet.textContent = `${net >= 0 ? '+' : ''}${net.toFixed(1)}`;

        tr.appendChild(tdState);
        tr.appendChild(tdMiles);
        tr.appendChild(tdPurchased);
        tr.appendChild(tdConsumed);
        tr.appendChild(tdNet);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      tableEl.appendChild(table);

      if (unassignedGal > 0) {
        const warn = Render.el('div', { cls: 'warning-banner', style: 'margin-top:8px;' });
        warn.textContent = `⚠️ ${unassignedGal.toFixed(1)} gallons have no state assigned. Add state to fuel entries for accurate IFTA.`;
        tableEl.appendChild(warn);
      }
    }

    $('iftaReport').style.display = 'block';
    showToast('📋 IFTA report generated');
  } catch (e) {
    console.error('[IFTA] Error:', e);
    showToast('IFTA report failed', true);
  }
}

function exportIFTACSV() {
  const d = window._lastIFTAData;
  if (!d || !d.stateRows) return showToast('Generate IFTA report first', true);
  const rows = [['State', 'Miles', 'Gallons Purchased', 'Gallons Consumed', 'Net Gallons']];
  d.stateRows.forEach(r => rows.push([r.state, Math.round(r.miles), r.galPurchased.toFixed(1), r.galConsumed.toFixed(1), r.netGallons.toFixed(1)]));
  rows.push([]);
  rows.push(['Total Miles', Math.round(d.totalMiles)]);
  rows.push(['Total Gallons', d.totalGallons.toFixed(1)]);
  rows.push(['Avg MPG', d.avgMPG.toFixed(1)]);
  rows.push(['Quarter', d.quarter + ' ' + d.year]);
  const csv = rows.map(r => r.map(sanitizeCSVCell).join(',')).join('\n');
  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
  downloadBlob(blob, `freight_logic_ifta_${d.year}_${d.quarter}.csv`);
  showToast('✅ IFTA CSV exported');
}

// ============================================================================
// FEATURE 2: RECURRING EXPENSES
// ============================================================================
async function processRecurringExpenses() {
  try {
    const templates = (await getSettingKV('recurringTemplatesV1', [])) || [];
    if (!templates.length) return;

    const today = getTodayStr();
    let generated = 0;

    for (const tmpl of templates) {
      if (!tmpl.active) continue;
      const lastDate = tmpl.lastGenerated || '1900-01-01';
      const nextDue = calculateNextDueDate(lastDate, tmpl.freq);

      if (nextDue <= today) {
        // Generate the expense
        const data = {
          category: tmpl.category || 'other',
          amount: safeFloat(tmpl.amount),
          date: nextDue,
          desc: (tmpl.desc || '') + ' [auto-recurring]',
          recurringId: tmpl.id,
          autoGenerated: true
        };
        if (data.amount > 0) {
          await dbOp('expenses', 'readwrite', s => s.add(data));
          tmpl.lastGenerated = nextDue;
          generated++;
        }
      }
    }

    if (generated > 0) {
      await setSettingKV('recurringTemplatesV1', templates);
      showToast(`🔁 ${generated} recurring expense${generated > 1 ? 's' : ''} auto-generated`);
    }
  } catch (e) {
    console.error('[Recurring] Error:', e);
  }
}

function calculateNextDueDate(lastDate, freq) {
  const d = new Date(lastDate + 'T00:00:00');
  if (isNaN(d.getTime())) return getTodayStr();
  switch (freq) {
    case 'weekly': d.setDate(d.getDate() + 7); break;
    case 'monthly': d.setMonth(d.getMonth() + 1); break;
    case 'quarterly': d.setMonth(d.getMonth() + 3); break;
    case 'yearly': d.setFullYear(d.getFullYear() + 1); break;
    default: d.setMonth(d.getMonth() + 1);
  }
  return d.toISOString().split('T')[0];
}

async function renderRecurringExpenseManager() {
  const el = $('recurringExpenseList');
  if (!el) return;
  try {
  const templates = (await getSettingKV('recurringTemplatesV1', [])) || [];
  if (!templates.length) {
    el.innerHTML = '';
    el.appendChild(Render.emptyPanel('No recurring expenses. Mark an expense as recurring when saving it.'));
    return;
  }
  const frag = document.createDocumentFragment();
  const catLabels = { fuel: '⛽ Fuel', repairs: '🔧 Repairs', tolls: '🛣️ Tolls', meals: '🍔 Meals', supplies: '📦 Supplies', phone: '📱 Phone', insurance: '🛡️ Insurance', licensing: '📋 Licensing', parking: '🅿️ Parking', other: '📌 Other' };
  templates.forEach((tmpl, idx) => {
    const row = Render.el('div', { style: 'display:flex; justify-content:space-between; align-items:center; padding:10px; background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; margin-bottom:8px;' });
    const left = Render.el('div');
    const title = Render.el('div', { style: 'font-weight:700; font-size:13px;' });
    title.textContent = (catLabels[tmpl.category] || tmpl.category) + ' — ' + formatMoney(tmpl.amount);
    const meta = Render.el('div', { style: 'font-size:11px; color:var(--text-secondary); margin-top:2px;' });
    meta.textContent = (tmpl.desc || 'No description') + ' • ' + tmpl.freq + ' • Last: ' + (tmpl.lastGenerated || 'never');
    left.appendChild(title);
    left.appendChild(meta);
    const btn = Render.el('button', { cls: 'btn btn-danger', text: '✕', style: 'padding:6px 10px; font-size:11px;' });
    btn.setAttribute('data-recurring-idx', idx);
    row.appendChild(left);
    row.appendChild(btn);
    frag.appendChild(row);
  });
  el.innerHTML = '';
  el.appendChild(frag);
  } catch (e) { console.error('[Recurring] Render error:', e); }
}

// ============================================================================
// FEATURE 3: CUSTOMER RATE HISTORY
// ============================================================================
async function refreshCustomerRateHistory() {
  const el = $('customerRateHistory');
  if (!el) return;
  try {
    const trips = (await dbOp('trips', 'readonly', s => s.getAll())).filter(isActiveRecord);
    if (!trips.length) {
      el.innerHTML = '';
      el.appendChild(Render.emptyPanel('No trip data yet'));
      return;
    }

    // Group by customer
    const custMap = {};
    trips.forEach(t => {
      const c = (t.customer || 'Unknown').trim();
      if (!custMap[c]) custMap[c] = [];
      custMap[c].push(t);
    });

    // Build analytics per customer
    const custArr = Object.entries(custMap).map(([name, trips]) => {
      trips.sort((a, b) => (a.pickupDate || '').localeCompare(b.pickupDate || ''));
      let totalRev = 0, totalMiles = 0;
      const rpmHistory = [];

      trips.forEach(t => {
        const rev = safeFloat(t.revenue);
        const mi = safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles);
        totalRev += rev;
        totalMiles += mi;
        if (mi > 0) rpmHistory.push({ date: t.pickupDate, rpm: rev / mi });
      });

      const avgRPM = totalMiles > 0 ? totalRev / totalMiles : 0;

      // Trend: compare first-half avg RPM to second-half avg RPM
      let trend = 0, trendLabel = 'Stable';
      if (rpmHistory.length >= 4) {
        const mid = Math.floor(rpmHistory.length / 2);
        const firstHalf = rpmHistory.slice(0, mid).reduce((s, r) => s + r.rpm, 0) / mid;
        const secondHalf = rpmHistory.slice(mid).reduce((s, r) => s + r.rpm, 0) / (rpmHistory.length - mid);
        if (firstHalf > 0) {
          trend = ((secondHalf - firstHalf) / firstHalf) * 100;
          trendLabel = trend > 5 ? '↑ Rising' : trend < -5 ? '↓ Declining' : '→ Stable';
        }
      }

      return { name, tripCount: trips.length, totalRev, totalMiles, avgRPM, trend, trendLabel, lastTrip: trips[trips.length - 1]?.pickupDate || '' };
    });

    custArr.sort((a, b) => b.tripCount - a.tripCount);

    el.innerHTML = '';
    const frag = document.createDocumentFragment();
    custArr.slice(0, 20).forEach(c => {
      const card = Render.el('div', { cls: 'cust-rate-card' });

      const header = Render.el('div', { cls: 'cust-rate-header' });
      const nameEl = Render.el('div', { cls: 'cust-rate-name', text: c.name });
      const badge = Render.el('div', { cls: 'cust-rate-badge' });
      badge.textContent = c.trendLabel;
      badge.style.background = c.trend > 5 ? 'rgba(105,240,174,0.12)' : c.trend < -5 ? 'rgba(255,82,82,0.12)' : 'rgba(255,179,0,0.12)';
      badge.style.color = c.trend > 5 ? 'var(--accent-success)' : c.trend < -5 ? 'var(--accent-danger)' : 'var(--accent-warning)';
      header.appendChild(nameEl);
      header.appendChild(badge);

      const stats = Render.el('div', { cls: 'cust-rate-stats' });
      [
        { v: c.tripCount, k: 'Trips' },
        { v: formatMoney(c.avgRPM) + '/mi', k: 'Avg RPM' },
        { v: formatMoney(c.totalRev), k: 'Revenue' },
        { v: c.lastTrip || '—', k: 'Last Trip' }
      ].forEach(s => {
        const st = Render.el('div', { cls: 'cust-rate-stat' });
        st.appendChild(Render.el('div', { cls: 'v', text: String(s.v) }));
        st.appendChild(Render.el('div', { cls: 'k', text: s.k }));
        stats.appendChild(st);
      });

      const trendLine = Render.el('div', { cls: 'cust-rate-trend' });
      if (c.trend !== 0 && c.tripCount >= 4) {
        trendLine.textContent = `Rate trend: ${c.trend > 0 ? '+' : ''}${c.trend.toFixed(1)}% (comparing first half to recent trips)`;
        trendLine.style.color = c.trend > 5 ? 'var(--accent-success)' : c.trend < -5 ? 'var(--accent-danger)' : 'var(--text-secondary)';
      } else {
        trendLine.textContent = c.tripCount < 4 ? 'Need 4+ trips for trend analysis' : 'Rate stable';
        trendLine.style.color = 'var(--text-tertiary)';
      }

      card.appendChild(header);
      card.appendChild(stats);
      card.appendChild(trendLine);
      frag.appendChild(card);
    });
    el.appendChild(frag);
  } catch (e) {
    console.error('[CustHistory] Error:', e);
  }
}

// ============================================================================
// FEATURE 4: RECEIPT AMOUNT QUICK-ENTRY
// ============================================================================
// After capturing a receipt photo, prompt user to enter the amount immediately
// This saves a separate step and pre-fills the form field
async function promptReceiptAmount(context) {
  try {
    const targetField = context === 'trip' ? 'revenue' :
                        context === 'meal' ? 'mealAmount' :
                        'expenseAmount';
    const el = $(targetField);
    if (el && !el.value) {
      el.style.transition = 'box-shadow 0.3s';
      el.style.boxShadow = '0 0 0 3px rgba(255,179,0,0.5)';
      el.focus();
      setTimeout(() => { el.style.boxShadow = ''; }, 2000);
      showToast('📸 Receipt captured — enter the amount');
    }
  } catch (e) { console.error('[ReceiptQuickEntry] Error:', e); }
}

// ============================================================================
// FEATURE 5: DASHBOARD SUMMARY ON APP OPEN
// ============================================================================
async function refreshDashboard() {
  try {
    const dashEl = $('m-dashboard');
    if (!dashEl) return;

    const today = new Date();
    const monthStart = today.getFullYear() + '-' + String(today.getMonth() + 1).padStart(2, '0') + '-01';
    const todayStr = getTodayStr();

    $('dashDate').textContent = today.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' });

    const trips = (await dbOp('trips', 'readonly', s => s.getAll())).filter(isActiveRecord);
    const fuel = (await dbOp('fuel', 'readonly', s => s.getAll())).filter(isActiveRecord);
    const expenses = (await dbOp('expenses', 'readonly', s => s.getAll())).filter(isActiveRecord);

    // Month revenue
    const monthTrips = trips.filter(t => (t.pickupDate || '') >= monthStart);
    const monthRev = monthTrips.reduce((s, t) => s + safeFloat(t.revenue), 0);
    const lastMonthStart = new Date(today.getFullYear(), today.getMonth() - 1, 1);
    const lastMonthEnd = new Date(today.getFullYear(), today.getMonth(), 0);
    const lmFrom = lastMonthStart.toISOString().split('T')[0];
    const lmTo = lastMonthEnd.toISOString().split('T')[0];
    const lastMonthTrips = trips.filter(t => (t.pickupDate || '') >= lmFrom && (t.pickupDate || '') <= lmTo);
    const lastMonthRev = lastMonthTrips.reduce((s, t) => s + safeFloat(t.revenue), 0);

    $('dashMonthRev').textContent = formatMoney(monthRev);
    if (lastMonthRev > 0) {
      const pct = ((monthRev - lastMonthRev) / lastMonthRev) * 100;
      $('dashMonthRevSub').textContent = `${pct >= 0 ? '+' : ''}${pct.toFixed(0)}% vs last month`;
      $('dashMonthRevSub').style.color = pct >= 0 ? 'var(--accent-success)' : 'var(--accent-danger)';
    } else {
      $('dashMonthRevSub').textContent = `${monthTrips.length} trips this month`;
    }

    // Unpaid A/R
    const unpaid = trips.filter(t => !t.paid);
    const unpaidRev = unpaid.reduce((s, t) => s + safeFloat(t.revenue), 0);
    const overdue60 = unpaid.filter(t => {
      const age = Math.floor((Date.now() - new Date((t.pickupDate || '') + 'T00:00:00').getTime()) / 86400000);
      return age > 60;
    });
    $('dashUnpaid').textContent = formatMoney(unpaidRev);
    $('dashUnpaidSub').textContent = unpaid.length + ' trips' + (overdue60.length ? ` (${overdue60.length} overdue 60+)` : '');

    // Month trips
    $('dashMonthTrips').textContent = monthTrips.length;
    const monthMiles = monthTrips.reduce((s, t) => s + safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles), 0);
    $('dashMonthTripsSub').textContent = monthMiles.toFixed(0) + ' miles';

    // Next IFTA deadline
    const qDeadlines = [
      { q: 'Q1', month: 3, day: 30 }, { q: 'Q2', month: 6, day: 30 },
      { q: 'Q3', month: 9, day: 30 }, { q: 'Q4', month: 0, day: 31 }  // Q4 = Jan 31 next year
    ];
    let nextIFTA = '';
    let nextIFTASub = '';
    for (const dl of qDeadlines) {
      const yr = dl.month === 0 ? today.getFullYear() + 1 : today.getFullYear();
      const deadline = new Date(yr, dl.month === 0 ? 0 : dl.month, dl.day);
      if (deadline > today) {
        const daysUntil = Math.ceil((deadline - today) / 86400000);
        nextIFTA = dl.q + ' ' + (dl.month === 0 ? yr : today.getFullYear());
        nextIFTASub = daysUntil + ' days';
        break;
      }
    }
    $('dashIFTA').textContent = nextIFTA || '—';
    $('dashIFTASub').textContent = nextIFTASub || '';

    // Alerts
    const alertsEl = $('dashAlerts');
    alertsEl.innerHTML = '';
    if (overdue60.length > 0) {
      const alert = Render.el('div', { cls: 'warning-banner', style: 'margin-bottom:6px;' });
      alert.textContent = `⚠️ ${overdue60.length} trip${overdue60.length > 1 ? 's' : ''} overdue 60+ days — total ${formatMoney(overdue60.reduce((s, t) => s + safeFloat(t.revenue), 0))}`;
      alertsEl.appendChild(alert);
    }

    // Backup reminder check
    const lastBackup = localStorage.getItem('backupLastExport');
    if (lastBackup) {
      const daysSince = Math.floor((Date.now() - parseInt(lastBackup, 10)) / 86400000);
      if (daysSince > 7) {
        const alert = Render.el('div', { cls: 'info-banner', style: 'margin-bottom:6px;' });
        alert.textContent = `💾 Last backup was ${daysSince} days ago. Consider exporting a backup.`;
        alertsEl.appendChild(alert);
      }
    }

  } catch (e) {
    console.error('[Dashboard] Error:', e);
  }
}

// ============================================================================
// FEATURE 7: ENHANCED LOAD SIMULATOR WITH HISTORICAL DEFAULTS
// ============================================================================
async function prefillSimulatorFromHistory() {
  try {
    const fuel = (await dbOp('fuel', 'readonly', s => s.getAll())).filter(isActiveRecord);
    const trips = (await dbOp('trips', 'readonly', s => s.getAll())).filter(isActiveRecord);

    // Calculate actual avg MPG from recent data
    const totalGallons = fuel.reduce((s, f) => s + safeFloat(f.gallons), 0);
    const totalMiles = trips.reduce((s, t) => s + safeFloat(t.loadedMiles) + safeFloat(t.emptyMiles), 0);
    const avgMPG = totalGallons > 0 && totalMiles > 0 ? totalMiles / totalGallons : 0;

    // Calculate avg fuel price from last 10 fills
    const recentFuel = fuel.filter(f => safeFloat(f.gallons) > 0).sort((a, b) => (b.date || '').localeCompare(a.date || '')).slice(0, 10);
    const avgPPG = recentFuel.length > 0 ? recentFuel.reduce((s, f) => s + (safeFloat(f.amount) / safeFloat(f.gallons)), 0) / recentFuel.length : 0;

    // Calculate avg deadhead %
    let totalLoaded = 0, totalEmpty = 0;
    trips.forEach(t => { totalLoaded += safeFloat(t.loadedMiles); totalEmpty += safeFloat(t.emptyMiles); });
    const deadheadPct = totalLoaded > 0 ? (totalEmpty / totalLoaded) * 100 : 0;

    // Pre-fill if fields are empty
    const simMPG = $('simMPG');
    const simFuelPrice = $('simFuelPrice');
    if (simMPG && !simMPG.value && avgMPG > 0) simMPG.value = avgMPG.toFixed(1);
    if (simFuelPrice && !simFuelPrice.value && avgPPG > 0) simFuelPrice.value = avgPPG.toFixed(2);

    // Show historical context
    const infoEl = $('simHistoricalInfo');
    if (infoEl) {
      if (avgMPG > 0 || avgPPG > 0) {
        infoEl.textContent = `Your data: ${avgMPG.toFixed(1)} MPG avg, $${avgPPG.toFixed(2)}/gal avg, ${deadheadPct.toFixed(0)}% deadhead ratio`;
        infoEl.style.display = 'block';
      }
    }
  } catch (e) {
    console.error('[Simulator] Prefill error:', e);
  }
}

// ============================================================================
// INIT
// ============================================================================

// Bind navigation tabs immediately (do not depend on IndexedDB init)
// This prevents "dead UI" if IndexedDB is blocked/unavailable on iOS.
(function bindNavOnce(){
  if (window.__XPEDITE_OS_NAV_BOUND__) return;
  window.__XPEDITE_OS_NAV_BOUND__ = true;

  // Event delegation keeps a single listener (prevents duplication/leaks)
  document.addEventListener('click', (e) => {
    const btn = e.target && e.target.closest ? e.target.closest('.nav-tab') : null;
    if (!btn) return;
    const id = btn.getAttribute('data-tab');
    if (!id) return;
    e.preventDefault();
    try { switchTab(id); } catch (err) { try { console.error(err); } catch(_) {} }
  }, { passive: false });
})();

initDB().then(async () => {
  // Prevent double-init (iOS can sometimes restore state / re-run scripts in edge cases)
  if (window.__XPEDITE_OS_INIT__) return;
  window.__XPEDITE_OS_INIT__ = true;

  try { await PINModule.init(); } catch (_) {}

  // Blacksite UI wiring self-test (fail loud instead of silent dead UI)
  try { assertCriticalUI(); } catch (e) {
    console.error(e);
    alert(String(e && e.message ? e.message : e));
    return;
  }
console.log('[App] Freight Logic v10.1.1 initializing');

  const today = getTodayStr();
  ['pickupDate','deliveryDate','fuelDate','expenseDate','mealDate'].forEach(id => {
    const el = $(id); if (el) el.value = today;
  });

  await loadAllRateSettings();

  try {
    const saved = await dbOp('settings', 'readonly', s => s.get('deductionMethod'));
    if (saved && saved.value) setDeductionMethod(saved.value);
  } catch (e) {}

  // ── Event listeners ──

  $safe('versionBadge').addEventListener('click', openSettings);
  $safe('settingsBtn').addEventListener('click', openSettings);

  // nav tabs handled by delegated listener in bindNavOnce()

  $safe('btnDuplicateTrip').addEventListener('click', duplicateLastTrip);
  $safe('btnUseLastDest').addEventListener('click', useLastDestination);


  // Integrations (deep links) — safe encoded params + fallbacks
  const updateNavButtons = () => {
    const o = $safe('origin').value.trim();
    const d = $safe('dest').value.trim();
    const enabled = !!(o && d);
    $safe('btnOpenGoogleMaps').disabled = !enabled;
    $safe('btnOpenCoPilot').disabled = !enabled;
    $safe('btnOpenTruckerPath').disabled = !enabled;
  };
  $safe('origin').addEventListener('input', updateNavButtons);
  $safe('dest').addEventListener('input', updateNavButtons);
  updateNavButtons();

  $safe('btnOpenGoogleMaps').addEventListener('click', () => openGoogleMaps());
  $safe('btnOpenCoPilot').addEventListener('click', () => openCoPilot());
  $safe('btnOpenTruckerPath').addEventListener('click', () => openTruckerPath());

  $safe('btnStartGPS').addEventListener('click', startGPSTracking);
  $safe('btnSaveTrip').addEventListener('click', saveTrip);


  // Receipts v2 (Trip)
  $safe('btnTripAddReceipt')?.addEventListener('click', () => $safe('tripReceiptFiles')?.click());
  $safe('tripReceiptFiles')?.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    await handleReceiptFilesForContext('trip', files);
  });
  $safe('btnTripViewReceipts').addEventListener('click', () => openReceiptsViewer({ type:'trip', orderNo: normalizeOrderNo($safe('orderNo').value) }));
  $safe('orderNo').addEventListener('input', () => { refreshReceiptCounts(); });

  // Receipts v2 (Expense)
  $safe('btnExpenseAddReceipt')?.addEventListener('click', () => $safe('expenseReceiptFiles')?.click());
  $safe('expenseReceiptFiles')?.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    await handleReceiptFilesForContext('expense', files);
  });
  $safe('btnExpenseViewReceipts')?.addEventListener('click', () => openReceiptsViewer({ type:'expense', temp:true }));

  // Receipts v2 (Meal)
  $safe('btnMealAddReceipt')?.addEventListener('click', () => $safe('mealReceiptFiles')?.click());
  $safe('mealReceiptFiles')?.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    await handleReceiptFilesForContext('meal', files);
  });
  $safe('btnMealViewReceipts')?.addEventListener('click', () => openReceiptsViewer({ type:'meal', temp:true }));

  // Receipts viewer modals
  $safe('closeReceiptsModal').addEventListener('click', () => $safe('receiptsModal').classList.remove('active'));
  $safe('closeReceiptFullscreen').addEventListener('click', () => {
    $safe('receiptFullscreen').classList.remove('active');
    // Reset transform state
    const imgEl = $('receiptFullscreenImg');
    if (imgEl) { imgEl.style.transform = ''; imgEl.style.filter = ''; }
    window._receiptViewState = null;
  });

  // Initialize Receipt Reader v2 toolbar
  initReceiptToolbar();

  $safe('btnStopGPS').addEventListener('click', stopGPSTracking);

  // Show order# normalization hint on focus
  $safe('orderNo').addEventListener('focus', () => { $safe('orderNoHint').style.display = 'block'; });
  $safe('orderNo').addEventListener('blur', () => {
    $safe('orderNoHint').style.display = 'none';
    // Auto-normalize on blur
    const raw = $safe('orderNo').value;
    const norm = normalizeOrderNo(raw);
    if (raw !== norm) $safe('orderNo').value = norm;
  });

  $safe('tripSearch').addEventListener('input', debouncedApplyFilters);
  $safe('filterCustomer').addEventListener('change', applyFilters);
  $safe('filterStatus').addEventListener('change', applyFilters);
  $safe('filterDateRange').addEventListener('change', e => {
    $safe('customDateRange').style.display = e.target.value === 'custom' ? 'flex' : 'none';
    applyFilters();
  });
  $safe('filterDateFrom').addEventListener('change', applyFilters);
  $safe('filterDateTo').addEventListener('change', applyFilters);

  $safe('btnBulkMode').addEventListener('click', toggleBulkMode);
  $safe('btnSelectAll').addEventListener('click', selectAllTrips);
  $safe('btnDeselectAll').addEventListener('click', deselectAllTrips);
  $safe('btnBulkMarkPaid').addEventListener('click', bulkMarkPaid);
  $safe('btnBulkMarkUnpaid').addEventListener('click', bulkMarkUnpaid);
  $safe('btnExitBulkMode').addEventListener('click', toggleBulkMode);

  // Pagination
  $safe('btnPrevPage').addEventListener('click', () => { currentPage--; refreshUI(); });
  $safe('btnNextPage').addEventListener('click', () => { currentPage++; refreshUI(); });

  $safe('reportPeriod').addEventListener('change', e => {
    $safe('reportCustomDates').style.display = e.target.value === 'custom' ? 'flex' : 'none';
  });

  // Helper: switch to a module by ID
  function setActiveModule(moduleId) {
    document.querySelectorAll('.module').forEach(m => m.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
    const mod = $(moduleId);
    if (mod) mod.classList.add('active');
    // Find matching tab
    const tabMap = {'m-trips':'trips','m-expenses':'expenses','m-ar':'ar','m-reports':'reports','m-summary':'summary'};
    const tabId = tabMap[moduleId];
    if (tabId) {
      const tab = document.querySelector(`[data-tab="${tabId}"]`);
      if (tab) tab.classList.add('active');
      if (tabId === 'summary') refreshSummary();
      if (tabId === 'reports') refreshSummary();
      if (tabId === 'ar') refreshARPanel();
    }
  }

  // Reports quick chips — keep selector as source of truth
  const reportChipsEl = $('reportChips');
  if (reportChipsEl) {
    reportChipsEl.addEventListener('click', e => {
      const btn = e.target.closest('.cc-chip');
      if (!btn) return;
      const p = btn.getAttribute('data-period');
      const sel = $('reportPeriod');
      if (!sel) return;
      sel.value = p;
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      reportChipsEl.querySelectorAll('.cc-chip').forEach(b => b.classList.toggle('active', b === btn));
    }, { passive: true });
  }

  // Jump shortcuts
  const btnJumpSummaryEl = $('btnJumpSummary');
  if (btnJumpSummaryEl) btnJumpSummaryEl.addEventListener('click', () => setActiveModule('m-summary'));
  const btnJumpAREl = $('btnJumpAR');
  if (btnJumpAREl) btnJumpAREl.addEventListener('click', () => setActiveModule('m-ar'));
  $safe('btnGenerateReport').addEventListener('click', generateReport);
  $safe('btnExportPDF').addEventListener('click', exportPDF);

  document.querySelectorAll('.expense-type-btn').forEach(btn => {
    btn.addEventListener('click', () => selectExpenseType(btn.getAttribute('data-expense-type')));
  });

  $safe('btnSaveFuel').addEventListener('click', saveFuel);
  $safe('btnSaveExpense').addEventListener('click', saveExpense);
  $safe('btnSaveMeal').addEventListener('click', saveMeal);

  $safe('toggleStdMileage').addEventListener('click', () => setDeductionMethod('standard'));
  $safe('toggleActualExp').addEventListener('click', () => setDeductionMethod('actual'));
  $safe('btnExportCSV').addEventListener('click', exportCSV);

  $safe('closeSettingsBtn').addEventListener('click', closeSettings);
  $safe('btnSaveAddress').addEventListener('click', saveHomeAddress);
  $safe('btnSaveBaselineMPG').addEventListener('click', saveBaselineMPG);
  $safe('homeState').addEventListener('change', saveHomeAddress);
  $safe('baselineMPG').addEventListener('change', () => { /* manual save via button */ });
  $safe('mpgAlertPct').addEventListener('change', () => { /* manual save via button */ });
  $safe('gpsEnabledToggle').addEventListener('change', e => saveGPSEnabled(e.target.checked));
  $safe('gpsHighAccuracyToggle').addEventListener('change', e => saveGPSHighAccuracy(e.target.checked));
  $safe('federalTaxBracket').addEventListener('change', saveTaxSettings);
  $safe('mileageRateSetting').addEventListener('change', saveMileageRate);
  $safe('perDiemRateSetting').addEventListener('change', savePerDiemSettings);
  $safe('btnImportCSV').addEventListener('click', () => $safe('fileImportCSV').click());

  // Encrypted backup/sync
  $safe('btnExportEncryptedBackup').addEventListener('click', exportEncryptedBackup);
  $safe('btnExportSyncPack').addEventListener('click', exportSyncPackLatestAndHistory);
  $safe('btnExportAccountantPacket').addEventListener('click', exportAccountantPacket);
  setTimeout(() => { try { renderBackupHistoryInline(); } catch {} }, 250);
  $safe('btnImportEncryptedBackup').addEventListener('click', () => $safe('fileImportBackup').click());
  $safe('fileImportBackup').addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0]; e.target.value = '';
    if (f) importEncryptedBackup(f);
  });
  $safe('backupEnabledToggle').addEventListener('change', (e) => {
    const enabled = e.target.checked;
    if (enabled && localStorage.getItem('pinEnabled') !== 'true') {
      showToast('Set a PIN first to enable encrypted backups', true);
      e.target.checked = false;
      openSettings();
      $safe('pinSetupForm').style.display = 'block';
      return;
    }
    localStorage.setItem('backupEnabled', enabled ? 'true' : 'false');
  });
  $safe('backupIncludeReceiptsToggle').addEventListener('change', (e) => localStorage.setItem('backupIncludeReceipts', e.target.checked ? 'true' : 'false'));
  $safe('backupReminderSelect').addEventListener('change', (e) => { localStorage.setItem('backupReminder', e.target.value); scheduleBackupReminder(); });

  // PIN Setup Toggle (null-safe)
  const pinToggle = $safe('pinEnabledToggle');
  if (pinToggle) {
    pinToggle.addEventListener('change', async (e) => {
      const enabled = e.target.checked;
      const setupForm = $safe('pinSetupForm');
      const status = $safe('pinStatus');
      if (enabled) {
        if (setupForm) setupForm.style.display = 'block';
      } else {
        if (confirm('Disable PIN lock? This will remove encryption protection.')) {
          PINModule.disable();
          if (setupForm) setupForm.style.display = 'none';
          if (status) { status.textContent = 'PIN disabled'; status.style.color = 'var(--text-tertiary)'; }
        } else {
          e.target.checked = true;
        }
      }
    });
  }

  // Save PIN Button (null-safe)
  const btnSavePinEl = $safe('btnSavePin');
  if (btnSavePinEl) {
    btnSavePinEl.addEventListener('click', async () => {
      const pin1 = $safe('newPinInput')?.value || '';
      const pin2 = $safe('confirmPinInput')?.value || '';
      const status = $safe('pinStatus');
      if (pin1.length < 4) return showToast('PIN must be at least 4 digits', true);
      if (pin1 !== pin2) return showToast('PINs do not match', true);
      try {
        await PINModule.setPIN(pin1);
        if (status) { status.textContent = '✅ PIN enabled and data encrypted'; status.style.color = 'var(--accent-success)'; }
        if ($safe('newPinInput')) $safe('newPinInput').value = '';
        if ($safe('confirmPinInput')) $safe('confirmPinInput').value = '';
        if ($safe('pinSetupForm')) $safe('pinSetupForm').style.display = 'none';
        showToast('✅ PIN lock enabled');
      } catch (e) { showToast('Error setting PIN: ' + e.message, true); }
    });
  }

  // Audit Log Viewer (null-safe, DOM-built)
  const btnAuditEl = $safe('btnViewAuditLog');
  if (btnAuditEl) {
    btnAuditEl.addEventListener('click', async () => {
      const preview = $safe('auditPreview');
      if (!preview) return;
      preview.style.display = 'block';
      Render.clear(preview);
      preview.appendChild(Render.emptyPanel('Loading audit trail...'));
      const history = await AuditModule.getHistory(null, null, 100);
      Render.clear(preview);
      if (!history.length) {
        preview.appendChild(Render.emptyPanel('No audit history yet. Trip edits will be logged here.'));
        return;
      }
      const frag = document.createDocumentFragment();
      history.forEach(entry => {
        const el = Render.el('div', { cls: 'audit-entry' });
        el.appendChild(Render.el('div', { cls: 'audit-timestamp', text: new Date(entry.timestamp).toLocaleString() + ' • Device: ' + (entry.deviceId || '').slice(-8) }));
        const actionDiv = Render.el('div');
        const strong = Render.el('strong', { text: entry.action.toUpperCase() + ' ' });
        actionDiv.appendChild(strong);
        actionDiv.appendChild(document.createTextNode(entry.entityType + ' '));
        actionDiv.appendChild(Render.el('code', { text: entry.entityId }));
        el.appendChild(actionDiv);
        const changes = Object.entries(entry.changes || {});
        if (changes.length) {
          const chgDiv = Render.el('div', { style: 'font-size:11px;margin-top:4px;' });
          chgDiv.textContent = changes.map(([k, v]) => k + ': ' + JSON.stringify(v.old) + ' → ' + JSON.stringify(v.new)).join(', ');
          el.appendChild(chgDiv);
        }
        frag.appendChild(el);
      });
      preview.appendChild(frag);
    });
  }


  // Expense category manager (Settings)
  $safe('newCategoryLabel').addEventListener('input', () => {
    const label = $safe('newCategoryLabel').value || '';
    const guess = normalizeCategoryKey(label.replace(/^[^a-z0-9]+/i,''));
    if (!$safe('newCategoryKey').value) $safe('newCategoryKey').value = guess;
  });
  $safe('btnAddCategory').addEventListener('click', async () => {
    const label = ($safe('newCategoryLabel').value || '').trim();
    if (!label) return showToast('Enter a category label', true);
    const key = normalizeCategoryKey(($safe('newCategoryKey').value || label));
    const cfg = await getExpenseCategoryConfig();
    cfg.categories = cfg.categories || [];
    if (cfg.categories.some(c => c.key === key)) return showToast('Category key already exists', true);
    cfg.categories.push({ key, label: label.slice(0,40) });
    await saveExpenseCategoryConfig(cfg);
    $safe('newCategoryLabel').value=''; $safe('newCategoryKey').value='';
    await renderCategoryManager();
    showToast('✅ Category added');
  });
  $safe('btnAddRule').addEventListener('click', async () => {
    const contains = ($safe('ruleContains').value || '').trim();
    const category = $safe('ruleCategory').value;
    if (!contains) return showToast('Enter a match string', true);
    const cfg = await getExpenseCategoryConfig();
    cfg.rules = cfg.rules || [];
    cfg.rules.push({ contains: contains.slice(0,40), category });
    await saveExpenseCategoryConfig(cfg);
    $safe('ruleContains').value='';
    await renderCategoryManager();
    showToast('✅ Rule added');
  });
  // Delegate remove buttons
  document.addEventListener('click', async (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.matches('[data-cat-idx]')) {
      const idx = Number(t.getAttribute('data-cat-idx'));
      const cfg = await getExpenseCategoryConfig();
      cfg.categories = (cfg.categories || []).filter((_,i)=>i!==idx);
      await saveExpenseCategoryConfig(cfg);
      await renderCategoryManager();
      showToast('Removed category');
    }
    if (t.matches('[data-rule-idx]')) {
      const idx = Number(t.getAttribute('data-rule-idx'));
      const cfg = await getExpenseCategoryConfig();
      cfg.rules = (cfg.rules || []).filter((_,i)=>i!==idx);
      await saveExpenseCategoryConfig(cfg);
      await renderCategoryManager();
      showToast('Removed rule');
    }
  }, { passive:true });

  setTimeout(() => { try { renderCategoryManager(); } catch {} }, 350);


  $safe('fileImportCSV').addEventListener('change', e => {
    const f = e.target.files && e.target.files[0]; if (f) importUnifiedCSV(f);
  });
  $safe('btnClearAll').addEventListener('click', clearAllData);
  $safe('btnRestoreLast').addEventListener('click', restoreLastDeleted);

  $safe('closeGPSModal').addEventListener('click', closeGPSModal);
  $safe('btnCancelGPS').addEventListener('click', closeGPSModal);
  $safe('btnEnableGPS').addEventListener('click', requestGPSPermission);

  $safe('closeDeleteModal').addEventListener('click', closeDeleteModal);
  $safe('btnCancelDelete').addEventListener('click', closeDeleteModal);
  $safe('btnConfirmDelete').addEventListener('click', executeDelete);

  // Periodic quota check
  checkStorageQuota();
  setInterval(checkStorageQuota, 60000);

  refreshUI();

  // Event Listeners (continued)
  // simBtn handled in v10.1.1 features block above
  $safe('closeSimModal').addEventListener('click', () => $safe('simulatorModal').classList.remove('active'));
  $safe('btnRunSimulator').addEventListener('click', runLoadSimulator);
  $safe('btnRefreshAR').addEventListener('click', refreshARPanel);
  $safe('btnCalcBreakeven').addEventListener('click', calculateBreakEven);
  
  // Handle PWA shortcuts
  const urlParams = new URLSearchParams(location.search);
  if (urlParams.get('action') === 'newtrip') {
    switchTab('trips');
    setTimeout(() => { const o = $('orderNo'); if (o) o.focus(); }, 300);
  }
  if (urlParams.get('action') === 'simulator') {
    $safe('simulatorModal').classList.add('active');
  }

  // ── Share Target: process screenshots shared from Dispatchland / other apps ──
  if (urlParams.get('share-target') === 'received') {
    try {
      const cache = await caches.open('freight-logic-shared-files-v10.1.1');
      const countResp = await cache.match('/shared-receipt-count');
      if (countResp) {
        const count = parseInt(await countResp.text(), 10);
        if (count > 0) {
          const files = [];
          for (let i = 0; i < count; i++) {
            const resp = await cache.match(`/shared-receipt-${i}`);
            if (resp) {
              const blob = await resp.blob();
              const name = resp.headers.get('X-Filename') || `shared-${i}.jpg`;
              files.push(new File([blob], name, { type: blob.type || 'image/jpeg' }));
            }
          }
          // Clean up cache
          const keys = await cache.keys();
          for (const k of keys) await cache.delete(k);

          // Ask SW to purge shared cache as well (best-effort)
          try {
            if (navigator.serviceWorker && navigator.serviceWorker.controller) {
              navigator.serviceWorker.controller.postMessage({ type: 'CLEAR_SHARED_FILES' });
            }
          } catch (_) {}

          if (files.length > 0) {
            // Switch to trips tab and load shared images as trip receipts
            switchTab('trips');
            await handleReceiptFilesForContext('trip', files);
            showToast(`📸 ${files.length} screenshot${files.length > 1 ? 's' : ''} received — fill in trip details & save`);
            setTimeout(() => { const o = $('orderNo'); if (o) o.focus(); }, 300);
          }
        }
      }
    } catch (e) {
      console.error('[Share Target] Error processing shared files:', e);
    }
    // Clean URL without reloading
    if (history.replaceState) history.replaceState({}, '', './');
  }
  
  
  // First-run onboarding + backup reminder
  initOnboarding();
  maybeShowBackupReminderOnOpen();

  // ── v10.1.1 FEATURES ──

  // Feature 1: IFTA
  $safe('btnGenerateIFTA').addEventListener('click', generateIFTAReport);
  $safe('btnExportIFTA').addEventListener('click', exportIFTACSV);
  // Populate IFTA year dropdown
  try {
    const iftaYearSel = $('iftaYear');
    if (iftaYearSel) {
      const yr = new Date().getFullYear();
      for (let y = yr; y >= yr - 3; y--) {
        const opt = document.createElement('option');
        opt.value = y; opt.textContent = y;
        iftaYearSel.appendChild(opt);
      }
    }
    // Default to current quarter
    const cq = Math.floor(new Date().getMonth() / 3);
    const iftaQSel = $('iftaQuarter');
    if (iftaQSel) iftaQSel.value = 'Q' + (cq + 1);
  } catch {}

  // Feature 2: Recurring expenses
  $safe('expenseRecurring').addEventListener('change', (e) => {
    const opts = $('recurringOptions');
    if (opts) opts.style.display = e.target.checked ? 'block' : 'none';
  });
  try { await processRecurringExpenses(); } catch {}
  // Delegate recurring expense delete
  document.addEventListener('click', async (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.matches('[data-recurring-idx]')) {
      const idx = Number(t.getAttribute('data-recurring-idx'));
      const templates = (await getSettingKV('recurringTemplatesV1', [])) || [];
      templates.splice(idx, 1);
      await setSettingKV('recurringTemplatesV1', templates);
      await renderRecurringExpenseManager();
      showToast('Removed recurring expense');
    }
  }, { passive: true });
  setTimeout(() => { try { renderRecurringExpenseManager(); } catch {} }, 400);

  // Feature 3: Customer rate history
  $safe('btnRefreshCustHistory').addEventListener('click', refreshCustomerRateHistory);

  // Feature 5: Dashboard
  try { await refreshDashboard(); } catch {}

  // Feature 7: Enhanced simulator - prefill on modal open
  $safe('simBtn').addEventListener('click', () => {
    $safe('simulatorModal').classList.add('active');
    prefillSimulatorFromHistory();
  });

  // Add historical info display area to simulator
  try {
    const simInfo = $('simResults');
    if (simInfo && !$('simHistoricalInfo')) {
      const infoDiv = document.createElement('div');
      infoDiv.id = 'simHistoricalInfo';
      infoDiv.style.cssText = 'display:none; margin-top:8px; font-size:11px; color:var(--text-secondary); background:var(--bg-tertiary); padding:8px; border-radius:6px;';
      simInfo.parentNode.insertBefore(infoDiv, simInfo);
    }
  } catch {}

  console.log('[App] Freight Logic v10.1.1 Ready');
}).catch(e => {
  // Keep navigation usable even if IndexedDB fails (private mode/quota/blocked).
  try { console.error('[App] Init failed:', e); } catch (_) {}
  window.__XPEDITE_OS_DB_READY__ = false;
  showToast('⚠️ Storage unavailable — some features disabled', true);
});

})();


// ─────────────────────────────────────────────────────────────────────────────
// Modal focus trap (a11y hardening)
// Keeps keyboard focus inside active .modal elements and restores focus on close.
// Disabled automatically if no modal is active.
// ─────────────────────────────────────────────────────────────────────────────
(() => {
  let activeModal = null;
  let lastFocus = null;

  const getFocusable = (root) => {
    const sel = [
      'a[href]', 'button:not([disabled])', 'input:not([disabled])',
      'select:not([disabled])', 'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])'
    ].join(',');
    return Array.from(root.querySelectorAll(sel))
      .filter(el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length));
  };

  const tryCloseModal = () => {
    if (!activeModal) return;
    // Prefer explicit close buttons if present
    const closeBtn =
      activeModal.querySelector('[data-close-modal]') ||
      activeModal.querySelector('button[aria-label="Close"]') ||
      activeModal.querySelector('button[id^="close"]') ||
      document.querySelector(`button[id^="close${activeModal.id.replace(/Modal$/,'')}"]`);
    if (closeBtn) closeBtn.click();
    else activeModal.classList.remove('active');
  };

  const onKeyDown = (e) => {
    if (!activeModal) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      tryCloseModal();
      return;
    }
    if (e.key !== 'Tab') return;

    const focusable = getFocusable(activeModal);
    if (!focusable.length) {
      e.preventDefault();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const cur = document.activeElement;

    if (e.shiftKey) {
      if (cur === first || !activeModal.contains(cur)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (cur === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  const activate = (modal) => {
    if (activeModal === modal) return;
    activeModal = modal;
    lastFocus = document.activeElement;
    document.addEventListener('keydown', onKeyDown, true);

    // Focus the first focusable element, else the modal itself
    setTimeout(() => {
      const focusable = getFocusable(modal);
      (focusable[0] || modal).focus?.();
    }, 0);
  };

  const deactivate = () => {
    if (!activeModal) return;
    document.removeEventListener('keydown', onKeyDown, true);
    const restore = lastFocus;
    activeModal = null;
    lastFocus = null;
    setTimeout(() => restore?.focus?.(), 0);
  };

  const modals = () => Array.from(document.querySelectorAll('.modal'));
  const sync = () => {
    const open = modals().find(m => m.classList.contains('active'));
    if (open) activate(open);
    else deactivate();
  };

  // Watch modal class changes
  const obs = new MutationObserver(sync);
  const start = () => {
    modals().forEach(m => {
      // Ensure modal is focusable as a last resort
      if (!m.hasAttribute('tabindex')) m.setAttribute('tabindex','-1');
      obs.observe(m, { attributes: true, attributeFilter: ['class'] });
    });
    sync();
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
})();