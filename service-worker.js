/* Freight Logic v16.3.1 — Service Worker */
const SW_VERSION = '16.3.1';
const CACHE_NAME = `freightlogic-${SW_VERSION}`;
const RECEIPT_CACHE = 'freightlogic-receipts-v1';
const CORE = [
  './',
  './index.html',
  './app.js',
  './manifest.json',
  './icons/icon64.png',
  './icons/icon128.png',
  './icons/icon192.png',
  './icons/icon256.png',
  './icons/icon512.png',
  './icons/icon180.png',
  './icons/icon167.png',
  './icons/icon152.png',
  './icons/icon120.png',
  './icons/favicon32.png',
  './icons/favicon16.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(CORE);
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    const keep = new Set([CACHE_NAME, RECEIPT_CACHE, 'freightlogic-share-v1']);
    await Promise.all(keys.map(k => keep.has(k) ? null : caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  const msg = event.data || {};
  if (msg.type === 'GET_VERSION') {
    try { event.ports?.[0]?.postMessage({ version: SW_VERSION }); } catch {}
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // ── Share Target: intercept POST from OS share sheet ──
  // Note: URL fragments (#share) are NOT sent in HTTP requests,
  // so we match on method + pathname only. The manifest's action
  // URL includes #share as a client-side hint after redirect.
  if (req.method === 'POST' && url.pathname.endsWith('index.html')) {
    event.respondWith((async () => {
      try {
        const formData = await req.formData();
        const files = formData.getAll('receipts');
        // Store shared files in a temporary cache for the app to pick up
        if (files && files.length > 0) {
          const shareCache = await caches.open('freightlogic-share-v1');
          for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const response = new Response(file, {
              headers: { 'Content-Type': file.type, 'X-Filename': file.name }
            });
            await shareCache.put(`/shared-file-${i}`, response);
          }
          // Store file count
          await shareCache.put('/shared-meta', new Response(JSON.stringify({ count: files.length, ts: Date.now() })));
        }
      } catch (e) {
        console.warn('[FL-SW] Share target error:', e);
      }
      // Redirect to the app with #share hash
      return Response.redirect('./index.html#share', 303);
    })());
    return;
  }

  if (req.method !== 'GET') return;

  // Cache Google Fonts for offline use
  const isFont = url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com';
  if (isFont) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(req);
      if (cached) return cached;
      try {
        const res = await fetch(req);
        if (res && res.status === 200) cache.put(req, res.clone());
        return res;
      } catch { return cached || new Response('', { status: 408 }); }
    })());
    return;
  }

  if (url.origin !== self.location.origin) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const isIcon = url.pathname.endsWith('.png') || url.pathname.endsWith('.ico');
    const cached = await cache.match(req, { ignoreSearch: isIcon });
    if (cached) return cached;
    try {
      const res = await fetch(req);
      if (res && res.status === 200 && (url.pathname.endsWith('.js') || url.pathname.endsWith('.html') || url.pathname.endsWith('.json') || url.pathname.endsWith('.png'))) {
        cache.put(req, res.clone());
      }
      return res;
    } catch {
      return cached || (await cache.match('./index.html'));
    }
  })());
});
