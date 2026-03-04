/* Freight Logic v14.3.4-hardened — Service Worker */
const SW_VERSION = '14.3.4-hardened';
const CACHE_NAME = `freightlogic-${SW_VERSION}`;
const RECEIPT_CACHE = 'freightlogic-receipts-v1';
const CORE = [
  './',
  './index.html',
  './app.js',
  './manifest.json',
  './icon64.png',
  './icon128.png',
  './icon192.png',
  './icon256.png',
  './icon512.png',
  './icon180.png',
  './icon167.png',
  './icon152.png',
  './icon120.png',
  './favicon32.png',
  './favicon16.png'
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
    const keep = new Set([CACHE_NAME, RECEIPT_CACHE]);
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
