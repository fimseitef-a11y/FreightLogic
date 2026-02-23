// Freight Logic Service Worker v10.3.0 — Enterprise Hardened — Enterprise Hardened
// NOTE: Security posture preserved (no "cache every GET" regression).

const CACHE_NAME = 'freight-logic-v10.3.0';
const RUNTIME_CACHE = 'freight-logic-runtime-v10.3.0';
const MAX_RUNTIME_ENTRIES = 60;
const RUNTIME_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const SHARED_CACHE = 'freight-logic-shared-files-v10.3.0';
const SHARED_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

const PRECACHE_URLS = [
  './',
  './index.html',
  './manifest.json',
  './app.js',
  './icon192.png',
  './icon512.png'
];

// ─── INSTALL ─────────────────────────────────────────────────────────────────
self.addEventListener('install', event => {
  console.log('[SW] v10.3.0 installing...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return Promise.allSettled(
          PRECACHE_URLS.map(url =>
            cache.add(url).catch(err => {
              console.warn(`[SW] Precache miss: ${url}`, err.message);
            })
          )
        );
      })
      .then(() => {
        console.log('[SW] v10.3.0 installed');
        return undefined; // skipWaiting only via message
      })
  );
});

// ─── ACTIVATE ────────────────────────────────────────────────────────────────
self.addEventListener('activate', event => {
  console.log('[SW] v10.3.0 activating...');
  event.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter(k => k !== CACHE_NAME && k !== RUNTIME_CACHE && k !== SHARED_CACHE)
          .map(k => {
            console.log(`[SW] Purging stale cache: ${k}`);
            return caches.delete(k);
          })
      );

      // Best-effort purge of stale shared receipts cache
      try {
        const sc = await caches.open(SHARED_CACHE);
        const tsResp = await sc.match('/shared-receipt-ts');
        if (tsResp) {
          const ts = parseInt(await tsResp.text(), 10);
          if (ts && (Date.now() - ts) > SHARED_TTL_MS) {
            const skeys = await sc.keys();
            for (const k of skeys) await sc.delete(k);
          }
        }
      } catch (_) {}

      console.log('[SW] v10.3.0 activated');

      // Notify all clients that new version is active
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({ type: 'SW_UPDATED', version: 'v10.3.0' });
      });

      await self.clients.claim();
    } catch (e) {
      console.error('[SW] activate error', e);
    }
  })());
});


// ─── FETCH ───────────────────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const reqURL = new URL(request.url);

  // ── Share Target: intercept POST from iOS/Android share sheet ──
  if (request.method === 'POST' && reqURL.searchParams.has('share-target')) {
    event.respondWith((async () => {
      try {
        const formData = await request.formData();
        const files = formData.getAll('receipts');
        if (files && files.length > 0) {
          // Cache shared files for the app to pick up
          const cache = await caches.open(SHARED_CACHE);

          // If previous shared payload is stale, purge it (privacy + correctness)
          try {
            const tsResp = await cache.match('/shared-receipt-ts');
            if (tsResp) {
              const ts = parseInt(await tsResp.text(), 10);
              if (ts && (Date.now() - ts) > SHARED_TTL_MS) {
                const oldKeys = await cache.keys();
                for (const k of oldKeys) await cache.delete(k);
              }
            }
          } catch (_) {}

          // Clear previous shared files

          const keys = await cache.keys();
          for (const k of keys) await cache.delete(k);
          // Store each shared file with a numbered key
          for (let i = 0; i < files.length; i++) {
            const response = new Response(files[i], {
              headers: { 'Content-Type': files[i].type || 'image/jpeg', 'X-Filename': files[i].name || `shared-${i}.jpg` }
            });
            await cache.put(`/shared-receipt-${i}`, response);
          }
          // Store count
          await cache.put('/shared-receipt-count', new Response(String(files.length)));
          await cache.put('/shared-receipt-ts', new Response(String(Date.now())));
        }
      } catch (e) {
        console.error('[SW] Share target error:', e);
      }
      // Redirect to app with share flag
      return Response.redirect('./?share-target=received', 303);
    })());
    return;
  }

  if (request.method !== 'GET') return;
  if (!request.url.startsWith('http')) return;

  const isSameOrigin = reqURL.origin === self.location.origin;

  // Network-first for HTML to ensure updates
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(response => {
          if (response && response.status === 200 && response.type === 'basic') {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => {
          return caches.match(request).then(cached => {
            return cached || caches.match('./index.html') || caches.match('./');
          });
        })
    );
    return;
  }

  // Cache-first for assets (with TTL for runtime cache)
  event.respondWith((async () => {
    try {
      // Prefer precache for known assets
      const precache = await caches.open(CACHE_NAME);
      const pre = await precache.match(request);
      if (pre) return pre;

      const cache = await caches.open(RUNTIME_CACHE);
      const metaKey = request.url + '::__meta';

      const cached = await cache.match(request);
      if (cached) {
        // TTL enforcement using separate meta entry
        try {
          const metaResp = await cache.match(metaKey);
          if (metaResp) {
            const ts = parseInt(await metaResp.text(), 10);
            if (ts && (Date.now() - ts) > RUNTIME_TTL_MS) {
              await cache.delete(request);
              await cache.delete(metaKey);
            } else {
              return cached;
            }
          } else {
            return cached;
          }
        } catch (_) {
          return cached;
        }
      }

      const response = await fetch(request);
      if (!response || response.status !== 200) return response;
      if (response.type !== 'basic') return response;
      if (!isSameOrigin) return response;

      // Store response + meta timestamp
      await cache.put(request, response.clone());
      await cache.put(metaKey, new Response(String(Date.now())));

      // Enforce max entries (ignore meta keys)
      const keys = await cache.keys();
      const assetKeys = keys.filter(k => !String(k.url || k).includes('::__meta'));
      if (assetKeys.length > MAX_RUNTIME_ENTRIES) {
        const victim = assetKeys[0];
        await cache.delete(victim);
        await cache.delete(String(victim.url || victim) + '::__meta');
      }

      return response;
    } catch (_) {
      return new Response('', { status: 503, statusText: 'Service Unavailable' });
    }
  })());


});

// ─── BACKGROUND SYNC ─────────────────────────────────────────────────────────
self.addEventListener('sync', event => {
  console.log('[SW] Background sync event:', event.tag);
  
  if (event.tag === 'sync-data') {
    event.waitUntil(
      self.clients.matchAll().then(clients => {
        clients.forEach(client => {
          client.postMessage({ type: 'BACKGROUND_SYNC_TRIGGER' });
        });
      })
    );
  }
});

// ─── MESSAGE ─────────────────────────────────────────────────────────────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    console.log('[SW] Skip waiting requested');
    self.skipWaiting();
  }

  if (event.data?.type === 'GET_VERSION') {
    event.ports[0]?.postMessage({ version: CACHE_NAME });
  }
  
  
  if (event.data?.type === 'CLEAR_SHARED_FILES') {
    event.waitUntil(
      caches.open(SHARED_CACHE).then(async cache => {
        const keys = await cache.keys();
        for (const k of keys) await cache.delete(k);
      }).then(() => {
        event.ports[0]?.postMessage?.({ success: true });
      }).catch(() => {})
    );
  }

if (event.data?.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then(keys => {
        return Promise.all(keys.map(key => caches.delete(key)));
      }).then(() => {
        event.ports[0]?.postMessage({ success: true });
      })
    );
  }
});

// ─── PUSH NOTIFICATIONS (Future: Cloud sync alerts) ─────────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  
  const data = event.data.json();
  const options = {
    body: data.body || 'New update available',
    icon: './icon192.png',
    badge: './icon192.png',
    data: data
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title || 'Freight Logic', options)
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow(event.notification.data?.url || '/')
  );
});

console.log('[SW] v10.3.0 loaded and ready');
