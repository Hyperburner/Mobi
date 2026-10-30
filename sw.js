// Bridge Learning Club — Safe PWA Service Worker (v2.0-2026-10-27)
// Caches the public application shell & Beginner Handbook for offline reading.
// Never caches or fabricates authenticated database/RPC mutations when offline.
const CACHE_NAME = 'bridge-club-pwa-v2-2026-10-27';
const STATIC_ASSETS = [
  './',
  './index.html',
  './first_six_hands.html',
  './manifest.json',
  './icon-192.svg',
  './icon-512.svg'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Never cache live Supabase REST/RPC/Auth endpoints
  if (url.hostname.includes('supabase.co')) return;

  // Network-first for HTML so updates deploy safely without stale lock-in; fallback to cache when offline
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith(
      fetch(req)
        .then(res => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req).then(r => r || caches.match('./index.html')))
    );
    return;
  }

  // Cache-first for static icons & manifest
  event.respondWith(
    caches.match(req).then(cached => cached || fetch(req))
  );
});
