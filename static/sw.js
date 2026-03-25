const CACHE_KEY = 'cvealert-last-check';
const CHECK_INTERVAL = 30 * 60 * 1000; // 30 min
const FEED_URL = self.registration.scope + 'index.xml';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => { self.clients.claim(); e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE_KEY).map(k=>caches.delete(k))))); });

// Offline cache
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).then(r => {
      const clone = r.clone();
      caches.open('cvealert-offline').then(c => c.put(e.request, clone));
      return r;
    }).catch(() => caches.match(e.request))
  );
});

async function checkForNewCVEs() {
  try {
    const resp = await fetch(FEED_URL, { cache: 'no-store' });
    const text = await resp.text();
    const items = text.match(/<item>[\s\S]*?<\/item>/g) || [];
    if (!items.length) return;

    const latest = items[0];
    const title = (latest.match(/<title>(.*?)<\/title>/) || [])[1] || '';
    const link = (latest.match(/<link>(.*?)<\/link>/) || [])[1] || '';
    const desc = (latest.match(/<description>(.*?)<\/description>/) || [])[1] || '';

    const cache = await caches.open(CACHE_KEY);
    const prev = await cache.match('latest');
    const prevTitle = prev ? await prev.text() : '';

    if (title && title !== prevTitle) {
      await cache.put('latest', new Response(title));
      if (prevTitle) {
        self.registration.showNotification(title, {
          body: desc.replace(/<[^>]*>/g, '').slice(0, 120),
          icon: self.registration.scope + 'favicon.svg',
          tag: title,
          data: { url: link }
        });
      }
    }
  } catch (e) {
    // silent fail
  }
}

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data.url || self.registration.scope));
});

// Periodic check via message from page
self.addEventListener('message', (e) => {
  if (e.data === 'check') checkForNewCVEs();
});

// Also check on periodic sync if supported
self.addEventListener('periodicsync', (e) => {
  if (e.tag === 'cve-check') e.waitUntil(checkForNewCVEs());
});
