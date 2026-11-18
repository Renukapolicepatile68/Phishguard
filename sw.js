const CACHE_NAME = "phishguard-shell-v4";
const APP_SHELL = [
  "./",
  "./index.html",
  "./signup.html",
  "./forgot-password.html",
  "./reset-password.html",
  "./dashboard.html",
  "./manifest.webmanifest",
  "./css/auth.css",
  "./css/style.css",
  "./js/config.js",
  "./js/auth.js",
  "./js/app.js",
  "./js/pwa.js",
  "./assets/app-icon-192.png",
  "./assets/app-icon-512.png",
  "./assets/app-icon.svg",
  "./assets/phishing-awareness.webp",
  "./assets/dashboard-background.webp",
  "./assets/scanner-background.jpg"
];

self.addEventListener("install", event => {
  event.waitUntil(Promise.all([
    caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)),
    self.skipWaiting()
  ]));
});

self.addEventListener("activate", event => {
  event.waitUntil(Promise.all([
    caches.keys().then(keys => Promise.all(
      keys.filter(key => key.startsWith("phishguard-shell-") && key !== CACHE_NAME)
        .map(key => caches.delete(key))
    )),
    self.clients.claim()
  ]));
});

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin ||
      url.pathname.includes("/api/") || url.search) return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).then(async response => {
        if (response.ok && !url.search) {
          try {
            const cache = await caches.open(CACHE_NAME);
            await cache.put(request, response.clone());
          } catch (error) {
            console.error("PhishGuard could not cache this page.", error);
          }
        }
        return response;
      }).catch(async () => {
        const fallback = new URL(request.url);
        fallback.search = "";
        const cached = (await caches.match(request)) ||
          (await caches.match(fallback.href)) ||
          (await caches.match("./index.html"));
        if (cached) return cached;
        throw new Error("The requested page is unavailable offline.");
      })
    );
    return;
  }

  event.respondWith(
    fetch(request).then(async response => {
      if (response.ok) {
        try {
          const cache = await caches.open(CACHE_NAME);
          await cache.put(request, response.clone());
        } catch (error) {
          console.error("PhishGuard could not cache this resource.", error);
        }
      }
      return response;
    }).catch(async () => {
      const cached = await caches.match(request);
      if (cached) return cached;
      throw new Error("The requested resource is unavailable offline.");
    })
  );
});
