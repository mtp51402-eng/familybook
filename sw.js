var CACHE="family-book-v3";
self.addEventListener("install",function(e){e.waitUntil(caches.open(CACHE).then(function(c){return c.addAll(["./","index.html"]);}).catch(function(){}).then(function(){return self.skipWaiting();}));});
self.addEventListener("activate",function(e){e.waitUntil(caches.keys().then(function(k){return Promise.all(k.filter(function(x){return x!==CACHE;}).map(function(x){return caches.delete(x);}));}).then(function(){return self.clients.claim();}));});
self.addEventListener("fetch",function(e){var r=e.request;if(r.method!=="GET"||new URL(r.url).origin!==location.origin||r.url.indexOf("/api/")>=0)return;
e.respondWith(fetch(r).then(function(x){if(x&&x.ok){var c=x.clone();caches.open(CACHE).then(function(h){h.put(r,c);});}return x;}).catch(function(){return caches.match(r).then(function(m){return m||caches.match("index.html");});}));});
