/* ServerPanel Service Worker（2.0 M4 PWA）
 *
 * 只做一件事：把**静态壳**缓存下来，让「杀了网络的面板」也能打开登录页。
 * 所有 /api/ 请求一律 network-only —— 面板是实时监控工具，缓存一份陈旧的
 * 指标或审计数据比报错更危险。
 *
 * 2.0 审查后调整缓存策略：
 * - 壳入口与主脚本（/、app.js、style.css）改 **network-first**：面板一键升级会
 *   自动刷新页面，若仍走 cache-first，用户会永远被固化成旧前端（清 SW 才能恢复）。
 * - 其余小资源 stale-while-revalidate（先给缓存，后台更新）。
 * - 升级静态资源后把 SHELL_VERSION 加一，install 会重建缓存并清掉旧版本。
 */
'use strict';

const SHELL_VERSION = 'v2';
const CACHE = `sp-shell-${SHELL_VERSION}`;
const NETWORK_FIRST = new Set(['/', '/static/app.js', '/static/style.css']);
const SHELL = [
  '/',
  '/static/app.js',
  '/static/style.css',
  '/static/favicon.svg',
  '/static/manifest.webmanifest',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
      .catch(() => {}),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE)
        .map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
      .catch(() => {}),
  );
});

function put(cacheName, request, response) {
  if (!response || !response.ok || response.type === 'opaque') return;
  const copy = response.clone();
  caches.open(cacheName).then((cache) => cache.put(request, copy)).catch(() => {});
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;  // 接口永远走网络
  if (url.pathname !== '/' && !SHELL.includes(url.pathname)) return;

  if (NETWORK_FIRST.has(url.pathname)) {
    // 在线时永远用最新文件（避免升级后仍加载旧前端）；离线回落到缓存
    event.respondWith(
      fetch(request)
        .then((response) => {
          put(CACHE, request, response);
          return response;
        })
        .catch(() => caches.match(request).then((hit) => hit || caches.match('/'))),
    );
    return;
  }
  event.respondWith(
    caches.match(request)
      .then((hit) => {
        const refresh = fetch(request)
          .then((response) => { put(CACHE, request, response); return response; })
          .catch(() => null);
        return hit || refresh || caches.match('/');
      })
      .catch(() => caches.match('/')),
  );
});
