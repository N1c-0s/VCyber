// Serveur VCyber pour VPS : sert public/ et expose les mêmes fonctions /api/* que sur Netlify.
// Écoute uniquement en local (127.0.0.1) : c'est Caddy qui reçoit le trafic public.
import http from "node:http";
import { readdir, stat } from "node:fs/promises";
import { createReadStream } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PUBLIC = path.join(ROOT, "public");
const FN_DIR = path.join(ROOT, "dist", "functions");
const PORT = +(process.env.PORT || 8790);
const HOST = process.env.HOST || "127.0.0.1";
const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------- Chargement des fonctions (compilées par `npm run build:vps`) ----------
const routes = new Map();
for (const f of (await readdir(FN_DIR)).filter((n) => n.endsWith(".mjs"))) {
  const m = await import(pathToFileURL(path.join(FN_DIR, f)).href);
  if (typeof m.default !== "function" || !m.config?.path) { log("ignoré :", f); continue; }
  routes.set(m.config.path, { handler: m.default, ...m.config });
  log("route", m.config.path, m.config.method || "*", m.config.rateLimit ? "(limitée)" : "");
}

// ---------- IP du visiteur (Caddy envoie X-Real-IP ; on ne le croit que s'il vient de la machine) ----------
function clientIp(req) {
  const sock = (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  const local = sock === "127.0.0.1" || sock === "::1";
  const real = req.headers["x-real-ip"] || (req.headers["x-forwarded-for"] || "").split(",")[0];
  return (local && String(real || "").trim()) || sock;
}

// ---------- Limite de requêtes (équivalent du rateLimit Netlify) : par IP et par route ----------
const hits = new Map();
function retryAfter(cfg, ip, p) {
  if (!cfg) return 0;
  const win = cfg.windowSize * 1000, now = Date.now(), key = p + "|" + ip;
  const e = hits.get(key);
  if (!e || now - e.start >= win) { hits.set(key, { start: now, count: 1, win }); return 0; }
  return ++e.count > cfg.windowLimit ? Math.ceil((e.start + win - now) / 1000) : 0;
}
setInterval(() => { const n = Date.now(); for (const [k, e] of hits) if (n - e.start >= e.win) hits.delete(k); }, 60_000).unref();

// ---------- Cache (équivalent du netlify-cdn-cache-control : s-maxage + stale-while-revalidate) ----------
const cache = new Map(), inflight = new Map();
const parseCdn = (h) => {
  const m = /s-maxage=(\d+)/.exec(h || ""), s = /stale-while-revalidate=(\d+)/.exec(h || "");
  return m ? { ttl: +m[1] * 1000, swr: s ? +s[1] * 1000 : 0 } : null;
};
async function invoke(route, url, ip) {
  const request = new Request(url, { method: "GET", headers: { "user-agent": "vcyber-server" } });
  let r;
  try {
    r = await route.handler(request, { ip, geo: undefined });
  } catch (e) {
    log("erreur", url.pathname, e);
    return { status: 500, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, body: Buffer.from('{"error":"Erreur interne."}') };
  }
  const cdn = parseCdn(r.headers.get("netlify-cdn-cache-control"));
  const headers = Object.fromEntries([...r.headers].filter(([k]) => k !== "netlify-cdn-cache-control"));
  return { status: r.status, headers, body: Buffer.from(await r.arrayBuffer()), cdn, at: Date.now() };
}
function fresh(route, url, ip) {
  const key = url.pathname + url.search;
  if (!inflight.has(key)) {
    inflight.set(key, invoke(route, url, ip).then((out) => {
      // On ne garde pas en cache une réponse d'actualités vide (flux injoignables) : on réessaiera à la requête suivante
      let empty = false;
      try { const j = JSON.parse(out.body); empty = Array.isArray(j.items) && j.items.length === 0; } catch {}
      if (out.cdn && out.status === 200 && !empty) cache.set(key, out);
      return out;
    }).finally(() => inflight.delete(key)));
  }
  return inflight.get(key);
}
async function cached(route, url, ip) {
  const key = url.pathname + url.search, e = cache.get(key), age = e ? Date.now() - e.at : 0;
  if (e && age < e.cdn.ttl) return [e, "HIT"];
  if (e && age < e.cdn.ttl + e.cdn.swr) { fresh(route, url, ip).catch((x) => log("rafraîchissement", x)); return [e, "STALE"]; }
  return [await fresh(route, url, ip), "MISS"];
}

// ---------- Fichiers statiques ----------
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8", ".webmanifest": "application/manifest+json" };
async function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return send(res, 400, "Requête invalide"); }
  if (rel.endsWith("/")) rel += "index.html";
  const file = path.normalize(path.join(PUBLIC, rel));
  if (file !== PUBLIC && !file.startsWith(PUBLIC + path.sep)) return send(res, 403, "Interdit");
  let st;
  try { st = await stat(file); } catch { return send(res, 404, "Introuvable"); }
  if (!st.isFile()) return send(res, 404, "Introuvable");
  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, {
    "content-type": MIME[ext] || "application/octet-stream", "content-length": st.size,
    "cache-control": ext === ".html" ? "no-cache" : "public, max-age=3600",
  });
  if (req.method === "HEAD") return res.end();
  createReadStream(file).pipe(res);
}
const send = (res, status, text) => { res.writeHead(status, { "content-type": "text/plain; charset=utf-8" }); res.end(text); };
const sendJson = (res, status, obj, extra = {}) => {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra });
  res.end(JSON.stringify(obj));
};

// ---------- Serveur ----------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/healthz") return send(res, 200, "ok");
    if (req.method !== "GET" && req.method !== "HEAD") return sendJson(res, 405, { error: "Méthode non autorisée." }, { allow: "GET, HEAD" });

    const route = routes.get(url.pathname);
    if (url.pathname.startsWith("/api/") && !route) return sendJson(res, 404, { error: "Route inconnue." });
    if (!route) return serveStatic(req, res, url.pathname);
    if (route.method && route.method !== "GET") return sendJson(res, 405, { error: "Méthode non autorisée." });

    const ip = clientIp(req);
    const wait = retryAfter(route.rateLimit, ip, url.pathname);
    if (wait) return sendJson(res, 429, { error: "Trop de requêtes en peu de temps. Patientez une minute." }, { "retry-after": String(wait) });

    const [out, state] = await cached(route, url, ip);
    res.writeHead(out.status, { ...out.headers, "x-cache": state, "content-length": out.body.length });
    res.end(req.method === "HEAD" ? undefined : out.body);
  } catch (e) {
    log("erreur", e);
    if (!res.headersSent) sendJson(res, 500, { error: "Erreur interne." }); else res.end();
  }
});
server.keepAliveTimeout = 65_000; // > délai de Caddy
process.on("unhandledRejection", (e) => log("rejet non géré", e));
server.listen(PORT, HOST, () => {
  log(`VCyber à l'écoute sur http://${HOST}:${PORT}`);
  // Préchauffe : l'accueil ne doit pas attendre la lecture des flux et la traduction
  setTimeout(() => {
    for (const p of ["/api/news", "/api/status"]) {
      const r = routes.get(p);
      if (r) fresh(r, new URL(p, "http://localhost"), "127.0.0.1").catch(() => {});
    }
  }, 2000).unref();
});
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => { log(sig, "arrêt"); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); });
