import type { Config, Context } from "@netlify/functions";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

// Boîte à outils : informations sur une IP, WHOIS (RDAP), analyse des en-têtes de sécurité d'un site.

const UA = "Mozilla/5.0 (compatible; VeilleCyberFR/1.0)";
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });

async function getJSON(url: string, ms = 8000): Promise<any> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { "user-agent": UA, accept: "application/json, application/rdap+json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

// ---------------------------------------------------------------------------
// Adresses privées / réservées (on ne les interroge jamais)
// ---------------------------------------------------------------------------
function isPrivate(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v.startsWith("::ffff:");
}

// ---------------------------------------------------------------------------
// Infos IP : géolocalisation, fournisseur, détection VPN / proxy / Tor
// ---------------------------------------------------------------------------
async function ipInfo(ip: string, context: Context, isVisitor: boolean) {
  const out: any = { ip, version: isIP(ip) === 6 ? "IPv6" : "IPv4", flags: {}, sources: [] };

  if (isVisitor && context.geo) {
    out.location = {
      city: context.geo.city, region: context.geo.subdivision?.name, country: context.geo.country?.name,
      countryCode: context.geo.country?.code, latitude: context.geo.latitude, longitude: context.geo.longitude,
      timezone: context.geo.timezone,
    };
    out.sources.push("Netlify");
  }

  try {
    const d = await getJSON(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`);
    out.isp = d?.company?.name || d?.asn?.org;
    out.ispType = d?.company?.type;
    out.asn = d?.asn?.asn ? `AS${d.asn.asn}` : undefined;
    out.asnOrg = d?.asn?.org;
    out.flags = {
      vpn: !!d?.is_vpn, proxy: !!d?.is_proxy, tor: !!d?.is_tor, hosting: !!d?.is_datacenter,
      mobile: !!d?.is_mobile, abuser: !!d?.is_abuser, bogon: !!d?.is_bogon,
    };
    if (d?.vpn?.service) out.vpnService = d.vpn.service;
    if (!out.location && d?.location) {
      out.location = {
        city: d.location.city, region: d.location.state, country: d.location.country, countryCode: d.location.country_code,
        latitude: d.location.latitude, longitude: d.location.longitude, timezone: d.location.timezone,
      };
    }
    out.sources.push("ipapi.is");
  } catch {
    // Repli : ip-api.com (gratuit, sans clé)
    try {
      const d = await getJSON(`http://ip-api.com/json/${encodeURIComponent(ip)}?lang=fr&fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`);
      if (d?.status === "success") {
        out.isp = d.isp || d.org;
        out.asn = d.as?.split(" ")[0];
        out.asnOrg = d.as?.split(" ").slice(1).join(" ");
        out.flags = { vpn: false, proxy: !!d.proxy, tor: false, hosting: !!d.hosting, mobile: !!d.mobile };
        if (!out.location) {
          out.location = { city: d.city, region: d.regionName, country: d.country, countryCode: d.countryCode, latitude: d.lat, longitude: d.lon, timezone: d.timezone };
        }
        out.sources.push("ip-api.com");
      }
    } catch { /* aucune source disponible */ }
  }

  // Reverse DNS
  try {
    const { reverse } = await import("node:dns/promises");
    out.reverse = (await reverse(ip)).slice(0, 3);
  } catch { out.reverse = []; }

  return out;
}

// ---------------------------------------------------------------------------
// WHOIS moderne (RDAP) pour un domaine ou une IP
// ---------------------------------------------------------------------------
const STATUS_FR: Record<string, string> = {
  "active": "actif", "client transfer prohibited": "transfert bloqué", "server transfer prohibited": "transfert bloqué (registre)",
  "client delete prohibited": "suppression bloquée", "server delete prohibited": "suppression bloquée (registre)",
  "client update prohibited": "modification bloquée", "server update prohibited": "modification bloquée (registre)",
  "client hold": "suspendu", "server hold": "suspendu (registre)", "redemption period": "en période de rédemption",
  "pending delete": "suppression imminente", "inactive": "inactif",
};

function vcardName(entity: any): string | undefined {
  const v = entity?.vcardArray?.[1];
  if (!Array.isArray(v)) return undefined;
  const fn = v.find((x: any[]) => x[0] === "fn");
  const org = v.find((x: any[]) => x[0] === "org");
  return (fn?.[3] || org?.[3] || undefined) as string | undefined;
}

async function rdap(q: string) {
  const ip = isIP(q);
  const url = ip ? `https://rdap.org/ip/${encodeURIComponent(q)}` : `https://rdap.org/domain/${encodeURIComponent(q)}`;
  const d = await getJSON(url, 10000);
  const events = Object.fromEntries((d.events ?? []).map((e: any) => [e.eventAction, e.eventDate]));
  const entities: any[] = d.entities ?? [];
  const byRole = (role: string) => entities.find((e) => (e.roles ?? []).includes(role));
  return {
    query: q,
    kind: ip ? "ip" : "domain",
    name: d.ldhName || d.name || d.handle,
    registrar: vcardName(byRole("registrar")) ?? undefined,
    registrant: vcardName(byRole("registrant")) ?? undefined,
    created: events["registration"],
    updated: events["last changed"],
    expires: events["expiration"],
    status: (d.status ?? []).map((s: string) => STATUS_FR[s] ?? s),
    nameservers: (d.nameservers ?? []).map((n: any) => String(n.ldhName ?? "").toLowerCase()).filter(Boolean),
    dnssec: d.secureDNS?.delegationSigned,
    range: ip ? [d.startAddress, d.endAddress].filter(Boolean).join(" – ") : undefined,
    country: d.country,
    network: ip ? d.name : undefined,
  };
}

// ---------------------------------------------------------------------------
// En-têtes de sécurité d'un site
// ---------------------------------------------------------------------------
const CHECKS = [
  { h: "strict-transport-security", name: "HSTS", why: "Force le navigateur à toujours utiliser HTTPS.", w: 20 },
  { h: "content-security-policy", name: "Content-Security-Policy", why: "Limite les scripts autorisés, protège contre les injections (XSS).", w: 25 },
  { h: "x-frame-options", name: "X-Frame-Options", why: "Empêche d'afficher le site dans une page piégée (clickjacking).", w: 15, alt: "content-security-policy", altTest: /frame-ancestors/i },
  { h: "x-content-type-options", name: "X-Content-Type-Options", why: "Empêche le navigateur de deviner le type des fichiers.", w: 15 },
  { h: "referrer-policy", name: "Referrer-Policy", why: "Limite les informations envoyées aux autres sites quand on clique sur un lien.", w: 15 },
  { h: "permissions-policy", name: "Permissions-Policy", why: "Restreint l'accès à la caméra, au micro, à la position…", w: 10 },
];

async function headersCheck(raw: string) {
  let url: URL;
  try {
    url = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    throw new Error("Adresse invalide.");
  }
  if (!/^https?:$/.test(url.protocol)) throw new Error("Seules les adresses http et https sont acceptées.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Seuls les ports standards (80 et 443) sont acceptés.");
  const ensurePublic = async (u: URL) => {
    if (!/^https?:$/.test(u.protocol)) throw new Error("Redirection vers une adresse non web.");
    if (u.port && !["80", "443"].includes(u.port)) throw new Error("Redirection vers un port non standard.");
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (isIP(host) ? isPrivate(host) : !/\.[a-z]{2,}$/i.test(host)) throw new Error("Adresse non publique.");
    const resolved = isIP(host) ? [{ address: host }] : await lookup(host, { all: true }).catch(() => []);
    if (!resolved.length) throw new Error("Ce nom de domaine n'existe pas.");
    if (resolved.some((r) => isPrivate(r.address))) throw new Error("Adresse non publique.");
  };

  // On suit les redirections nous-mêmes pour vérifier chaque étape
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 9000);
  let res: Response;
  let current = url;
  try {
    for (let hop = 0; ; hop++) {
      await ensurePublic(current);
      res = await fetch(current, { method: "GET", redirect: "manual", signal: ctrl.signal, headers: { "user-agent": UA } });
      const loc = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && loc) {
        res.body?.cancel().catch(() => {});
        if (hop >= 5) throw new Error("Trop de redirections.");
        current = new URL(loc, current);
        continue;
      }
      break;
    }
  } finally {
    clearTimeout(t);
  }
  res.body?.cancel().catch(() => {});
  const final = current;
  const get = (h: string) => res.headers.get(h);

  let score = 0;
  const checks = CHECKS.map((c) => {
    let value = get(c.h);
    let ok = !!value;
    if (!ok && c.alt && c.altTest?.test(get(c.alt) ?? "")) { ok = true; value = `via CSP (frame-ancestors)`; }
    if (ok) score += c.w;
    return { name: c.name, ok, value: value ? value.slice(0, 160) : null, why: c.why };
  });
  const https = final.protocol === "https:";
  if (!https) score = Math.min(score, 30);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 35 ? "D" : score >= 15 ? "E" : "F";

  return {
    url: final.toString(),
    status: res.status,
    https,
    grade,
    score,
    server: get("server") ?? undefined,
    poweredBy: get("x-powered-by") ?? undefined,
    checks,
  };
}

// ---------------------------------------------------------------------------
export default async (req: Request, context: Context) => {
  const params = new URL(req.url).searchParams;
  const action = params.get("action");
  try {
    if (action === "ip") {
      const q = (params.get("q") ?? "").trim();
      const ip = q || context.ip;
      if (!isIP(ip)) return reply({ error: "Adresse IP invalide." }, 400);
      if (isPrivate(ip)) return reply({ error: "C'est une adresse privée (réseau local) : elle n'est pas visible sur Internet." }, 400);
      return reply(await ipInfo(ip, context, !q || q === context.ip));
    }
    if (action === "rdap") {
      const q = (params.get("q") ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!q || (!isIP(q) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q))) return reply({ error: "Saisissez un nom de domaine (ex. : exemple.be) ou une adresse IP." }, 400);
      if (isIP(q) && isPrivate(q)) return reply({ error: "C'est une adresse privée : il n'existe pas de WHOIS pour elle." }, 400);
      try {
        return reply(await rdap(q));
      } catch {
        return reply({ error: "Aucune information WHOIS trouvée. Certaines extensions (comme .be ou .de) ne publient pas ces données." }, 404);
      }
    }
    if (action === "headers") {
      const q = (params.get("q") ?? "").trim();
      if (!q) return reply({ error: "Saisissez l'adresse d'un site." }, 400);
      return reply(await headersCheck(q));
    }
    return reply({ error: "Action inconnue." }, 400);
  } catch (e: any) {
    const msg = e?.name === "AbortError" ? "Le site n'a pas répondu à temps." : e?.message || "Erreur inattendue.";
    return reply({ error: msg }, 400);
  }
};

export const config: Config = {
  path: "/api/tools",
  method: "GET",
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
