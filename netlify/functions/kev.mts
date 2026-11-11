import type { Config } from "@netlify/functions";

// Failles activement exploitées : catalogue KEV de la CISA (flux JSON public, sans clé).
const FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const UA = "Mozilla/5.0 (compatible; VeilleCyberFR/1.0)";
const HEADERS = { "content-type": "application/json; charset=utf-8" };
const clip = (v: unknown, n = 120) => String(v ?? "").slice(0, n);

export default async () => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 12_000);
  try {
    const res = await fetch(FEED, { signal: ctrl.signal, headers: { "user-agent": UA, accept: "application/json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json: any = await res.json();
    const all: any[] = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
    const items = all
      .filter((v) => /^CVE-\d{4}-\d{4,}$/.test(v?.cveID ?? "") && /^\d{4}-\d{2}-\d{2}$/.test(v?.dateAdded ?? ""))
      .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || b.cveID.localeCompare(a.cveID))
      .slice(0, 5)
      .map((v) => ({
        cve: v.cveID,
        vendor: clip(v.vendorProject, 60),
        product: clip(v.product, 80),
        name: clip(v.vulnerabilityName, 160),
        added: v.dateAdded,
        ransomware: v.knownRansomwareCampaignUse === "Known",
        link: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      }));
    if (!items.length) throw new Error("catalogue vide");
    const body = { updatedAt: new Date().toISOString(), catalogVersion: clip(json.catalogVersion, 20), total: all.length, items };
    return new Response(JSON.stringify(body), {
      headers: {
        ...HEADERS,
        "cache-control": "public, max-age=300",
        "netlify-cdn-cache-control": "public, durable, s-maxage=3600, stale-while-revalidate=86400",
      },
    });
  } catch {
    return new Response(JSON.stringify({ error: "Catalogue de la CISA indisponible pour le moment." }), {
      status: 502,
      headers: { ...HEADERS, "cache-control": "no-store" },
    });
  } finally {
    clearTimeout(timer);
  }
};

export const config: Config = { path: "/api/kev", method: "GET" };
