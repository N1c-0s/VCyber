import type { Config } from "@netlify/functions";

// Nouveautés GitHub : nouveaux projets et nouvelles versions d'outils de cybersécurité (Red / Blue Team).
// Découverte par thèmes (topics) via l'API de recherche ; versions lues dans les flux Atom publics des dépôts.
// Un jeton GitHub en lecture seule (GITHUB_TOKEN, facultatif) relève la limite de requêtes.
const UA = "Mozilla/5.0 (compatible; VeilleCyberFR/1.0)";
const HEADERS = { "content-type": "application/json; charset=utf-8" };

const RED = ["red-team", "redteam", "pentest", "penetration-testing", "offensive-security"];
const BLUE = ["blue-team", "dfir", "threat-hunting", "incident-response", "siem", "detection-engineering"];
const OTHER = ["osint", "malware-analysis"];
const TEAM: Record<string, "red" | "blue" | "other"> = {};
for (const t of RED) TEAM[t] = "red";
for (const t of BLUE) TEAM[t] = "blue";
for (const t of OTHER) TEAM[t] = "other";
// Dépôts d'attaque clés en main : écartés (on ne met en avant que des outils)
const BLOCK = new Set(["exploit", "exploits", "poc", "cve-poc", "malware-samples", "malware-source", "ransomware", "ransomware-source", "rat", "botnet", "stealer", "keylogger", "phishing-kit", "ddos"]);
const BLOCK_RE = /\b(poc|exploit for|ransomware|stealer|keylogger|botnet|phishing kit|rat builder)\b/i;
const PRE_RE = /(alpha|beta|rc\d*|nightly|preview|snapshot|dev)\b/i;

const clip = (v: unknown, n: number) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const day = (ms: number) => new Date(Date.now() - ms * 86_400_000).toISOString().slice(0, 10);

async function gh(path: string, token: string | undefined, signal: AbortSignal): Promise<any> {
  const res = await fetch("https://api.github.com" + path, {
    signal,
    headers: { "user-agent": UA, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  });
  if (res.status === 403 || res.status === 429) throw new Error("limite");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function teamOf(topics: string[]): "red" | "blue" | "other" {
  let r = 0, b = 0, o = 0;
  for (const t of topics) { const k = TEAM[t]; if (k === "red") r++; else if (k === "blue") b++; else if (k === "other") o++; }
  return r > b && r >= o ? "red" : b > r && b >= o ? "blue" : r && r === b ? "red" : "other";
}
const bad = (it: any) => it.fork || it.archived || (it.topics || []).some((t: string) => BLOCK.has(t)) || BLOCK_RE.test(`${it.name} ${it.description || ""}`);

const dec = (t: string) => t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
function textOf(html: string) {
  return clip(dec(dec(html).replace(/<[^>]*>/g, " ")), 220);
}
async function latestRelease(repo: string, signal: AbortSignal) {
  const res = await fetch(`https://github.com/${repo}/releases.atom`, { signal, headers: { "user-agent": UA, accept: "application/atom+xml" } });
  if (!res.ok) return null;
  const xml = await res.text();
  const e = xml.match(/<entry>([\s\S]*?)<\/entry>/)?.[1];
  if (!e) return null;
  const title = clip(e.match(/<title>([\s\S]*?)<\/title>/)?.[1], 80);
  const date = e.match(/<updated>([^<]+)<\/updated>/)?.[1];
  const link = e.match(/<link[^>]*rel="alternate"[^>]*href="([^"]+)"/)?.[1] ?? e.match(/<link[^>]*href="([^"]+)"/)?.[1];
  const content = e.match(/<content[^>]*>([\s\S]*?)<\/content>/)?.[1] ?? "";
  if (!title || !date || !link || !link.startsWith(`https://github.com/${repo}/`) || Number.isNaN(Date.parse(date))) return null;
  return { tag: title, date: new Date(date).toISOString(), link, notes: textOf(content) };
}

async function pool<T>(jobs: (() => Promise<T>)[], size: number): Promise<PromiseSettledResult<T>[]> {
  const out: PromiseSettledResult<T>[] = new Array(jobs.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, jobs.length) }, async () => {
    while (i < jobs.length) {
      const k = i++;
      try { out[k] = { status: "fulfilled", value: await jobs[k]() }; } catch (reason) { out[k] = { status: "rejected", reason }; }
    }
  }));
  return out;
}

export default async () => {
  const token = (globalThis as any).process?.env?.GITHUB_TOKEN?.trim() || undefined;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 28_000);
  try {
    // Priorité : un thème de chaque camp d'abord. Sans jeton, budget réduit (limite de recherche : 10 / min).
    const order = [RED[0], BLUE[0], RED[1], BLUE[1], OTHER[0], RED[2], BLUE[2], BLUE[3], RED[3], BLUE[4], BLUE[5], RED[4], OTHER[1]];
    const topics = token ? order : order.slice(0, 4);
    const since30 = day(30), since10 = day(10);
    const jobs: (() => Promise<any>)[] = [];
    for (const t of topics) {
      jobs.push(async () => ({ kind: "new", data: await gh(`/search/repositories?q=${encodeURIComponent(`topic:${t} created:>${since30} stars:>=30 fork:false archived:false`)}&sort=stars&order=desc&per_page=15`, token, ctrl.signal) }));
      jobs.push(async () => ({ kind: "rel", data: await gh(`/search/repositories?q=${encodeURIComponent(`topic:${t} pushed:>${since10} stars:>=500 fork:false archived:false`)}&sort=stars&order=desc&per_page=12`, token, ctrl.signal) }));
    }
    const results = await pool(jobs, token ? 4 : 1);
    const newRepos = new Map<string, any>(), relRepos = new Map<string, any>();
    let limited = false;
    for (const r of results) {
      if (r.status === "rejected") { if (String((r.reason as Error)?.message) === "limite") limited = true; continue; }
      const { kind, data } = r.value;
      for (const it of data?.items ?? []) {
        if (!/^[\w.-]+\/[\w.-]+$/.test(it.full_name ?? "") || bad(it)) continue;
        (kind === "new" ? newRepos : relRepos).set(it.full_name, it);
      }
    }
    const projects = [...newRepos.values()]
      .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
      .slice(0, 40)
      .map((it) => {
        const tp: string[] = (it.topics || []).filter((t: string) => typeof t === "string");
        return { name: it.full_name, url: it.html_url, desc: clip(it.description, 220), stars: it.stargazers_count, lang: clip(it.language, 30), topics: tp.slice(0, 4).map((t) => clip(t, 30)), created: it.created_at, team: teamOf(tp) };
      });
    const cands = [...relRepos.values()].sort((a, b) => b.stargazers_count - a.stargazers_count).slice(0, 36);
    const rels = await pool(cands.map((c) => () => latestRelease(c.full_name, ctrl.signal)), 6);
    const cut = Date.now() - 14 * 86_400_000;
    const releases: any[] = [];
    rels.forEach((r, i) => {
      if (r.status !== "fulfilled" || !r.value) return;
      const rel = r.value, c = cands[i];
      if (Date.parse(rel.date) < cut || PRE_RE.test(rel.tag)) return;
      const tp: string[] = (c.topics || []).filter((t: string) => typeof t === "string");
      releases.push({ name: c.full_name, url: c.html_url, desc: clip(c.description, 160), stars: c.stargazers_count, lang: clip(c.language, 30), topics: tp.slice(0, 4).map((t) => clip(t, 30)), team: teamOf(tp), tag: rel.tag, date: rel.date, link: rel.link, notes: rel.notes });
    });
    releases.sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
    if (!projects.length && !releases.length) throw new Error(limited ? "limite" : "vide");
    return new Response(JSON.stringify({ updatedAt: new Date().toISOString(), authenticated: !!token, partial: limited, projects, releases: releases.slice(0, 40) }), {
      headers: { ...HEADERS, "cache-control": "public, max-age=300", "netlify-cdn-cache-control": "public, durable, s-maxage=3600, stale-while-revalidate=86400" },
    });
  } catch {
    return new Response(JSON.stringify({ error: "GitHub est indisponible pour le moment." }), { status: 502, headers: { ...HEADERS, "cache-control": "no-store" } });
  } finally {
    clearTimeout(timer);
  }
};

export const config: Config = {
  path: "/api/github",
  method: "GET",
  rateLimit: { windowLimit: 30, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
