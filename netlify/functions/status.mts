import type { Config } from "@netlify/functions";

// État des grands services en ligne, d'après leurs pages de statut officielles.

const UA = "Mozilla/5.0 (compatible; VeilleCyberFR/1.0)";
type State = "ok" | "minor" | "major" | "unknown";
type Service = { name: string; group: string; page: string; kind: "statuspage" | "slack" | "google" | "azure" | "aws" | "link"; api?: string };

const SERVICES: Service[] = [
  { name: "Microsoft 365", group: "Bureautique", page: "https://status.cloud.microsoft/", kind: "link" },
  { name: "Microsoft Azure", group: "Cloud", page: "https://azure.status.microsoft/fr-fr/status", kind: "azure", api: "https://rssfeed.azure.status.microsoft/en-us/status/feed/" },
  { name: "Google Workspace", group: "Bureautique", page: "https://www.google.com/appsstatus/dashboard/", kind: "google", api: "https://www.google.com/appsstatus/dashboard/incidents.json" },
  { name: "Google Cloud", group: "Cloud", page: "https://status.cloud.google.com/", kind: "google", api: "https://status.cloud.google.com/incidents.json" },
  { name: "Amazon Web Services", group: "Cloud", page: "https://health.aws.amazon.com/health/status", kind: "aws", api: "https://health.aws.amazon.com/public/currentevents" },
  { name: "Cloudflare", group: "Cloud", page: "https://www.cloudflarestatus.com/", kind: "statuspage", api: "https://www.cloudflarestatus.com" },
  { name: "GitHub", group: "Développement", page: "https://www.githubstatus.com/", kind: "statuspage", api: "https://www.githubstatus.com" },
  { name: "Netlify", group: "Développement", page: "https://www.netlifystatus.com/", kind: "statuspage", api: "https://www.netlifystatus.com" },
  { name: "Slack", group: "Communication", page: "https://slack-status.com/", kind: "slack", api: "https://slack-status.com/api/v2.0.0/current" },
  { name: "Zoom", group: "Communication", page: "https://status.zoom.us/", kind: "statuspage", api: "https://status.zoom.us" },
  { name: "Discord", group: "Communication", page: "https://discordstatus.com/", kind: "statuspage", api: "https://discordstatus.com" },
  { name: "Dropbox", group: "Bureautique", page: "https://status.dropbox.com/", kind: "statuspage", api: "https://status.dropbox.com" },
  { name: "ChatGPT (OpenAI)", group: "IA", page: "https://status.openai.com/", kind: "statuspage", api: "https://status.openai.com" },
  { name: "Claude (Anthropic)", group: "IA", page: "https://status.claude.com/", kind: "statuspage", api: "https://status.claude.com" },
  { name: "Reddit", group: "Réseaux sociaux", page: "https://www.redditstatus.com/", kind: "statuspage", api: "https://www.redditstatus.com" },
  { name: "Meta (Facebook, Instagram, WhatsApp)", group: "Réseaux sociaux", page: "https://metastatus.com/", kind: "link" },
];

async function get(url: string, ms = 7000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { "user-agent": UA } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  } finally {
    clearTimeout(t);
  }
}

async function check(s: Service): Promise<{ state: State; detail?: string }> {
  switch (s.kind) {
    case "link":
      return { state: "unknown", detail: "Consulter la page officielle" };
    case "statuspage": {
      const d = await (await get(`${s.api}/api/v2/status.json`)).json();
      const ind = d?.status?.indicator;
      const map: Record<string, State> = { none: "ok", minor: "minor", major: "major", critical: "major", maintenance: "minor" };
      const state = map[ind] ?? "unknown";
      return { state, detail: state === "ok" ? undefined : d?.status?.description };
    }
    case "slack": {
      const d = await (await get(s.api!)).json();
      const n = (d?.active_incidents ?? []).length;
      return n ? { state: "minor", detail: d.active_incidents[0]?.title } : { state: "ok" };
    }
    case "google": {
      const list = await (await get(s.api!)).json();
      const active = (Array.isArray(list) ? list : []).filter((i: any) => !i.end);
      if (!active.length) return { state: "ok" };
      const severe = active.some((i: any) => /high|outage/i.test(String(i.severity ?? i.status_impact ?? "")));
      return { state: severe ? "major" : "minor", detail: String(active[0].external_desc ?? "").slice(0, 140) };
    }
    case "azure": {
      const xml = await (await get(s.api!)).text();
      const items = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) ?? [];
      if (!items.length) return { state: "ok" };
      const title = items[0].match(/<title>([\s\S]*?)<\/title>/i)?.[1]?.replace(/<!\[CDATA\[|\]\]>/g, "").trim();
      return { state: "minor", detail: title };
    }
    case "aws": {
      const buf = new Uint8Array(await (await get(s.api!)).arrayBuffer());
      const utf16 = (buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff);
      const text = new TextDecoder(utf16 ? "utf-16" : "utf-8").decode(buf).replace(/^﻿/, "");
      const list = JSON.parse(text || "[]");
      const n = Array.isArray(list) ? list.length : 0;
      return n ? { state: "minor", detail: `${n} incident${n > 1 ? "s" : ""} en cours` } : { state: "ok" };
    }
  }
}

export default async () => {
  const results = await Promise.all(
    SERVICES.map(async (s) => {
      try {
        const r = await check(s);
        return { name: s.name, group: s.group, url: s.page, ...r };
      } catch {
        return { name: s.name, group: s.group, url: s.page, state: "unknown" as State, detail: "Statut indisponible" };
      }
    }),
  );
  return new Response(JSON.stringify({ checkedAt: new Date().toISOString(), services: results }), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=60",
      "netlify-cdn-cache-control": "public, durable, s-maxage=120, stale-while-revalidate=300",
    },
  });
};

export const config: Config = { path: "/api/status", method: "GET" };
