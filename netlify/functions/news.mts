import type { Config } from "@netlify/functions";
import { getStore } from "@netlify/blobs";

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------
type Feed = { name: string; url: string; lang: "en" | "fr"; hint?: Category };
type Category = "fuite" | "ransomware" | "vuln" | "alerte" | "actu";

const FEEDS: Feed[] = [
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/", lang: "en" },
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews", lang: "en" },
  { name: "SecurityWeek", url: "https://www.securityweek.com/feed/", lang: "en" },
  { name: "The Record", url: "https://therecord.media/feed", lang: "en" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/", lang: "en" },
  { name: "DataBreaches.net", url: "https://databreaches.net/feed/", lang: "en", hint: "fuite" },
  { name: "ZATAZ", url: "https://www.zataz.com/feed/", lang: "fr" },
  { name: "CERT-FR", url: "https://www.cert.ssi.gouv.fr/feed/", lang: "fr", hint: "alerte" },
];

const PER_FEED = 12;
const MAX_ITEMS = 90;
const MAX_AGE_DAYS = 14;
const UA = "Mozilla/5.0 (compatible; VeilleCyberFR/1.0; +https://veille-cyber-fr.netlify.app)";

// ---------------------------------------------------------------------------
// Petits utilitaires texte
// ---------------------------------------------------------------------------
const ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", hellip: "…",
  rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", ndash: "–", mdash: "—",
  eacute: "é", egrave: "è", agrave: "à", ccedil: "ç", ecirc: "ê", ocirc: "ô",
};

function decode(s: string): string {
  return s
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&([a-z]+);/gi, (m, n) => ENTITIES[n.toLowerCase()] ?? m);
}

function clean(s: string | undefined): string {
  if (!s) return "";
  let t = s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
  t = decode(t); // certaines sources encodent le HTML deux fois
  t = t.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ");
  t = decode(t);
  t = t.replace(/The post .*? appeared first on .*$/i, "");
  t = t.replace(/L’article .*? est apparu en premier sur .*$/i, "");
  return t.replace(/\s+/g, " ").trim();
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  const cut = s.slice(0, n);
  const lastStop = Math.max(cut.lastIndexOf(". "), cut.lastIndexOf(" "));
  return cut.slice(0, lastStop > n * 0.6 ? lastStop : n).trim() + "…";
}

function tag(block: string, name: string): string | undefined {
  const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${name}>`, "i"));
  return m?.[1];
}

async function hash(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

async function fetchText(url: string, ms = 8000): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "user-agent": UA, accept: "application/rss+xml, application/xml, text/xml, */*" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Lecture des flux RSS / Atom
// ---------------------------------------------------------------------------
type Item = {
  id: string;
  title: string;
  summary: string;
  link: string;
  source: string;
  date: string;
  lang: "en" | "fr";
  category: Category;
  translated: boolean;
  originalTitle?: string;
};

function parseFeed(xml: string, feed: Feed) {
  const blocks = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) ?? xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi) ?? [];
  return blocks.slice(0, PER_FEED).map((b) => {
    let link = clean(tag(b, "link"));
    if (!link) {
      const href = b.match(/<link[^>]*href="([^"]+)"/i);
      link = href ? decode(href[1]) : "";
    }
    const rawDate = clean(tag(b, "pubDate") ?? tag(b, "published") ?? tag(b, "updated") ?? tag(b, "dc:date"));
    const d = new Date(rawDate);
    const summary = clean(tag(b, "description") ?? tag(b, "summary") ?? tag(b, "content:encoded") ?? tag(b, "content"));
    return {
      title: clean(tag(b, "title")),
      summary: truncate(summary, 320),
      link,
      date: isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString(),
    };
  }).filter((i) => i.title && i.link);
}

// ---------------------------------------------------------------------------
// Catégorisation par mots-clés (sur le texte original, anglais ou français)
// ---------------------------------------------------------------------------
const RULES: [Category, RegExp][] = [
  ["ransomware", /ransom|rançongiciel|rançon|lockbit|akira|qilin|blackcat|clop|extortion|extorsion/i],
  ["fuite", /breach|leak|exposed|stolen data|data theft|compromised (data|records|accounts)|records|fuite|piratage de données|données (volées|personnelles|dérobées)|dump|hacked/i],
  ["vuln", /cve-\d|vulnerab|zero-day|0-day|exploit|patch|flaw|faille|correctif|bug|rce\b|update now|mise à jour/i],
];

function categorize(text: string, hint?: Category): Category {
  if (hint === "alerte") return "alerte";
  for (const [cat, re] of RULES) if (re.test(text)) return cat;
  return hint ?? "actu";
}

// ---------------------------------------------------------------------------
// Traduction (Google Translate, avec repli MyMemory) + cache Blobs
// ---------------------------------------------------------------------------
async function translateGoogle(text: string): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 7000);
  try {
    const res = await fetch("https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=fr&dt=t", {
      method: "POST",
      signal: ctrl.signal,
      headers: { "content-type": "application/x-www-form-urlencoded;charset=UTF-8", "user-agent": UA },
      body: "q=" + encodeURIComponent(text),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const out = (data?.[0] ?? []).map((seg: any[]) => seg?.[0] ?? "").join("");
    if (!out) throw new Error("vide");
    return out;
  } finally {
    clearTimeout(timer);
  }
}

async function translateMyMemory(text: string): Promise<string> {
  const res = await fetch(
    "https://api.mymemory.translated.net/get?langpair=en|fr&q=" + encodeURIComponent(text.slice(0, 480)),
    { headers: { "user-agent": UA } },
  );
  const data = await res.json();
  const out = data?.responseData?.translatedText;
  if (!out || /MYMEMORY WARNING/i.test(out)) throw new Error("quota");
  return decode(out);
}

async function translate(text: string): Promise<string> {
  if (!text) return "";
  try {
    return await translateGoogle(text);
  } catch {
    return await translateMyMemory(text);
  }
}

async function pool<T>(items: T[], size: number, fn: (x: T) => Promise<void>, deadline: number) {
  let i = 0;
  const workers = Array.from({ length: size }, async () => {
    while (i < items.length && Date.now() < deadline) {
      const x = items[i++];
      await fn(x).catch(() => {});
    }
  });
  await Promise.all(workers);
}

type CacheEntry = { t: string; s: string; at: number };

// ---------------------------------------------------------------------------
// Have I Been Pwned : dernières fuites ajoutées
// ---------------------------------------------------------------------------
type Breach = {
  name: string; domain: string; breachDate: string; addedDate: string;
  count: number; dataClasses: string[]; description: string; link: string;
};

const DATA_CLASSES: Record<string, string> = {
  "Email addresses": "adresses e-mail", "Passwords": "mots de passe", "Names": "noms",
  "Usernames": "noms d'utilisateur", "Phone numbers": "numéros de téléphone",
  "Physical addresses": "adresses postales", "IP addresses": "adresses IP",
  "Dates of birth": "dates de naissance", "Genders": "genres", "Geographic locations": "localisations",
  "Job titles": "postes", "Employers": "employeurs", "Credit cards": "cartes bancaires",
  "Partial credit card data": "données de carte partielles", "Bank account numbers": "numéros de compte bancaire",
  "Government issued IDs": "pièces d'identité", "Social media profiles": "profils de réseaux sociaux",
  "Purchases": "achats", "Device information": "informations sur l'appareil", "Website activity": "activité sur le site",
  "Salutations": "civilités", "Auth tokens": "jetons d'authentification", "Security questions and answers": "questions de sécurité",
  "Payment histories": "historiques de paiement", "Spoken languages": "langues parlées", "Ages": "âges",
  "Education levels": "niveaux d'études", "Income levels": "niveaux de revenus", "Passport numbers": "numéros de passeport",
  "Social security numbers": "numéros de sécurité sociale", "Private messages": "messages privés",
  "Time zones": "fuseaux horaires", "Browser user agent details": "informations de navigateur",
  "Account balances": "soldes de compte", "Nationalities": "nationalités", "Marital statuses": "situations familiales",
  "Biometric data": "données biométriques", "Health insurance information": "données d'assurance santé",
  "Medical records": "dossiers médicaux", "Avatars": "avatars", "Profile photos": "photos de profil",
};

async function fetchBreaches(): Promise<Breach[]> {
  const res = await fetch("https://haveibeenpwned.com/api/v3/breaches", { headers: { "user-agent": UA } });
  if (!res.ok) throw new Error(`HIBP ${res.status}`);
  const all = (await res.json()) as any[];
  return all
    .filter((b) => b.IsVerified && !b.IsSpamList)
    .sort((a, b) => String(b.AddedDate).localeCompare(String(a.AddedDate)))
    .slice(0, 8)
    .map((b) => ({
      name: b.Title || b.Name,
      domain: b.Domain || "",
      breachDate: b.BreachDate,
      addedDate: b.AddedDate,
      count: b.PwnCount,
      dataClasses: (b.DataClasses ?? []).map((c: string) => DATA_CLASSES[c] ?? c.toLowerCase()),
      description: truncate(clean(b.Description), 400),
      link: `https://haveibeenpwned.com/Breach/${encodeURIComponent(b.Name)}`,
    }));
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------
export default async () => {
  const started = Date.now();
  const deadline = started + 40_000;

  const sourceStatus: { name: string; ok: boolean; count: number }[] = [];

  const [feedResults, breachesResult] = await Promise.all([
    Promise.all(
      FEEDS.map(async (feed) => {
        try {
          const xml = await fetchText(feed.url);
          const parsed = parseFeed(xml, feed);
          sourceStatus.push({ name: feed.name, ok: true, count: parsed.length });
          return parsed.map((p) => ({ ...p, feed }));
        } catch {
          sourceStatus.push({ name: feed.name, ok: false, count: 0 });
          return [];
        }
      }),
    ),
    fetchBreaches().catch(() => [] as Breach[]),
  ]);

  const cutoff = Date.now() - MAX_AGE_DAYS * 86_400_000;
  const seen = new Set<string>();
  const raw = feedResults
    .flat()
    .filter((i) => new Date(i.date).getTime() >= cutoff)
    .sort((a, b) => b.date.localeCompare(a.date))
    .filter((i) => {
      const k = i.link.replace(/[?#].*$/, "");
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .slice(0, MAX_ITEMS);

  // Cache des traductions déjà faites
  const store = getStore("traductions");
  let cache: Record<string, CacheEntry> = {};
  try {
    cache = ((await store.get("cache-v1", { type: "json" })) as Record<string, CacheEntry>) ?? {};
  } catch {
    cache = {};
  }

  const items: Item[] = await Promise.all(
    raw.map(async (r) => ({
      id: await hash(r.link),
      title: r.title,
      summary: r.summary,
      link: r.link,
      source: r.feed.name,
      date: r.date,
      lang: r.feed.lang,
      category: categorize(`${r.title} ${r.summary}`, r.feed.hint),
      translated: r.feed.lang === "fr",
    })),
  );

  const breachKeys = await Promise.all(breachesResult.map((b) => hash("hibp:" + b.name + b.addedDate)));

  // Ce qui reste à traduire
  const todo = items.filter((i) => i.lang === "en" && !cache[i.id]);
  const breachTodo = breachesResult
    .map((b, n) => ({ b, key: breachKeys[n] }))
    .filter(({ key }) => !cache[key]);

  let newTranslations = 0;
  await pool(
    [
      ...breachTodo.map(({ b, key }) => async () => {
        const s = await translate(b.description);
        cache[key] = { t: "", s, at: Date.now() };
        newTranslations++;
      }),
      ...todo.map((i) => async () => {
        const [t, s] = await Promise.all([translate(i.title), translate(i.summary)]);
        cache[i.id] = { t, s, at: Date.now() };
        newTranslations++;
      }),
    ],
    6,
    (job) => job(),
    deadline,
  );

  // Applique les traductions
  for (const i of items) {
    const c = cache[i.id];
    if (i.lang === "en" && c) {
      i.originalTitle = i.title;
      i.title = c.t || i.title;
      i.summary = c.s || i.summary;
      i.translated = true;
    }
  }
  const breaches = breachesResult.map((b, n) => {
    const c = cache[breachKeys[n]];
    return { ...b, description: c?.s || b.description, translated: !!c };
  });

  // Sauvegarde du cache (on oublie ce qui a plus de 30 jours)
  if (newTranslations > 0) {
    const keep = Date.now() - 30 * 86_400_000;
    for (const k of Object.keys(cache)) if (cache[k].at < keep) delete cache[k];
    try {
      await store.setJSON("cache-v1", cache);
    } catch (e) {
      console.error("Échec de la sauvegarde du cache", e);
    }
  }

  const untranslated = items.filter((i) => !i.translated).length;
  const body = {
    updatedAt: new Date().toISOString(),
    items,
    breaches,
    sources: sourceStatus.sort((a, b) => a.name.localeCompare(b.name)),
    stats: { total: items.length, untranslated, newTranslations, ms: Date.now() - started },
  };

  // Si des articles n'ont pas pu être traduits, on garde en cache moins longtemps
  const ttl = untranslated > 0 ? 300 : 1800;
  return new Response(JSON.stringify(body), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=120",
      "netlify-cdn-cache-control": `public, durable, s-maxage=${ttl}, stale-while-revalidate=21600`,
    },
  });
};

export const config: Config = { path: "/api/news" };
