import type { Config } from "@netlify/functions";

// Vérifie si une adresse e-mail apparaît dans des fuites de données connues,
// en interrogeant plusieurs services gratuits. Rien n'est stocké ni journalisé.

const UA = "Mozilla/5.0 (compatible; VeilleCyberFR/1.0)";

const FIELDS: Record<string, string> = {
  "email addresses": "adresses e-mail", "email": "adresse e-mail", "passwords": "mots de passe", "password": "mot de passe",
  "names": "noms", "name": "nom", "first_name": "prénom", "last_name": "nom", "usernames": "noms d'utilisateur", "username": "nom d'utilisateur",
  "phone numbers": "numéros de téléphone", "phone": "téléphone", "physical addresses": "adresses postales", "address": "adresse",
  "ip addresses": "adresses IP", "ip": "adresse IP", "dates of birth": "dates de naissance", "dob": "date de naissance",
  "genders": "genres", "geographic locations": "localisations", "country": "pays", "city": "ville", "zip": "code postal",
  "job titles": "postes", "employers": "employeurs", "credit cards": "cartes bancaires",
  "partial credit card data": "données de carte partielles", "bank account numbers": "comptes bancaires",
  "government issued ids": "pièces d'identité", "social media profiles": "profils de réseaux sociaux",
  "purchases": "achats", "device information": "infos sur l'appareil", "website activity": "activité sur le site",
  "auth tokens": "jetons d'authentification", "security questions and answers": "questions de sécurité",
  "payment histories": "historiques de paiement", "ages": "âges", "passport numbers": "numéros de passeport",
  "social security numbers": "numéros de sécurité sociale", "private messages": "messages privés",
  "account balances": "soldes de compte", "nationalities": "nationalités", "spoken languages": "langues parlées",
  "time zones": "fuseaux horaires", "salutations": "civilités", "browser user agent details": "infos de navigateur",
  "avatars": "avatars", "profile photos": "photos de profil", "education levels": "niveaux d'études",
  "income levels": "revenus", "marital statuses": "situations familiales", "medical records": "dossiers médicaux",
  "hash": "mot de passe chiffré", "origin": "origine",
};
const fr = (s: string) => FIELDS[s.trim().toLowerCase()] ?? s.trim().toLowerCase();

async function getJSON(url: string, ms = 9000): Promise<{ status: number; data: any }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { "user-agent": UA, accept: "application/json" } });
    const text = await res.text();
    let data: any = null;
    try { data = JSON.parse(text); } catch { data = null; }
    return { status: res.status, data };
  } finally {
    clearTimeout(timer);
  }
}

type ServiceResult = {
  service: string;
  url: string;
  status: "found" | "clean" | "error";
  message?: string;
  breaches: { name: string; domain?: string; date?: string; records?: number; data: string[]; industry?: string }[];
  risk?: { label: string; score: number };
  passwords?: { plain: number; weak: number; strong: number; unknown: number };
};

async function xposedOrNot(email: string): Promise<ServiceResult> {
  const base: ServiceResult = { service: "XposedOrNot", url: "https://xposedornot.com/", status: "error", breaches: [] };
  try {
    const { status, data } = await getJSON(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`);
    if (status === 429) return { ...base, message: "Limite de recherches atteinte pour le moment, réessayez dans une heure." };
    if (status === 404) return { ...base, status: "clean" };
    if (status >= 400 || !data) return { ...base, message: `Service indisponible (code ${status}).` };
    const details = data?.ExposedBreaches?.breaches_details;
    if (!Array.isArray(details) || details.length === 0) return { ...base, status: "clean" };
    const risk = data?.BreachMetrics?.risk?.[0];
    const pw = data?.BreachMetrics?.passwords_strength?.[0];
    return {
      ...base,
      status: "found",
      breaches: details.map((b: any) => ({
        name: String(b.breach ?? "Inconnu"),
        domain: b.domain || undefined,
        date: b.xposed_date ? String(b.xposed_date) : undefined,
        records: Number(b.xposed_records) || undefined,
        industry: b.industry || undefined,
        data: String(b.xposed_data ?? "").split(";").filter(Boolean).map(fr),
      })).sort((a: any, b: any) => String(b.date ?? "").localeCompare(String(a.date ?? ""))),
      risk: risk ? { label: String(risk.risk_label), score: Number(risk.risk_score) } : undefined,
      passwords: pw ? { plain: pw.PlainText ?? 0, weak: pw.EasyToCrack ?? 0, strong: pw.StrongHash ?? 0, unknown: pw.Unknown ?? 0 } : undefined,
    };
  } catch {
    return { ...base, message: "Le service n'a pas répondu à temps." };
  }
}

async function leakCheck(email: string): Promise<ServiceResult> {
  const base: ServiceResult = { service: "LeakCheck", url: "https://leakcheck.io/", status: "error", breaches: [] };
  try {
    const { status, data } = await getJSON(`https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`);
    if (status === 429) return { ...base, message: "Limite de recherches atteinte pour le moment, réessayez plus tard." };
    if (!data) return { ...base, message: `Service indisponible (code ${status}).` };
    if (data.success === false) {
      if (/not found/i.test(String(data.error ?? data.message ?? ""))) return { ...base, status: "clean" };
      return { ...base, message: "Le service a refusé la recherche." };
    }
    const found = Number(data.found ?? 0);
    if (!found) return { ...base, status: "clean" };
    const fields: string[] = Array.isArray(data.fields) ? data.fields.map(fr) : [];
    const sources: any[] = Array.isArray(data.sources) ? data.sources : [];
    const breaches = sources.length
      ? sources.map((s) => ({ name: String(s.name ?? s ?? "Source inconnue"), date: s.date || undefined, data: fields }))
      : [{ name: `${found} fuite${found > 1 ? "s" : ""} (sources non détaillées)`, data: fields }];
    return { ...base, status: "found", breaches };
  } catch {
    return { ...base, message: "Le service n'a pas répondu à temps." };
  }
}

const EMAIL_RE = /^[^\s@<>()"',;:]+@[^\s@<>()"',;:]+\.[a-z]{2,}$/i;

export default async (req: Request) => {
  const email = (new URL(req.url).searchParams.get("email") ?? "").trim().toLowerCase();
  const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return new Response(JSON.stringify({ error: "Adresse e-mail invalide." }), { status: 400, headers });
  }
  const results = await Promise.all([xposedOrNot(email), leakCheck(email)]);
  return new Response(JSON.stringify({ checkedAt: new Date().toISOString(), results }), { headers });
};

export const config: Config = {
  path: "/api/check",
  method: "GET",
  rateLimit: { windowLimit: 10, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
