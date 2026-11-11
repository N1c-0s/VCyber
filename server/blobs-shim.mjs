// Remplace @netlify/blobs sur le VPS : mêmes méthodes (get / set / setJSON), stockage dans des fichiers.
import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import path from "node:path";

const BASE = process.env.DATA_DIR || (process.env.STATE_DIRECTORY || "").split(":")[0] || path.resolve("data");
const safe = (s) => String(s).replace(/[^a-zA-Z0-9._-]/g, "_");

export function getStore(name) {
  const dir = path.join(BASE, "blobs", safe(name));
  const file = (key) => path.join(dir, safe(encodeURIComponent(key)) + ".json");
  const write = async (key, text) => {
    await mkdir(dir, { recursive: true });
    const f = file(key);
    const tmp = `${f}.${process.pid}.tmp`;
    await writeFile(tmp, text);
    await rename(tmp, f); // écriture atomique : jamais de fichier à moitié écrit
  };
  return {
    async get(key, opts) {
      try {
        const txt = await readFile(file(key), "utf8");
        return opts?.type === "json" ? JSON.parse(txt) : txt;
      } catch (e) {
        if (e.code === "ENOENT") return null;
        throw e;
      }
    },
    setJSON: (key, value) => write(key, JSON.stringify(value)),
    set: (key, value) => write(key, typeof value === "string" ? value : JSON.stringify(value)),
  };
}
