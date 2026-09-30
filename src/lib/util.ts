export function uid(prefix = "id"): string {
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${Date.now().toString(36)}${rand}`;
}

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export function fmtDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

export function relTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.max(0, Math.round(diff / 1000));
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return `${d} d ago`;
}

export function pct(n: number, d: number): number {
  return d === 0 ? 0 : Math.round((n / d) * 100);
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function truncate(s: string, n = 80): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * File saving works in two environments:
 *  - a normal host (localhost, GitHub Pages): a plain anchor download;
 *  - the claude.ai artifact viewer: saves must go through the host's
 *    `downloads` capability, which asks the viewer to confirm.
 */
interface HostDownloads {
  save(req: { filename: string; data: Blob | string }): Promise<{ status: string }>;
}
type HostClaude = { use?: (name: string) => Promise<HostDownloads | null> };

let hostDownloads: Promise<HostDownloads | null> | null = null;
function resolveHostDownloads(): Promise<HostDownloads | null> {
  if (hostDownloads) return hostDownloads;
  const claude = (globalThis as { claude?: HostClaude }).claude;
  hostDownloads = claude && typeof claude.use === "function" ? claude.use("downloads").catch(() => null) : Promise.resolve(null);
  return hostDownloads;
}
// Start resolving early so the first click does not wait.
if (typeof window !== "undefined") resolveHostDownloads();

export type SaveOutcome = "saved" | "declined" | "fallback";

function anchorDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export async function downloadBlob(blob: Blob, filename: string): Promise<SaveOutcome> {
  const host = await resolveHostDownloads();
  if (host) {
    try {
      await host.save({ filename, data: blob });
      return "saved";
    } catch (e) {
      const code = (e as { code?: string })?.code;
      if (code === "declined" || code === "rate_limited") return "declined";
      // any other rejection: fall through to the plain download
    }
  }
  anchorDownload(blob, filename);
  return "fallback";
}

export function downloadText(text: string, filename: string, mime = "text/plain;charset=utf-8"): Promise<SaveOutcome> {
  return downloadBlob(new Blob([text], { type: mime }), filename);
}

export function safeLocalStorage(): Storage | null {
  try {
    const s = globalThis.localStorage;
    const k = "__ns_probe__";
    s.setItem(k, "1");
    s.removeItem(k);
    return s;
  } catch {
    return null;
  }
}

export function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n));
}

export function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
