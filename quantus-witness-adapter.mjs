import { sha256Hex } from "./atmos-canonical.mjs";
import { verifyQuantusStatus } from "./quantus-status.mjs";

export const QUANTUS_WITNESS_SCHEMA = "QUANTUS_WITNESS_STATUS/v1";
export const QUANTUS_SIGNED_FIELDS = [
  "capabilities", "checks", "host", "nodeId", "observedAt", "reviewBoundary", "schema", "service", "status",
];

// A parsed object loses Python's numeric spelling (e.g. 1.0), so callers of
// the earlier object-based API must pass the raw response text instead.
export function verifyQuantusWitnessStatus(raw, expectedFingerprint, options = {}) {
  if (typeof raw !== "string") return { valid: false, reason: "RAW_BODY_REQUIRED" };
  if (Buffer.byteLength(raw) > 1024 * 1024) return { valid: false, reason: "INVALID_JSON_SIZE" };
  if (typeof expectedFingerprint !== "string" || !/^[0-9a-f]{64}$/.test(expectedFingerprint)) return { valid: false, reason: "FINGERPRINT_NOT_CONFIGURED" };
  try {
    const document = JSON.parse(raw);
    if (typeof document.publicKey !== "string" || !/^[0-9a-f]{64}$/i.test(document.publicKey)) return { valid: false, reason: "PUBLIC_KEY_INVALID" };
    const fingerprint = sha256Hex(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(document.publicKey, "hex")]));
    if (fingerprint !== expectedFingerprint) return { valid: false, reason: "PUBLIC_KEY_FINGERPRINT_MISMATCH", fingerprint };
    return { ...verifyQuantusStatus(raw, document.publicKey, options), fingerprint };
  } catch {
    return { valid: false, reason: "INVALID_DOCUMENT" };
  }
}

// This standalone helper preserves the previous API and adds raw bytes for the
// verifier. The caller remains responsible for operator authorization.
export async function fetchQuantusWitnessStatus(endpoint) {
  const url = new URL("/v1/health", endpoint);
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("HTTPS endpoint without credentials required");
  const response = await fetch(url.toString(), { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10000), headers: { Accept: "application/json" } });
  const chunks = [];
  let total = 0;
  const reader = response.body?.getReader();
  if (reader) {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > 1024 * 1024) {
          await reader.cancel();
          throw new Error("Response exceeds the 1 MiB limit");
        }
        chunks.push(Buffer.from(value));
      }
    } finally { reader.releaseLock(); }
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  let parsed = null;
  try { parsed = JSON.parse(raw); } catch { /* Unparseable status remains untrusted. */ }
  return { url: url.toString(), statusCode: response.status, bodySha256: sha256Hex(raw), parsed, raw };
}
