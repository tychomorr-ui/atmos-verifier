import { createPublicKey, verify } from "node:crypto";
import { sha256Hex } from "./atmos-canonical.mjs";

// Parse JSON into an AST so Python's serialized numeric tokens (notably 1.0)
// survive parsing. Reject duplicate names: different parsers must not disagree
// about which value was signed. This is deliberately separate from the legacy
// canonicalizer, whose behavior is part of the existing signed-manifest format.
function parseWireJson(text) {
  if (typeof text !== "string" || Buffer.byteLength(text) > 1024 * 1024) throw new Error("INVALID_JSON_SIZE");
  let i = 0;
  const ws = () => { while (/[\t\n\r ]/.test(text[i] ?? "") && i < text.length) i++; };
  function string() {
    const start = i++;
    while (i < text.length) {
      if (text[i] === '"') {
        i++;
        const result = JSON.parse(text.slice(start, i));
        // Python's UTF-8 signing path cannot encode unpaired surrogates.
        if (/(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF])/.test(result)) throw new Error("INVALID_UNICODE");
        return result;
      }
      if (text[i] === "\\") i++;
      i++;
    }
    throw new Error("INVALID_JSON_STRING");
  }
  function value(depth = 0) {
    if (depth > 100) throw new Error("JSON_TOO_DEEP");
    ws();
    if (text[i] === '"') return { type: "string", value: string() };
    if (text[i] === "{") {
      i++; ws();
      const entries = [], names = new Set();
      if (text[i] === "}") { i++; return { type: "object", entries }; }
      while (true) {
        ws(); if (text[i] !== '"') throw new Error("INVALID_JSON_OBJECT");
        const key = string();
        if (names.has(key)) throw new Error("DUPLICATE_JSON_KEY");
        names.add(key); ws(); if (text[i++] !== ":") throw new Error("INVALID_JSON_OBJECT");
        entries.push([key, value(depth + 1)]); ws();
        if (text[i] === "}") { i++; break; }
        if (text[i++] !== ",") throw new Error("INVALID_JSON_OBJECT");
      }
      return { type: "object", entries };
    }
    if (text[i] === "[") {
      i++; ws(); const items = [];
      if (text[i] === "]") { i++; return { type: "array", items }; }
      while (true) {
        items.push(value(depth + 1)); ws();
        if (text[i] === "]") { i++; break; }
        if (text[i++] !== ",") throw new Error("INVALID_JSON_ARRAY");
      }
      return { type: "array", items };
    }
    const tail = text.slice(i);
    const literal = /^(?:true|false|null)/.exec(tail);
    if (literal) { i += literal[0].length; return { type: "literal", raw: literal[0] }; }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(tail);
    if (number) { i += number[0].length; return { type: "number", raw: number[0] }; }
    throw new Error("INVALID_JSON_VALUE");
  }
  const root = value(); ws();
  if (i !== text.length || root.type !== "object") throw new Error("INVALID_JSON_DOCUMENT");
  return root;
}

// Python sorts strings by Unicode code point, not UTF-16 code unit or locale.
function pythonCompare(a, b) {
  const x = Array.from(a, c => c.codePointAt(0)), y = Array.from(b, c => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

function canonicalNode(node) {
  if (node.type === "string") return JSON.stringify(node.value);
  if (node.type === "number" || node.type === "literal") return node.raw;
  if (node.type === "array") return `[${node.items.map(canonicalNode).join(",")}]`;
  return `{${node.entries.slice().sort(([a], [b]) => pythonCompare(a, b)).map(([key, item]) => `${JSON.stringify(key)}:${canonicalNode(item)}`).join(",")}}`;
}

export function quantusCanonicalPayload(raw) {
  const root = parseWireJson(raw);
  const excluded = new Set(["payloadHash", "publicKey", "signatureAlgorithm", "signature"]);
  return canonicalNode({ type: "object", entries: root.entries.filter(([key]) => !excluded.has(key)) });
}

const base64Signature = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/;
const rawKeyHex = /^[0-9a-fA-F]{64}$/;
const hash = /^sha256:[0-9a-f]{64}$/;
const MAX_AGE_SECONDS = 300;
const MAX_FUTURE_SKEW_SECONDS = 30;

export function verifyQuantusStatus(raw, pinnedPublicKey, { nowSeconds = Date.now() / 1000, maxAgeSeconds = 300, maxFutureSkewSeconds = 30 } = {}) {
  if (!pinnedPublicKey) return { valid: false, reason: "PIN_NOT_CONFIGURED" };
  if (typeof pinnedPublicKey !== "string" || !rawKeyHex.test(pinnedPublicKey)) return { valid: false, reason: "INVALID_PIN" };
  if (!Number.isFinite(nowSeconds) || !Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0 || maxAgeSeconds > MAX_AGE_SECONDS || !Number.isFinite(maxFutureSkewSeconds) || maxFutureSkewSeconds < 0 || maxFutureSkewSeconds > MAX_FUTURE_SKEW_SECONDS) return { valid: false, reason: "INVALID_TIME_POLICY" };
  try {
    const canonical = quantusCanonicalPayload(raw);
    const doc = JSON.parse(raw);
    if (doc.schema !== "QUANTUS_WITNESS_STATUS/v1" || doc.nodeId !== "QUANTUS" || doc.service !== "QUANTUS_WITNESS_CONSOLE" || doc.signatureAlgorithm !== "Ed25519" || !["READY", "DEGRADED"].includes(doc.status) || doc.reviewBoundary !== "OBSERVATION_ONLY_NOT_A_LEGAL_EFFECT_DETERMINATION" || !Array.isArray(doc.capabilities) || !doc.checks || typeof doc.checks !== "object" || Array.isArray(doc.checks) || !doc.host || typeof doc.host !== "object" || Array.isArray(doc.host)) return { valid: false, reason: "UNEXPECTED_DOCUMENT" };
    if (typeof doc.publicKey !== "string" || !rawKeyHex.test(doc.publicKey) || doc.publicKey.toLowerCase() !== pinnedPublicKey.toLowerCase()) return { valid: false, reason: "PUBLIC_KEY_MISMATCH" };
    if (!Number.isSafeInteger(doc.observedAt) || doc.observedAt < 0) return { valid: false, reason: "INVALID_OBSERVED_AT" };
    if (doc.observedAt < nowSeconds - maxAgeSeconds) return { valid: false, reason: "STALE" };
    if (doc.observedAt > nowSeconds + maxFutureSkewSeconds) return { valid: false, reason: "FUTURE" };
    if (typeof doc.payloadHash !== "string" || !hash.test(doc.payloadHash) || doc.payloadHash !== `sha256:${sha256Hex(canonical)}`) return { valid: false, reason: "PAYLOAD_HASH_MISMATCH" };
    if (typeof doc.signature !== "string" || !base64Signature.test(doc.signature)) return { valid: false, reason: "INVALID_SIGNATURE" };
    const signature = Buffer.from(doc.signature, "base64");
    if (signature.length !== 64 || signature.toString("base64") !== doc.signature) return { valid: false, reason: "INVALID_SIGNATURE" };
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pinnedPublicKey, "hex")]), format: "der", type: "spki" });
    if (!verify(null, Buffer.from(canonical, "utf8"), key, signature)) return { valid: false, reason: "INVALID_SIGNATURE" };
    return { valid: true, reason: null, observedAt: doc.observedAt, reportedStatus: doc.status, payloadHash: doc.payloadHash };
  } catch (error) {
    return { valid: false, reason: error?.message === "DUPLICATE_JSON_KEY" ? "DUPLICATE_JSON_KEY" : "INVALID_DOCUMENT" };
  }
}
