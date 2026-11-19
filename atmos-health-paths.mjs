const permittedPaths = new Set(["/health", "/v1/health", "/v1/status", "/.well-known/atmos-health.json"]);

export async function selectHealthProbe(endpoint, paths, fetchOnce) {
  if (!Array.isArray(paths) || paths.length === 0 || paths.some(path => !permittedPaths.has(path)) || new Set(paths).size !== paths.length) throw new Error("Invalid or duplicate configured health path");
  const attempts = [];
  for (const path of paths) {
    const probe = await fetchOnce(new URL(path, endpoint).toString());
    attempts.push({ path, outcome: probe.outcome, statusCode: probe.statusCode, bodySha256: probe.bodySha256 ?? null, error: probe.error ?? null });
    // Only an explicitly absent endpoint permits another path. A 200 with an
    // invalid signature, redirects, failures, and all other statuses stop.
    if (probe.outcome !== "RESPONDED" || ![404, 410].includes(probe.statusCode)) return { selectedPath: path, attempts, probe };
  }
  return { selectedPath: attempts.at(-1).path, attempts, probe: { outcome: "RESPONDED", statusCode: attempts.at(-1).statusCode, parsed: null, raw: null, bodySha256: attempts.at(-1).bodySha256 } };
}
