import { appendFileSync, readFileSync } from "node:fs";
const routes = JSON.parse(readFileSync(process.env.ATMOS_TEST_ROUTES, "utf8"));
globalThis.fetch = async (url, options) => {
  const method = options?.method ?? "GET";
  appendFileSync(process.env.ATMOS_TEST_LOG, `${method} ${url}\n`);
  if (method !== "GET") throw new Error("Only GET is permitted in tests");
  if (!Object.hasOwn(routes, url)) throw new Error(`Unexpected URL ${url}`);
  const route = routes[url];
  return new Response(route.body ?? "", { status: route.status, headers: { "content-type": "application/json" } });
};
