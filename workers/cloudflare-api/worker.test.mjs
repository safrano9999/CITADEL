import test from "node:test";
import assert from "node:assert/strict";
import worker, { handle, verifyAssertion, openSession, sealSession } from "./worker.mjs";

const routeID = "p3070_0123456789abcdef0123";
const bearer = "a".repeat(64);
const route = { id: routeID, path: "/mcp", protocol: "mcp", credential_ref: routeID,
  operations: ["GET", "POST", "DELETE"].map(method => ({ method, path: "/mcp" })) };
const sessionKey = "c".repeat(64);
function environment(mode = "api-bearer") {
  const hostname = mode === "api-bearer" ? "api-3070.example.com" : "oauth.api-3070.example.com";
  return {
    ROUTE_TABLE: JSON.stringify({ schema: 1, issuer: "https://test.cloudflareaccess.com", hosts: {
      [hostname]: { mode, origin: "https://origin-api-3070.example.com", routes: [route],
        audience: "correct-audience", emails: ["owner@example.com"] },
    } }),
    CLIENT_BEARER: bearer, SESSION_KEY: sessionKey, ORIGIN_CLIENT_ID: "machine.access",
    ORIGIN_CLIENT_SECRET: "origin-secret", [`BACKEND_${routeID}`]: JSON.stringify({ authorization: "Bearer backend-secret" }),
    API_LIMIT: { async limit() { return { success: true }; } },
  };
}
function request(path = "/mcp", headers = {}, hostname = "api-3070.example.com", method = "POST") {
  return new Request(`https://${hostname}${path}`, { method,
    headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json", ...headers },
    ...(method === "POST" ? { body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }) } : {}),
  });
}
const mustNotFetch = () => { throw new Error("Unauthorized fetch"); };

test("missing/wrong bearer is rejected without calling an upstream", async () => {
  for (const authorization of ["", "Bearer wrong", "Basic credentials"]) {
    const response = await handle(request("/mcp", { authorization }), environment(), mustNotFetch);
    assert.equal(response.status, 401);
  }
});

test("only allowlisted host, path and method can be forwarded", async () => {
  for (const req of [request("/admin"), request("/api/cloudflare/ports"), request("/mcp%2Fadmin"),
    request("/mcp", {}, "worker.workers.dev"), request("/mcp", {}, "api-3070.example.com", "PUT")]) {
    assert.equal((await handle(req, environment(), mustNotFetch)).status, 404);
  }
});

test("client auth and identity headers are replaced by separate origin/backend credentials", async () => {
  let calls = 0;
  const response = await handle(request("/mcp", {
    "cf-access-jwt-assertion": "untrusted", "cf-access-client-secret": "client-injected",
    "x-forwarded-user": "admin", cookie: "browser-session", "mcp-protocol-version": "2025-06-18",
  }), environment(), async (url, options) => {
    calls++;
    assert.equal(url, "https://origin-api-3070.example.com/mcp");
    assert.equal(options.redirect, "manual");
    assert.equal(options.headers.get("authorization"), "Bearer backend-secret");
    assert.equal(options.headers.get("cf-access-client-id"), "machine.access");
    assert.equal(options.headers.get("cf-access-client-secret"), "origin-secret");
    for (const name of ["cf-access-jwt-assertion", "cookie", "x-forwarded-user"]) assert.equal(options.headers.get(name), null);
    assert.equal(options.headers.get("mcp-protocol-version"), "2025-06-18");
    return Response.json({ result: {} }, { headers: { "set-cookie": "secret", "cf-access-jwt-assertion": "secret" } });
  });
  assert.equal(response.status, 200);
  assert.equal(calls, 1);
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(response.headers.get("cf-access-jwt-assertion"), null);
});

test("backend auth failures and redirects never expose credential-bearing errors", async () => {
  for (const status of [302, 401, 403]) {
    const response = await handle(request(), environment(), async () => new Response("backend-secret", {
      status, headers: { location: "https://evil.example/?token=backend-secret" },
    }));
    assert.equal(response.status, 502);
    assert.equal(response.headers.get("location"), null);
    assert.ok(!(await response.text()).includes("backend-secret"));
  }
});

test("SSE is delivered before stream completion and cancellation reaches upstream", async () => {
  let cancelled = false;
  const req = request();
  const response = await handle(req, environment(), async (url, options) => {
    assert.equal(options.signal, req.signal);
    return new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode("data: first\n\n")); },
      cancel() { cancelled = true; },
    }), { headers: { "content-type": "text/event-stream", "mcp-session-id": "upstream-session" } });
  });
  assert.equal(response.status, 200);
  assert.ok(response.headers.get("mcp-session-id").startsWith("v1."));
  assert.ok(!response.headers.get("mcp-session-id").includes("upstream-session"));
  const reader = response.body.getReader();
  assert.equal(new TextDecoder().decode((await reader.read()).value), "data: first\n\n");
  await reader.cancel();
  assert.ok(cancelled);
});

test("MCP sessions cannot be reused by another identity, route, key or after expiry", async () => {
  const token = await sealSession("server-session", routeID, "oauth:alice", sessionKey, 1000);
  assert.equal(await openSession(token, routeID, "oauth:alice", sessionKey, 1001), "server-session");
  for (const [route, principal, key, now] of [
    [routeID, "oauth:bob", sessionKey, 1001], ["another-route", "oauth:alice", sessionKey, 1001],
    [routeID, "oauth:alice", "d".repeat(64), 1001], [routeID, "oauth:alice", sessionKey, 87401],
  ]) await assert.rejects(() => openSession(token, route, principal, key, now));
});

test("raw backend session IDs are not accepted from clients", async () => {
  const response = await handle(request("/mcp", { "mcp-session-id": "server-session" }), environment(), mustNotFetch);
  assert.equal(response.status, 404);
});

test("rate limiting uses identity rather than the tunnel IP", async () => {
  const env = environment();
  let key;
  env.API_LIMIT.limit = async input => { key = input.key; return { success: false }; };
  assert.equal((await handle(request(), env, mustNotFetch)).status, 429);
  assert.ok(key && key !== "127.0.0.1" && !key.includes(bearer));
});

test("missing backend or origin secret fails closed", async () => {
  for (const binding of [`BACKEND_${routeID}`, "ORIGIN_CLIENT_SECRET"]) {
    const env = environment();
    delete env[binding];
    assert.ok((await handle(request(), env, mustNotFetch)).status >= 500);
  }
});

const pair1 = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
const pair2 = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
const jwk1 = { ...await crypto.subtle.exportKey("jwk", pair1.publicKey), kid: "first", alg: "RS256", use: "sig" };
const jwk2 = { ...await crypto.subtle.exportKey("jwk", pair2.publicKey), kid: "second", alg: "RS256", use: "sig" };
const hostPolicy = { audience: "correct-audience", emails: ["owner@example.com"] };
async function jwt(issuer, claims = {}, pair = pair1, kid = "first") {
  const now = Math.floor(Date.now() / 1000);
  const encoded = value => Buffer.from(JSON.stringify(value)).toString("base64url");
  const payload = encoded({ alg: "RS256", kid }) + "." + encoded({ iss: issuer, aud: ["correct-audience"],
    exp: now + 300, iat: now, sub: "user-id", email: "owner@example.com", ...claims });
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(payload));
  return payload + "." + Buffer.from(signature).toString("base64url");
}

test("signed assertion verifies issuer, audience, expiry, signature and current identity policy", async () => {
  const issuer = "https://verification.cloudflareaccess.com";
  const fetcher = async () => Response.json({ keys: [jwk1] });
  assert.equal(await verifyAssertion(await jwt(issuer), issuer, hostPolicy, fetcher), "oauth:user-id:owner@example.com");
  for (const claims of [{ iss: "https://other.cloudflareaccess.com" }, { aud: ["another-app-same-team"] },
    { exp: 1 }, { nbf: Date.now() / 1000 + 1000 }, { email: "removed@example.com" }]) {
    const jwtToken = await jwt(issuer, claims);
    await assert.rejects(() => verifyAssertion(jwtToken, issuer, hostPolicy, fetcher));
  }
  const forged = await jwt(issuer, {}, pair2);
  await assert.rejects(() => verifyAssertion(forged, issuer, hostPolicy, fetcher));
});

test("unknown kid refreshes JWKS, with a bounded retry window", async () => {
  const issuer = "https://rotation.cloudflareaccess.com";
  let calls = 0;
  const fetcher = async () => Response.json({ keys: [++calls === 1 ? jwk1 : jwk2] });
  const now = Date.now() / 1000;
  await verifyAssertion(await jwt(issuer), issuer, hostPolicy, fetcher, now);
  await verifyAssertion(await jwt(issuer, {}, pair2, "second"), issuer, hostPolicy, fetcher, now + 1);
  assert.equal(calls, 2);
  const unknown = await jwt(issuer, {}, pair2, "unknown");
  await assert.rejects(() => verifyAssertion(unknown, issuer, hostPolicy, fetcher, now + 2));
  assert.equal(calls, 2);
});

test("OAuth-only operation needs no client bearer and forwards no opaque OAuth token", async () => {
  const env = environment("api-oauth");
  delete env.CLIENT_BEARER;
  const token = await jwt("https://test.cloudflareaccess.com");
  let originCalls = 0;
  const response = await handle(request("/mcp", { authorization: "Bearer oauth:opaque-client-token",
    "cf-access-jwt-assertion": token }, "oauth.api-3070.example.com"), env, async (url, options) => {
    if (url.endsWith("/cdn-cgi/access/certs")) return Response.json({ keys: [jwk1] });
    originCalls++;
    assert.equal(options.headers.get("authorization"), "Bearer backend-secret");
    assert.equal(options.headers.get("cf-access-jwt-assertion"), null);
    return Response.json({ result: {} });
  });
  assert.equal(response.status, 200);
  assert.equal(originCalls, 1);
  assert.equal((await handle(request("/mcp", {}, "oauth.api-3070.example.com"), env, mustNotFetch)).status, 401);
});

test("Cloudflare execution context is not interpreted as the fetch implementation", async () => {
  const response = await worker.fetch(request("/unknown"), environment(), { waitUntil() {} });
  assert.equal(response.status, 404);
});
