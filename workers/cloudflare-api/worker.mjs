// One Worker per Citadel installation. Configuration is supplied as a versioned
// route table; credentials are Worker Secret bindings, never table fields.
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const jwksCache = new Map();
const routingCache = new WeakMap();
let validatedTable;
const inputHeaders = ["accept", "accept-language", "content-type", "content-encoding",
  "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "range",
  "mcp-protocol-version", "last-event-id"];
const outputHeaders = ["content-type", "content-encoding", "content-disposition", "etag",
  "last-modified", "accept-ranges", "content-range", "mcp-protocol-version"];
const adminPaths = ["/api/cloudflare", "/api/scan", "/api/extensions", "/api/settings"];

function deny(status, error) {
  return Response.json({ error }, { status, headers: {
    "cache-control": "no-store", ...(status === 401 ? { "www-authenticate": 'Bearer realm="citadel-api"' } : {}),
  } });
}

function decode64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid encoding");
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

function encode64(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function safePath(path) {
  return typeof path === "string" && path.startsWith("/") && !path.includes("//")
    && !/[%\\?#\x00-\x20\x7f-\uffff]/.test(path)
    && !path.split("/").some(part => part === "." || part === "..");
}

function pathPattern(template) {
  const pattern = template.split("/").map(part => /^\{[A-Za-z_][A-Za-z0-9_.-]*\}$/.test(part)
    ? "[^/{}]+" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("/");
  return new RegExp(`^${pattern}$`);
}

function routeFor(host, path, method) {
  if (adminPaths.some(prefix => path === prefix || path.startsWith(prefix + "/"))) return null;
  let index = routingCache.get(host);
  if (!index) {
    index = new Map();
    for (const route of host.routes) for (const operation of route.operations) {
      if (!index.has(operation.method)) index.set(operation.method, { exact: new Map(), patterns: [] });
      const group = index.get(operation.method);
      if (operation.path.includes("{")) group.patterns.push({ route, pattern: pathPattern(operation.path) });
      else {
        if (!group.exact.has(operation.path)) group.exact.set(operation.path, new Set());
        group.exact.get(operation.path).add(route);
      }
    }
    routingCache.set(host, index);
  }
  const group = index.get(method);
  if (!group) return null;
  const exact = [...(group.exact.get(path) || [])];
  const protocol = exact.filter(route => route.protocol !== "rest" && route.path === path);
  if (protocol.length === 1) return protocol[0];
  const matches = [...new Set([...exact, ...group.patterns.filter(entry => entry.pattern.test(path)).map(entry => entry.route)])];
  return matches.length === 1 ? matches[0] : null;
}

export function configuration(env) {
  let raw = env.ROUTE_TABLE;
  if (raw === undefined) {
    const count = Number(env.ROUTE_TABLE_PARTS);
    if (!Number.isInteger(count) || count < 1 || count > 60) throw new Error("Missing route table");
    const parts = Array.from({ length: count }, (_, index) => env[`ROUTE_TABLE_${index}`]);
    if (parts.some(part => typeof part !== "string" || part.length > 4000)) throw new Error("Incomplete route table");
    raw = parts.join("");
  }
  if (typeof raw === "string" && validatedTable?.raw === raw) return validatedTable.config;
  const config = typeof raw === "string" ? JSON.parse(raw) : (raw || {});
  if (config.schema !== 1 || !config.hosts || typeof config.hosts !== "object" || Array.isArray(config.hosts)) {
    throw new Error("Invalid route table");
  }
  if (Object.keys(config.hosts).length > 200) throw new Error("Host limit exceeded");
  for (const [hostname, host] of Object.entries(config.hosts)) {
    const match = /^(oauth\.)?api-([1-9][0-9]{0,4})\.([a-z0-9.-]+)$/.exec(hostname);
    if (!match || Number(match[2]) > 65535 || host.mode !== (match[1] ? "api-oauth" : "api-bearer")
        || host.origin !== `https://origin-api-${match[2]}.${match[3]}` || !Array.isArray(host.routes)
        || host.routes.length > 100) throw new Error("Invalid host binding");
    if (host.mode === "api-oauth" && (!/^[A-Za-z0-9_-]+$/.test(host.audience || "")
        || !Array.isArray(host.emails) || !host.emails.length
        || !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(config.issuer || ""))) {
      throw new Error("Invalid OAuth policy");
    }
    for (const route of host.routes) {
      if (!/^p[0-9]{1,5}_[a-f0-9]{20}$/.test(route.id || "") || !safePath(route.path)
          || !["mcp", "rest", "graphql", "rpc"].includes(route.protocol) || !Array.isArray(route.operations)
          || route.access_ref !== route.id || !/^[a-f0-9]{64}$/.test(route.access_revision || "")
          || !route.operations.length || route.operations.length > 2000) throw new Error("Invalid endpoint binding");
      for (const operation of route.operations) {
        if (!safePath(operation.path) || !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(operation.method)) {
          throw new Error("Invalid operation binding");
        }
      }
    }
  }
  if (typeof raw === "string") validatedTable = { raw, config };
  return config;
}

async function digest(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function bearerHash(routeID, token, secret) {
  if (!/^[a-f0-9]{64}$/.test(secret || "")) throw new Error("Missing authentication key");
  const bytes = Uint8Array.from(secret.match(/../g), byte => parseInt(byte, 16));
  const key = await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(routeID + "\0" + token)));
  return Array.from(hash, byte => byte.toString(16).padStart(2, "0")).join("");
}

function sameHash(a, b) {
  let difference = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ (b.charCodeAt(i) || 0);
  return difference === 0;
}

async function signingKey(issuer, kid, fetcher, now) {
  let entry = jwksCache.get(issuer);
  if (!entry) {
    entry = { keys: new Map(), expires: 0, retryAfter: 0, retryUnknownAfter: 0, pending: null };
    if (jwksCache.size >= 4) jwksCache.delete(jwksCache.keys().next().value);
    jwksCache.set(issuer, entry);
  }
  const unknown = !entry.keys.has(kid);
  if (!entry.pending && (entry.expires <= now ? now >= entry.retryAfter
      : unknown && now >= entry.retryUnknownAfter)) {
    const hadKeys = entry.keys.size > 0;
    // Collapse concurrent refreshes; failed requests also get a retry window.
    entry.retryAfter = now + 5;
    entry.retryUnknownAfter = now + 5;
    entry.pending = (async () => {
      const response = await fetcher(`${issuer}/cdn-cgi/access/certs`, {
        redirect: "error", signal: AbortSignal.timeout(5000), headers: { accept: "application/json" },
      });
      if (!response.ok) throw new Error("Signing keys unavailable");
      const reader = response.body.getReader();
      let text = "";
      let length = 0;
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          length += value.byteLength;
          if (length > 65536) throw new Error("Signing key response too large");
          text += new TextDecoder().decode(value);
        }
      } finally {
        await reader.cancel().catch(() => {});
      }
      const document = JSON.parse(text);
      if (!Array.isArray(document.keys) || document.keys.length > 32) throw new Error("Invalid signing keys");
      const keys = new Map();
      for (const key of document.keys) {
        if (key.kty !== "RSA" || (key.alg && key.alg !== "RS256") || (key.use && key.use !== "sig")
            || typeof key.kid !== "string" || keys.has(key.kid)) continue;
        keys.set(key.kid, await crypto.subtle.importKey("jwk", key,
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]));
      }
      entry.keys = keys;
      entry.expires = now + 300;
      if (!hadKeys) entry.retryUnknownAfter = 0;
    })().finally(() => { entry.pending = null; });
  }
  if (entry.pending) await entry.pending;
  if (entry.expires <= now) throw new Error("Signing keys unavailable");
  const key = entry.keys.get(kid);
  if (!key) throw new Error("Unknown signing key");
  return key;
}

export async function verifyAssertion(token, issuer, host, fetcher = fetch, now = Date.now() / 1000) {
  if (typeof token !== "string" || token.length > 16384) throw new Error("Missing assertion");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid assertion");
  const header = JSON.parse(decoder.decode(decode64(parts[0])));
  const claims = JSON.parse(decoder.decode(decode64(parts[1])));
  if (header.alg !== "RS256" || typeof header.kid !== "string" || header.kid.length > 128 || header.crit) {
    throw new Error("Unsupported signing algorithm");
  }
  if (claims.iss !== issuer || !(Array.isArray(claims.aud) ? claims.aud : [claims.aud]).includes(host.audience)
      || !Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.iat) || claims.iat > now + 30
      || (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now + 30))
      || typeof claims.sub !== "string" || !claims.sub || typeof claims.email !== "string") {
    throw new Error("Invalid assertion claims");
  }
  const key = await signingKey(issuer, header.kid, fetcher, now);
  if (!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decode64(parts[2]), encoder.encode(parts[0] + "." + parts[1]))) {
    throw new Error("Invalid assertion signature");
  }
  const email = claims.email.toLowerCase();
  if (!host.emails.includes(email)) throw new Error("Identity no longer allowed");
  return { principal: `oauth:${claims.sub}:${email}`, email };
}

async function sessionKey(secret) {
  if (typeof secret !== "string" || !/^[a-f0-9]{64}$/.test(secret)) throw new Error("Missing session key");
  const bytes = Uint8Array.from(secret.match(/../g), byte => parseInt(byte, 16));
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function sealSession(sid, route, principal, secret, now = Date.now() / 1000) {
  if (typeof sid !== "string" || !/^[\x21-\x7e]{1,1024}$/.test(sid)) throw new Error("Invalid upstream session");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const value = encoder.encode(JSON.stringify({ sid, route, principal, exp: Math.floor(now + 86400) }));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv,
    additionalData: encoder.encode("citadel-mcp-session-v1") }, await sessionKey(secret), value));
  return `v1.${encode64(iv)}.${encode64(encrypted)}`;
}

export async function openSession(token, route, principal, secret, now = Date.now() / 1000) {
  if (typeof token !== "string" || token.length > 8192) throw new Error("Invalid session");
  const [version, iv, ciphertext, extra] = token.split(".");
  if (version !== "v1" || extra !== undefined) throw new Error("Invalid session version");
  const value = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode64(iv),
    additionalData: encoder.encode("citadel-mcp-session-v1") }, await sessionKey(secret), decode64(ciphertext));
  const data = JSON.parse(decoder.decode(value));
  if (data.route !== route || data.principal !== principal || !Number.isFinite(data.exp) || data.exp <= now
      || typeof data.sid !== "string" || !/^[\x21-\x7e]{1,1024}$/.test(data.sid)) throw new Error("Session not authorized");
  return data.sid;
}

function routeAccess(route, env) {
  const access = JSON.parse(env[`ACCESS_${route.id}`] || "null");
  if (!access || !Array.isArray(access.bearer) || access.bearer.length > 64
      || !access.oauth || typeof access.oauth !== "object" || Array.isArray(access.oauth)
      || Object.keys(access.oauth).length > 64) throw new Error("Invalid route access policy");
  const valid = value => value === null || (typeof value === "string" && value.length <= 4096 && /^[A-Za-z0-9._~+/-]+=*$/.test(value));
  if (access.bearer.some(rule => !/^[a-f0-9]{64}$/.test(rule.hash || "") || !valid(rule.backend))
      || Object.values(access.oauth).some(value => !valid(value))) throw new Error("Invalid route credentials");
  return access;
}

export async function handle(request, env, fetcher = fetch) {
  let config, host, route;
  const url = new URL(request.url);
  if (url.protocol !== "https:" || url.port || !safePath(url.pathname)) return deny(404, "Unknown route");
  try {
    config = configuration(env);
    host = config.hosts[url.hostname];
    if (!host) return deny(404, "Unknown route");
  } catch {
    return deny(503, "Route configuration unavailable");
  }
  if (request.headers.has("upgrade")) return deny(501, "Unsupported transport");
  let principal, identity, backend;
  const authorization = request.headers.get("authorization") || "";
  if (host.mode === "api-bearer" && !/^Bearer [A-Za-z0-9._~+/-]+=*$/.test(authorization)) {
    return deny(401, "Invalid bearer");
  }
  if (host.mode === "api-oauth") {
    try {
      identity = await verifyAssertion(request.headers.get("cf-access-jwt-assertion"), config.issuer, host, fetcher);
    } catch {
      return deny(401, "Invalid identity assertion");
    }
  }
  route = routeFor(host, url.pathname, request.method);
  if (!route) return deny(404, "Unknown endpoint or method");
  let access;
  try { access = routeAccess(route, env); }
  catch { return deny(503, "Route access policy unavailable"); }
  if (host.mode === "api-bearer") {
    const token = authorization.slice(7);
    if (token.length > 4096) return deny(401, "Invalid bearer");
    let hash;
    try { hash = await bearerHash(route.id, token, env.SESSION_KEY); }
    catch { return deny(503, "Authentication key unavailable"); }
    const matches = access.bearer.filter(rule => sameHash(hash, rule.hash));
    if (matches.length !== 1) return deny(401, "Invalid bearer");
    backend = matches[0].backend === null ? token : matches[0].backend;
    principal = `bearer:${hash}`;
  } else {
    if (!Object.hasOwn(access.oauth, identity.email)) return deny(403, "Identity not allowed for this route");
    backend = access.oauth[identity.email];
    principal = identity.principal;
  }
  // Bind MCP sessions to both the caller and the applied grant revision.
  // Changed backend mappings and revoked grants cannot reuse old sessions.
  principal += `:${route.access_revision}`;
  try {
    if (!env.API_LIMIT || typeof env.API_LIMIT.limit !== "function") return deny(503, "Rate control unavailable");
    const allowed = await env.API_LIMIT.limit({ key: encode64(await digest(principal)) });
    if (!allowed.success) return deny(429, "Request limit reached");
    if (route.protocol === "mcp" && !/^[a-f0-9]{64}$/.test(env.SESSION_KEY || "")) return deny(503, "Session key unavailable");
    const headers = new Headers();
    for (const name of inputHeaders) if (request.headers.has(name)) headers.set(name, request.headers.get(name));
    if (route.protocol === "mcp" && request.headers.has("mcp-session-id")) {
      try {
        headers.set("mcp-session-id", await openSession(request.headers.get("mcp-session-id"), route.id, principal, env.SESSION_KEY));
      } catch {
        return deny(404, "Invalid MCP session");
      }
    }
    if (backend !== null) headers.set("Authorization", "Bearer " + backend);
    if (!env.ORIGIN_CLIENT_ID || !env.ORIGIN_CLIENT_SECRET) return deny(503, "Origin credentials unavailable");
    headers.set("CF-Access-Client-Id", env.ORIGIN_CLIENT_ID);
    headers.set("CF-Access-Client-Secret", env.ORIGIN_CLIENT_SECRET);
    const upstream = await fetcher(host.origin + url.pathname + url.search, {
      method: request.method, headers, body: request.body, redirect: "manual", signal: request.signal, duplex: "half",
    });
    if (upstream.status >= 300 && upstream.status < 400 && upstream.status !== 304) {
      await upstream.body?.cancel();
      return deny(502, "Upstream redirect refused");
    }
    if (upstream.status >= 400) {
      await upstream.body?.cancel();
      return deny([401, 403].includes(upstream.status) ? 502 : upstream.status, "Upstream rejected request");
    }
    const responseHeaders = new Headers({ "cache-control": "no-store", "x-content-type-options": "nosniff" });
    for (const name of outputHeaders) if (upstream.headers.has(name)) responseHeaders.set(name, upstream.headers.get(name));
    if (route.protocol === "mcp" && upstream.headers.has("mcp-session-id")) {
      responseHeaders.set("mcp-session-id", await sealSession(upstream.headers.get("mcp-session-id"), route.id, principal, env.SESSION_KEY));
    }
    // Passing the stream through preserves backpressure and cancellation. Never
    // buffer the MCP/SSE body or follow a backend URL with credentials attached.
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return deny(502, "Protected upstream unavailable");
  }
}

export default { fetch(request, env) { return handle(request, env); } };
