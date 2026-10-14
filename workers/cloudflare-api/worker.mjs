// One Worker per Citadel installation. Configuration is supplied as a versioned
// route table; credentials are Worker Secret bindings, never table fields.
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const jwksCache = new Map();
const inputHeaders = ["accept", "accept-language", "content-type", "content-encoding",
  "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "range",
  "mcp-protocol-version", "last-event-id"];
const outputHeaders = ["content-type", "content-encoding", "content-disposition", "etag",
  "last-modified", "accept-ranges", "content-range", "mcp-protocol-version"];
const reservedHeaders = /^(?:cf-|x-forwarded-|host$|connection$|content-length$|transfer-encoding$|upgrade$|cookie$|set-cookie$|forwarded$|proxy-authorization$|mcp-session-id$|mcp-protocol-version$|origin$)/i;
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

function pathMatches(template, path) {
  if (!safePath(template) || !safePath(path)) return false;
  const pattern = template.split("/").map(part => /^\{[A-Za-z_][A-Za-z0-9_.-]*\}$/.test(part)
    ? "[^/{}]+" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("/");
  return new RegExp(`^${pattern}$`).test(path);
}

function routeFor(host, path, method) {
  if (adminPaths.some(prefix => path === prefix || path.startsWith(prefix + "/"))) return null;
  // Exact endpoint protocols take precedence over REST path parameters.
  const matches = host.routes.filter(route => route.operations.some(operation =>
    operation.method === method && pathMatches(operation.path, path)));
  const exact = matches.filter(route => route.protocol !== "rest" && route.path === path);
  if (exact.length === 1) return exact[0];
  return matches.length === 1 ? matches[0] : null;
}

export function configuration(env) {
  const config = typeof env.ROUTE_TABLE === "string" ? JSON.parse(env.ROUTE_TABLE) : (env.ROUTE_TABLE || {});
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
          || !["mcp", "rest", "graphql"].includes(route.protocol) || !Array.isArray(route.operations)
          || !route.operations.length || route.operations.length > 2000) throw new Error("Invalid endpoint binding");
      for (const operation of route.operations) {
        if (!safePath(operation.path) || !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(operation.method)) {
          throw new Error("Invalid operation binding");
        }
      }
    }
  }
  return config;
}

async function digest(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function sameSecret(actual, expected) {
  if (typeof expected !== "string" || expected.length < 32 || typeof actual !== "string" || actual.length > 8192) return false;
  const [a, b] = await Promise.all([digest(actual), digest(expected)]);
  let difference = 0;
  for (let i = 0; i < 32; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

async function signingKey(issuer, kid, fetcher, now) {
  let entry = jwksCache.get(issuer);
  const unknown = entry && !entry.keys.has(kid);
  if (!entry || entry.expires <= now || (unknown && now >= entry.retryUnknownAfter)) {
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
    entry = { keys, expires: now + 300, retryUnknownAfter: unknown ? now + 5 : 0 };
    // One issuer per installation; bound cache even if versions change teams.
    if (jwksCache.size >= 4 && !jwksCache.has(issuer)) jwksCache.delete(jwksCache.keys().next().value);
    jwksCache.set(issuer, entry);
  }
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
  return `oauth:${claims.sub}:${email}`;
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

function backendHeaders(route, env) {
  if (!route.credential_ref) return {};
  if (route.credential_ref !== route.id) throw new Error("Invalid credential reference");
  const headers = JSON.parse(env[`BACKEND_${route.id}`] || "null");
  if (!headers || typeof headers !== "object" || Array.isArray(headers) || Object.keys(headers).length > 16) {
    throw new Error("Missing backend credentials");
  }
  for (const [name, value] of Object.entries(headers)) {
    if (reservedHeaders.test(name) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)
        || typeof value !== "string" || !value || value.length > 8192 || /[\x00-\x1f\x7f]/.test(value)) {
      throw new Error("Invalid backend credential");
    }
  }
  return headers;
}

export async function handle(request, env, fetcher = fetch) {
  let config, host, route;
  const url = new URL(request.url);
  if (url.protocol !== "https:" || url.port || !safePath(url.pathname)) return deny(404, "Unknown route");
  try {
    config = configuration(env);
    host = config.hosts[url.hostname];
    if (!host) return deny(404, "Unknown route");
    route = routeFor(host, url.pathname, request.method);
    if (!route) return deny(404, "Unknown endpoint or method");
  } catch {
    return deny(503, "Route configuration unavailable");
  }
  if (request.headers.has("upgrade")) return deny(501, "Unsupported transport");
  let principal;
  try {
    if (host.mode === "api-bearer") {
      const authorization = request.headers.get("authorization") || "";
      if (!authorization.startsWith("Bearer ") || !await sameSecret(authorization.slice(7), env.CLIENT_BEARER)) {
        return deny(401, "Invalid bearer");
      }
      principal = "bearer:" + encode64(await digest(env.CLIENT_BEARER));
    } else {
      principal = await verifyAssertion(request.headers.get("cf-access-jwt-assertion"), config.issuer, host, fetcher);
    }
  } catch {
    return deny(401, "Invalid identity assertion");
  }
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
    for (const [name, value] of Object.entries(backendHeaders(route, env))) headers.set(name, value);
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
