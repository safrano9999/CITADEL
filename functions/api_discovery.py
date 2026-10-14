"""Bounded, read-only API discovery on listeners from the normal Citadel scan.

Targets are always loopback listeners, never URLs supplied by a backend.
Probes identify protocols; a status code or path name alone is not evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urljoin, urlsplit

from cloudflare_api_policy import endpoint_path, route_id

MCP_PATHS = ("/mcp", "/api/mcp", "/api/v1/mcp", "/api/v2/mcp")
DOC_PATHS = ("/openapi.json", "/swagger.json", "/api/docs.json", "/api/openapi.json",
             "/api/v1/docs.json", "/api/v2/docs.json", "/v3/api-docs")
GRAPHQL_PATHS = ("/graphql", "/api/graphql")
API_ROOTS = ("/api", "/api/v1", "/api/v2")
METHODS = {"get", "head", "post", "put", "patch", "delete", "options"}
MAX_BODY = 512 * 1024
MAX_REQUESTS = 20
MAX_OPERATIONS = 2000
PROTOCOL_VERSION = "2025-06-18"
GRAPHQL_QUERY = "query CitadelDiscovery { __typename }"


@dataclass
class Probe:
    status: int
    headers: dict[str, str]
    body: bytes


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def json_message(probe: Probe):
    content_type = probe.headers.get("content-type", "").split(";")[0].lower()
    try:
        if content_type == "text/event-stream":
            for event in probe.body.replace(b"\r\n", b"\n").split(b"\n\n"):
                data = b"\n".join(line[5:].lstrip() for line in event.split(b"\n") if line.startswith(b"data:"))
                if not data:
                    continue
                value = json.loads(data)
                if isinstance(value, dict) and value.get("id") == 1:
                    return value
            return None
        if content_type == "application/json" or content_type.endswith("+json"):
            return json.loads(probe.body)
    except (ValueError, UnicodeError):
        pass
    return None


class LocalProbes:
    def __init__(self, scheme: str, port: int, *, seconds: float = 10):
        if scheme not in {"http", "https"} or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid local listener")
        self.base = f"{scheme}://127.0.0.1:{port}"
        self.deadline = time.monotonic() + seconds
        self.count = 0
        # Caddy's local listeners may use an internal CA, as in the normal scan.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))

    def __call__(self, path: str, method="GET", payload=None, headers=None, *, query=None) -> Probe:
        endpoint_path(path)
        self.count += 1
        remaining = self.deadline - time.monotonic()
        if self.count > MAX_REQUESTS or remaining <= 0:
            return Probe(0, {}, b"")
        if method not in {"GET", "POST"}:
            raise ValueError("Unsupported discovery method")
        if method == "POST" and (not isinstance(payload, dict) or payload.get("method") != "initialize"):
            raise ValueError("Discovery may only POST MCP initialize")
        if query is not None and (method != "GET" or query != {"query": GRAPHQL_QUERY}):
            raise ValueError("Only the read-only GraphQL discovery query is allowed")
        request_headers = {"Accept": "application/json, text/event-stream", **(headers or {})}
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        url = self.base + path + ("?" + urlencode(query) if query is not None else "")
        request = urllib.request.Request(url, method=method,
            data=json.dumps(payload).encode() if payload is not None else None, headers=request_headers)
        response = None
        try:
            try:
                response = self.opener.open(request, timeout=min(1.0, remaining))
            except urllib.error.HTTPError as exc:
                response = exc
            result = Probe(response.code, {k.lower(): v for k, v in response.headers.items()}, b"")
            # Do not consume bodies from redirects/auth failures or wait on a
            # persistent SSE connection after the initialize result arrives.
            if response.code < 200 or response.code >= 300:
                return result
            chunks = bytearray()
            while len(chunks) <= MAX_BODY and time.monotonic() < self.deadline:
                chunk = response.read1(min(16384, MAX_BODY + 1 - len(chunks)))
                if not chunk:
                    return Probe(result.status, result.headers, bytes(chunks))
                chunks.extend(chunk)
                if result.headers.get("content-type", "").startswith("text/event-stream"):
                    candidate = Probe(result.status, result.headers, bytes(chunks))
                    if json_message(candidate) is not None:
                        return candidate
            return Probe(0, {}, b"")
        except (OSError, urllib.error.URLError, ValueError):
            return Probe(0, {}, b"")
        finally:
            if response is not None:
                response.close()


def openapi_operations(document: dict, base_url: str) -> tuple[str, list[dict]]:
    """Resolve only local OpenAPI/Swagger paths; never fetch external $refs."""
    version = str(document.get("openapi") or document.get("swagger") or "")
    if not version.startswith(("3.0.", "3.1.", "3.2.", "2.0")) or not isinstance(document.get("paths"), dict):
        raise ValueError("Not an OpenAPI document")
    if version.startswith("2."):
        base = endpoint_path(document.get("basePath", "/"))
    else:
        servers = document.get("servers") or [{"url": "/"}]
        if not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], dict):
            raise ValueError("Multiple OpenAPI server targets require explicit review")
        server = servers[0].get("url")
        if not isinstance(server, str):
            raise ValueError("Invalid OpenAPI server")
        resolved = urlsplit(urljoin(base_url, server))
        origin = urlsplit(base_url)
        if (resolved.scheme, resolved.netloc) != (origin.scheme, origin.netloc) or resolved.query or resolved.fragment:
            raise ValueError("External OpenAPI servers are not scanned")
        base = endpoint_path(resolved.path or "/")
    operations = []
    for path, methods in document["paths"].items():
        endpoint_path(path, template=True)
        if not isinstance(methods, dict) or "$ref" in methods or "servers" in methods:
            raise ValueError("Unsupported OpenAPI path reference or server override")
        for method, spec in methods.items():
            if method not in METHODS:
                continue
            if not isinstance(spec, dict) or "servers" in spec:
                raise ValueError("Invalid OpenAPI operation or server override")
            security = spec.get("security", document.get("security", []))
            if not isinstance(security, list) or any(not isinstance(s, dict) for s in security):
                raise ValueError("Invalid OpenAPI security requirement")
            operations.append({"path": endpoint_path(base.rstrip("/") + path, template=True),
                               "method": method.upper(), "requires_auth": bool(security) and {} not in security})
            if len(operations) > MAX_OPERATIONS:
                raise ValueError("OpenAPI operation limit exceeded")
    if not operations:
        raise ValueError("OpenAPI document has no supported HTTP operations")
    return base, operations


def documentation_links(response: Probe, source_url: str) -> list[str]:
    """A few explicit same-origin document references, never a general crawler."""
    candidates = []
    data = json_message(response)
    if isinstance(data, dict):
        candidates += [data.get(key) for key in ("openapi_url", "swagger_url", "documentation_url")]
    for target, relation in re.findall(r'<([^>]+)>;\s*rel="?([^";, ]+)', response.headers.get("link", "")):
        if relation in {"service-desc", "describedby"}:
            candidates.append(target)
    if "text/html" in response.headers.get("content-type", ""):
        html = response.body.decode("utf-8", errors="replace")
        candidates += re.findall(r'''(?:url\s*:|href\s*=)\s*["']([^"']+\.json)["']''', html)[:4]
    origin = urlsplit(source_url)
    paths = []
    for candidate in candidates[:8]:
        if not isinstance(candidate, str):
            continue
        target = urlsplit(urljoin(source_url, candidate))
        if ((target.scheme, target.netloc) != (origin.scheme, origin.netloc)
                or target.query or target.fragment):
            continue
        try:
            paths.append(endpoint_path(target.path))
        except ValueError:
            continue
    return list(dict.fromkeys(paths))[:4]


def discover_service(service: dict, credentials: dict, *, probe=None, admin_ports=()) -> list[dict]:
    port, scheme = service.get("port"), service.get("scheme")
    if type(port) is not int or not 1 <= port <= 65535 or scheme not in {"http", "https"}:
        raise ValueError("Invalid scanned HTTP listener")
    titles = {str(service.get(key) or "").strip().lower() for key in ("name", "title")}
    if port in admin_ports or service.get("citadel_webui") or "citadel" in titles:
        return []
    probe = probe or LocalProbes(scheme, port)
    rows = {}

    def record(path, protocol, response, status, evidence, operations=()):
        key = route_id(port, protocol, path)
        previous = rows.get(key, {})
        if protocol == "rest" and previous.get("operations"):
            # A later /api probe is weaker evidence than its OpenAPI document.
            # Multiple documents for one API base contribute a single scope.
            if not operations:
                return previous
            combined = {(op["method"], op["path"]): dict(op) for op in previous["operations"]}
            for op in operations:
                identity = (op["method"], op["path"])
                old = combined.get(identity, {})
                combined[identity] = {**op, "requires_auth": bool(old.get("requires_auth") or op.get("requires_auth"))}
            if len(combined) > MAX_OPERATIONS:
                raise ValueError("Combined OpenAPI operation limit exceeded")
            operations = [combined[identity] for identity in sorted(combined)]
            needs_auth = any(op["requires_auth"] for op in operations) and not credentials.get(key)
            status = "authentication-required" if needs_auth else "ready"
            evidence = "Merged OpenAPI operations" + (" require backend credentials" if needs_auth else "")
        rows[key] = {"id": key, "port": port, "scheme": scheme, "path": path,
            "protocol": protocol, "status": status, "evidence": evidence,
            "http_status": response.status, "operations": list(operations),
            "credential_ref": key if credentials.get(key) else None}
        return rows[key]

    for path in MCP_PATHS:
        key = route_id(port, "mcp", path)
        response = probe(path, "POST", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "citadel-discovery", "version": "1"}}}, credentials.get(key, {}))
        data = json_message(response)
        result = data.get("result") if isinstance(data, dict) else None
        if (200 <= response.status < 300 and isinstance(data, dict) and data.get("jsonrpc") == "2.0"
                and data.get("id") == 1 and isinstance(result, dict)
                and isinstance(result.get("serverInfo"), dict) and isinstance(result.get("capabilities"), dict)
                and result.get("protocolVersion") in {"2025-03-26", "2025-06-18", "2025-11-25"}):
            record(path, "mcp", response, "ready", "MCP initialize result", [
                {"path": path, "method": method} for method in ("GET", "POST", "DELETE")])
        elif response.status in {401, 403}:
            record(path, "mcp", response, "authentication-required", "Credentials required; protocol unverified")
        elif response.status not in {404, 405}:
            record(path, "mcp", response, "unknown", "No valid Streamable HTTP initialize result")

    document_paths = list(DOC_PATHS + API_ROOTS)
    followed = 0
    for path in document_paths:
        # Discovery credentials for a protected document use that document's
        # stable candidate ID. Runtime credentials use the resolved API base ID.
        key = route_id(port, "rest", path)
        response = probe(path, headers=credentials.get(key, {}))
        data = json_message(response)
        source_url = f"{scheme}://127.0.0.1:{port}{path}"
        if response.status == 0:
            record(path, "rest", response, "unknown", "Discovery timeout or request budget exhausted")
            continue
        if 200 <= response.status < 300:
            for link in documentation_links(response, source_url):
                if followed < 4 and link not in document_paths:
                    document_paths.append(link)
                    followed += 1
        if response.status in {401, 403}:
            record(path, "rest", response, "authentication-required", "API documentation requires credentials")
            continue
        if not isinstance(data, dict) or not 200 <= response.status < 300:
            continue
        if isinstance(data.get("info"), dict) and str(data["info"].get("title", "")).lower() == "citadel":
            return []
        try:
            base, operations = openapi_operations(data, source_url)
        except ValueError:
            record(path, "rest", response, "unknown", "No supported local OpenAPI operation map")
            continue
        key = route_id(port, "rest", base)
        needs_auth = any(op["requires_auth"] for op in operations) and not credentials.get(key)
        record(base, "rest", response, "authentication-required" if needs_auth else "ready",
               "OpenAPI operations" if not needs_auth else "OpenAPI operations require backend credentials", operations)

    for path in GRAPHQL_PATHS:
        # GET with a query is a read-only GraphQL operation. Keep query construction
        # inside the probe API instead of accepting arbitrary target URLs.
        key = route_id(port, "graphql", path)
        response = probe(path, headers=credentials.get(key, {}), query={"query": GRAPHQL_QUERY})
        data = json_message(response)
        if response.status in {401, 403}:
            record(path, "graphql", response, "authentication-required", "Credentials required; protocol unverified")
        elif (200 <= response.status < 300 and isinstance(data, dict) and isinstance(data.get("data"), dict)
              and isinstance(data["data"].get("__typename"), str)):
            record(path, "graphql", response, "ready", "GraphQL __typename query", [
                {"path": path, "method": method} for method in ("GET", "POST")])
        elif isinstance(data, dict) and isinstance(data.get("errors"), list):
            record(path, "graphql", response, "unknown", "GraphQL-like error; read-only verification required")
    return sorted(rows.values(), key=lambda row: (row["protocol"], row["path"]))
