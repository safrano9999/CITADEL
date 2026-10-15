#!/usr/bin/env python3
"""Standalone Citadel checker. Python standard library only; no scan or login.

Exports use the server's index artifact/hash validation; running Caddy is not
validated and exported files are never probed over HTTP.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

SCHEMA_VERSION = 1
MAX_BODY = 2_000_000


def clean_url(url):
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Expected HTTP(S) URL without credentials")
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def fetch(url, timeout):
    request = Request(url, headers={"User-Agent": "Citadel-Health/1", "Accept": "text/html,application/json"})
    try:
        response = urlopen(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        return response.status, response.geturl(), response.read(MAX_BODY + 1)


class AccessForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.login_form = False
        self.login_input = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and "/cdn-cgi/access/" in attrs.get("action", ""):
            self.login_form = True
        if tag == "input" and (attrs.get("type") in ("email", "password") or attrs.get("name") in ("code", "email", "password")):
            self.login_input = True


def is_cloudflare_access(final_url, body):
    p = urlsplit(final_url)
    trusted = p.scheme == "https" and (p.hostname or "").endswith(".cloudflareaccess.com")
    if not trusted or not p.path.startswith("/cdn-cgi/access/login/"):
        return False
    parser = AccessForm()
    parser.feed(body.decode("utf-8", errors="replace"))
    return parser.login_form and parser.login_input


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def api_auth_probe(url, mode, timeout):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "Citadel-Health/1"})
    try:
        response = build_opener(NoRedirect()).open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        code = response.status
        challenge = response.headers.get("WWW-Authenticate", "")
        content_type = response.headers.get("Content-Type", "")
        body = response.read(4097)
    protected = code == 401 and ("resource_metadata=" in challenge if mode == "api-oauth"
                                else content_type.startswith("application/json") and len(body) <= 4096)
    return code, protected


def probe(extension, service, timeout):
    result = {"extension": extension, "port": service["port"], "status": "FAIL"}
    try:
        url = clean_url(service["url"])
        result["url"] = url
        if extension == "CLOUDFLARE-API":
            code, protected = api_auth_probe(url, service.get("provider"), timeout)
            result.update(http_status=code, status="PASS" if protected else "FAIL",
                          detail="Machine authentication challenge verified; authenticated backend NOT_TESTED" if protected
                          else "Expected a machine-readable 401; browser OTP redirects are not accepted")
            return result
        code, final, body = fetch(url, timeout)
        result["http_status"] = code
        result["final_url"] = clean_url(final)
        if code != 200:
            result["detail"] = "Expected HTTP 200"
        elif extension == "cloudflare":
            passed = is_cloudflare_access(final, body)
            result.update(status="PASS" if passed else "FAIL",
                          detail="Cloudflare Access login recognized; backend NOT_TESTED" if passed else "Cloudflare Access login not recognized")
        else:
            result.update(status="PASS", detail="HTTP 200")
    except Exception as error:
        result["detail"] = type(error).__name__
    return result


def check(base_url, extensions, timeout=5, workers=8):
    result = {"schema_version": SCHEMA_VERSION, "status": "FAIL",
              "checked_at": datetime.now(timezone.utc).isoformat(), "last_index_at": None,
              "gates": {"citadel_self": False, "citadel_links": False},
              "citadel_self": {"status": "FAIL"},
              "extensions": [{"id": e, "status": "NOT_TESTED"} for e in extensions], "results": []}
    try:
        base = clean_url(base_url).rstrip("/")
        code, _, _ = fetch(base + "/", timeout)
        if code != 200:
            raise ValueError("Citadel dashboard did not return HTTP 200")
        result["citadel_self"] = {"status": "PASS", "http_status": code}
        result["gates"]["citadel_self"] = True
        code, _, body = fetch(base + "/api/health?" + urlencode({"extensions": ",".join(extensions)}), timeout)
        if code != 200 or len(body) > MAX_BODY:
            raise ValueError("Citadel health endpoint unavailable or response too large")
        data = json.loads(body)
        if data.get("schema_version") != SCHEMA_VERSION or data.get("scope") != "index":
            raise ValueError("Unsupported health response")
        entries = data["extensions"]
        if not isinstance(entries, list) or sorted(e["id"] for e in entries) != sorted(extensions):
            raise ValueError("Health response does not match requested extensions")
        result["last_index_at"] = data.get("last_index_at")
        result["extensions"] = []
        jobs = []
        for entry in entries:
            name = entry["id"]
            status = entry["status"]
            kind = entry.get("kind", "provider")
            if kind not in ("provider", "export"):
                raise ValueError("Unknown extension kind")
            if status not in ("PASS", "FAIL", "SKIP", "NOT_TESTED"):
                raise ValueError("Invalid health status")
            checked = {"id": name, "kind": kind, "status": status, "detail": entry.get("detail", "")}
            result["extensions"].append(checked)
            if kind == "export":
                artifacts = entry.get("artifacts", [])
                checked.update(artifacts=artifacts, services=[])
                for key in ("generated_file", "mappings_count", "generated_at", "label"):
                    if key in entry:
                        checked[key] = entry[key]
                if status == "PASS":
                    if entry.get("services"):
                        raise ValueError("Passing export contains service routes")
                    if (not isinstance(artifacts, list) or not artifacts
                            or any(not isinstance(a, dict) or a.get("status") != "PASS" for a in artifacts)):
                        raise ValueError("Passing export has no validated artifacts")
                    checked["detail"] = "Index artifact validation reported by Citadel; running Caddy and live reachability NOT_TESTED"
                continue
            if status == "PASS":
                if not entry.get("services"):
                    raise ValueError("Passing extension has no routes")
                for service in entry["services"]:
                    if service.get("status") != "PASS":
                        raise ValueError("Passing extension contains a failed service")
                    jobs.append((name, service, timeout))
        if jobs:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                result["results"] = list(pool.map(lambda args: probe(*args), jobs))
        for entry in result["extensions"]:
            if any(r["extension"] == entry["id"] and r["status"] != "PASS" for r in result["results"]):
                entry.update(status="FAIL", detail="External reachability check failed")
        statuses = [e["status"] for e in result["extensions"]]
        passed = (data.get("status") == "PASS" and bool(result["last_index_at"]) and
                  "PASS" in statuses and all(s in ("PASS", "SKIP") for s in statuses))
        result["gates"]["citadel_links"] = passed
        result["status"] = "PASS" if passed else "FAIL"
    except Exception as error:
        result["error"] = type(error).__name__
        if not result["gates"]["citadel_self"]:
            result["citadel_self"]["detail"] = type(error).__name__
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Citadel base URL, e.g. its Tailscale HTTPS address")
    parser.add_argument("--extensions", nargs="+", required=True, help="Only these extensions are checked (spaces or commas)")
    parser.add_argument("--timeout", type=float, default=5, help="Per-request socket timeout; no retries (default 5s)")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    names = list(dict.fromkeys(v for arg in args.extensions for v in arg.split(",") if v))
    if not names or any(not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", n) for n in names):
        parser.error("Invalid extension names")
    if args.timeout <= 0 or not 1 <= args.workers <= 32:
        parser.error("timeout must be positive; workers must be between 1 and 32")
    result = check(args.url, names, args.timeout, args.workers)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
