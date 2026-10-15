from __future__ import annotations

import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class CloudflareAPIError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class CloudflareAPI:
    def __init__(self, token: str, base_url: str = "https://api.cloudflare.com/client/v4") -> None:
        self.token = token
        self.base_url = base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        if payload is not None and body is not None:
            raise ValueError("Specify JSON or a raw body, not both")
        body = body if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": content_type,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            # Error bodies can echo submitted Worker Secrets. Never log them.
            exc.close()
            raise CloudflareAPIError(
                f"Cloudflare API HTTP {exc.code} during {method}",
                status_code=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise CloudflareAPIError(f"Cloudflare API unavailable: {exc.reason}") from exc

        if not raw:
            return None
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CloudflareAPIError("Cloudflare API returned invalid JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("success") is not True:
            errors = envelope.get("errors", []) if isinstance(envelope, dict) else []
            codes = [error.get("code") for error in errors if isinstance(error, dict)
                     and type(error.get("code")) is int] if isinstance(errors, list) else []
            raise CloudflareAPIError(f"Cloudflare API rejected {method} request (codes: {codes})")
        return envelope.get("result")

    def verify_token(self) -> None:
        result = self.request("GET", "/user/tokens/verify")
        if not isinstance(result, dict) or result.get("status") != "active":
            raise CloudflareAPIError("Cloudflare management token is not active")

    def list_all(self, path: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        page = 1
        while True:
            batch = self.request("GET", path, query={"page": page, "per_page": 100})
            if not isinstance(batch, list):
                raise CloudflareAPIError("Cloudflare returned an invalid resource list")
            for item in batch:
                identity = item.get("id") if isinstance(item, dict) else None
                if not isinstance(identity, str) or not identity or identity in seen:
                    raise CloudflareAPIError("Cloudflare returned missing/duplicate resource IDs")
                seen.add(identity)
            records.extend(batch)
            if len(batch) < 100:
                return records
            page += 1

    def dns_records(self, zone_id: str) -> list[dict[str, Any]]:
        return self.list_all(f"/zones/{zone_id}/dns_records")

    def zone(self, zone_id: str) -> dict[str, Any]:
        result = self.request("GET", f"/zones/{zone_id}")
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare did not return the configured zone")
        return result

    def zones(self) -> list[dict[str, Any]]:
        result = self.request("GET", "/zones", query={"per_page": 100})
        return result if isinstance(result, list) else []

    def tunnels(self, account_id: str) -> list[dict[str, Any]]:
        result = self.request(
            "GET",
            f"/accounts/{account_id}/cfd_tunnel",
            query={"is_deleted": "false", "per_page": 100},
        )
        return result if isinstance(result, list) else []

    def tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        result = self.request(
            "GET",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token",
        )
        if not isinstance(result, str) or not result:
            raise CloudflareAPIError("Cloudflare did not return a Tunnel token")
        return result

    def access_identity_providers(self, account_id: str) -> list[dict[str, Any]]:
        result = self.request(
            "GET",
            f"/accounts/{account_id}/access/identity_providers",
            query={"per_page": 100},
        )
        return result if isinstance(result, list) else []

    def access_organization(self, account_id: str) -> dict[str, Any]:
        result = self.request("GET", f"/accounts/{account_id}/access/organizations")
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare did not return the Zero Trust organization")
        return result

    def create_access_organization(
        self,
        account_id: str,
        auth_domain: str,
        name: str,
    ) -> dict[str, Any]:
        result = self.request(
            "POST",
            f"/accounts/{account_id}/access/organizations",
            payload={"auth_domain": auth_domain, "name": name},
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare did not return the created Zero Trust organization")
        return result

    def create_access_identity_provider(
        self,
        account_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        result = self.request(
            "POST",
            f"/accounts/{account_id}/access/identity_providers",
            payload=payload,
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare did not return the created identity provider")
        return result

    def tunnel_connections(self, account_id: str, tunnel_id: str) -> list[dict[str, Any]]:
        result = self.request(
            "GET",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
        )
        return result if isinstance(result, list) else []

    def tunnel_configuration(self, account_id: str, tunnel_id: str) -> dict[str, Any]:
        result = self.request(
            "GET",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare returned an invalid tunnel configuration")
        config = result.get("config")
        if config is not None and not isinstance(config, dict):
            raise CloudflareAPIError("Cloudflare returned an invalid tunnel configuration")
        return config or {}

    def update_tunnel_configuration(
        self,
        account_id: str,
        tunnel_id: str,
        config: dict[str, Any],
    ) -> None:
        self.request(
            "PUT",
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            payload={"config": config},
        )

    def create_tunnel_dns(
        self,
        zone_id: str,
        hostname: str,
        tunnel_id: str,
    ) -> str:
        name = hostname.rstrip(".").lower()
        content = f"{tunnel_id}.cfargotunnel.com"
        payload = {
            "type": "CNAME",
            "name": name,
            "content": content,
            "proxied": True,
            "ttl": 1,
        }
        result = self.request("POST", f"/zones/{zone_id}/dns_records", payload=payload)
        if not isinstance(result, dict) or not result.get("id"):
            raise CloudflareAPIError(f"Cloudflare did not return a DNS record id for {name}")
        return str(result["id"])

    def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        try:
            self.request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise

    def access_apps(self, account_id: str) -> list[dict[str, Any]]:
        return self.list_all(f"/accounts/{account_id}/access/apps")

    def create_access_app(self, account_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.request("POST", f"/accounts/{account_id}/access/apps", payload=payload)
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare did not return the created Access application")
        return result

    def merge_access_resource(
        self, account_id: str, kind: str, identity: str, changes: dict[str, Any],
    ) -> dict[str, Any]:
        """Preserve all GET fields during PUT, including OAuth registrations.

        Access uses replacement updates; sending only changed fields can reset
        configuration which is not owned by this caller.
        """
        if kind not in {"apps", "policies"}:
            raise ValueError("Unsupported Access resource")
        path = f"/accounts/{account_id}/access/{kind}/{identity}"
        current = self.request("GET", path)
        if not isinstance(current, dict) or current.get("id") != identity:
            raise CloudflareAPIError("Access resource identity changed during reconciliation")
        result = self.request("PUT", path, payload={**current, **changes})
        if not isinstance(result, dict) or result.get("id") != identity:
            raise CloudflareAPIError("Access update did not preserve the resource identity")
        return result

    def update_access_app(self, account_id: str, app_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        return self.merge_access_resource(account_id, "apps", app_id, changes)

    def update_access_policy(self, account_id: str, policy_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        return self.merge_access_resource(account_id, "policies", policy_id, changes)

    def delete_access_app(self, account_id: str, app_id: str) -> None:
        try:
            self.request("DELETE", f"/accounts/{account_id}/access/apps/{app_id}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise

    def access_policies(self, account_id: str) -> list[dict[str, Any]]:
        return self.list_all(f"/accounts/{account_id}/access/policies")

    def create_access_policy(
        self,
        account_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        result = self.request(
            "POST",
            f"/accounts/{account_id}/access/policies",
            payload=payload,
        )
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare did not return the created Access policy")
        return result

    def delete_access_policy(self, account_id: str, policy_id: str) -> None:
        try:
            self.request("DELETE", f"/accounts/{account_id}/access/policies/{policy_id}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise

    def service_tokens(self, account_id: str) -> list[dict[str, Any]]:
        return self.list_all(f"/accounts/{account_id}/access/service_tokens")

    def create_service_token(self, account_id: str, name: str) -> dict[str, Any]:
        result = self.request("POST", f"/accounts/{account_id}/access/service_tokens",
                              payload={"name": name, "duration": "8760h"})
        if not isinstance(result, dict) or not all(result.get(key) for key in ("id", "client_id", "client_secret")):
            raise CloudflareAPIError("Created service token is missing credentials")
        return result

    def delete_service_token(self, account_id: str, identity: str) -> None:
        try:
            self.request("DELETE", f"/accounts/{account_id}/access/service_tokens/{identity}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise

    def worker_settings(self, account_id: str, name: str) -> dict[str, Any] | None:
        try:
            result = self.request("GET", f"/accounts/{account_id}/workers/scripts/{name}/settings")
        except CloudflareAPIError as exc:
            if exc.status_code == 404:
                return None
            raise
        if not isinstance(result, dict):
            raise CloudflareAPIError("Invalid Worker settings inventory")
        return result

    def delete_worker_secret(self, account_id: str, name: str, secret: str) -> None:
        try:
            self.request("DELETE", f"/accounts/{account_id}/workers/scripts/{name}/secrets/{secret}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise

    def upload_worker(self, account_id: str, name: str, metadata: dict,
                      modules: dict[str, tuple[str, bytes]]) -> dict:
        """Atomically deploy code, route module and all Secret bindings together."""
        boundary = "citadel-" + secrets.token_hex(24)
        parts = [("metadata", "application/json", json.dumps(metadata).encode())]
        parts += [(filename, kind, data) for filename, (kind, data) in modules.items()]
        body = bytearray()
        for filename, kind, data in parts:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", filename) or kind not in {
                "application/json", "application/javascript+module", "text/plain",
            }:
                raise ValueError("Invalid Worker multipart module")
            body.extend((f'--{boundary}\r\nContent-Disposition: form-data; name="{filename}"; '
                         f'filename="{filename}"\r\nContent-Type: {kind}\r\n\r\n').encode())
            body.extend(data)
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode())
        result = self.request("PUT", f"/accounts/{account_id}/workers/scripts/{name}", body=bytes(body),
                              content_type=f"multipart/form-data; boundary={boundary}")
        if not isinstance(result, dict):
            raise CloudflareAPIError("Worker deployment returned an invalid result")
        return result

    def worker_domains(self, account_id: str) -> list[dict[str, Any]]:
        return self.list_all(f"/accounts/{account_id}/workers/domains")

    def create_worker_domain(self, account_id: str, zone_id: str, name: str, hostname: str) -> dict:
        result = self.request("PUT", f"/accounts/{account_id}/workers/domains", payload={
            "hostname": hostname, "service": name, "environment": "production", "zone_id": zone_id})
        if not isinstance(result, dict) or not result.get("id"):
            raise CloudflareAPIError("Worker Custom Domain creation returned no identity")
        return result

    def delete_worker_domain(self, account_id: str, identity: str) -> None:
        try:
            self.request("DELETE", f"/accounts/{account_id}/workers/domains/{identity}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise

    def worker_subdomain(self, account_id: str, name: str) -> dict:
        result = self.request("GET", f"/accounts/{account_id}/workers/scripts/{name}/subdomain")
        if not isinstance(result, dict):
            raise CloudflareAPIError("Invalid Worker subdomain configuration")
        return result

    def disable_worker_subdomain(self, account_id: str, name: str) -> None:
        self.request("POST", f"/accounts/{account_id}/workers/scripts/{name}/subdomain",
                     payload={"enabled": False, "previews_enabled": False})
