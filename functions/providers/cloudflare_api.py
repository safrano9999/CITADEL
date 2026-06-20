from __future__ import annotations

import json
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
    ) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise CloudflareAPIError(
                f"Cloudflare API HTTP {exc.code}: {detail[:500]}",
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
            errors = envelope.get("errors") if isinstance(envelope, dict) else None
            raise CloudflareAPIError(f"Cloudflare API rejected request: {errors or 'unknown error'}")
        return envelope.get("result")

    def verify_token(self) -> None:
        self.request("GET", "/user/tokens/verify")

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
            return {}
        config = result.get("config")
        return config if isinstance(config, dict) else {}

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

    def ensure_tunnel_dns(
        self,
        zone_id: str,
        hostname: str,
        tunnel_id: str,
        managed_record_id: str = "",
    ) -> str:
        name = hostname.rstrip(".").lower()
        content = f"{tunnel_id}.cfargotunnel.com"
        records = self.request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            query={"name": name, "per_page": 100},
        )
        records = records if isinstance(records, list) else []
        matching = next((item for item in records if isinstance(item, dict)), None)
        payload = {
            "type": "CNAME",
            "name": name,
            "content": content,
            "proxied": True,
            "ttl": 1,
        }
        if matching:
            record_id = str(matching.get("id") or "")
            if matching.get("type") != "CNAME":
                raise CloudflareAPIError(f"DNS record {name} exists and is not a CNAME")
            if not record_id:
                raise CloudflareAPIError(f"DNS record {name} has no id")
            if record_id != managed_record_id:
                raise CloudflareAPIError(
                    f"DNS record {name} already exists and is not managed by CITADEL"
                )
            self.request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", payload=payload)
            return record_id
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
        result = self.request(
            "GET",
            f"/accounts/{account_id}/access/apps",
            query={"per_page": 100},
        )
        return result if isinstance(result, list) else []

    def create_access_app(self, account_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.request("POST", f"/accounts/{account_id}/access/apps", payload=payload)
        if not isinstance(result, dict):
            raise CloudflareAPIError("Cloudflare did not return the created Access application")
        return result

    def update_access_app(self, account_id: str, app_id: str, payload: dict[str, Any]) -> None:
        self.request("PUT", f"/accounts/{account_id}/access/apps/{app_id}", payload=payload)

    def delete_access_app(self, account_id: str, app_id: str) -> None:
        try:
            self.request("DELETE", f"/accounts/{account_id}/access/apps/{app_id}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise

    def access_policies(self, account_id: str) -> list[dict[str, Any]]:
        result = self.request(
            "GET",
            f"/accounts/{account_id}/access/policies",
            query={"per_page": 100},
        )
        return result if isinstance(result, list) else []

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

    def update_access_policy(
        self,
        account_id: str,
        policy_id: str,
        payload: dict[str, Any],
    ) -> None:
        self.request(
            "PUT",
            f"/accounts/{account_id}/access/policies/{policy_id}",
            payload=payload,
        )

    def delete_access_policy(self, account_id: str, policy_id: str) -> None:
        try:
            self.request("DELETE", f"/accounts/{account_id}/access/policies/{policy_id}")
        except CloudflareAPIError as exc:
            if exc.status_code != 404:
                raise
