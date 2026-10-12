"""Reconcile Citadel's optional port-443 canonical-host redirect at Cloudflare."""
from __future__ import annotations

import hashlib
from typing import Any

from cloudflare_api import CloudflareAPI, CloudflareAPIError


SETTING = "CITADEL_CLOUDFLARE_REDIRECT_TO_WWW"
PHASE = "http_request_dynamic_redirect"


def prepare_redirect(api: CloudflareAPI, zone_id: str, tunnel_id: str, domain: str,
                     desired: dict, setting: str, *, add: bool = False) -> dict:
    """Read/validate before other provider writes; never change remote state here."""
    from cloudflare_policy import normalize_hostname
    raw = setting.strip().lower()
    if raw in ("", "blank"):
        return {"action": "unmanaged"}  # Existing installations need no new permission.
    if raw not in ("0", "1", "false", "true", "off", "on", "no", "yes"):
        raise ValueError(f"{SETTING} must be a boolean")
    enabled = raw in ("1", "true", "on", "yes")
    domain = normalize_hostname(domain)
    target = normalize_hostname(f"www.{domain}")
    has_443 = any(route.get("port") == 443 for route in desired.values())
    if enabled and has_443 and any(desired.get(host, {}).get("port") != 443
                                  for host in (domain, target)):
        raise ValueError(f"{SETTING}=1 requires WWW443=1 and DOMAIN443=1 for port 443")
    ref = "citadel_www443_" + hashlib.sha256(tunnel_id.encode()).hexdigest()[:24]
    wanted: dict[str, Any] | None = None
    if enabled and has_443:
        wanted = {
            "ref": ref,
            "description": f"CITADEL port 443: {domain} to www",
            "expression": f'(http.host eq "{domain}")',
            "action": "redirect",
            "action_parameters": {"from_value": {
                "target_url": {"expression": f'concat("https://{target}", http.request.uri.path)'},
                "status_code": 301,
                "preserve_query_string": True,
            }},
            "enabled": True,
        }
    try:
        ruleset = api.request("GET", f"/zones/{zone_id}/rulesets/phases/{PHASE}/entrypoint")
    except CloudflareAPIError as exc:
        if exc.status_code == 404:
            ruleset = None
        elif exc.status_code == 403 and not enabled:
            # Default-off must not break deployments whose token lacks this scope.
            return {"action": "unverified_disabled", "warning":
                    "Redirect disabled in config, but Cloudflare denied reading rules; "
                    "removal of a previously created redirect cannot be verified. "
                    "Grant Zone > Dynamic URL Redirects > Edit."}
        elif exc.status_code == 403:
            raise CloudflareAPIError(
                f"{SETTING} requires Zone > Dynamic URL Redirects > Edit (HTTP 403)", 403
            ) from exc
        else:
            raise
    rules = []
    if ruleset is not None:
        if (not isinstance(ruleset, dict) or not ruleset.get("id")
                or ruleset.get("phase") != PHASE or ruleset.get("kind") != "zone"
                or not isinstance(ruleset.get("rules", []), list)):
            raise CloudflareAPIError("Invalid Cloudflare redirect ruleset; no changes applied")
        rules = ruleset.get("rules", [])
    if any(not isinstance(rule, dict) for rule in rules):
        raise CloudflareAPIError("Invalid Cloudflare redirect rule")
    owned = [rule for rule in rules if rule.get("ref") == ref]
    if len(owned) > 1 or any(not rule.get("id") for rule in owned):
        raise CloudflareAPIError("Duplicate or unidentified Citadel redirect rule")
    current = owned[0] if owned else None
    if current and wanted and all(current.get(key) == value for key, value in wanted.items()):
        action = "unchanged"
    elif current:
        action = "update" if wanted else "delete"
    else:
        action = "create" if wanted else "disabled"
    if add and action in ("update", "delete"):
        raise CloudflareAPIError("Existing redirect differs; Add will not modify it")
    return {"action": action, "ruleset_id": ruleset["id"] if ruleset else None,
            "rule_id": current["id"] if current else None, "rule": wanted}


def apply_redirect(api: CloudflareAPI, zone_id: str, plan: dict) -> None:
    """Touch only this tunnel's marked rule; preserve all unrelated rules."""
    action = plan["action"]
    if action not in ("create", "update", "delete"):
        return
    base = f"/zones/{zone_id}/rulesets"
    ruleset_id = plan["ruleset_id"]
    if action == "create":
        if ruleset_id:
            api.request("POST", f"{base}/{ruleset_id}/rules",
                        payload={**plan["rule"], "position": {"index": 1}})
        else:
            api.request("POST", base, payload={"name": "Redirect rules",
                        "kind": "zone", "phase": PHASE, "rules": [plan["rule"]]})
    elif action == "update":
        api.request("PATCH", f"{base}/{ruleset_id}/rules/{plan['rule_id']}",
                    payload=plan["rule"])
    else:
        api.request("DELETE", f"{base}/{ruleset_id}/rules/{plan['rule_id']}")
