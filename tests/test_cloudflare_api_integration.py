from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions"))
sys.path.insert(0, str(ROOT / "functions/providers"))
import core
import dispatch
import cloudflare
import cloudflare_policy
from cloudflare_api_routes import output, route_readiness
from cloudflare_api_policy import route_id
from test_cloudflare_api_lifecycle import FakeCloudflare
from health import snapshot


class APIIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, provider in (("cloudflare", "cloudflare"), ("CLOUDFLARE-API", "cloudflare_api_routes")):
            self.write(f"extensions/enabled/{name}/extension.json", {"provider": provider, "enabled": True})
        self.write("CITADEL_DATA/services.json", {"http_services": [{"port": 3070, "scheme": "https", "name": "Blender"}]})
        self.write("CITADEL_DATA/ports.filter.json", {})
        self.write("cache/3070.json", {"kind": "http-service", "scheme": "https"})
        self.write("CITADEL_DATA/providers_state.json", {"providers": {
            "cloudflare": {"status": "ok"}, "CLOUDFLARE-API": {"status": "ok"}}})
        (self.root / "CITADEL_DATA/last_scan.txt").write_text("2026-10-14T00:00:00Z")
        self.browser_payload = {"considered": True, "available": True,
            "services": {"3070": {"url": "https://3070.example.com"}}, "errors": []}
        hosts = {}
        for mode, hostname in (("api-bearer", "api-3070.example.com"), ("api-oauth", "oauth.api-3070.example.com")):
            hosts[hostname] = {"mode": mode, "port": 3070, "routes": [
                {"id": "mcp", "protocol": "mcp", "path": "/mcp"},
                {"id": "rest", "protocol": "rest", "path": "/api/v1"}]}
        self.api_payload = output({"hosts": hosts}, considered=True, authenticated=True, verify=lambda _: True)
        self.write("cache/cloudflare-routes.json", self.browser_payload)
        self.write("cache/CLOUDFLARE-API-routes.json", self.api_payload)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_either_provider_filter_runs_one_shared_reconciliation(self):
        for selected in ([], ["--provider", "cloudflare"], ["--provider", "CLOUDFLARE-API"]):
            calls = []

            def run(command, **_):
                calls.append(command)
                self.write("cache/cloudflare-routes.json", self.browser_payload)
                self.write("cache/CLOUDFLARE-API-routes.json", self.api_payload)
                return subprocess.CompletedProcess(command, 0, "", "")

            args = ["dispatch.py", "--enabled-dir", str(self.root / "extensions/enabled"),
                "--services-file", str(self.root / "CITADEL_DATA/services.json"), "--cache-dir", str(self.root / "cache"),
                "--config-ini", str(self.root / "config.ini"), "--state-file", str(self.root / "CITADEL_DATA/providers_state.json"),
                "--tailscale-file", str(self.root / "tailscale.json"), "--strict", *selected]
            with self.subTest(selected=selected), patch.object(sys, "argv", args), patch.object(dispatch.subprocess, "run", side_effect=run):
                self.assertEqual(dispatch.main(), 0)
                self.assertEqual(len(calls), 1)
                state = json.loads((self.root / "CITADEL_DATA/providers_state.json").read_text())
                self.assertEqual(set(state["available_providers"]), {"cloudflare", "CLOUDFLARE-API"})

    def dashboard(self):
        with patch.multiple(core, BASE_DIR=self.root, SERVICES_FILE=self.root / "CITADEL_DATA/services.json",
            LAST_SCAN_FILE=self.root / "CITADEL_DATA/last_scan.txt", ENABLED_EXT_DIR=self.root / "extensions/enabled",
            PROVIDERS_STATE_FILE=self.root / "CITADEL_DATA/providers_state.json", UI_CONFIG_FILE=self.root / "extensions/ui.json",
            PORT_FILTER_FILE=self.root / "CITADEL_DATA/ports.filter.json"):
            return core.build_dashboard()

    def test_one_extension_yields_two_modes_and_all_endpoint_links(self):
        dashboard = self.dashboard()
        self.assertEqual(set(dashboard["provider_options"]), {"cloudflare", "api-bearer", "api-oauth"})
        tile = dashboard["http_tiles"][0]
        for mode in ("api-bearer", "api-oauth"):
            self.assertEqual(len(tile["provider_endpoints"][mode]), 2)
        self.assertEqual(tile["provider_urls"]["cloudflare"], "https://3070.example.com")
        from jinja2 import Environment, FileSystemLoader
        page = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True).get_template("index.html").render(data=dashboard)
        self.assertIn('value="api-bearer"', page)
        self.assertIn('value="api-oauth"', page)
        self.assertIn("oauth.api-3070.example.com/mcp", page)
        self.assertIn("oauth.api-3070.example.com/api/v1", page)
        from dashboard_dom import simulate_dashboard
        modes = simulate_dashboard(page)
        for mode, host in (("api-bearer", "api-3070.example.com"), ("api-oauth", "oauth.api-3070.example.com")):
            tiles = modes[mode]["visible"]
            self.assertEqual([tile["port"] for tile in tiles], [3070])
            self.assertEqual(set(tiles[0]["links"]), {f"https://{host}/mcp", f"https://{host}/api/v1"})
            self.assertFalse(tiles[0]["grey"])
            self.assertEqual(len(tiles[0]["statusLines"]), 4)
            self.assertEqual(tiles[0]["statusLines"][-1], "REST, MCP")

    def test_health_keeps_both_modes_and_does_not_claim_authenticated_protocol_success(self):
        result = snapshot(self.root, ["CLOUDFLARE-API"])
        self.assertEqual(result["status"], "PASS")
        endpoints = result["extensions"][0]["services"]
        self.assertEqual(len(endpoints), 4)
        self.assertEqual({endpoint["provider"] for endpoint in endpoints}, {"api-bearer", "api-oauth"})
        self.assertTrue(all("NOT_TESTED" in endpoint["detail"] for endpoint in endpoints))

    def test_inactive_mode_hidden_and_disabled_extension_reports_pending_cleanup(self):
        self.api_payload["views"].pop("api-bearer")
        self.write("cache/CLOUDFLARE-API-routes.json", self.api_payload)
        self.assertNotIn("api-bearer", self.dashboard()["provider_options"])
        disabled = self.root / "extensions/disabled"
        disabled.mkdir()
        (self.root / "extensions/enabled/CLOUDFLARE-API").rename(disabled / "CLOUDFLARE-API")
        self.write("cache/CLOUDFLARE-API-routes.json", {"cleanup_pending": True})
        dashboard = self.dashboard()
        self.assertNotIn("api-oauth", dashboard["provider_options"])
        self.assertTrue(any("cleanup is pending" in alert for alert in dashboard["alerts"]))

    def test_configured_modes_remain_visible_without_published_routes(self):
        for modes in ((), ("api-bearer",), ("api-oauth",), ("api-bearer", "api-oauth")):
            for errors in ((), ("Cloudflare API HTTP 403 during POST",)):
                with self.subTest(modes=modes, errors=errors):
                    payload = output({"hosts": {}}, considered=bool(modes), authenticated=False,
                                     modes=modes, errors=errors)
                    self.write("cache/CLOUDFLARE-API-routes.json", payload)
                    dashboard = self.dashboard()
                    self.assertEqual(set(dashboard["provider_options"]), {"cloudflare", *modes})
                    self.assertFalse(payload["available"])
                    self.assertEqual(payload["services"], {})
                    for view in payload["views"].values():
                        self.assertFalse(view["available"])
                        self.assertEqual(view["services"], {})
                    urls = dashboard["http_tiles"][0]["provider_urls"]
                    self.assertEqual({mode: url for mode, url in urls.items() if url},
                                     {"cloudflare": "https://3070.example.com"})
                    self.assertTrue(all(not urls.get(mode) for mode in modes))
                    from jinja2 import Environment, FileSystemLoader
                    page = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True).get_template("index.html").render(data=dashboard)
                    for mode in ("api-bearer", "api-oauth"):
                        self.assertEqual(f'value="{mode}"' in page, mode in modes)
                    if modes:
                        self.assertTrue(any("No API routes" in alert for alert in dashboard["alerts"]))
                    if errors:
                        self.assertTrue(any("HTTP 403" in alert for alert in dashboard["alerts"]))

    def test_api_modes_only_show_detected_services_even_when_publication_fails(self):
        self.write("CITADEL_DATA/services.json", {
            "http_services": [{"port": port, "scheme": "https", "name": f"Service {port}"}
                              for port in range(3070, 3075)],
            "other_ports": [{"port": 5432}],
        })
        inventory = [
            {"id": "mcp", "port": 3070, "protocol": "mcp", "path": "/mcp", "status": "ready"},
            {"id": "rest", "port": 3072, "protocol": "rest", "path": "/api", "status": "authentication-required",
             "operations": [{"path": "/api/items", "method": "GET"}]},
            {"id": "guess", "port": 3073, "protocol": "mcp", "path": "/mcp", "status": "authentication-required"},
            {"id": "graphql", "port": 3074, "protocol": "graphql", "path": "/graphql", "status": "ready"},
        ]
        self.write("cache/CLOUDFLARE-API-routes.json", output({"hosts": {}}, considered=True,
            authenticated=False, modes=("api-bearer", "api-oauth"), inventory=inventory, errors=["Cloudflare unavailable"]))
        dashboard = self.dashboard()
        dashboard["default_mode"] = "api-oauth"
        from jinja2 import Environment, FileSystemLoader
        from dashboard_dom import simulate_dashboard
        page = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True).get_template("index.html").render(data=dashboard)
        modes = simulate_dashboard(page)
        for mode in ("api-bearer", "api-oauth"):
            self.assertEqual([tile["port"] for tile in modes[mode]["visible"]], [3070, 3072, 3074])
            self.assertTrue(modes[mode]["otherHidden"])
            self.assertFalse(modes[mode]["empty"])
            self.assertTrue(all(not tile["grey"] for tile in modes[mode]["visible"]))
            self.assertEqual(modes[mode]["visible"][0]["cardHref"], "https://3070.example.com/mcp")
            self.assertEqual(modes[mode]["visible"][0]["statusLines"][:3],
                             ["🔴 Access", "🟢 Reachable", "🔴 Authentication prompt"])
            self.assertTrue(all(not tile["links"] for tile in modes[mode]["visible"][1:]))
            self.assertEqual(modes[mode]["visible"][1]["statusLines"],
                             ["🔴 Access", "🔴 Reachable", "🔴 Authentication prompt", "REST"])
        self.assertEqual(len(modes["cloudflare"]["visible"]), 5)
        self.assertFalse(modes["cloudflare"]["otherHidden"])

        # A subsequent successful discovery with no APIs removes every API tile.
        self.write("cache/CLOUDFLARE-API-routes.json", output({"hosts": {}}, considered=True,
            authenticated=True, modes=("api-oauth",), inventory=[]))
        page = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True).get_template("index.html").render(data=self.dashboard())
        modes = simulate_dashboard(page)
        self.assertEqual(modes["api-oauth"]["visible"], [])
        self.assertTrue(modes["api-oauth"]["empty"])

    def test_shared_entrypoint_applies_all_modes_then_reports_unverified_cleanup(self):
        self.write("CLOUDFLARE-API_ignore.json", {"ports": []})
        self.write("CLOUDFLARE_OAUTH_Whitelist.json", {"allow_loopback": True})
        code = self.root / "workers/cloudflare-api/worker.mjs"
        code.parent.mkdir(parents=True)
        code.write_bytes((ROOT / "workers/cloudflare-api/worker.mjs").read_bytes())
        remote = FakeCloudflare()
        remote.verify_token = lambda: None
        remote.tunnel_connections = lambda *_: [{}]
        remote.zone = lambda *_: {"name": "example.com"}
        values = {"CLOUDFLARE_API_TOKEN": "management", "CITADEL_CLOUDFLARE_ACCOUNT_ID": "account",
            "CITADEL_CLOUDFLARE_ZONE_ID": "zone", "CITADEL_CLOUDFLARE_TUNNEL_ID": "tunnel",
            "CITADEL_CLOUDFLARE_DOMAIN": "example.com", "CLOUDFLARE_EMAIL": "owner@example.com",
            "CITADEL_CLOUDFLARE_API_OAUTH": "1"}
        endpoint = {"id": route_id(3070, "mcp", "/mcp"), "port": 3070, "scheme": "https", "path": "/mcp",
            "protocol": "mcp", "status": "ready", "operations": [{"path": "/mcp", "method": "POST"}]}
        self.write("CLOUDFLARE-API_access.json", {"routes": {endpoint["id"]: "client;backend,owner@example.com;backend"}})
        (self.root / "CLOUDFLARE-API_access.json").chmod(0o600)
        args = ["cloudflare.py", "--provider-dir", str(self.root / "extensions/enabled/cloudflare"),
                "--routes-out", str(self.root / "cache/cloudflare-routes.json"),
                "--services-file", str(self.root / "CITADEL_DATA/services.json")]
        with patch.object(sys, "argv", args), patch.object(cloudflare, "load_project_getter", return_value=values.get), \
                patch.object(cloudflare, "CloudflareAPI", return_value=remote), \
                patch.object(cloudflare_policy, "read_policy", wraps=cloudflare_policy.read_policy) as policy_read, \
                patch.object(cloudflare, "discover_api", return_value=[endpoint]), \
                patch.object(cloudflare, "api_output", side_effect=lambda *a, **kw: output(*a, **kw, verify=lambda _: True)):
            self.assertEqual(cloudflare.main(), 0)
            policy_read.assert_called_once()  # Rules and defaults use the same local snapshot.
            self.assertEqual(len(remote.domains), 2)
            self.assertEqual(len(remote.apps), 3)  # Browser OTP, OAuth, machine origin.
            remote.events.clear()
            self.assertEqual(cloudflare.main(), 0)
            self.assertEqual(remote.events, [])
            identities = {app["domain"]: (app["id"], app["aud"]) for app in remote.apps}
            uris = ["https://client.example/callback", "https://client.example/oauth/*"]
            self.write("CLOUDFLARE_OAUTH_Whitelist.json", {"allowed_redirect_uris": uris})
            self.assertEqual(cloudflare.main(), 0)
            self.assertEqual({app["domain"]: (app["id"], app["aud"]) for app in remote.apps}, identities)
            oauth_apps = [app for app in remote.apps if app.get("oauth_configuration", {}).get("enabled")]
            self.assertEqual(len(oauth_apps), 1)
            dcr = oauth_apps[0]["oauth_configuration"]["dynamic_client_registration"]
            self.assertEqual(dcr["allowed_uris"], uris)
            self.assertFalse(dcr["allow_any_on_loopback"])
            remote.events.clear()
            self.assertEqual(cloudflare.main(), 0)
            self.assertEqual(remote.events, [])
            values["CLOUDFLARE_API_TOKEN"] = ""
            values["CITADEL_CLOUDFLARE_API_OAUTH"] = "0"
            cloudflare.main()
            self.assertEqual(remote.events, [])
            payload = json.loads((self.root / "cache/CLOUDFLARE-API-routes.json").read_text())
            self.assertTrue(payload["cleanup_pending"])
            self.assertFalse(payload["remote_verified"])
            self.assertEqual(payload["views"], {})

            # A failed management operation must preserve configured menu modes,
            # while exposing neither stale routes nor a successful connection.
            from cloudflare_api import CloudflareAPIError
            values["CLOUDFLARE_API_TOKEN"] = "management"
            values["CITADEL_CLOUDFLARE_API_OAUTH"] = "1"
            with patch.object(cloudflare, "APIReconciler", side_effect=CloudflareAPIError("HTTP 403")):
                self.assertEqual(cloudflare.main(), 1)
            payload = json.loads((self.root / "cache/CLOUDFLARE-API-routes.json").read_text())
            self.assertEqual(set(payload["views"]), {"api-bearer", "api-oauth"})
            self.assertFalse(payload["available"])
            self.assertEqual(payload["services"], {})

            # A network failure during token verification also keeps the modes
            # visible without claiming authentication or publishing any links.
            with patch.object(remote, "verify_token", side_effect=OSError("The read operation timed out")):
                self.assertEqual(cloudflare.main(), 1)
            payload = json.loads((self.root / "cache/CLOUDFLARE-API-routes.json").read_text())
            self.assertEqual(set(payload["views"]), {"api-bearer", "api-oauth"})
            self.assertFalse(payload["authenticated"])
            self.assertFalse(payload["available"])
            self.assertEqual(payload["services"], {})
            self.assertEqual([row["id"] for row in payload["discovered"]], [endpoint["id"]])
            self.assertEqual(self.dashboard()["http_tiles"][0]["provider_endpoints"]["api-oauth"][0]["status"], "not-published")

            # A missing management token still skips publication and both modes,
            # even when client bearer/OAuth are configured.
            values["CLOUDFLARE_API_TOKEN"] = ""
            cloudflare.main()
            payload = json.loads((self.root / "cache/CLOUDFLARE-API-routes.json").read_text())
            self.assertFalse(payload["considered"])
            self.assertEqual(payload["views"], {})

    def test_disabled_directories_still_run_cleanup_coordinator(self):
        self.write("CITADEL_DATA/cloudflare-api/runtime.json", {"owner": "fixture"})
        disabled = self.root / "extensions/disabled"
        disabled.mkdir()
        for name in ("cloudflare", "CLOUDFLARE-API"):
            (self.root / "extensions/enabled" / name).rename(disabled / name)
        args = ["dispatch.py", "--enabled-dir", str(self.root / "extensions/enabled"),
            "--services-file", str(self.root / "CITADEL_DATA/services.json"), "--cache-dir", str(self.root / "cache"),
            "--config-ini", str(self.root / "config.ini"), "--state-file", str(self.root / "CITADEL_DATA/providers_state.json"),
            "--tailscale-file", str(self.root / "tailscale.json")]
        with patch.object(sys, "argv", args), patch.object(dispatch.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.assertEqual(dispatch.main(), 0)
        run.assert_called_once()
        state = json.loads((self.root / "CITADEL_DATA/providers_state.json").read_text())
        self.assertEqual(state["enabled_providers"], [])

    def test_readiness_rejects_browser_redirect_or_html_login(self):
        from unittest.mock import Mock
        for status, headers, expected in (
            (302, {"Location": "https://team.cloudflareaccess.com/login"}, "pending-auth"),
            (200, {"Content-Type": "text/html"}, "pending-auth"),
            (401, {"Content-Type": "application/json"}, "pending-auth"),
            (401, {"Content-Type": "application/json", "WWW-Authenticate": 'Bearer realm="citadel-api"'}, "provisioned"),
        ):
            connection = Mock()
            connection.getresponse.return_value = Mock(status=status, getheader=lambda name, default="": headers.get(name, default))
            with patch("cloudflare_api_routes.http.client.HTTPSConnection", return_value=connection):
                self.assertEqual(route_readiness("api-3070.example.com"), expected)
            connection.close.assert_called_once()

    def test_readiness_distinguishes_dns_tls_and_connection_failures(self):
        import socket
        import ssl
        from unittest.mock import Mock
        for error, expected in ((socket.gaierror("lookup failed"), "pending-dns"),
                                (ssl.SSLError("TLS failed"), "pending-tls"),
                                (ConnectionRefusedError(), "unreachable")):
            connection = Mock()
            connection.request.side_effect = error
            with patch("cloudflare_api_routes.http.client.HTTPSConnection", return_value=connection):
                self.assertEqual(route_readiness("oauth.api-3070.example.com"), expected)

    def test_pending_route_keeps_full_url_below_separate_statuses(self):
        from jinja2 import Environment, FileSystemLoader
        from dashboard_dom import simulate_dashboard
        for state in ("pending-dns", "pending-tls", "pending-auth", "provisioned"):
            for view in self.api_payload['views'].values():
                for route in view['services'].values():
                    for endpoint in route['endpoints']:
                        endpoint['status'] = state
            self.write('cache/CLOUDFLARE-API-routes.json', self.api_payload)
            page = Environment(loader=FileSystemLoader(ROOT / 'templates'), autoescape=True).get_template('index.html').render(data=self.dashboard())
            tile = simulate_dashboard(page)['api-oauth']['visible'][0]
            self.assertEqual(tile['links'], tile['linkLabels'])
            detail = tile['details'][0]
            self.assertEqual(tile['statusLines'], [
                '🟢 Access',
                '🟢 Reachable',
                ('🟢' if state == 'provisioned' else '🔴') + ' Authentication prompt',
                'REST, MCP',
            ])
            self.assertLess(detail.index('Authentication prompt'), detail.index('https://'))
            self.assertNotIn('Copy URL', detail)
            self.assertEqual(tile['cardHref'], tile['url'])
            self.assertNotIn('Login successful', detail)

    def test_mixed_interfaces_keep_full_links_and_prefer_mcp(self):
        from jinja2 import Environment, FileSystemLoader
        from dashboard_dom import simulate_dashboard
        self.write("cache/3070.json", {"kind": "html", "scheme": "https"})
        self.api_payload["discovered"] = [{"id": "rest", "port": 3070,
            "protocol": "rest", "path": "/api/v1", "status": "authentication-required"}]
        for view in self.api_payload["views"].values():
            view["services"]["3070"]["endpoints"] = [
                endpoint for endpoint in view["services"]["3070"]["endpoints"] if endpoint["protocol"] == "mcp"]
        self.write("cache/CLOUDFLARE-API-routes.json", self.api_payload)
        page = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True).get_template("index.html").render(data=self.dashboard())
        tile = simulate_dashboard(page)["api-oauth"]["visible"][0]
        self.assertEqual(tile["statusLines"], ["🟢 Access", "🟢 Reachable", "🟢 Authentication prompt", "HTTP, REST, MCP"])
        self.assertEqual(tile["links"], ["https://oauth.api-3070.example.com/mcp",
            "https://3070.example.com/api/v1", "https://3070.example.com"])
        self.assertEqual(tile["cardHref"], tile["links"][0])
        self.assertEqual(tile["links"], tile["linkLabels"])

    def test_discovery_landing_page_has_no_http_type_or_browser_link(self):
        from jinja2 import Environment, FileSystemLoader
        from dashboard_dom import simulate_dashboard
        self.write("cache/3070.json", {"kind": "html", "scheme": "https", "browser_page": False})
        page = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=True).get_template("index.html").render(data=self.dashboard())
        tile = simulate_dashboard(page)["api-oauth"]["visible"][0]
        self.assertEqual(tile["statusLines"][-1], "REST, MCP")
        self.assertEqual(tile["statusLines"][1], "🟢 Reachable")
        self.assertNotIn("https://3070.example.com", tile["links"])
        self.assertEqual(tile["cardHref"], "https://oauth.api-3070.example.com/mcp")

    def test_filtered_scan_replaces_stale_errors_and_preserves_other_providers(self):
        self.write('CITADEL_DATA/providers_state.json', {
            'providers': {'cloudflare': {'status': 'error'}, 'CLOUDFLARE-API': {'status': 'error'},
                          'tailscale': {'status': 'error'}},
            'enabled_providers': ['cloudflare', 'CLOUDFLARE-API', 'tailscale'],
            'errors': ['Provider cloudflare failed', 'Provider CLOUDFLARE-API: old error', 'Provider tailscale failed']})
        args = ['dispatch.py', '--enabled-dir', str(self.root / 'extensions/enabled'),
                '--services-file', str(self.root / 'CITADEL_DATA/services.json'), '--cache-dir', str(self.root / 'cache'),
                '--config-ini', str(self.root / 'config.ini'), '--state-file', str(self.root / 'CITADEL_DATA/providers_state.json'),
                '--tailscale-file', str(self.root / 'tailscale.json'), '--provider', 'CLOUDFLARE-API']
        with patch.object(sys, 'argv', args), patch.object(dispatch.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            self.assertEqual(dispatch.main(), 0)
        state = json.loads((self.root / 'CITADEL_DATA/providers_state.json').read_text())
        self.assertEqual(state['errors'], ['Provider tailscale failed'])
        self.assertEqual(state['providers']['cloudflare']['status'], 'ok')
        self.assertEqual(state['providers']['tailscale']['status'], 'error')


if __name__ == "__main__":
    unittest.main()
