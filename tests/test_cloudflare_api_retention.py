from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'functions'), str(ROOT / 'functions/providers')]
from cloudflare_api_access import parse_entries
from cloudflare_api_policy import APISettings, owner_id, route_id
from cloudflare_api_routes import discover, output, retained_mcp_routes
from cloudflare_plan import api_routes


class RetainedMCPTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = APISettings(enabled=True, oauth=True)
        self.identity = route_id(3070, 'mcp', '/mcp')
        self.route = {'id': self.identity, 'protocol': 'mcp', 'path': '/mcp',
                      'operations': [{'method': method, 'path': '/mcp'} for method in ('GET', 'POST', 'DELETE')]}
        self.table = {'schema': 1, 'hosts': {}}
        for mode, hostname in (('api-bearer', 'api-3070.example.com'), ('api-oauth', 'oauth.api-3070.example.com')):
            self.table['hosts'][hostname] = {'port': 3070, 'mode': mode,
                'origin': 'https://origin.api-3070.example.com', 'routes': [deepcopy(self.route),
                    {'id': route_id(3070, 'rest', '/api'), 'protocol': 'rest', 'path': '/api',
                     'operations': [{'method': 'GET', 'path': '/api'}]}]}
        self.remote = {'tags': ['citadel-owner:' + owner_id('account', 'zone', 'tunnel')],
            'bindings': [{'name': 'ROUTE_TABLE', 'type': 'plain_text', 'text': json.dumps(self.table)}]}
        self.api = Mock()
        self.api.worker_settings.return_value = self.remote
        self.api.tunnel_configuration.return_value = {'ingress': [{
            'hostname': 'origin.api-3070.example.com', 'service': 'https://127.0.0.1:3070'}]}

    def retain(self, settings=None):
        return retained_mcp_routes(self.api, self.root, 'account', 'zone', 'tunnel', settings or self.settings)

    def test_deployed_mcp_survives_absent_listener_but_rest_does_not(self):
        kept, _ = self.retain()
        self.assertEqual(len(kept), 1)
        self.assertTrue(kept[0]['retained'])
        endpoints = discover({'http_services': []}, self.settings, {}, 11000, retained=kept)
        access = {self.identity: parse_entries('client;backend,owner@example.com;backend')}
        plan = api_routes(endpoints, self.settings, 'example.com', access)
        self.assertEqual(len(plan['hosts']), 2)
        self.assertTrue(all([route['protocol'] for route in host['routes']] == ['mcp'] for host in plan['hosts'].values()))

    def test_zero_does_not_read_remote_routes_and_empty_scan_removes_them(self):
        self.assertEqual(self.retain(replace(self.settings, keep_mcp_routes=False)), ([], {}))
        self.api.worker_settings.assert_not_called()
        endpoints = discover({'http_services': []}, self.settings, {}, 11000)
        self.assertEqual(api_routes(endpoints, self.settings, 'example.com')['hosts'], {})

    def test_excluded_ports_and_disabled_modes_are_not_retained(self):
        self.assertEqual(self.retain(replace(self.settings, excluded=frozenset({3070})))[0], [])
        self.assertEqual(self.retain(replace(self.settings, enabled=False)), ([], {}))

    def test_foreign_worker_and_missing_origin_are_rejected(self):
        self.remote['tags'] = []
        with self.assertRaisesRegex(ValueError, 'foreign'):
            self.retain()
        self.remote['tags'] = ['citadel-owner:' + owner_id('account', 'zone', 'tunnel')]
        self.api.tunnel_configuration.return_value = {'ingress': []}
        with self.assertRaisesRegex(ValueError, 'origin'):
            self.retain()

    def test_retained_mcp_host_skips_public_probe_but_mixed_host_does_not(self):
        kept, _ = self.retain()
        table = deepcopy(self.table)
        for host in table['hosts'].values():
            host['routes'] = [deepcopy(self.route)]
        statuses = {hostname: 'provisioned' for hostname in table['hosts']}
        verify = Mock(return_value='pending-auth')
        result = output(table, considered=True, authenticated=True, inventory=kept,
                        retained_statuses=statuses, verify=verify)
        verify.assert_not_called()
        self.assertEqual(len(result['services']['3070']['endpoints']), 2)
        self.assertTrue(all(endpoint['status'] == 'provisioned' and endpoint['retained']
                            for endpoint in result['services']['3070']['endpoints']))
        output(self.table, considered=True, authenticated=True, inventory=kept,
               retained_statuses=statuses, verify=verify)
        self.assertEqual(verify.call_count, 2)

    def test_saved_display_status_is_reused_without_requiring_a_local_cache(self):
        _, statuses = self.retain()
        self.assertTrue(all(status == 'not-checked' for status in statuses.values()))
        (self.root / 'cache').mkdir()
        previous = output(self.table, considered=True, authenticated=True, verify=lambda _: 'pending-tls')
        (self.root / 'cache/CLOUDFLARE-API-routes.json').write_text(json.dumps(previous))
        _, statuses = self.retain()
        self.assertTrue(all(status == 'pending-tls' for status in statuses.values()))
