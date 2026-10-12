from copy import deepcopy
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'functions'))
sys.path.insert(0, str(ROOT / 'functions/providers'))
from cloudflare_api import CloudflareAPIError
from cloudflare_redirect import PHASE, prepare_redirect, apply_redirect


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock()
        self.api.request.return_value = None
        self.desired = {'example.com': {'port': 443}, 'www.example.com': {'port': 443}}

    def plan(self, setting='1', **kwargs):
        return prepare_redirect(self.api, 'zone', 'tunnel', 'example.com',
                                self.desired, setting, **kwargs)

    def ruleset(self, rules):
        return {'id': 'set', 'phase': PHASE, 'kind': 'zone', 'rules': rules}

    def test_new_redirect_preserves_path_query_and_uses_permanent_status(self):
        plan = self.plan()
        rule = plan['rule']
        self.assertEqual(rule['expression'], '(http.host eq "example.com")')
        self.assertEqual(rule['action_parameters']['from_value'], {
            'target_url': {'expression': 'concat("https://www.example.com", http.request.uri.path)'},
            'status_code': 301, 'preserve_query_string': True})
        self.api.request.reset_mock()
        apply_redirect(self.api, 'zone', plan)
        self.api.request.assert_called_once_with('POST', '/zones/zone/rulesets', payload={
            'name': 'Redirect rules', 'kind': 'zone', 'phase': PHASE, 'rules': [rule]})

    def test_append_and_update_only_own_rule(self):
        foreign = {'id': 'foreign', 'ref': 'operator_rule'}
        self.api.request.return_value = self.ruleset([foreign])
        plan = self.plan()
        apply_redirect(self.api, 'zone', plan)
        self.assertEqual(self.api.request.call_args.args, ('POST', '/zones/zone/rulesets/set/rules'))
        self.assertEqual(foreign, {'id': 'foreign', 'ref': 'operator_rule'})
        own = {**deepcopy(plan['rule']), 'id': 'own', 'enabled': False}
        self.api.request.return_value = self.ruleset([foreign, own])
        plan = self.plan()
        self.assertEqual(plan['action'], 'update')
        self.api.request.reset_mock()
        apply_redirect(self.api, 'zone', plan)
        self.assertEqual(self.api.request.call_args.args, ('PATCH', '/zones/zone/rulesets/set/rules/own'))

    def test_unchanged_is_read_only_and_zero_removes_only_owned_rule(self):
        own = {**self.plan()['rule'], 'id': 'own', 'version': '2'}
        self.api.request.return_value = self.ruleset([{'id': 'foreign'}, own])
        plan = self.plan()
        self.assertEqual(plan['action'], 'unchanged')
        self.api.request.reset_mock()
        apply_redirect(self.api, 'zone', plan)
        self.api.request.assert_not_called()
        plan = self.plan('0')
        self.api.request.reset_mock()
        apply_redirect(self.api, 'zone', plan)
        self.api.request.assert_called_once_with('DELETE', '/zones/zone/rulesets/set/rules/own')

    def test_missing_port_removes_rule_but_add_never_does(self):
        own = {**self.plan()['rule'], 'id': 'own'}
        self.api.request.return_value = self.ruleset([own])
        self.desired = {}
        self.assertEqual(self.plan()['action'], 'delete')
        with self.assertRaisesRegex(CloudflareAPIError, 'Add will not modify'):
            self.plan(add=True)

    def test_required_hostnames_and_invalid_boolean_fail_before_api(self):
        self.desired.pop('www.example.com')
        with self.assertRaisesRegex(ValueError, 'requires WWW443'):
            self.plan()
        with self.assertRaisesRegex(ValueError, 'boolean'):
            self.plan('perhaps')
        self.api.request.assert_not_called()

    def test_permissions_and_legacy_default(self):
        self.assertEqual(self.plan('')['action'], 'unmanaged')
        self.api.request.assert_not_called()
        self.api.request.side_effect = CloudflareAPIError('forbidden', 403)
        with self.assertRaisesRegex(CloudflareAPIError, 'Dynamic URL Redirects'):
            self.plan()
        plan = self.plan('0')
        self.assertEqual(plan['action'], 'unverified_disabled')
        self.assertIn('cannot be verified', plan['warning'])
        self.api.request.side_effect = CloudflareAPIError('not found', 404)
        self.assertEqual(self.plan()['action'], 'create')

    def test_missing_permission_never_treated_as_missing_ruleset(self):
        self.api.request.side_effect = CloudflareAPIError('outage', 503)
        with self.assertRaises(CloudflareAPIError):
            self.plan()
        self.api.request.assert_called_once()


if __name__ == '__main__':
    unittest.main()
