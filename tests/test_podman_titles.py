import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'functions'))
from podman_titles import published_titles


class PodmanTitleTests(unittest.TestCase):
    def lookup(self, upstreams, *, broken_snapshot=False):
        config = {'apps': {'http': {'servers': {'backend': {
            'listen': [':8443'],
            'routes': [{'match': [{'host': ['127.0.0.1']}], 'handle': [{
                'handler': 'subroute', 'routes': [{'handle': [{
                    'handler': 'reverse_proxy', 'upstreams': [{'dial': dial} for dial in upstreams]
                }]}]
            }]}],
        }}}}}

        def podman(uid, command, *args):
            if command == 'ps':
                return 'aa\tcaddy\t""\nbb\taudio\t"Speech service"\n'
            if command == 'port':
                return 'aa 8443/tcp -> 0.0.0.0:2008\nbb 8000/tcp -> 0.0.0.0:9010\n'
            if broken_snapshot:
                raise subprocess.CalledProcessError(1, 'cat')
            return json.dumps(config)

        with patch('podman_titles.podman', side_effect=podman):
            return published_titles(1000, {2008, 9010})

    def test_caddy_and_direct_published_port(self):
        self.assertEqual(self.lookup(['audio:8000']), {2008: 'Speech service', 9010: 'Speech service'})

    def test_multiple_distinct_upstreams_leave_proxy_title_alone(self):
        self.assertEqual(self.lookup(['audio:8000', 'other:8000']), {9010: 'Speech service'})

    def test_unavailable_snapshot_preserves_direct_title(self):
        self.assertEqual(self.lookup([], broken_snapshot=True), {9010: 'Speech service'})
