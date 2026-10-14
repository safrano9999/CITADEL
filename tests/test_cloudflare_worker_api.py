from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions/providers"))
from cloudflare_api import CloudflareAPI, CloudflareAPIError


class WorkerTransportTests(unittest.TestCase):
    def test_code_table_and_secret_bindings_form_one_multipart_deployment(self):
        api = CloudflareAPI("management-secret")
        metadata = {"main_module": "entry.mjs", "bindings": [
            {"name": "ACCESS_fixture", "type": "secret_text", "text": "client-secret"}]}
        with patch.object(api, "request", return_value={"id": "worker"}) as request:
            api.upload_worker("account", "citadel-owner", metadata, {
                "entry.mjs": ("application/javascript+module", b"export default {};"),
                "routes.json": ("application/json", b'{"schema":1,"hosts":{}}'),
            })
        kwargs = request.call_args.kwargs
        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {kwargs['content_type']}\r\nMIME-Version: 1.0\r\n\r\n".encode() + kwargs["body"])
        parts = {part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
                 for part in message.iter_parts()}
        self.assertEqual(set(parts), {"metadata", "entry.mjs", "routes.json"})
        self.assertEqual(json.loads(parts["metadata"]), metadata)
        self.assertNotIn(b"management-secret", kwargs["body"])
        self.assertEqual(request.call_count, 1)

    def test_api_errors_never_echo_submitted_secrets(self):
        api = CloudflareAPI("management-secret")
        failure = urllib.error.HTTPError("https://api.cloudflare.com/client/v4/test", 400, "Bad request", {},
                                        io.BytesIO(b'{"error":"client-secret rejected"}'))
        with patch("urllib.request.urlopen", side_effect=failure):
            with self.assertRaises(CloudflareAPIError) as result:
                api.request("PUT", "/test", payload={"text": "client-secret"})
        self.assertNotIn("client-secret", str(result.exception))
        self.assertEqual(result.exception.status_code, 400)

    def test_unavailable_settings_are_not_misinterpreted_as_absent_worker(self):
        api = CloudflareAPI("unused")
        for status in (403, 429, 500):
            with patch.object(api, "request", side_effect=CloudflareAPIError("unavailable", status)):
                with self.assertRaises(CloudflareAPIError):
                    api.worker_settings("account", "worker")
        with patch.object(api, "request", side_effect=CloudflareAPIError("missing", 404)):
            self.assertIsNone(api.worker_settings("account", "worker"))

    def test_explicit_secret_deletion_is_idempotent_only_for_missing_secret(self):
        api = CloudflareAPI("unused")
        with patch.object(api, "request", return_value={}) as request:
            api.delete_worker_secret("account", "worker", "ACCESS_fixture")
        request.assert_called_once_with("DELETE", "/accounts/account/workers/scripts/worker/secrets/ACCESS_fixture")
        with patch.object(api, "request", side_effect=CloudflareAPIError("missing", 404)):
            api.delete_worker_secret("account", "worker", "ACCESS_fixture")
        with patch.object(api, "request", side_effect=CloudflareAPIError("denied", 403)):
            with self.assertRaises(CloudflareAPIError):
                api.delete_worker_secret("account", "worker", "ACCESS_fixture")

    def test_expired_management_token_is_rejected(self):
        api = CloudflareAPI("unused")
        for result in (None, {}, {"status": "expired"}, {"status": "disabled"}):
            with patch.object(api, "request", return_value=result), self.assertRaises(CloudflareAPIError):
                api.verify_token()


if __name__ == "__main__":
    unittest.main()
