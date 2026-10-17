"""Tests for deterministic IOC extraction and CTI exports."""
from __future__ import annotations

import json
import unittest

from xikin.iocs import (extract, find_secret_hits, mask_secret, render_csv,
                        render_markdown, to_misp, to_stix, total_count)

_XMR = "4A" + "B" * 93  # syntactically valid 95-char Monero-shaped address
_BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

SAMPLE = """
Ransomware crew contact: lockbit@onionmail.example and https://lockbit7z6choojah4ipvdpzzfzxxchjbecnmtn4povk6ifdvx2dpnid.onion/blog
Wallet: {btc} and {xmr}
Sample hash: 44d88612fea6f8a36e8b76b4d12d4c3e0a6f1d2f9a3c4b5d6e7f809a1b2c3d4e
CVE-2026-12345 exploit talked about on da7576dyrtn5a2xnfo6oqoigqvyv26q7475pwczihylhcia5c6y5ofid.onion
Leaked key: AKIAFAKEFAKEFAKEFAKE and password: hunter2secret
""".format(btc=_BTC, xmr=_XMR)


class TestIocExtraction(unittest.TestCase):
    def setUp(self):
        self.iocs = extract({"page1": SAMPLE, "page2": "again lockbit@onionmail.example"})

    def test_onion_url(self):
        values = [entry["value"] for entry in self.iocs["onion_url"]]
        self.assertIn("https://lockbit7z6choojah4ipvdpzzfzxxchjbecnmtn4povk6ifdvx2dpnid.onion/blog",
                      values)

    def test_onion_host_from_bare_address(self):
        hosts = [entry["value"] for entry in self.iocs["onion_host"]]
        self.assertIn("da7576dyrtn5a2xnfo6oqoigqvyv26q7475pwczihylhcia5c6y5ofid.onion", hosts)

    def test_email_merge_and_count(self):
        entries = {entry["value"]: entry for entry in self.iocs["email"]}
        self.assertEqual(entries["lockbit@onionmail.example"]["count"], 2)
        self.assertEqual(len(entries["lockbit@onionmail.example"]["sources"]), 2)

    def test_wallets_hashes_cve_secret(self):
        self.assertTrue(self.iocs["btc"])
        self.assertTrue(self.iocs["xmr"])
        self.assertEqual(self.iocs["cve"][0]["value"], "cve-2026-12345")
        secrets = [entry["value"] for entry in self.iocs["secret"]]
        self.assertTrue(any("AKIAFAKEFAKEFAKEFAKE" in value for value in secrets))

    def test_sha256_not_reported_as_sha1(self):
        self.assertNotIn("sha1", self.iocs)

    def test_mask_secret(self):
        masked = mask_secret("AKIAFAKEFAKEFAKEFAKE")
        self.assertIn("REDACTED", masked)
        self.assertNotIn("IOSFODNN7EXAMPLE", masked)

    def test_find_secret_hits(self):
        hits = find_secret_hits({"p": "password: hunter2secret"})
        self.assertTrue(hits)

    def test_renderers(self):
        self.assertIn("Extracted indicators", render_markdown(self.iocs))
        self.assertIn("type,value,count,sources", render_csv(self.iocs))
        stix = to_stix(self.iocs, query="test")
        self.assertEqual(stix["type"], "bundle")
        self.assertTrue(all(obj["type"] in ("identity", "indicator")
                            for obj in stix["objects"]))
        patterns = [obj["pattern"] for obj in stix["objects"]
                    if obj["type"] == "indicator"]
        self.assertTrue(any("domain-name" in pattern for pattern in patterns))
        misp = to_misp(self.iocs, query="test")
        self.assertIn("Attribute", misp["Event"])
        self.assertGreater(total_count(self.iocs), 5)

    def test_stix_is_valid_json(self):
        json.loads(json.dumps(to_stix(self.iocs), default=str))
        json.loads(json.dumps(to_misp(self.iocs), default=str))


if __name__ == "__main__":
    unittest.main()
