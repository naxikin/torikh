"""Unit tests for engine result parsing — fixture HTML, no network."""
from __future__ import annotations

import unittest
from pathlib import Path

from xikin.engines import looks_js_only, parse_results

FIXTURES = Path(__file__).parent / "fixtures"

AHMIA = {"name": "Ahmia", "kind": "onion",
         "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"}
DDG = {"name": "DuckDuckGo-Tor", "kind": "onion",
       "url": "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/?q={query}"}
TOR66 = {"name": "Tor66", "kind": "onion",
         "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"}


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestParseResults(unittest.TestCase):
    def test_ahmia_redirect_and_direct_links(self):
        results = parse_results(_read("ahmia.html"), AHMIA)
        urls = [row["url"] for row in results]
        self.assertTrue(any("duckduckgogg" in url for url in urls))
        self.assertTrue(any("tor66seweb" in url for url in urls))
        self.assertFalse(any("ahmia" in url for url in urls),
                         "self-links must be dropped")
        self.assertFalse(any("example.com" in url for url in urls),
                         "clearnet links must be dropped for onion engines")
        self.assertTrue(all(row["engine"] == "Ahmia" for row in results))

    def test_ddg_uddg_redirect(self):
        results = parse_results(_read("ddg.html"), DDG)
        urls = [row["url"] for row in results]
        self.assertEqual(len(results), 1)
        self.assertIn("searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion",
                      urls[0])
        self.assertEqual(results[0]["title"], "TheDeepSearches onion")

    def test_clearnet_engine_keeps_http(self):
        clearnet_engine = {"name": "Ahmia-clearnet", "kind": "clearnet",
                           "url": "https://ahmia.fi/search/?q={query}"}
        results = parse_results(_read("tor66.html"), clearnet_engine)
        urls = [row["url"] for row in results]
        self.assertTrue(any("tor66seweb" in url for url in urls))
        self.assertTrue(any("example.com" in url for url in urls))

    def test_empty_html(self):
        self.assertEqual(parse_results("", TOR66), [])
        self.assertEqual(parse_results("<html></html>", TOR66), [])

    def test_chrome_links_are_dropped(self):
        results = parse_results(_read("results_with_chrome.html"), TOR66)
        urls = [row["url"] for row in results]
        self.assertEqual(len(results), 2)
        self.assertTrue(all("ffffffff" in url or "gggggggg" in url for url in urls))
        for junk in ("cccccccc", "dddddddd", "eeeeeeee"):
            self.assertFalse(any(junk in url for url in urls))

    def test_js_only_detection(self):
        interstitial = ("<html><body>Unfortunately we have not deployd "
                        "non-JavaScript version of Ahmia yet.</body></html>")
        self.assertTrue(looks_js_only(interstitial))
        self.assertTrue(looks_js_only("<p>Please enable JavaScript to continue</p>"))
        self.assertFalse(looks_js_only(_read("results_with_chrome.html")))


if __name__ == "__main__":
    unittest.main()
