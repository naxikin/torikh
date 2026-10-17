"""Unit tests for text/URL helpers — no network, no Tor."""
from __future__ import annotations

import unittest

from xikin.textutil import (clean_html_text, deduplicate, extract_keywords,
                            heuristic_query, is_onion_url, normalize_url,
                            page_title, resolve_redirect, score_results,
                            truncate)


class TestUrlHelpers(unittest.TestCase):
    def test_is_onion_url(self):
        self.assertTrue(is_onion_url(
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"))
        self.assertTrue(is_onion_url("http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion"))
        self.assertFalse(is_onion_url("https://ahmia.fi/search/"))
        self.assertFalse(is_onion_url("http://notonion.onion.example.com/"))
        self.assertFalse(is_onion_url(""))

    def test_normalize_url_is_scheme_agnostic_for_onion(self):
        first = normalize_url("http://abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd.onion/page/?b=2&a=1")
        second = normalize_url("https://abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd.onion/page?a=1&b=2")
        self.assertEqual(first, second)

    def test_normalize_url_drops_tracking(self):
        self.assertEqual(normalize_url("http://x.onion/p?utm_source=news"),
                         normalize_url("http://x.onion/p"))

    def test_resolve_redirect(self):
        wrapped = "/search/redirect?redirect_url=http%3A%2F%2Fabc.onion%2F&onion=true"
        self.assertEqual(resolve_redirect(wrapped), "http://abc.onion/")
        uddg = "//duckduckgo.com/l/?uddg=http%3A%2F%2Fdef.onion%2Fpage&rut=1"
        self.assertEqual(resolve_redirect(uddg), "http://def.onion/page")
        self.assertEqual(resolve_redirect("http://plain.onion/"), "http://plain.onion/")

    def test_deduplicate(self):
        rows = [
            {"title": "A", "url": "http://abc.onion/", "engine": "X"},
            {"title": "A copy", "url": "https://abc.onion", "engine": "Y"},
            {"title": "B", "url": "http://def.onion/", "engine": "Z"},
        ]
        unique = deduplicate(rows)
        self.assertEqual(len(unique), 2)
        self.assertEqual(unique[0]["title"], "A")


class TestTextHelpers(unittest.TestCase):
    def test_clean_html_text(self):
        html = "<html><head><style>x{}</style></head><body><nav>menu</nav>" \
               "<h1>Hello</h1><p>World</p><script>alert(1)</script></body></html>"
        text = clean_html_text(html)
        self.assertIn("Hello", text)
        self.assertIn("World", text)
        self.assertNotIn("alert", text)
        self.assertNotIn("menu", text)

    def test_page_title(self):
        self.assertEqual(page_title("<html><title>  Test   page </title></html>"),
                         "Test page")
        self.assertEqual(page_title("<html></html>"), "")

    def test_truncate(self):
        self.assertEqual(truncate("abcdef", 10), "abcdef")
        self.assertIn("truncated", truncate("abcdef", 3))

    def test_heuristic_query(self):
        self.assertEqual(heuristic_query("what is the LockBit ransomware leak site"),
                         "LockBit ransomware leak site")

    def test_extract_keywords(self):
        words = extract_keywords("ransomware leak ransomware leak hospital payment", 3)
        self.assertEqual(words[0], "ransomware")
        self.assertIn("leak", words)

    def test_score_results_orders_by_overlap(self):
        rows = [
            {"title": "cooking recipes", "url": "http://abc.onion/", "engine": "X"},
            {"title": "lockbit ransomware healthcare leak",
             "url": "http://def.onion/", "engine": "Y"},
        ]
        scored = score_results("lockbit ransomware healthcare leak", rows)
        self.assertEqual(scored[0]["engine"], "Y")
        self.assertGreater(scored[0]["score"], scored[1]["score"])

    def test_score_results_corroboration_bonus(self):
        base = {"title": "lockbit leak", "url": "http://abc.onion/", "engine": "X"}
        single = dict(base, corroboration=1)
        multi = dict(base, corroboration=3)
        scored = {row["corroboration"]: row for row in
                  score_results("lockbit leak", [single, multi])}
        self.assertGreater(scored[3]["score"], scored[1]["score"])


if __name__ == "__main__":
    unittest.main()
