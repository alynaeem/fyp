import unittest

from ui_server import (
    _build_dual_mode_seo_report,
    _extract_seo_dom_snapshot,
)


class DummyResponse:
    status_code = 200
    headers = {"Content-Encoding": "gzip"}
    history = []

    def __init__(self, html: str):
        self.content = html.encode("utf-8")


ROBOTS_OK = {
    "url": "https://example.test/robots.txt",
    "statusCode": 200,
    "score": 1.0,
    "status": "pass",
    "message": "robots.txt returned HTTP 200 with 20 characters.",
}


def build_report(raw_html: str, rendered_html: str | None = None):
    final_url = "https://example.test/"
    raw = _extract_seo_dom_snapshot(raw_html, final_url, source="raw_html")
    raw.update({"url": final_url, "statusCode": 200, "xRobotsTag": ""})
    rendered = None
    rendered_error = None
    if rendered_html is not None:
        rendered = _extract_seo_dom_snapshot(rendered_html, final_url, source="rendered_dom")
        rendered.update({"url": final_url, "statusCode": 200})
    else:
        rendered_error = {"kind": "test_no_render", "message": "Rendered DOM scan failed in test."}
    return _build_dual_mode_seo_report(
        url=final_url,
        final_url=final_url,
        requested_host="example.test",
        response=DummyResponse(raw_html),
        raw=raw,
        rendered=rendered,
        rendered_error=rendered_error,
        robots=ROBOTS_OK,
    )


class SeoDualModeTests(unittest.TestCase):
    def test_static_html_has_high_confidence_and_confirmed_failures(self):
        html = """
        <html lang="en"><head><title>Static Test Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        </head><body><h1>Static Test Page</h1><p>Useful content for the test page.</p></body></html>
        """
        report = build_report(html, html)

        self.assertEqual(report["crawlerVisibility"]["level"], "high")
        self.assertEqual(report["scanConfidenceGrade"], "High")
        self.assertEqual(report["audits"]["meta-description"]["status"], "fail")
        self.assertEqual(report["audits"]["meta-description"]["confidence"], "high")
        self.assertEqual(report["audits"]["canonical"]["status"], "fail")

    def test_app_shell_low_confidence_marks_content_findings_needs_review(self):
        scripts = "".join("<script src='/app.js'></script>" for _ in range(12))
        raw_html = f"<html><head><title>App</title></head><body><div id='root'></div>{scripts}</body></html>"
        report = build_report(raw_html, None)

        self.assertEqual(report["crawlerVisibility"]["level"], "low")
        self.assertEqual(report["scanConfidenceGrade"], "Low")
        self.assertTrue(report["crawlerVisibility"]["signals"]["jsHeavyLikely"])
        self.assertEqual(report["audits"]["single-h1"]["status"], "needs_review")
        self.assertEqual(report["audits"]["single-h1"]["confidence"], "low")
        self.assertEqual(report["audits"]["canonical"]["status"], "needs_review")
        self.assertEqual(report["audits"]["social-metadata"]["status"], "needs_review")

    def test_rendered_dom_evidence_overrides_missing_raw_html(self):
        raw_html = "<html><head><title>Shell</title></head><body><div id='root'></div><script src='/app.js'></script></body></html>"
        rendered_html = """
        <html lang="en"><head><title>Rendered Product Page</title>
        <meta name="description" content="A useful rendered description for the product page and its search snippet.">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="canonical" href="https://example.test/">
        </head><body><h1>Rendered Product Page</h1><p>Rendered content is available for crawler inspection.</p></body></html>
        """
        report = build_report(raw_html, rendered_html)

        self.assertTrue(report["renderedScanAvailable"])
        self.assertEqual(report["audits"]["meta-description"]["status"], "pass")
        self.assertEqual(report["audits"]["meta-description"]["evidenceSource"], "rendered_dom")
        self.assertEqual(report["audits"]["canonical"]["status"], "pass")
        self.assertEqual(report["audits"]["single-h1"]["status"], "pass")

    def test_access_gated_page_sets_access_limited_and_low_confidence(self):
        scripts = "".join("<script></script>" for _ in range(8))
        raw_html = f"<html><head><title>Login</title></head><body><div id='root'>Log in to continue. Create account.</div>{scripts}</body></html>"
        report = build_report(raw_html, None)

        self.assertTrue(report["crawlerVisibility"]["signals"]["accessLimitedSignals"])
        self.assertTrue(report["crawlerVisibility"]["signals"]["loginWallLikely"])
        self.assertEqual(report["crawlerVisibility"]["level"], "low")
        self.assertEqual(report["audits"]["single-h1"]["status"], "needs_review")

    def test_zero_links_are_not_counted_as_perfect_pass(self):
        html = """
        <html lang="en"><head><title>Zero Link Page</title>
        <meta name="description" content="This page deliberately has no links but enough content to test link scoring.">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="canonical" href="https://example.test/">
        </head><body><h1>Zero Link Page</h1><p>There are no anchors in this document, so link text should not pass by 0/0 math.</p></body></html>
        """
        report = build_report(html, html)

        self.assertEqual(report["audits"]["link-text"]["status"], "not_applicable")
        self.assertLess(report["audits"]["link-text"]["score"], 1)


if __name__ == "__main__":
    unittest.main()
