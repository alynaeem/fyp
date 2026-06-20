import io
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from api_collector.scripts.github_trivy_checker import (
    _download_github_archive,
    _run_blocking,
)
from ui_server import _parse_github_repo_url


class FakeArchiveResponse:
    status_code = 200

    def __init__(self, payload: bytes):
        self.payload = payload

    def iter_content(self, chunk_size: int):
        yield self.payload

    def close(self):
        return None


class GithubRepoScanTests(unittest.TestCase):
    def test_parses_full_and_short_github_urls(self):
        expected = ("octocat", "Spoon-Knife", "https://github.com/octocat/Spoon-Knife")
        self.assertEqual(_parse_github_repo_url("octocat/Spoon-Knife"), expected)
        self.assertEqual(_parse_github_repo_url("https://github.com/octocat/Spoon-Knife.git"), expected)

    def test_subprocess_timeout_returns_without_hanging(self):
        started = time.monotonic()
        result = _run_blocking(["sh", "-c", "sleep 10"], timeout=1)
        elapsed = time.monotonic() - started

        self.assertEqual(result["return_code"], -1)
        self.assertIn("timed out", result["stderr"])
        self.assertLess(elapsed, 4)

    def test_archive_fallback_extracts_repository_files(self):
        archive_buffer = io.BytesIO()
        content = b'{"name":"fixture"}'
        with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("fixture-root/package.json")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "repo"
            with patch("requests.get", return_value=FakeArchiveResponse(archive_buffer.getvalue())):
                result = _download_github_archive("owner/repo", "", destination, timeout=10)

            self.assertEqual(result["return_code"], 0)
            self.assertEqual((destination / "package.json").read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
