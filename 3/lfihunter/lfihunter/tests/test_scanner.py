import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lfihunter.payloads import Payload
from lfihunter.scanner import _looks_like_base64_blob, scan


def test_url_template_without_fuzz_marker_raises():
    try:
        scan("http://target/index.php?page=notfuzzed")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_base64_blob_detection_accepts_real_looking_blob():
    blob = "PD9waHAKLy8gZmFrZSBpbmRleC5waHAgc291cmNlCj8+"
    assert _looks_like_base64_blob(blob) is True


def test_base64_blob_detection_rejects_html_error_page():
    html = "<html><body>404 not found, this page does not exist</body></html>"
    assert _looks_like_base64_blob(html) is False


def test_base64_blob_detection_rejects_short_strings():
    assert _looks_like_base64_blob("hi") is False


def test_scan_confirms_hit_against_matching_signature():
    # Uses a fake payload list against a URL that will 404 (no real server) --
    # this test exists to confirm scan() doesn't crash on network errors,
    # not to confirm a real hit (that's covered by the live test server
    # exercised manually / in test_server/).
    fake_payloads = [Payload("../../etc/passwd", "test target", "root:", "traversal")]
    summary = scan("http://127.0.0.1:1/index.php?page=FUZZ", timeout=0.5, payloads=fake_payloads)
    assert summary.total_sent == 1
    assert summary.errors == 1  # connection refused, since nothing is listening on port 1
    assert len(summary.findings) == 0


if __name__ == "__main__":
    test_url_template_without_fuzz_marker_raises()
    test_base64_blob_detection_accepts_real_looking_blob()
    test_base64_blob_detection_rejects_html_error_page()
    test_base64_blob_detection_rejects_short_strings()
    test_scan_confirms_hit_against_matching_signature()
    print("All tests passed.")
