import hashlib
import http.server
import json
import os
import sys
import threading

import pytest

from filespy import virustotal
from filespy.cli import main
from filespy.config import Config


class FakeVirusTotal:
    """A local stand-in for the VirusTotal API that records what it receives."""

    def __init__(self, status=200):
        self.uploads = []  # (path, headers, body)
        self.status = status
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, code, payload):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.endswith("/files/upload_url"):
                    self._reply(200, {"data": f"http://127.0.0.1:{outer.port}/big-upload"})
                else:
                    self._reply(404, {})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                outer.uploads.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                if outer.status != 200:
                    self._reply(outer.status, {"error": {"code": "x"}})
                else:
                    self._reply(200, {"data": {"type": "analysis", "id": "analysis-123"}})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}/api/v3"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake_vt():
    server = FakeVirusTotal()
    yield server
    server.close()


def test_addresses_and_keys(monkeypatch):
    digest = "AB" * 32
    assert virustotal.report_url(digest) == "https://www.virustotal.com/gui/file/" + "ab" * 32
    for bad in ("", "xyz", "ab" * 31, "zz" * 32, "../" * 30):
        with pytest.raises(virustotal.VirusTotalError):
            virustotal.report_url(bad)
    assert virustotal.upload_page_url() == "https://www.virustotal.com/gui/home/upload"
    monkeypatch.delenv("FILESPY_VT_KEY", raising=False)
    cfg = Config()
    assert virustotal.api_key(cfg) == ""
    monkeypatch.setenv("FILESPY_VT_KEY", " from-env ")
    assert virustotal.api_key(cfg) == "from-env"
    cfg.detection.virustotal_api_key = "from-settings"
    assert virustotal.api_key(cfg) == "from-settings"


def test_only_virustotal_pages_are_opened(monkeypatch):
    opened = []
    monkeypatch.setattr(virustotal.webbrowser, "open", lambda url, new=0: opened.append(url) or True)
    assert virustotal.open_url(virustotal.report_url("ab" * 32))
    for bad in ("https://evil.example/", "javascript:alert(1)", "file:///etc/passwd", "https://www.virustotal.com.evil.example/x"):
        assert virustotal.open_url(bad) is False
    assert opened == ["https://www.virustotal.com/gui/file/" + "ab" * 32]
    launched = []
    monkeypatch.setattr(virustotal.subprocess, "Popen", lambda argv: launched.append(argv))
    assert virustotal.open_url(virustotal.upload_page_url(), platform="win32")
    assert launched[-1][0].lower().endswith("explorer.exe") and launched[-1][1] == virustotal.upload_page_url()
    assert virustotal.open_url(virustotal.upload_page_url() + '" & calc', platform="win32") is False


def test_hashing_refuses_links(tmp_path):
    target = tmp_path / "a.bin"
    target.write_bytes(b"hello")
    assert virustotal.sha256_of(str(target)) == hashlib.sha256(b"hello").hexdigest()
    if sys.platform != "win32":
        link = tmp_path / "link"
        link.symlink_to(target)
        with pytest.raises(OSError):
            virustotal.sha256_of(str(link))


def test_upload_sends_the_file_and_returns_its_page(tmp_path, fake_vt):
    sample = tmp_path / 'we"ird\nname.exe'
    content = b"MZ" + os.urandom(5000)
    sample.write_bytes(content)
    result = virustotal.upload(str(sample), "secret-key", base=fake_vt.base)
    digest = hashlib.sha256(content).hexdigest()
    assert result.sha256 == digest and result.analysis_id == "analysis-123"
    assert result.url == f"https://www.virustotal.com/gui/file/{digest}"
    path, headers, body = fake_vt.uploads[0]
    assert path == "/api/v3/files" and headers["x-apikey"] == "secret-key"
    assert headers["content-type"].startswith("multipart/form-data; boundary=")
    boundary = headers["content-type"].split("boundary=")[1].encode()
    assert body.startswith(b"--" + boundary + b"\r\n") and body.endswith(b"\r\n--" + boundary + b"--\r\n")
    assert content in body and b'filename="we_ird_name.exe"' in body  # characters that could break the form are replaced


def test_large_files_use_a_separate_upload_address(tmp_path, fake_vt, monkeypatch):
    monkeypatch.setattr(virustotal, "DIRECT_LIMIT", 1000)
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"x" * 5000)
    virustotal.upload(str(sample), "k", base=fake_vt.base)
    assert fake_vt.uploads[0][0] == "/big-upload"


def test_upload_refusals_are_explained(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    with pytest.raises(virustotal.VirusTotalError, match="empty"):
        virustotal.upload(str(empty), "k")
    with pytest.raises(virustotal.VirusTotalError, match="API key"):
        virustotal.upload(str(empty), "")
    with pytest.raises(virustotal.VirusTotalError, match="cannot be read"):
        virustotal.upload(str(tmp_path / "missing"), "k")
    monkeypatch.setattr(virustotal, "MAX_UPLOAD", 3)
    (tmp_path / "four").write_bytes(b"1234")
    with pytest.raises(virustotal.VirusTotalError, match="650 MB"):
        virustotal.upload(str(tmp_path / "four"), "k")
    monkeypatch.setattr(virustotal, "MAX_UPLOAD", 650 * 1024 * 1024)
    with pytest.raises(virustotal.VirusTotalError, match="not secure"):
        virustotal.upload(str(tmp_path / "four"), "k", base="http://example.com/api")


@pytest.mark.parametrize("status,message", [(401, "API key"), (429, "allowance"), (500, "error \\(500\\)")])
def test_upload_errors_from_virustotal(tmp_path, status, message):
    server = FakeVirusTotal(status=status)
    try:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"abc")
        with pytest.raises(virustotal.VirusTotalError, match=message):
            virustotal.upload(str(sample), "k", base=server.base)
    finally:
        server.close()


def test_upload_reports_an_unreachable_service(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"abc")
    with pytest.raises(virustotal.VirusTotalError, match="could not be reached"):
        virustotal.upload(str(sample), "k", base="http://127.0.0.1:9/api/v3", timeout=3)


def test_cli_vt_lookup_and_upload(tmp_path, capsys, monkeypatch, fake_vt):
    opened = []
    monkeypatch.setattr(virustotal, "open_url", lambda url: opened.append(url) or True)
    monkeypatch.setattr(virustotal, "reveal", lambda path: opened.append("reveal:" + os.path.basename(path)) or True)
    monkeypatch.delenv("FILESPY_VT_KEY", raising=False)
    home = str(tmp_path / "home")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ-sample")
    digest = hashlib.sha256(b"MZ-sample").hexdigest()

    assert main(["--data-dir", home, "vt", str(sample)]) == 0
    assert digest in capsys.readouterr().out and opened[-1].endswith(digest)

    assert main(["--data-dir", home, "vt", str(sample), "--upload"]) == 0  # no key: upload page + folder window
    assert "No VirusTotal API key" in capsys.readouterr().out
    assert opened[-2:] == [virustotal.upload_page_url(), "reveal:s.exe"]

    real_upload = virustotal.upload
    monkeypatch.setattr(virustotal, "upload", lambda path, key: real_upload(path, key, base=fake_vt.base))
    assert main(["--data-dir", home, "config", "set", "detection.virustotal_api_key", "k-123"]) == 0
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    assert main(["--data-dir", home, "vt", str(sample), "--upload"]) == 1  # said no
    assert not fake_vt.uploads
    assert main(["--data-dir", home, "vt", str(sample), "--upload", "--yes", "--no-browser"]) == 0
    assert digest in capsys.readouterr().out and fake_vt.uploads[0][1]["x-apikey"] == "k-123"
    assert main(["--data-dir", home, "vt", str(tmp_path / "missing")]) == 2
