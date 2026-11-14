"""VirusTotal: look a file up by its hash, or upload it when the user asks.

Looking a file up sends nothing: it opens the file's VirusTotal page in the browser,
addressed by its SHA-256. Uploading sends the whole file to VirusTotal, which shares
submitted files with security companies, so FileSpy only does that when the user clicks
Upload and confirms. Without an API key the upload page is opened instead and the file
is shown in a folder window, ready to be dragged in.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from filespy import fileinfo

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
DIRECT_LIMIT = 32 * 1024 * 1024  # larger files need a one-time upload address first
MAX_UPLOAD = 650 * 1024 * 1024  # the largest file VirusTotal accepts
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class VirusTotalError(Exception):
    """A plain-English reason why a lookup or upload did not happen."""


@dataclass
class UploadResult:
    sha256: str
    analysis_id: str
    url: str  # the file's page on VirusTotal


def report_url(sha256: str) -> str:
    """The VirusTotal page of a file, addressed by its SHA-256."""
    digest = str(sha256).strip().lower()
    if not _SHA256.match(digest):
        raise VirusTotalError("this is not a SHA-256 hash")
    return f"{GUI}/file/{digest}"


def upload_page_url() -> str:
    return f"{GUI}/home/upload"


def api_key(cfg: Any = None) -> str:
    """The API key from the settings, or from the FILESPY_VT_KEY environment variable."""
    key = ""
    if cfg is not None:
        key = getattr(getattr(cfg, "detection", None), "virustotal_api_key", "") or ""
    return (key or os.environ.get("FILESPY_VT_KEY", "")).strip()


def sha256_of(path: str) -> str:
    """SHA-256 of a regular file. Links and special files are refused, never followed."""
    digest = hashlib.sha256()
    with fileinfo.open_regular(path) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_url(url: str, platform: str = sys.platform) -> bool:
    """Open a VirusTotal page in the default browser. Any other address is refused.

    On Windows the page is handed to Explorer, which opens it in the user's browser with
    normal rights even when FileSpy itself runs as administrator.
    """
    if not url.startswith(GUI + "/") or any(c in url for c in ' "<>\r\n\t'):
        return False
    if platform == "win32":
        explorer = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "explorer.exe")
        try:
            subprocess.Popen([explorer, url])  # noqa: S603 - a fixed VirusTotal address, checked above
            return True
        except OSError:
            pass
    try:
        return bool(webbrowser.open(url, new=2))
    except webbrowser.Error:
        return False


def reveal(path: str) -> bool:
    """Show the file, selected, in the system's file manager so it can be dragged somewhere."""
    if not os.path.isfile(path):
        return False
    try:
        if os.name == "nt":
            explorer = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "explorer.exe")
            # A Windows path cannot contain a double quote, so the quoting below cannot be broken.
            subprocess.Popen(f'"{explorer}" /select,"{os.path.normpath(os.path.abspath(path))}"')  # noqa: S603
        elif sys.platform == "darwin":
            subprocess.Popen(["/usr/bin/open", "-R", path])  # noqa: S603
        else:
            tool = shutil.which("xdg-open")
            if tool is None:
                return False
            subprocess.Popen([tool, os.path.dirname(os.path.abspath(path))],  # noqa: S603
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def _safe_address(url: str) -> bool:
    """HTTPS anywhere, or plain HTTP to this computer only (used by the tests)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme == "https" and parts.hostname:
        return True
    return parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")


def _filename(path: str) -> str:
    """The file name for the upload form, with characters that could break the form replaced."""
    name = os.path.basename(path) or "file"
    return "".join(c if c.isprintable() and c not in '"\\' else "_" for c in name)[:200]


def _request(url: str, key: str, timeout: float, data: Any = None, headers: dict[str, str] | None = None,
             method: str = "GET") -> dict[str, Any]:
    if not _safe_address(url):
        raise VirusTotalError("VirusTotal returned an upload address that is not secure; nothing was sent")
    request = urllib.request.Request(url, data=data, method=method,  # noqa: S310 - checked by _safe_address
                                     headers={"x-apikey": key, "accept": "application/json",
                                              "User-Agent": "FileSpy", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read(1024 * 1024) or b"{}")
    except urllib.error.HTTPError as exc:
        reasons = {
            400: "VirusTotal could not accept this file",
            401: "VirusTotal did not accept the API key; check it in Settings",
            403: "VirusTotal refused the request; check the API key in Settings",
            404: "VirusTotal did not find what was asked for",
            413: "the file is too large for VirusTotal",
            429: "the VirusTotal API key has used up its allowance for now; try again later",
        }
        raise VirusTotalError(reasons.get(exc.code, f"VirusTotal answered with an error ({exc.code})")) from exc
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise VirusTotalError(f"VirusTotal could not be reached: {reason}") from exc
    except ValueError as exc:
        raise VirusTotalError("VirusTotal sent an answer that could not be read") from exc


def upload(path: str, key: str, timeout: float = 300.0, base: str = API) -> UploadResult:
    """Send the file to VirusTotal for analysis and return the page that shows the result.

    The file is read once, through the same handle that measured it, and hashed as it is
    sent, so the page returned is the page of exactly the bytes that were uploaded.
    """
    if not key:
        raise VirusTotalError("an API key is needed to upload from FileSpy")
    try:
        handle = fileinfo.open_regular(path)
    except OSError as exc:
        raise VirusTotalError(f"the file cannot be read: {exc.strerror or exc}") from exc
    with handle:
        size = os.fstat(handle.fileno()).st_size
        if size == 0:
            raise VirusTotalError("the file is empty, so there is nothing to analyse")
        if size > MAX_UPLOAD:
            raise VirusTotalError("the file is larger than the 650 MB VirusTotal accepts")
        target = f"{base}/files"
        if size > DIRECT_LIMIT:
            answer = _request(f"{base}/files/upload_url", key, timeout=60)
            target = str(answer.get("data") or "")
            if not target:
                raise VirusTotalError("VirusTotal did not provide an upload address")
        boundary = "filespy-" + uuid.uuid4().hex
        head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{_filename(path)}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        tail = f"\r\n--{boundary}--\r\n".encode("ascii")
        digest = hashlib.sha256()

        def body() -> Iterator[bytes]:
            yield head
            remaining = size
            while remaining > 0:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise VirusTotalError("the file got shorter while it was being uploaded")
                digest.update(chunk)
                remaining -= len(chunk)
                yield chunk
            yield tail

        answer = _request(target, key, timeout=timeout, data=body(), method="POST", headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(head) + size + len(tail)),
        })
    analysis = answer.get("data") if isinstance(answer.get("data"), dict) else {}
    sha256 = digest.hexdigest()
    return UploadResult(sha256=sha256, analysis_id=str(analysis.get("id", "")), url=report_url(sha256))
