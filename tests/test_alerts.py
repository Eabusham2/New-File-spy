import io
import json

from filespy.alerts import (
    AlertManager,
    ConsoleNotifier,
    DesktopNotifier,
    WebhookNotifier,
    format_event,
    notification_command,
    webhook_allowed,
)
from filespy.config import Config
from filespy.events import Indicator, Severity, make_event

HOSTILE = "evil\x1b[2J\x07name\u202egpj.exe\r\nFAKE LINE"


def hostile_event(score=80):
    return make_event("file", "created", "New program dropped: " + HOSTILE, "/tmp/" + HOSTILE,
                      [Indicator("x", score, "reason " + HOSTILE)], {"sha256": "ab" * 32, "size": 1234})


def test_console_output_cannot_be_hijacked_by_file_names():
    for color in (False, True):
        text = format_event(hostile_event(), color)
        body = text.replace("\x1b[1;31m", "").replace("\x1b[0m", "").replace("\x1b[2m", "")
        assert "\x1b" not in body and "\x07" not in body and "\u202e" not in body and "\r" not in body
        assert all(not line.startswith("FAKE LINE") for line in text.splitlines())
        assert "HIGH" in text and "sha256 " + "ab" * 32 in text and "1,234 bytes" in text


def test_console_threshold_json_mode_and_odd_encodings():
    stream = io.StringIO()
    notifier = ConsoleNotifier(Severity.MEDIUM, "never", stream)
    notifier(make_event("file", "created", "quiet"))
    assert stream.getvalue() == ""
    notifier(hostile_event())
    assert "New program dropped" in stream.getvalue()

    stream = io.StringIO()
    ConsoleNotifier(Severity.INFO, "never", stream, as_json=True)(hostile_event())
    assert json.loads(stream.getvalue())["severity"] == "high"

    class Ascii(io.StringIO):
        encoding = "ascii"

        def write(self, text):
            text.encode("ascii")
            return super().write(text)

    stream = Ascii()
    ConsoleNotifier(Severity.INFO, "never", stream)(make_event("file", "created", "caf\u00e9 \u4e2d", min_severity=Severity.LOW))
    assert "caf" in stream.getvalue()


def test_notification_text_is_data_never_code():
    title, body = "FileSpy", 'x"; Remove-Item C:\\ -Recurse; $(calc) `whoami` <b>'
    argv, env = notification_command(title, body, "win32", {"SystemRoot": r"C:\Windows"})
    assert argv[0] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert all(body not in part for part in argv) and env["FILESPY_BODY"] == body
    argv, _env = notification_command(title, body, "darwin", {})
    assert argv[0] == "/usr/bin/osascript" and argv[-1] == body and body not in argv[2]


def test_desktop_notifications_are_rate_limited():
    calls = []
    notifier = DesktopNotifier(Severity.HIGH, per_minute=2, runner=lambda argv, env: calls.append(argv))
    notifier(make_event("file", "created", "low", min_severity=Severity.LOW))
    for _ in range(10):
        notifier(hostile_event())
    import time
    deadline = time.time() + 5
    while len(calls) < 2 and time.time() < deadline and not notifier._unsupported:
        time.sleep(0.02)
    assert notifier._unsupported or (len(calls) == 2 and notifier._suppressed == 8)


def test_webhook_rules_and_payload():
    assert webhook_allowed("https://hooks.example/x") and webhook_allowed("http://localhost:9000/x")
    assert not webhook_allowed("http://example.com/x") and not webhook_allowed("file:///etc/passwd")
    assert not webhook_allowed("ftp://x/y") and not webhook_allowed("notaurl")
    payload = WebhookNotifier.payload(hostile_event())
    assert "\x1b" not in payload["text"] and payload["event"]["severity"] == "high"
    json.dumps(payload)


def test_manager_builds_channels_and_refuses_insecure_webhook(tmp_path):
    cfg = Config()
    cfg.alerts.desktop = False
    cfg.alerts.webhook_url = "http://example.com/hook"
    stream = io.StringIO()
    manager = AlertManager(cfg, tmp_path, stream)
    assert manager.warnings and len(manager.channels) == 2
    manager.handle(hostile_event())
    manager.close()
    assert "New program dropped" in stream.getvalue()
    log_text = (tmp_path / "logs" / "filespy.log").read_text(encoding="utf-8")
    assert "HIGH file/created" in log_text and len(log_text.splitlines()) == 1 and "\x1b" not in log_text
