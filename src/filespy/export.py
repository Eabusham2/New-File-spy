"""Exports: JSON, JSON Lines, CSV, a self-contained HTML report, or a ZIP of all of them.

Every value that came from the monitored machine is escaped for the format it is
written to. Secrets in the configuration are redacted before it is embedded.
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
import platform
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from filespy import __version__
from filespy.config import Config
from filespy.events import Event, Severity
from filespy.sanitize import clean, csv_cell, json_safe

FORMATS = ("json", "jsonl", "csv", "html", "zip")
CSV_COLUMNS = ("time", "severity", "score", "category", "action", "title", "subject", "indicators",
               "sha256", "pid", "command_line", "session", "id")


def _stamp(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def build_meta(events: list[Event], cfg: Config | None, filters: dict[str, Any] | None = None) -> dict[str, Any]:
    severities = Counter(e.severity.label for e in events)
    meta: dict[str, Any] = {
        "tool": "FileSpy",
        "version": __version__,
        "exported_at": _stamp(time.time()),
        "host": platform.node(),
        "system": f"{platform.system()} {platform.release()}",
        "event_count": len(events),
        "by_severity": {s.label: severities.get(s.label, 0) for s in reversed(Severity)},
        "by_category": dict(Counter(e.category for e in events)),
        "first_event": _stamp(events[0].ts) if events else "",
        "last_event": _stamp(events[-1].ts) if events else "",
        "filters": filters or {},
    }
    if cfg is not None and cfg.export.include_settings:
        meta["settings"] = cfg.to_dict(redact=True)
    return meta


def filter_events(events: list[Event], cfg: Config) -> list[Event]:
    """Apply the export section of the configuration (severity, categories, quiet process noise)."""
    minimum = Severity.parse(cfg.export.min_severity, Severity.INFO)
    wanted = set(cfg.export.categories)
    out = []
    for event in events:
        if event.severity < minimum or (wanted and event.category not in wanted):
            continue
        if event.category == "process" and event.severity is Severity.INFO and not cfg.export.include_info_processes:
            continue
        out.append(event)
    return out


def to_json(events: list[Event], meta: dict[str, Any]) -> str:
    return json.dumps(json_safe({"meta": meta, "events": [e.to_dict() for e in events]}), indent=2)


def to_jsonl(events: list[Event]) -> str:
    return "".join(json.dumps(json_safe(e.to_dict())) + "\n" for e in events)


def to_csv(events: list[Event]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for e in events:
        d = e.details
        writer.writerow([
            _stamp(e.ts), e.severity.label, e.score, csv_cell(e.category), csv_cell(e.action), csv_cell(e.title),
            csv_cell(e.subject), csv_cell("; ".join(i.description for i in e.indicators)),
            csv_cell(d.get("sha256", "")), csv_cell(d.get("pid", "")), csv_cell(d.get("cmdline", "")),
            csv_cell(e.session), csv_cell(e.id),
        ])
    return buffer.getvalue()


_CSS = """
body{font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f4f5f7;color:#1c2330}
header{background:#1c2330;color:#fff;padding:18px 28px}header h1{margin:0;font-size:20px}
header p{margin:4px 0 0;color:#aeb6c4;font-size:13px}main{padding:20px 28px;max-width:1300px;margin:auto}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.card{background:#fff;border-radius:8px;padding:10px 16px;min-width:92px;border-top:4px solid #8a94a6}
.card b{display:block;font-size:22px}.card span{font-size:12px;color:#5c6676;text-transform:uppercase}
.critical{border-color:#b3123d}.high{border-color:#d9480f}.medium{border-color:#c98a00}.low{border-color:#2b6cb0}.info{border-color:#8a94a6}
input{width:100%;box-sizing:border-box;padding:9px 12px;margin:0 0 12px;border:1px solid #c5ccd6;border-radius:6px;font-size:14px}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden}
th{background:#e7eaef;text-align:left;padding:8px 10px;font-size:12px;text-transform:uppercase;color:#465066}
td{padding:8px 10px;border-top:1px solid #e7eaef;vertical-align:top}
td.sev{font-weight:700;white-space:nowrap}td.critical{color:#b3123d}td.high{color:#d9480f}td.medium{color:#946500}td.low{color:#2b6cb0}td.info{color:#5c6676}
td.when{white-space:nowrap;color:#5c6676}.subject{font-family:Consolas,Menlo,monospace;font-size:12px;color:#465066;word-break:break-all}
ul{margin:4px 0 0;padding-left:18px;color:#3a4354}li{font-size:13px}
details{margin-top:6px}summary{cursor:pointer;color:#2b6cb0;font-size:12px}
pre{background:#f4f5f7;padding:8px;border-radius:6px;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:6px 0 0}
footer{color:#5c6676;font-size:12px;padding:16px 28px}
"""
_JS = """
const box=document.getElementById('q');
box.addEventListener('input',()=>{const q=box.value.toLowerCase();
for(const row of document.querySelectorAll('tbody tr')){row.style.display=row.textContent.toLowerCase().includes(q)?'':'none';}});
"""


def to_html(events: list[Event], meta: dict[str, Any]) -> str:
    esc = html.escape
    cards = "".join(
        f'<div class="card {s.label}"><b>{meta["by_severity"].get(s.label, 0)}</b><span>{s.label}</span></div>'
        for s in reversed(Severity)
    )
    rows = []
    for e in sorted(events, key=lambda ev: ev.ts, reverse=True):
        reasons = "".join(
            f"<li>{esc(clean(i.description, 300))} <small>(+{i.score}{' ' + esc(i.mitre) if i.mitre else ''})</small></li>"
            for i in e.indicators
        )
        details = esc(json.dumps(json_safe(e.details), indent=2))
        rows.append(
            f'<tr><td class="when">{esc(_stamp(e.ts))}</td><td class="sev {e.severity.label}">{e.severity.label.upper()}</td>'
            f"<td>{esc(clean(e.category, 30))}</td><td><b>{esc(clean(e.title, 300))}</b>"
            f'<div class="subject">{esc(clean(e.subject, 600))}</div>'
            f"{'<ul>' + reasons + '</ul>' if reasons else ''}"
            f"<details><summary>details</summary><pre>{details}</pre></details></td></tr>"
        )
    settings = ""
    if "settings" in meta:
        settings = ("<details><summary>Settings used for this run</summary><pre>"
                    + esc(json.dumps(meta["settings"], indent=2)) + "</pre></details>")
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\">"
        f"<title>FileSpy report</title><style>{_CSS}</style></head><body>"
        f"<header><h1>FileSpy report</h1><p>{esc(str(meta['host']))} &middot; {esc(str(meta['system']))} &middot; "
        f"{meta['event_count']} events &middot; {esc(meta['first_event'])} to {esc(meta['last_event'])}</p></header>"
        f"<main><div class=\"cards\">{cards}</div>"
        "<input id=\"q\" type=\"search\" placeholder=\"Filter events (file name, severity, hash, anything)\">"
        "<table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>What happened</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>{settings}</main>"
        f"<footer>Generated by FileSpy {esc(__version__)} on {esc(meta['exported_at'])}</footer>"
        f"<script>{_JS}</script></body></html>"
    )


def render(events: list[Event], fmt: str, meta: dict[str, Any]) -> bytes:
    if fmt == "json":
        return to_json(events, meta).encode("utf-8")
    if fmt == "jsonl":
        return to_jsonl(events).encode("utf-8")
    if fmt == "csv":
        return ("\ufeff" + to_csv(events)).encode("utf-8")
    if fmt == "html":
        return to_html(events, meta).encode("utf-8")
    if fmt == "zip":
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("events.json", to_json(events, meta))
            archive.writestr("events.csv", "\ufeff" + to_csv(events))
            archive.writestr("report.html", to_html(events, meta))
            if "settings" in meta:
                archive.writestr("settings.json", json.dumps(meta["settings"], indent=2))
        return buffer.getvalue()
    raise ValueError(f"unknown export format: {fmt} (choose from {', '.join(FORMATS)})")


def export_events(
    events: list[Event], fmt: str, destination: Path | str, cfg: Config | None = None, filters: dict[str, Any] | None = None
) -> Path:
    """Write ``events`` to ``destination`` in ``fmt`` and return the path."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = render(events, fmt, build_meta(events, cfg, filters))
    # A freshly created, unpredictable temporary file: a link planted in the folder cannot redirect the write.
    handle, tmp = tempfile.mkstemp(dir=destination.parent, prefix=".filespy-", suffix=".part")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(payload)
        os.replace(tmp, destination)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return destination


def auto_export(events: list[Event], cfg: Config, data_dir: Path, session: str) -> list[Path]:
    """Export a finished session in every configured format; returns the files written."""
    folder = Path(cfg.export.directory) if cfg.export.directory else Path(data_dir) / "exports"
    selected = filter_events(events, cfg)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return [
        export_events(selected, fmt, folder / f"filespy-{stamp}-{session[:8]}.{fmt}", cfg, {"session": session})
        for fmt in cfg.export.formats
    ]
