import os
import sys

import pytest

from filespy import fileinfo
from filespy.analyzer import FileAnalyzer, name_indicators
from filespy.events import Severity, summarize
from filespy.rules import RuleSet, load_rules
from filespy.testing import eicar_bytes, make_elf, make_pe


def ids(report):
    return {i.id for i in report.indicators}


@pytest.mark.parametrize(
    "head,name,kind",
    [
        (make_pe(), "a.exe", "pe"),
        (make_elf(), "a", "elf"),
        (b"\xcf\xfa\xed\xfe" + b"\0" * 60, "a", "macho"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\0" * 60, "a", "macho"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 60, "A.class", "javaclass"),
        (b"#!/bin/sh\necho hi\n", "x", "script"),
        (b"Write-Host 1\n", "x.ps1", "script"),
        (b"hello world\n", "notes.txt", "text"),
        (b"<html><script>1</script></html>", "x.hta", "html"),
        (b"PK\x03\x04rest", "a.zip", "zip"),
        (b"L\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 80, "a.lnk", "lnk"),
        (b"\x00\x01\x02\x03\xff\xfe\x00\x00", "blob", "data"),
        (b"", "empty", "empty"),
        (b"MZ", "short", "text"),
    ],
)
def test_detect_kind(head, name, kind):
    assert fileinfo.detect_kind(head, name) == kind


def test_extension():
    assert fileinfo.extension("C:\\a\\b.TXT") == "txt"
    assert fileinfo.extension("/a/.bashrc") == ""
    assert fileinfo.extension("invoice.pdf.exe ") == "exe"


def test_parse_pe_fields_and_garbage():
    pe = fileinfo.parse_pe(make_pe(("UPX0", "UPX1"), dll=True, signed=True))
    assert pe and pe.is_dll and pe.signed and pe.packer == "UPX" and len(pe.sections) == 2
    assert fileinfo.parse_pe(b"MZ" + b"\xff" * 200) is None
    assert fileinfo.parse_pe(b"") is None
    for cut in range(0, 700, 7):  # truncated images must never raise
        fileinfo.parse_pe(make_pe()[:cut])


def test_rules_load_cleanly_and_eicar_is_never_stored_whole():
    rules = load_rules()
    assert not rules.errors and len(rules.rules) >= 30
    import filespy
    root = os.path.dirname(filespy.__file__)
    needle = eicar_bytes()
    for folder, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith((".py", ".json")):
                with open(os.path.join(folder, name), "rb") as handle:
                    assert needle not in handle.read(), name


def test_rule_matching_modes():
    rs = RuleSet()
    rs.load_text('{"rules":[{"id":"t","score":50,"kinds":["pe"],"nocase":true,"min_match":2,'
                 '"strings":["AlphaBeta","GammaDelta","EpsilonZeta"]}]}', "t")
    assert rs.match(b"xx alphabeta yy GAMMADELTA", "pe")
    assert not rs.match(b"xx alphabeta yy", "pe")
    assert not rs.match(b"xx alphabeta yy GAMMADELTA", "text")
    assert rs.match("alphabeta".encode("utf-16-le") + b"gammadelta", "pe")
    bad = RuleSet()
    bad.load_text("not json", "x")
    bad.load_text('{"rules":[{"id":"a","strings":["ab"]}]}', "y")
    assert len(bad.errors) == 2 and not bad.rules


def test_eicar_is_critical(tmp_path):
    target = tmp_path / "test.com"
    target.write_bytes(eicar_bytes())
    report = FileAnalyzer().analyze(str(target))
    assert "file.hash_blocklist" in ids(report) and "file.rule.eicar" in ids(report)
    assert summarize(report.indicators)[1] is Severity.CRITICAL


def test_rat_marker_in_program(tmp_path):
    target = tmp_path / "client.exe"
    target.write_bytes(make_pe(payload=b"AsyncMutex_6SI8OkPnk"))
    report = FileAnalyzer().analyze(str(target))
    assert "file.rule.rat.asyncrat" in ids(report)
    assert summarize(report.indicators)[1] >= Severity.HIGH


def test_marker_in_plain_text_is_not_a_rat(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("Article about AsyncRAT, Quasar.Client and mimikatz sekurlsa::logonpasswords")
    assert not FileAnalyzer().analyze(str(target)).indicators


def test_windows_drop_scoring(tmp_path):
    analyzer = FileAnalyzer(platform="win32")
    target = tmp_path / "x.exe"
    target.write_bytes(make_pe())
    report = analyzer.analyze(str(target))
    report.location = "user_writable"
    assert report.kind == "pe" and report.sha256 and report.interesting


def test_location_and_name_indicators(tmp_path, monkeypatch):
    analyzer = FileAnalyzer(platform="win32")
    monkeypatch.setattr("filespy.analyzer.classify_location", lambda p, plat=None: "temp")
    target = tmp_path / "invoice.pdf.exe"
    target.write_bytes(make_pe())
    found = ids(analyzer.analyze(str(target)))
    assert {"file.program_in_temp", "file.double_extension", "file.unsigned"} <= found
    decoy = tmp_path / "photo.jpg"
    decoy.write_bytes(make_pe())
    assert "file.type_mismatch" in ids(analyzer.analyze(str(decoy)))
    system = tmp_path / "svchost.exe"
    system.write_bytes(make_pe())
    assert "file.system_name" in ids(analyzer.analyze(str(system)))
    packed = tmp_path / "p.exe"
    packed.write_bytes(make_pe(("UPX0", "UPX1")))
    assert "file.packed" in ids(analyzer.analyze(str(packed)))


def test_name_tricks():
    assert {i.id for i in name_indicators("report\u202egpj.exe", "pe")} >= {"file.name_bidi"}
    assert not name_indicators("setup.exe", "pe")
    assert not name_indicators("archive.tar.gz", "gzip")
    assert not name_indicators("my.report.docx", "zip")
    assert {i.id for i in name_indicators("doc.pdf" + " " * 40 + ".exe", "pe")} >= {"file.name_padding"}


def test_ordinary_files_are_quiet(tmp_path):
    analyzer = FileAnalyzer()
    for name, body in (("a.txt", b"hello"), ("b.json", b'{"a":1}'), ("c.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 50)):
        target = tmp_path / name
        target.write_bytes(body)
        report = analyzer.analyze(str(target))
        assert not report.indicators and not report.interesting, name


def test_own_rule_file_is_not_flagged(tmp_path):
    from filespy.rules import builtin_rules_text
    target = tmp_path / "rules.json"
    target.write_text(builtin_rules_text(), encoding="utf-8")
    report = FileAnalyzer().analyze(str(target))
    assert not report.indicators and report.details.get("allowlisted")


def test_never_follows_links_or_opens_special_files(tmp_path):
    analyzer = FileAnalyzer()
    missing = analyzer.analyze(str(tmp_path / "nope"))
    assert not missing.exists and missing.error
    assert analyzer.analyze(str(tmp_path)).kind == "special"
    if sys.platform != "win32":
        real = tmp_path / "real.exe"
        real.write_bytes(eicar_bytes())
        link = tmp_path / "link.exe"
        link.symlink_to(real)
        report = analyzer.analyze(str(link))
        assert report.kind == "link" and not report.indicators
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        assert analyzer.analyze(str(fifo)).kind == "special"


def test_user_hash_lists(tmp_path):
    import hashlib

    from filespy.config import DetectionCfg
    body = b"totally unique sample bytes"
    digest = hashlib.sha256(body).hexdigest()
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text(f"# comment\n{digest}  MyThreat\nnot-a-hash\n")
    sample = tmp_path / "s.bin"
    sample.write_bytes(body)
    report = FileAnalyzer(DetectionCfg(hash_blocklists=[str(blocklist)])).analyze(str(sample))
    assert any(i.id == "file.hash_blocklist" and "MyThreat" in i.description for i in report.indicators)
    allowed = FileAnalyzer(DetectionCfg(hash_blocklists=[str(blocklist)], hash_allowlists=[str(blocklist)])).analyze(str(sample))
    assert not allowed.indicators
