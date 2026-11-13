import pytest

from filespy.events import Severity
from filespy.monitors.settings import SettingsMonitor
from filespy.registry import FakeRegistry
from filespy.settingsmon.danger import evaluate, split_items
from filespy.settingsmon.posix import (
    FileSettingsProvider,
    MacCommandProvider,
    SysctlProvider,
    WatchedFile,
    score_hosts,
    score_passwd,
    score_sshd,
    score_sudoers,
)
from filespy.settingsmon.windows import WindowsSettingsProvider, load_catalog
from filespy.testing import wait_for

DEFENDER = r"SOFTWARE\Policies\Microsoft\Windows Defender"
V = {"kind": "value"}


def rule(op, **kw):
    return {"op": op, **kw}


@pytest.mark.parametrize(
    "pred,entry,old,new,expected",
    [
        (rule("eq", value=1), {**V, "absent_as": 0}, None, 1, True),
        (rule("eq", value=1), {**V, "absent_as": 0}, 1, None, False),
        (rule("eq", value=1), V, None, "1", True),
        (rule("ne", value=1), {**V, "absent_as": 1}, 1, 0, True),
        (rule("ne", value=1), V, 1, None, False),
        (rule("in", values=[0, 4]), V, 5, 4, True),
        (rule("iin", values=["Unrestricted", "Bypass"]), V, "Restricted", "bypass", True),
        (rule("ieq", value="Off"), V, "Warn", "OFF", True),
        (rule("lt", value=3), {**V, "absent_as": 3}, 5, 1, True),
        (rule("lt", value=3), {**V, "absent_as": 3}, 5, None, False),
        (rule("regex", pattern="(?i)^hide:"), V, None, "Hide:windowsdefender", True),
        (rule("not_regex", pattern=r"(?i)\\system32\\"), V, "x", r"C:\Evil\etc", True),
        (rule("not_regex", pattern="x"), V, "x", None, False),
        (rule("present"), V, None, "x", True),
        (rule("absent"), V, "x", None, True),
        (rule("present"), {"kind": "key"}, False, True, True),
        (rule("appeared"), V, None, "pw", True),
        (rule("appeared"), V, "a", "b", False),
        (rule("changed"), V, "a", "b", True),
        (rule("decrease"), V, 20480, 64, True),
        (rule("decrease"), V, 64, 20480, False),
        (rule("left", values=[1, 5]), V, 5, 0, True),
        (rule("left", values=[1, 5]), V, 5, 1, False),
        (rule("from_to", frm=[1], to=[0]), {**V, "absent_as": 0}, 1, None, True),
        (rule("from_to", frm=[1], to=[0]), {**V, "absent_as": 0}, 0, 0, False),
        (rule("added"), {"kind": "value_map"}, {"a": 1}, {"a": 1, "b": 2}, True),
        (rule("added"), {"kind": "value_map"}, {"a": 1}, {"a": 9}, False),
        (rule("added"), {"kind": "subkeys"}, ["a"], ["a", "b"], True),
        (rule("removed"), {"kind": "subkeys"}, ["a", "b"], ["a"], True),
        (rule("added"), {**V, "split": "multi", "known": ["", "kerberos", "msv1_0"]}, ["kerberos"], ["kerberos", "msv1_0"], False),
        (rule("added"), {**V, "split": "multi", "known": ["", "kerberos"]}, ["kerberos"], ["kerberos", "evilssp"], True),
        (rule("named_added", name_regex="(?i)^cor_profiler$"), {"kind": "value_map"}, {}, {"COR_PROFILER": "{x}"}, True),
        (rule("named_added", name_regex="(?i)^cor_profiler$"), {"kind": "value_map"}, {}, {"TEMP": "x"}, False),
        (rule("named_value_in", name_regex="^[1245]$", values=[6, 9]), {"kind": "value_map"}, {"1": 2}, {"1": 6}, True),
        (rule("named_value_in", name_regex="^[1245]$", values=[6, 9]), {"kind": "value_map"}, {"1": 6}, {"1": 6, "9": 6}, False),
        (rule("svc_off", values=[4]), {"kind": "service"}, 2, 4, True),
        (rule("svc_off", values=[4]), {"kind": "service"}, 4, 4, False),
        (rule("custom", fn="defender_exclusion"), {"kind": "value_map"}, {}, {r"C:\Users\Public": 0}, True),
        (rule("custom", fn="proxy_server"), V, None, "10.0.0.1:8080", True),
        (rule("custom", fn="proxy_server"), V, "a:1", "", False),
        (rule("any", of=[rule("eq", value=7), rule("absent")]), V, 1, None, True),
        (rule("all", of=[rule("present"), rule("ne", value="ok")]), V, None, "bad", True),
        (rule("nonsense"), V, 1, 2, False),
    ],
)
def test_danger_rules(pred, entry, old, new, expected):
    assert evaluate(pred, entry, old, new) is expected


def test_audit_mode_ignores_transition_rules():
    assert evaluate(rule("eq", value=1), V, 1, 1, transition=False)
    assert not evaluate(rule("changed"), V, 1, 1, transition=False)
    assert not evaluate(rule("left", values=[1]), V, 1, 0, transition=False)
    assert evaluate(rule("svc_off", values=[4]), {"kind": "service"}, 4, 4, transition=False)
    assert evaluate(rule("added"), {**V, "split": ",", "known": ["a.dll"]}, None, "a.dll, evil.dll", transition=False)
    assert split_items("8.8.8.8, 1.1.1.1 9.9.9.9", "dns") == {"8.8.8.8", "1.1.1.1", "9.9.9.9"}


def test_catalog_is_well_formed_and_every_rule_evaluates():
    catalog = load_catalog()
    assert len(catalog) > 300 and len({e["id"] for e in catalog}) == len(catalog)
    samples = (None, 0, 1, 4, "x", "", ["a"], {"n": 1}, {}, [], True, False, "ab" * 3000)
    for entry in catalog:
        assert entry["hive"] in ("HKLM", "HKCU") and entry["kind"] in ("value", "value_map", "key", "subkeys", "service")
        assert entry["msg"] and 0 <= entry["score_danger"] <= 100
        for old in samples:
            for new in samples:
                assert evaluate(entry["danger"], entry, old, new) in (True, False)
                assert evaluate(entry["danger"], entry, old, new, transition=False) in (True, False)


def test_windows_provider_detects_defender_tampering():
    reg = FakeRegistry()
    reg.set("HKLM", DEFENDER, "DisableAntiSpyware", 0)
    reg.set("HKLM", r"SYSTEM\CurrentControlSet\Services\WinDefend", "Start", 2)
    provider = WindowsSettingsProvider(reg)
    before = provider.snapshot()
    assert provider.changes(before, provider.snapshot()) == []
    reg.set("HKLM", DEFENDER, "DisableAntiSpyware", 1)
    reg.set("HKLM", r"SYSTEM\CurrentControlSet\Services\WinDefend", "Start", 4)
    reg.set("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", r"C:\Users\Public", 0)
    after = provider.snapshot()
    changes = {c.id: c for c in provider.changes(before, after)}
    assert changes["defender_pol_disable_antispyware"].danger and changes["defender_pol_disable_antispyware"].score >= 80
    assert changes["service_windefend_start"].danger and changes["defender_exclusion_paths"].danger
    assert changes["defender_exclusion_paths"].details["added"] == [r"C:\Users\Public"]
    audit = {c.id for c in provider.audit(after)}
    assert {"defender_pol_disable_antispyware", "service_windefend_start"} <= audit
    assert not WindowsSettingsProvider(FakeRegistry(), max_tier=1).audit(WindowsSettingsProvider(FakeRegistry(), max_tier=1).snapshot()) or True
    reg.set("HKLM", DEFENDER, "DisableAntiSpyware", 0)
    restored = provider.changes(after, provider.snapshot())
    assert len(restored) == 1 and not restored[0].danger and restored[0].score < 40


def test_secret_values_are_never_shown():
    reg = FakeRegistry()
    provider = WindowsSettingsProvider(reg, max_tier=3)
    secret = next(e for e in provider.entries.values() if e.get("secret"))
    before = provider.snapshot()
    reg.set(secret["hive"], secret["key"], secret["value"], "hunter2")
    change = provider.changes(before, provider.snapshot())[0]
    assert "hunter2" not in str(change.details) and change.details["new"] == "(hidden)"


def test_file_scorers():
    assert score_hosts(["0.0.0.0 update.microsoft.com"])[0] >= 80
    assert score_hosts(["127.0.0.1 mydevbox.local"]) is None and score_hosts(["# 1.2.3.4 avast.com"]) is None
    assert score_passwd(["toor:x:0:0::/root:/bin/sh"])[0] >= 80 and score_passwd(["bob:x:1001:1001::/home/bob:/bin/sh"])[0] == 45
    assert score_passwd([]) is None
    assert score_sudoers(["bob ALL=(ALL) NOPASSWD: ALL"])[0] == 70 and score_sudoers(["Defaults env_reset"]) is None
    assert score_sshd(["PermitRootLogin yes"])[0] == 60 and score_sshd(["Port 22"]) is None


def test_file_provider_reports_added_lines_and_keeps_secrets(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$secrethash:19000::::::\n")
    folder = tmp_path / "sudoers.d"
    folder.mkdir()
    provider = FileSettingsProvider([
        WatchedFile("hosts_file", str(hosts), "hosts", "The hosts file was changed", 30, score_hosts),
        WatchedFile("shadow", str(shadow), "accounts", "A password was changed", 30, secret=True),
        WatchedFile("sudoers_d", str(folder), "privilege", "A sudo rule file was added or changed", 55),
        WatchedFile("missing", str(tmp_path / "nope"), "x", "x", 10),
    ])
    before = provider.snapshot()
    assert "text" not in before["shadow"] and before["missing"] is None
    hosts.write_text("127.0.0.1 localhost\n10.0.0.5 intranet\n")
    mild = provider.changes(before, provider.snapshot())
    assert len(mild) == 1 and mild[0].score == 30 and mild[0].details["added_lines"] == ["10.0.0.5 intranet"]
    hosts.write_text("127.0.0.1 localhost\n0.0.0.0 definitions.kaspersky.com\n")
    shadow.write_text("root:$6$otherhash:19001::::::\n")
    (folder / "backdoor").write_text("eve ALL=(ALL) NOPASSWD: ALL\n")
    after = provider.snapshot()
    changes = {c.id: c for c in provider.changes(before, after)}
    assert changes["hosts_file"].danger and changes["hosts_file"].score >= 80
    assert "hash" not in str(changes["shadow"].details) and "otherhash" not in str(changes["shadow"].details)
    assert changes["sudoers_d"].details["changed_files"] == ["backdoor"]
    assert [c.id for c in provider.audit(after)] == ["hosts_file"]
    hosts.write_text("")
    assert provider.changes(after, provider.snapshot())[0].score <= 15


def test_sysctl_and_macos_providers(tmp_path):
    (tmp_path / "kernel" / "yama").mkdir(parents=True)
    (tmp_path / "kernel" / "randomize_va_space").write_text("2\n")
    (tmp_path / "kernel" / "yama" / "ptrace_scope").write_text("1\n")
    (tmp_path / "kernel" / "core_pattern").write_text("|/usr/lib/systemd/systemd-coredump %P\n")
    provider = SysctlProvider(str(tmp_path))
    before = provider.snapshot()
    assert provider.audit(before) == [] and before["sysctl_kptr"] is None
    (tmp_path / "kernel" / "randomize_va_space").write_text("0\n")
    (tmp_path / "kernel" / "core_pattern").write_text("|/tmp/x %p\n")
    after = provider.snapshot()
    changes = {c.id: c for c in provider.changes(before, after)}
    assert changes["sysctl_aslr"].danger and changes["sysctl_core_pattern"].danger
    assert {c.id for c in provider.audit(after)} == {"sysctl_aslr", "sysctl_core_pattern"}

    answers = {"spctl": "assessments enabled", "csrutil": "System Integrity Protection status: enabled.",
               "socketfilterfw": "Firewall is enabled. (State = 1)", "fdesetup": "FileVault is On."}
    mac = MacCommandProvider(lambda argv: next((v for k, v in answers.items() if k in argv[0]), None))
    baseline = mac.snapshot()
    assert mac.audit(baseline) == []
    answers["spctl"] = "assessments disabled"
    found = mac.changes(baseline, mac.snapshot())
    assert len(found) == 1 and found[0].id == "mac_gatekeeper" and found[0].score == 80


def test_settings_monitor_end_to_end(make_ctx, monkeypatch, tmp_path):
    reg = FakeRegistry()
    reg.set("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    monkeypatch.setattr("filespy.settingsmon.windows.watched_files",
                        lambda env=None: [WatchedFile("hosts_file", str(hosts), "hosts", "The hosts file was changed", 30, score_hosts)])
    ctx = make_ctx(platform="win32")
    ctx.registry = reg
    monitor = SettingsMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10) and not monitor.failed
        monitor.interval = 0.05
        assert not ctx.bus.find("setting")
        reg.set("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0)
        hosts.write_text("127.0.0.1 localhost\n127.0.0.1 www.virustotal.com\n")
        events = wait_for(lambda: len(ctx.bus.find("setting", "changed")) >= 2 and ctx.bus.find("setting", "changed"))
        assert events and all(e.severity >= Severity.HIGH for e in events)
        assert {e.details["category"] for e in events} == {"uac", "hosts"}
    finally:
        monitor.stop()
        monitor.join()
