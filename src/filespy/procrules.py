"""Runtime heuristics over one process: command line, image location, name and parent.

All patterns use bounded repetition so an attacker-supplied command line cannot make
matching slow, and command lines are truncated before matching.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

from filespy import fileinfo
from filespy.analyzer import WINDOWS_SYSTEM_NAMES, name_indicators
from filespy.events import Indicator, Severity
from filespy.paths import basename, classify_location
from filespy.state import SharedState

MAX_CMDLINE = 8192
H, C = Severity.HIGH, Severity.CRITICAL


@dataclass
class ProcInfo:
    pid: int
    name: str = ""
    exe: str = ""
    cmdline: list[str] = field(default_factory=list)
    ppid: int = 0
    username: str = ""
    create_time: float = 0.0
    parent_name: str = ""
    parent_exe: str = ""

    @property
    def command(self) -> str:
        return " ".join(self.cmdline)[:MAX_CMDLINE]


@dataclass(frozen=True)
class CmdRule:
    id: str
    score: int
    platforms: str  # win | posix | mac | any
    pattern: re.Pattern[str]
    description: str
    mitre: str = ""
    floor: Severity | None = None


def _r(id: str, score: int, platforms: str, pattern: str, description: str, mitre: str = "", floor: Severity | None = None) -> CmdRule:
    return CmdRule(id, score, platforms, re.compile(pattern, re.IGNORECASE | re.DOTALL), description, mitre, floor)


_PS = r"\b(?:powershell|pwsh)(?:\.exe)?\b"
_SECURITY = (r"(?:windefend|wscsvc|securityhealth|mpssvc|msmpeng|sense\b|sysmon|mbam|avast|avg|kaspersky|"
             r"bitdefender|eset|sophos|mcafee|norton|malwarebytes)")
_USERDIR = r"(?:\\appdata\\|\\temp\\|\\downloads\\|\\programdata\\|\\users\\public\\)"

CMD_RULES: tuple[CmdRule, ...] = (
    # ---- Windows -------------------------------------------------------------------------
    _r("ps_encoded", 60, "win", _PS + r".{0,400}?\s[-/](?:e|ec|en|enc|enco\w*)\s+[\"']?[A-Za-z0-9+/=]{16,}",
       "PowerShell was started with a hidden, base64-encoded command", "T1059.001"),
    _r("ps_hidden_bypass", 45, "win",
       _PS + r"(?=.{0,400}\s[-/]w(?:in(?:dowstyle)?)?\s+h(?:id(?:den)?)?\b)"
       r"(?=.{0,400}(?:\s[-/](?:ep|ex(?:ec(?:utionpolicy)?)?)\s+(?:bypass|unrestricted)|\s[-/]nop(?:rofile)?\b))",
       "PowerShell was started hidden with its safety policy bypassed", "T1059.001"),
    _r("ps_download", 50, "win",
       _PS + r".{0,600}(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|"
       r"\birm\b|start-bitstransfer|net\.webclient)",
       "PowerShell is downloading something from the internet", "T1105"),
    _r("ps_decode_run", 40, "win", _PS + r".{0,600}frombase64string",
       "PowerShell is decoding hidden content", "T1027"),
    _r("defender_tamper", 80, "win",
       r"(?:set-mppreference\b.{0,200}-disable\w+\s+(?:\$?true|1)\b|add-mppreference\b.{0,200}-exclusion(?:path|process|extension))",
       "A command is switching off Microsoft Defender or adding an exclusion", "T1562.001", H),
    _r("mshta_remote", 70, "win", r"\bmshta(?:\.exe)?[\"']?\s+.{0,60}(?:https?://|javascript:|vbscript:)",
       "mshta is running script from the internet or from its command line", "T1218.005"),
    _r("regsvr32_scriptlet", 70, "win", r"\bregsvr32(?:\.exe)?\b.{0,200}(?:/i:\s*[\"']?(?:https?|ftp)://|scrobj\.dll)",
       "regsvr32 is being used to run a remote script", "T1218.010"),
    _r("rundll32_abuse", 70, "win",
       r"\brundll32(?:\.exe)?\b.{0,200}(?:javascript:|vbscript:|url\.dll\s*,\s*(?:fileprotocolhandler|openurl)|"
       r"shell32(?:\.dll)?\s*,\s*shellexec_rundll|comsvcs(?:\.dll)?[\s,]+(?:#24|minidump))",
       "rundll32 is being used to run script or dump memory", "T1218.011"),
    _r("certutil_download", 60, "win", r"\bcertutil(?:\.exe)?\b.{0,200}[-/](?:urlcache|verifyctl)\b",
       "certutil is being used to download a file", "T1105"),
    _r("certutil_decode", 35, "win", r"\bcertutil(?:\.exe)?\b.{0,200}[-/]decode(?:hex)?\b",
       "certutil is decoding a hidden file", "T1140"),
    _r("bitsadmin_transfer", 55, "win", r"\bbitsadmin(?:\.exe)?\b.{0,200}/(?:transfer|addfile|setnotifycmdline)\b",
       "bitsadmin is being used to download or run a file", "T1197"),
    _r("wmic_exec", 55, "win",
       r"\bwmic(?:\.exe)?\b.{0,200}(?:process\s+call\s+create|/format:\s*[\"']?(?:https?://|\\\\))",
       "WMIC is being used to start a program or load a remote stylesheet", "T1047"),
    _r("shadow_delete", 85, "win",
       r"(?:\bvssadmin(?:\.exe)?\b.{0,100}delete\s+shadows|\bwmic(?:\.exe)?\b.{0,100}shadowcopy\b.{0,50}delete|"
       r"\bwbadmin(?:\.exe)?\b.{0,100}delete\s+(?:catalog|systemstatebackup)|"
       r"\bbcdedit(?:\.exe)?\b.{0,200}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))",
       "Backups or recovery options are being deleted - typical ransomware preparation", "T1490", H),
    _r("log_clear", 60, "win", r"(?:\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|\bclear-eventlog\b|\bfsutil(?:\.exe)?\s+usn\s+deletejournal)",
       "Windows event logs are being erased", "T1070.001"),
    _r("schtasks_create_suspicious", 60, "win",
       r"\bschtasks(?:\.exe)?\b.{0,300}/create\b.{0,500}(?:" + _USERDIR + r"|powershell|mshta|wscript|cscript|cmd(?:\.exe)?\s+/c|rundll32|regsvr32)",
       "A scheduled task is being created that runs a script host or a program from a user folder", "T1053.005"),
    _r("schtasks_create", 30, "win", r"\bschtasks(?:\.exe)?\b.{0,300}/create\b",
       "A scheduled task is being created", "T1053.005"),
    _r("reg_persistence", 55, "win",
       r"\breg(?:\.exe)?\s+add\b.{0,300}(?:\\currentversion\\(?:run|runonce|policies\\explorer\\run)\b|\\winlogon\b|image file execution options)",
       "A startup entry is being written to the registry", "T1547.001"),
    _r("reg_security_tamper", 80, "win",
       r"\breg(?:\.exe)?\s+add\b.{0,300}(?:windows defender|disableantispyware|disablerealtimemonitoring|enablelua|disabletaskmgr|disableregistrytools)",
       "Security settings are being changed through the registry", "T1562.001", H),
    _r("service_create", 40, "win", r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?(?:create|config)\b.{0,300}binpath\s*=",
       "A Windows service is being created or re-pointed", "T1543.003"),
    _r("firewall_tamper", 60, "win",
       r"\bnetsh(?:\.exe)?\b.{0,100}(?:advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(?:mode\s*=\s*)?disable|"
       r"firewall\s+add\s+allowedprogram|interface\s+portproxy\s+add)",
       "The Windows firewall is being switched off or opened up", "T1562.004"),
    _r("security_tool_stop", 70, "win",
       r"(?:\bsc(?:\.exe)?\s+(?:stop|delete|config)|\bnet1?(?:\.exe)?\s+stop|\bstop-service|\btaskkill(?:\.exe)?\b.{0,80}/im)\s.{0,80}" + _SECURITY,
       "A security product or service is being stopped", "T1562.001"),
    _r("account_add", 50, "win", r"\bnet1?(?:\.exe)?\s+(?:user|localgroup)\b.{0,120}/add\b",
       "A user account is being created or added to a group", "T1136.001"),
    _r("credential_dump", 90, "any",
       r"(?:\bprocdump(?:64)?(?:\.exe)?\b.{0,100}lsass|sekurlsa::|lsadump::|privilege::debug|"
       r"\breg(?:\.exe)?\s+save\s+hk(?:lm|ey_local_machine)\\(?:sam|security|system)\b|\bntdsutil\b.{0,100}\bifm\b)",
       "Stored passwords are being dumped", "T1003", H),
    _r("script_from_user_dir", 50, "win",
       r"\b(?:wscript|cscript)(?:\.exe)?\b.{0,200}" + _USERDIR + r".{0,200}\.(?:vbs|vbe|js|jse|wsf|wsh)\b",
       "Windows Script Host is running a script from a user or temporary folder", "T1059.005"),
    _r("attrib_hide", 30, "win", r"\battrib(?:\.exe)?\s.{0,60}\+[hs]\b.{0,60}\+[hs]\b",
       "Files are being marked hidden and system", "T1564.001"),
    _r("tunnel_tool", 40, "any",
       r"(?:^|[\\/\s\"'])(?:ngrok|chisel|frpc|cloudflared)(?:\.exe)?[\"']?\s.{0,200}(?:\btcp\b|\bhttp\b|\bclient\b|\btunnel\b|\s-c\s)",
       "A tunnelling tool is exposing this computer to the internet", "T1572"),
    # ---- Linux / macOS -------------------------------------------------------------------
    _r("reverse_shell", 85, "posix",
       r"(?:/dev/(?:tcp|udp)/\d|\bn(?:c|cat)\b.{0,80}\s-[a-z]*e\s+\S*(?:sh|bash)\b|\bsocat\b.{0,200}exec:|"
       r"\bbash\s+-i\s*>&|pty\.spawn\(|\bmkfifo\s.{0,100}\|\s*n(?:c|cat)\b)",
       "A reverse shell is giving someone remote control of this computer", "T1059.004", H),
    _r("pipe_to_shell", 60, "posix",
       r"\b(?:curl|wget)\b.{1,300}\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[\d.]*|perl|osascript)\b",
       "A download is being piped straight into an interpreter", "T1105"),
    _r("base64_to_shell", 70, "posix", r"\bbase64\s+(?:-d|-D|--decode)\b.{0,100}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
       "Hidden (base64) content is being decoded and executed", "T1027"),
    _r("history_tamper", 40, "posix", r"(?:\bunset\s+histfile\b|\bhistsize=0\b|\bhistory\s+-c\b|\bhistfile=/dev/null\b)",
       "Shell history is being disabled or erased", "T1070.003"),
    _r("security_disable", 55, "posix",
       r"(?:\bsetenforce\s+0\b|\bufw\s+disable\b|\biptables\s+(?:-F|--flush)\b|"
       r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:--now\s+)?(?:auditd|apparmor|firewalld|falco|clamav\S*|ufw)\b)",
       "A firewall or security service is being switched off", "T1562.001"),
    _r("preload_write", 80, "posix", r"(?:>>?|\btee\s+(?:-a\s+)?)\s*/etc/ld\.so\.preload\b",
       "The system-wide library preload file is being written - a rootkit technique", "T1574.006", H),
    _r("preload_env", 45, "posix", r"\bLD_PRELOAD=\S",
       "A program is being started with an injected library (LD_PRELOAD)", "T1574.006"),
    _r("cron_edit", 50, "posix", r"(?:\|\s*crontab\s+-(?:\s|$)|>>?\s*/etc/cron|>>?\s*/var/spool/cron)",
       "A scheduled job (cron) is being installed from a script", "T1053.003"),
    _r("miner", 70, "any", r"(?:stratum\+(?:tcp|ssl)://|--donate-level\b|(?:^|[\\/\s])xmrig(?:\.exe)?\b|--coin[= ]monero)",
       "A cryptocurrency miner is running", "T1496"),
    # ---- macOS ---------------------------------------------------------------------------
    _r("osascript_prompt", 60, "mac",
       r"\bosascript\b.{0,400}(?:with\s+administrator\s+privileges|hidden\s+answer|display\s+dialog.{0,200}password)",
       "A script is asking for your password or for administrator rights", "T1059.002"),
    _r("quarantine_removed", 45, "mac", r"\bxattr\b.{0,40}\s-[a-z]*d[a-z]*\s+com\.apple\.quarantine",
       "The download quarantine flag is being removed so Gatekeeper will not check a file", "T1553.001"),
    _r("gatekeeper_off", 70, "mac", r"(?:\bspctl\s+--(?:master|global)-disable\b|\bcsrutil\s+disable\b)",
       "Gatekeeper or System Integrity Protection is being switched off", "T1553.001"),
    _r("keychain_dump", 55, "mac", r"\bsecurity\s+(?:dump-keychain\b|find-(?:generic|internet)-password\b.{0,200}\s-w\b)",
       "Saved passwords are being read from the keychain", "T1555.001"),
    _r("launchctl_temp", 60, "mac", r"\blaunchctl\s+(?:load|bootstrap)\b.{0,200}(?:/tmp/|/private/tmp/|/users/shared/|/var/tmp/)",
       "A background service is being loaded from a temporary folder", "T1543.001"),
)

_OFFICE = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
    "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe", "thunderbird.exe", "wordpad.exe",
})
_SCRIPT_HOSTS = frozenset({"wscript.exe", "cscript.exe", "mshta.exe"})
_BROWSERS = frozenset({"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"})
_SHELLS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe", "schtasks.exe",
})
_SQUAT_TARGETS = (
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "explorer.exe", "spoolsv.exe",
    "dllhost.exe", "conhost.exe", "rundll32.exe", "powershell.exe", "taskmgr.exe",
)
_LEGIT_NEAR = frozenset({"taskhost.exe", "taskhostw.exe", "taskhostex.exe", "service.exe", "explore.exe"})
_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a", "|": "l",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0456": "i",
    "\u0131": "i", "\u03bf": "o",
})


def _edit_distance_one(a: str, b: str) -> bool:
    """True if a and b differ by exactly one insertion, deletion, substitution or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(long_)):
        if long_[:i] + long_[i + 1:] == short:
            return True
    return False


def lookalike_of(name: str) -> str:
    """Return the Windows system program this name imitates ("svch0st.exe" -> "svchost.exe"), or ""."""
    lowered = name.lower()
    if lowered in WINDOWS_SYSTEM_NAMES or lowered in _LEGIT_NEAR or not lowered.endswith(".exe"):
        return ""
    folded = lowered.translate(_HOMOGLYPHS).replace("vv", "w").replace("rn", "m")
    for target in _SQUAT_TARGETS:
        if folded == target or _edit_distance_one(lowered, target):
            return target
    return ""


def _created_since(path: str, moment: float) -> bool:
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return False
    return max(info.st_ctime, info.st_mtime) >= moment


def _platform_tag(platform: str) -> set[str]:
    if platform == "win32":
        return {"win", "any"}
    if platform == "darwin":
        return {"posix", "mac", "any"}
    return {"posix", "any"}


def command_indicators(command: str, platform: str) -> list[Indicator]:
    if not command:
        return []
    tags = _platform_tag(platform)
    command = command[:MAX_CMDLINE]
    out = []
    for rule in CMD_RULES:
        if rule.platforms in tags and rule.pattern.search(command):
            out.append(Indicator(f"proc.cmd.{rule.id}", rule.score, rule.description, rule.mitre, rule.floor))
    ids = {i.id for i in out}
    if "proc.cmd.schtasks_create_suspicious" in ids:  # the generic rule adds nothing on top
        out = [i for i in out if i.id != "proc.cmd.schtasks_create"]
    return out


def evaluate(
    proc: ProcInfo,
    platform: str,
    state: SharedState | None = None,
    young_minutes: float = 15.0,
    now: float | None = None,
) -> list[Indicator]:
    """Every reason this newly started process looks suspicious (empty for a normal one)."""
    out = command_indicators(proc.command, platform)
    name = (proc.name or basename(proc.exe)).lower()
    parent = proc.parent_name.lower()
    exe = proc.exe
    location = classify_location(exe, platform) if exe else "other"

    drop = state.lookup_drop(exe.removesuffix(" (deleted)")) if exe and state is not None else None
    dropped = drop is not None
    if not dropped and state is not None and exe and location not in ("system", "program"):
        # The file monitor may not have reported it yet (or the folder is not watched):
        # a program file created after FileSpy started is a drop all the same.
        dropped = _created_since(exe, state.started)
    if dropped:
        score = drop.score if drop is not None else 0
        floor = C if score >= 90 else H if score >= 40 else None
        out.append(Indicator("proc.dropped_file_executed", 50,
                             "This program is a file that was dropped while FileSpy was watching", "T1204.002", floor))
    elif location == "temp":
        out.append(Indicator("proc.image_in_temp", 25, "The program is running from a temporary folder", "T1204.002"))
    elif location == "startup":
        out.append(Indicator("proc.image_in_startup", 25, "The program is running from a startup location", "T1547.001"))
    elif location == "user_writable":
        out.append(Indicator("proc.image_user_writable", 10, "The program is running from a user-writable folder", ""))
    if not dropped and exe and location in ("temp", "user_writable", "startup", "other") and young_minutes > 0:
        try:
            info = os.stat(exe)
            age = (now or time.time()) - max(info.st_mtime, info.st_ctime)
            # A coarse system clock can lag a file's timestamp by a few milliseconds, so allow a little skew.
            if -5 <= age < young_minutes * 60:
                out.append(Indicator("proc.young_image", 20, "The program file was created or changed only minutes ago", "T1204.002"))
        except OSError:
            pass
    if state is not None and not dropped:
        for argument in proc.cmdline[1:6]:
            # A dropped script is run by an interpreter, so it shows up as an argument, not as the image.
            if len(argument) > 2 and os.path.isabs(argument) and (
                state.lookup_drop(argument) is not None
                or (fileinfo.extension(argument) in fileinfo.RISKY_EXTS and _created_since(argument, state.started))
            ):
                record = state.lookup_drop(argument)
                score = record.score if record is not None else 0
                floor = C if score >= 90 else H if score >= 40 else None
                out.append(Indicator("proc.dropped_script_executed", 45,
                                     "It is running a script that was dropped while FileSpy was watching", "T1204.002", floor))
                break
    if platform != "win32" and exe and (exe.endswith(" (deleted)") or exe.startswith(("memfd:", "/memfd:"))):
        out.append(Indicator("proc.deleted_image", 55, "The program deleted its own file after starting, or runs only from memory", "T1070.004"))

    if platform == "win32" and name:
        if name in WINDOWS_SYSTEM_NAMES and exe and location not in ("system", "program"):
            out.append(Indicator("proc.system_name_wrong_dir", 70,
                                 f"Uses the name of the Windows system program {name} but runs from another folder", "T1036.005"))
        else:
            target = lookalike_of(name)
            if target:
                out.append(Indicator("proc.lookalike_name", 55, f"The name imitates the Windows system program {target}", "T1036.005"))
        if name in _SHELLS:
            if parent in _OFFICE:
                out.append(Indicator("proc.office_child", 60, f"A document or mail program ({parent}) started {name}", "T1204.002"))
            elif parent in _SCRIPT_HOSTS and name != parent:
                out.append(Indicator("proc.script_host_child", 45, f"A script host ({parent}) started {name}", "T1059"))
            elif parent in _BROWSERS and name in _SCRIPT_HOSTS | {"powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe"}:
                out.append(Indicator("proc.browser_child", 45, f"A web browser ({parent}) started {name}", "T1189"))
    image_name = basename(exe) if exe else proc.name
    for ind in name_indicators(image_name, "pe"):
        if ind.id in ("file.name_bidi", "file.double_extension", "file.name_padding"):
            out.append(Indicator(ind.id.replace("file.", "proc."), ind.score, ind.description, ind.mitre))
    if exe and fileinfo.extension(image_name) in fileinfo.DECOY_EXTS:
        out.append(Indicator("proc.decoy_extension", 50, "A running program is named like a document or picture", "T1036.008"))
    return out
