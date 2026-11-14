"""Network side of runtime detection: new listeners, and connections made by suspicious programs."""

from __future__ import annotations

import ipaddress
import os

from filespy import sanitize
from filespy.events import Indicator, Severity
from filespy.monitors.base import Monitor
from filespy.paths import classify_location

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

#: Default ports of common remote-access tools and C2 frameworks. A port alone proves
#: nothing, so a match only adds a small score on top of other evidence.
KNOWN_PORTS = {
    1177: "njRAT", 5552: "njRAT", 1604: "DarkComet", 2404: "Remcos", 4782: "Quasar", 6606: "AsyncRAT",
    7707: "AsyncRAT", 8808: "AsyncRAT", 54984: "NanoCore", 3460: "Poison Ivy", 5200: "Warzone",
    7000: "XWorm", 10134: "Orcus", 4444: "Metasploit", 4445: "Metasploit", 31337: "Back Orifice / Sliver",
    50050: "Cobalt Strike", 40056: "Havoc", 12345: "NetBus", 27374: "SubSeven", 6667: "IRC", 6697: "IRC",
    9001: "Tor", 9030: "Tor", 9050: "Tor", 9150: "Tor", 3333: "mining pool", 14444: "mining pool",
}
#: Windows programs that have little reason to talk to the internet on their own.
QUIET_PROGRAMS = frozenset({
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe",
})


def is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


class NetworkMonitor(Monitor):
    name = "network"

    def setup(self) -> None:
        if psutil is None:
            raise RuntimeError("psutil is not installed (pip install psutil)")
        self.interval = self.ctx.config.network.interval
        self._listeners: set[tuple[int, int]] = set()
        self._outbound: set[tuple[int, str, int]] = set()
        self._denied = False
        for conn in self._connections():
            self._remember(conn)

    def _connections(self) -> list:
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            if not self._denied:
                self._denied = True
                self.system("warning", "Network connections of other programs are not visible without administrator rights "
                                       "on this system; only limited network monitoring is active.", Severity.LOW)
            return []

    def _remember(self, conn) -> bool:
        """Record a connection; True if it has not been seen before."""
        pid = conn.pid or 0
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            key = (pid, conn.laddr.port)
            if key in self._listeners:
                return False
            self._listeners.add(key)
            return True
        if conn.raddr:
            key3 = (pid, conn.raddr.ip, conn.raddr.port)
            if key3 in self._outbound:
                return False
            if len(self._outbound) > 50000:
                self._outbound.clear()
            self._outbound.add(key3)
            return True
        return False

    def poll(self) -> None:
        for conn in self._connections():
            if self._remember(conn) and conn.pid and conn.pid != self.ctx.state.own_pid:
                if conn.status == psutil.CONN_LISTEN:
                    self._on_listen(conn)
                elif conn.raddr:
                    self._on_connect(conn)

    def _process(self, pid: int) -> tuple[str, str]:
        try:
            proc = psutil.Process(pid)
            return proc.name(), proc.exe()
        except (psutil.Error, OSError):
            return "", ""

    def _on_listen(self, conn) -> None:
        if not self.ctx.config.network.report_listeners:
            return
        name, exe = self._process(conn.pid)
        port, address = conn.laddr.port, conn.laddr.ip
        flagged = self.ctx.state.flagged(conn.pid)
        location = classify_location(exe, self.ctx.platform) if exe else "other"
        exposed = address not in ("127.0.0.1", "::1")
        indicators = []
        if flagged:
            indicators.append(Indicator("net.flagged_listener", 60, "A program already flagged as suspicious opened a port for incoming connections", "T1571", Severity.HIGH))
        elif location in ("temp", "startup"):
            indicators.append(Indicator("net.temp_listener", 45, "A program running from a temporary folder opened a port for incoming connections", "T1571"))
        elif location == "user_writable" and exposed:
            indicators.append(Indicator("net.user_dir_listener", 20, "A program in a user-writable folder is accepting connections from the network", "T1571"))
        if port in KNOWN_PORTS and indicators:
            indicators.append(Indicator("net.known_port", 15, f"Port {port} is the default for {KNOWN_PORTS[port]}", "T1571"))
        if not indicators:
            return
        shown = sanitize.clean(name or f"pid {conn.pid}", 80)
        self.emit("network", "listen", f"{shown} is listening on port {port}", f"{address}:{port}", indicators,
                  {"pid": conn.pid, "name": name, "exe": exe, "local_address": address, "local_port": port})

    def _on_connect(self, conn) -> None:
        remote, port = conn.raddr.ip, conn.raddr.port
        if not is_public(remote):
            return
        flagged = self.ctx.state.flagged(conn.pid)
        name, exe = (flagged.name, flagged.exe) if flagged else self._process(conn.pid)
        indicators = []
        if flagged:
            indicators.append(Indicator("net.flagged_connect", 60, "A program already flagged as suspicious connected to the internet", "T1071", Severity.HIGH))
        elif self.ctx.platform == "win32" and os.path.basename(name).lower() in QUIET_PROGRAMS:
            indicators.append(Indicator("net.quiet_program_connect", 45, f"{name} rarely needs the internet but connected to a remote host", "T1218"))
        elif exe and classify_location(exe, self.ctx.platform) in ("temp", "startup"):
            indicators.append(Indicator("net.temp_connect", 30, "A program running from a temporary folder connected to the internet", "T1071"))
        if not indicators:
            return
        if port in KNOWN_PORTS:
            indicators.append(Indicator("net.known_port", 15, f"Port {port} is the default for {KNOWN_PORTS[port]}", "T1571"))
        shown = sanitize.clean(name or f"pid {conn.pid}", 80)
        details = {"pid": conn.pid, "name": name, "exe": exe, "remote_address": remote, "remote_port": port}
        if flagged:
            details["flag_reason"] = flagged.reason
        self.emit("network", "connect", f"{shown} connected to {remote}:{port}", f"{remote}:{port}", indicators, details)
