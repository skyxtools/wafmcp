"""OAST via interactsh - the strongest evidence a blind finding is real.

Blind SSRF, blind RCE, blind SQLi (out-of-band), XXE - none reflect anything in
the HTTP response. The only trustworthy proof is that the *target* reached out to
an infrastructure endpoint we control. This wraps `interactsh-client` when the
binary is available, and degrades gracefully otherwise.

Flow:
  session = OastSession.start()          # registers a unique callback domain
  payload_host = session.domain          # embed http://<payload_host>/x in payload
  ... send payload via Probe ...
  hits = session.poll()                  # any DNS/HTTP interaction == real callback
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# Strip ANSI colour codes interactsh-client emits on its log lines.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A payload domain looks like "<32+ base36 chars>.oast.<tld>" possibly wrapped in
# a log line like "[INF] d98h...oast.fun". Match it anywhere on the line.
_DOMAIN_RE = re.compile(r"\b([a-z0-9]{20,}\.oast\.[a-z]+)\b", re.IGNORECASE)


class OastUnavailable(Exception):
    pass


@dataclass
class Interaction:
    protocol: str          # dns | http | smtp
    remote_addr: str
    raw: dict[str, Any]
    timestamp: str


@dataclass
class OastSession:
    domain: str
    _proc: subprocess.Popen | None = None
    _interactions: list[Interaction] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _reader: threading.Thread | None = None
    _err_reader: threading.Thread | None = None
    _alive: bool = True

    @classmethod
    def available(cls) -> bool:
        return shutil.which("interactsh-client") is not None

    @classmethod
    def start(cls, server: str | None = None, token: str | None = None) -> "OastSession":
        if not cls.available():
            raise OastUnavailable(
                "interactsh-client not found on PATH. Install from "
                "https://github.com/projectdiscovery/interactsh (or self-host and set the "
                "server URL) to enable out-of-band verification."
            )
        cmd = ["interactsh-client", "-json", "-v"]
        if server:
            cmd += ["-server", server]
        if token:
            cmd += ["-token", token]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        sess = cls(domain="", _proc=proc)
        # Two independent readers: the payload domain is logged to stderr, while
        # interaction JSON arrives on stdout. Reading them in one loop would block
        # on stderr (which never closes while the client runs) and miss stdout.
        sess._reader = threading.Thread(target=sess._pump_stdout, daemon=True)
        sess._reader.start()
        sess._err_reader = threading.Thread(target=sess._pump_stderr, daemon=True)
        sess._err_reader.start()
        # wait for the client to announce the payload domain
        deadline = time.time() + 12
        while time.time() < deadline and not sess.domain:
            time.sleep(0.2)
        if not sess.domain:
            sess.stop()
            raise OastUnavailable("interactsh-client did not report a payload domain in time.")
        return sess

    def _pump_stderr(self) -> None:
        """Scan stderr log lines for the payload domain (ANSI/prefix tolerant)."""
        assert self._proc is not None
        for line in self._proc.stderr:  # type: ignore[union-attr]
            clean = _ANSI.sub("", line).strip()
            if not self.domain:
                m = _DOMAIN_RE.search(clean)
                if m:
                    self.domain = m.group(1).lower()

    def _pump_stdout(self) -> None:
        """Collect interaction JSON lines from stdout."""
        assert self._proc is not None
        for line in self._proc.stdout:  # type: ignore[union-attr]
            clean = _ANSI.sub("", line).strip()
            if not clean:
                continue
            try:
                obj = json.loads(clean)
            except json.JSONDecodeError:
                # some builds also print the domain to stdout; catch it here too
                if not self.domain:
                    m = _DOMAIN_RE.search(clean)
                    if m:
                        self.domain = m.group(1).lower()
                continue
            with self._lock:
                self._interactions.append(
                    Interaction(
                        protocol=obj.get("protocol", "?"),
                        remote_addr=obj.get("remote-address", obj.get("remote_addr", "?")),
                        raw=obj,
                        timestamp=obj.get("timestamp", ""),
                    )
                )

    def poll(self, wait: float = 3.0) -> list[Interaction]:
        """Return interactions seen so far, optionally waiting `wait` seconds first."""
        if wait > 0:
            time.sleep(wait)
        with self._lock:
            return list(self._interactions)

    def stop(self) -> None:
        self._alive = False
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
