"""Fixed read-only Windows resource adapter, for trusted hosts only.

No network endpoint, no arbitrary script content, no shell expansion, and
no public/production data upload. Deployment requires separate user activation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

class WindowsPressureAdapter:
    def __init__(self, trusted_script: str, expected_sha256: str, timeout_seconds: int = 35):
        if os.name != "nt":
            raise RuntimeError("Windows-only adapter")
        if type(timeout_seconds) is not int or not 5 <= timeout_seconds <= 60:
            raise ValueError("bounded timeout required")
        script = Path(trusted_script).resolve(strict=True)
        if script.name != "ReadOnly-Pressure.ps1" or script.suffix.lower() != ".ps1":
            raise ValueError("unexpected trusted script basename")
        if script.is_symlink() or not script.is_file():
            raise ValueError("trusted script must be a regular file")
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise ValueError("pinned script hash required")
        actual = hashlib.sha256(script.read_bytes()).hexdigest()
        if actual != expected_sha256.lower():
            raise PermissionError("read-only script pin mismatch")
        systemroot = os.environ.get("SystemRoot", r"C:\Windows")
        executable = Path(systemroot) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if not executable.is_file():
            raise RuntimeError("Windows PowerShell 5.1 not found")
        self._script = script
        self._expected = actual
        self._exe = str(executable)
        self._timeout = timeout_seconds

    def snapshot(self, payload: dict) -> dict:
        if payload != {}:
            raise ValueError("this operation accepts no arguments")
        if hashlib.sha256(self._script.read_bytes()).hexdigest() != self._expected:
            raise PermissionError("trusted script changed after registration")
        # Fixed path and arguments; never accept shell strings from a request.
        completed = subprocess.run(
            [self._exe, "-NoProfile", "-NonInteractive", "-File", str(self._script)],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=self._timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("bounded read-only diagnostic failed")
        if len(completed.stdout) > 128 * 1024:
            raise ValueError("diagnostic result too large")
        payload = json.loads(completed.stdout)
        ram = payload.get("ram") or {}
        if payload.get("schema") != 1 or "used_pct" not in ram:
            raise ValueError("diagnostic output schema mismatch")
        # Local-only, minimal aggregate return. Raw PID/service/log evidence is
        # never transmitted by the adapter and can be retained locally separately.
        return {
            "schema": 1,
            "utc": payload.get("utc"),
            "ram_used_percent": ram["used_pct"],
            "process_count": payload["process_count"],
            "status": "read_only",
        }
