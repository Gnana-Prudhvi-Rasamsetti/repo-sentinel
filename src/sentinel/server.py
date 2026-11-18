"""Small HTTP interface for Repo Sentinel's repository scanner."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from .scanner import load_config, scan

MAX_BODY_BYTES = 1_000_000

_SECURITY_TERMS = re.compile(
    r"\b(?:secret|credential|api[_ -]?key|password|token|sql injection|shell=true|"
    r"eval\s*\(|exec\s*\(|pickle|unsafe deserialization|ssrf|tls verification)\b",
    re.IGNORECASE,
)
_QUALITY_TERMS = re.compile(
    r"\b(?:todo|fixme|hack|xxx|placeholder|notimplemented|unimplemented|debugger|unfinished)\b",
    re.IGNORECASE,
)
_URGENT_TERMS = re.compile(r"\b(?:critical|urgent|actively exploited|exposed credential)\b", re.IGNORECASE)


def classify(text: str) -> dict[str, str | float]:
    """Triage a finding description using transparent keyword rules."""
    security_match = _SECURITY_TERMS.search(text)
    quality_match = _QUALITY_TERMS.search(text)
    if security_match:
        category = "security"
        urgency = "high" if _URGENT_TERMS.search(text) or re.search(
            r"\b(?:credential|password|api[_ -]?key|sql injection|shell=true|eval\s*\(|exec\s*\()\b",
            text, re.IGNORECASE,
        ) else "medium"
        confidence = 0.9
    elif quality_match:
        category, urgency, confidence = "quality", "low", 0.85
    else:
        category, urgency, confidence = "general", "low", 0.6
    return {"category": category, "urgency": urgency, "confidence": confidence}


def _scan_root() -> Path:
    return Path(os.environ.get("SENTINEL_SCAN_ROOT", Path.cwd())).resolve()


def _scan_payload(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    requested = data.get("path", ".")
    if not isinstance(requested, str) or not requested.strip():
        return 400, {"error": "path_must_be_a_nonempty_relative_path"}
    relative = Path(requested)
    if relative.is_absolute():
        return 400, {"error": "path_must_be_relative"}
    root = _scan_root()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        return 400, {"error": "path_outside_scan_root"}
    if not target.is_dir():
        return 404, {"error": "scan_directory_not_found"}
    try:
        findings = scan(target, load_config(target / ".sentinel.json"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return 400, {"error": "invalid_scan_configuration", "detail": str(error)}
    summary = {severity: sum(item.severity == severity for item in findings)
               for severity in ("high", "medium", "low")}
    return 200, {"root": str(target), "summary": summary,
                 "findings": [finding.to_dict() for finding in findings]}


class Handler(BaseHTTPRequestHandler):
    server_version = "RepoSentinel/0.1"

    def _reply(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in {"/classify", "/scan"}:
            self._reply(404, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, {"error": "invalid_content_length"})
            return
        if not 1 <= size <= MAX_BODY_BYTES:
            self._reply(413, {"error": "body_size_out_of_range"})
            return
        try:
            data = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeError, TimeoutError):
            self._reply(400, {"error": "invalid_json"})
            return
        if not isinstance(data, dict):
            self._reply(400, {"error": "json_object_required"})
            return
        if path == "/classify":
            text = data.get("text")
            if not isinstance(text, str) or not text.strip():
                self._reply(400, {"error": "text_required"})
                return
            self._reply(200, classify(text))
            return
        status, response = _scan_payload(data)
        self._reply(status, response)

    def log_message(self, *_: object) -> None:
        # Request bodies and paths can contain source snippets; do not log them.
        return


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
