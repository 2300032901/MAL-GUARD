"""Small, in-memory client for a local ClamAV daemon using INSTREAM."""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path


DEFAULT_SOCKETS = (
    "/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock",
    "/run/clamd.scan/clamd.sock",
    "/var/run/clamd.scan/clamd.sock",
)
SOCKET_TIMEOUT_SECONDS = 30
CHUNK_SIZE = 64 * 1024


def socket_path() -> str | None:
    configured = os.environ.get("CLAMD_SOCKET_PATH")
    candidates = (configured,) if configured else DEFAULT_SOCKETS
    return next((path for path in candidates if Path(path).exists()), None)


def engine_status() -> tuple[bool, str]:
    """Return whether a local clamd socket answers PING, and a short status."""
    path = socket_path()
    if path is None:
        return False, "ClamAV daemon not found"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(path)
            client.sendall(b"zPING\0")
            reply = client.recv(64).strip(b"\0\r\n")
        if reply == b"PONG":
            return True, "ClamAV connected"
        return False, "ClamAV did not answer PING"
    except OSError:
        return False, "ClamAV socket unavailable"


def scan_bytes(data: bytes) -> dict[str, str]:
    """Submit bytes to local clamd without writing the uploaded file to disk."""
    path = socket_path()
    if path is None:
        return {"status": "unavailable", "engine": "ClamAV", "message": "ClamAV daemon not found"}

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(SOCKET_TIMEOUT_SECONDS)
            client.connect(path)
            client.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), CHUNK_SIZE):
                chunk = data[offset : offset + CHUNK_SIZE]
                client.sendall(struct.pack("!I", len(chunk)))
                client.sendall(chunk)
            client.sendall(struct.pack("!I", 0))
            response = bytearray()
            while len(response) < 8192:
                part = client.recv(1024)
                if not part:
                    break
                response.extend(part)
                if b"\0" in part or b"\n" in part:
                    break
    except (OSError, TimeoutError) as exc:
        return {"status": "unavailable", "engine": "ClamAV", "message": f"ClamAV scan unavailable: {exc.__class__.__name__}"}

    message = bytes(response).strip(b"\0\r\n").decode("utf-8", "replace")
    if message.endswith(": OK"):
        return {"status": "clean", "engine": "ClamAV", "message": "No signature match found"}
    if message.endswith(" FOUND"):
        detection = message.rsplit(": ", 1)[-1].removesuffix(" FOUND")
        return {"status": "infected", "engine": "ClamAV", "message": detection}
    if not message:
        message = "ClamAV returned an empty response"
    return {"status": "error", "engine": "ClamAV", "message": message[:300]}
