"""Local MAL-Guard dashboard with basic static PDF and PE heuristics."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import json
import os
import re
import secrets
import struct
import sys
from datetime import datetime, timezone


HOST = "127.0.0.1"
PORT = int(os.environ.get("MAL_GUARD_PORT", "8501"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_REQUEST_BYTES = 25 * 1024 * 1024
MAX_BATCH_FILES = 10
REPORTS: dict[str, dict[str, object]] = {}
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detection.clamav import engine_status, scan_bytes  # noqa: E402


PDF_RULES = (
    (b"/javascript", 3, "PDF JavaScript action"),
    (b"/js", 2, "PDF JavaScript entry"),
    (b"/openaction", 2, "Automatic action when the PDF opens"),
    (b"/aa", 2, "Additional automatic action"),
    (b"/launch", 4, "Launch action"),
    (b"/embeddedfile", 2, "Embedded file"),
    (b"/richmedia", 2, "Rich media content"),
    (b"/submitform", 2, "Form submission action"),
    (b"/importdata", 2, "Import data action"),
)
PE_STRINGS = (
    (b"virtualallocex", "Process memory allocation API string"),
    (b"writeprocessmemory", "Process memory writing API string"),
    (b"createremotethread", "Remote thread creation API string"),
    (b"urldownloadtofile", "URL download API string"),
    (b"winexec", "Command execution API string"),
)


def risk_level(score: int) -> str:
    if score >= 6:
        return "Elevated indicators"
    if score >= 3:
        return "Some indicators"
    if score:
        return "Few indicators"
    return "No configured indicators found"


def inspect_pdf(data: bytes) -> tuple[str, list[str], str]:
    findings: list[str] = []
    score = 0
    lowered = data.lower()
    if b"%pdf-" not in lowered[:1024]:
        return "Invalid or unrecognized PDF", ["The file extension is .pdf, but a PDF header was not found."], "Not analyzed"

    for marker, weight, label in PDF_RULES:
        count = len(re.findall(re.escape(marker), lowered))
        if count:
            findings.append(f"{label} (found {count} time{'s' if count != 1 else ''})")
            score += min(count, 3) * weight
    if b"/uri" in lowered:
        findings.append("External link annotation")
        score += 1
    if b"/encrypt" in lowered:
        findings.append("Encrypted PDF (contents cannot be inspected by these simple rules)")
        score += 1
    if not findings:
        findings.append("No configured suspicious PDF markers were found.")
    return "PDF document", findings, risk_level(score)


def inspect_pe(data: bytes) -> tuple[str, list[str], str]:
    findings: list[str] = []
    score = 0
    if len(data) < 64 or data[:2] != b"MZ":
        return "Invalid or unrecognized Windows executable", ["The file extension suggests an executable, but a valid DOS header was not found."], "Not analyzed"
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 24 or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return "Invalid or incomplete Windows executable", ["A valid PE header was not found within the uploaded file."], "Not analyzed"

    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    if section_count == 0 or section_count > 16:
        findings.append(f"Unusual PE section count ({section_count})")
        score += 2
    if optional_size < 60:
        findings.append("Unusually small PE optional header")
        score += 2
    scan_data = data.lower()
    for marker, label in PE_STRINGS:
        if marker in scan_data:
            findings.append(label)
            score += 2
    if not findings:
        findings.append("No configured suspicious PE markers were found.")
    return "Windows PE executable/library", findings, risk_level(score)


def inspect_file(filename: str, data: bytes) -> tuple[str, list[str], str]:
    if b"MZ" == data[:2]:
        kind, findings, risk = inspect_pe(data)
        if Path(filename).suffix.lower() not in {".exe", ".dll", ".ocx", ".sys"}:
            findings.append("Filename extension does not match Windows executable content")
            if risk == "No configured indicators found":
                risk = "Few indicators"
        return kind, findings, risk
    if Path(filename).suffix.lower() == ".pdf" or b"%pdf-" in data[:1024].lower():
        kind, findings, risk = inspect_pdf(data)
        if Path(filename).suffix.lower() != ".pdf" and kind == "PDF document":
            findings.append("Filename extension does not match PDF content")
            if risk == "No configured indicators found":
                risk = "Few indicators"
        return kind, findings, risk
    return "File (no analyzer available)", ["Static checks are currently available only for PDF and Windows PE files."], "Not analyzed"


def page(results: list[dict[str, object]] | None = None, report_url: str | None = None, error: str | None = None) -> bytes:
    result_html = ""
    clamav_online, clamav_status = engine_status()
    status_class = "online" if clamav_online else "offline"
    if results:
        cards = []
        for result in results:
            findings = "".join(f"<li>{escape(str(item))}</li>" for item in result["findings"])
            cards.append(f"""
        <section class="result" aria-live="polite">
          <div class="result-title"><span class="dot"></span><div><small>FILE {escape(str(result['index']))} OF {len(results)}</small><h2>{escape(str(result['name']))}</h2></div></div>
          <div class="facts"><div><small>FILE TYPE</small><strong>{escape(result['kind'])}</strong></div>
          <div><small>FILE SIZE</small><strong>{escape(result['size'])}</strong></div>
          <div class="hash"><small>SHA-256</small><strong>{escape(result['sha256'])}</strong></div></div>
          <div class="engine"><small>CLAMAV SIGNATURE SCAN</small><strong>{escape(str(result['clamav_label']))}</strong><span>{escape(str(result['clamav_message']))}</span></div>
          <div class="scan"><small>SUPPLEMENTARY STATIC HEURISTICS</small><strong class="risk">{escape(result['risk'])}</strong><ul>{findings}</ul></div>
          <p class="notice"><b>Use caution</b> · A clean antivirus result is not proof that a file is safe. Heuristic checks are supplementary and can miss threats or flag harmless files.</p>
        </section>""")
        result_html = "".join(cards)
        if report_url:
            result_html += f'<p class="report-link"><a href="{escape(report_url)}">Download batch report (JSON)</a></p>'
    error_html = f'<p class="error">{escape(error)}</p>' if error else ""
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MAL-Guard · File workspace</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2b;--line:#26334a;--text:#edf2fb;--muted:#93a3ba;--mint:#62e6bd;--blue:#84a7ff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at 80% 0%,#172b40 0,transparent 38%),var(--bg);color:var(--text);font:16px/1.55 Inter,ui-sans-serif,system-ui,sans-serif;min-height:100vh}}
.wrap{{max-width:980px;margin:auto;padding:38px 24px 64px}}header{{display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--line);padding-bottom:22px}}
.logo{{width:42px;height:42px;display:grid;place-items:center;border-radius:12px;background:#16362f;color:var(--mint);font-weight:900;font-size:21px}}.brand{{font-weight:750;letter-spacing:.08em}}.tag{{margin-left:auto;color:var(--muted);font-size:13px}}
.eyebrow{{color:var(--mint);font-size:12px;font-weight:750;letter-spacing:.16em;margin:48px 0 10px}}h1{{font-size:clamp(32px,6vw,54px);line-height:1.08;letter-spacing:-.04em;margin:0;max-width:720px}}.sub{{color:var(--muted);max-width:650px;margin:16px 0 30px}}
.card{{background:linear-gradient(145deg,#141e31,#101827);border:1px solid var(--line);border-radius:18px;padding:24px;box-shadow:0 20px 70px #0003}}.upload{{border:1px dashed #445573;border-radius:13px;padding:24px;display:flex;align-items:center;gap:15px;background:#0d1524}}.upload-icon{{font-size:25px;color:var(--blue)}}.upload-text strong{{display:block}}.upload-text span{{color:var(--muted);font-size:13px}}
input[type=file]{{display:block;width:100%;margin:18px 0;color:var(--muted)}}button{{border:0;border-radius:10px;background:var(--mint);color:#07221b;padding:12px 18px;font-weight:800;font-size:14px;cursor:pointer}}button:hover{{background:#8af2d3}}.hint{{display:block;color:var(--muted);font-size:12px;margin-top:13px}}
.error{{color:#ffb5b5;background:#391e2a;border:1px solid #673344;border-radius:10px;padding:12px 14px;margin:16px 0 0}}.result{{margin-top:22px;padding:21px;background:#0d1725;border:1px solid #284536;border-radius:14px}}.result-title{{display:flex;align-items:center;gap:12px}}.dot{{width:11px;height:11px;border-radius:99px;background:var(--mint);box-shadow:0 0 16px #62e6bd88}}small{{display:block;color:var(--muted);font-size:10px;font-weight:750;letter-spacing:.14em}}h2{{font-size:19px;margin:2px 0;overflow-wrap:anywhere}}.facts{{display:grid;grid-template-columns:1fr 1fr 2fr;gap:12px;margin-top:22px}}.facts>div{{border-top:1px solid var(--line);padding-top:11px;min-width:0}}.facts strong{{display:block;margin-top:5px;overflow-wrap:anywhere;font-size:14px}}.engine{{margin-top:18px;padding:13px;border-radius:10px;background:#101d2c;border:1px solid var(--line)}}.engine strong,.engine span{{display:block;margin-top:5px;font-size:14px}}.engine span{{color:var(--muted);font-size:12px;overflow-wrap:anywhere}}.scan{{margin-top:22px;border-top:1px solid var(--line);padding-top:15px}}.risk{{display:block;margin:6px 0;color:#f2d58e;font-size:18px}}.scan ul{{margin:8px 0;padding-left:20px;color:#c4cfdf;font-size:13px}}.notice{{background:#25251e;border-left:3px solid #e4bb65;padding:11px 13px;border-radius:5px;color:#d4c8a8;font-size:13px;margin:20px 0 0}}.notice b{{color:#f2d58e}}.report-link{{margin:16px 0 0}}.report-link a{{color:var(--mint);font-weight:700}}.engine-status{{margin:15px 0 0;padding:10px 12px;border-radius:8px;font-size:13px}}.engine-status.online{{color:#a9f2d6;background:#153329}}.engine-status.offline{{color:#e5cb91;background:#302a1c}}footer{{margin-top:25px;color:var(--muted);font-size:12px}}@media(max-width:640px){{.facts{{grid-template-columns:1fr 1fr}}.facts .hash{{grid-column:1/-1}}.tag{{font-size:11px}}}}
</style></head><body><main class="wrap"><header><div class="logo">M</div><div class="brand">MAL-GUARD</div><div class="tag">LOCAL FILE WORKSPACE</div></header>
<p class="eyebrow">LOCAL THREAT CHECK · UPLOAD SCANNING</p><h1>Check files before<br>you open them.</h1>
<p class="sub">Send files to the local ClamAV signature engine and review supplementary static indicators, file fingerprints, and a downloadable batch report.</p>
<section class="card"><form method="post" enctype="multipart/form-data"><label class="upload" for="sample"><span class="upload-icon">↥</span><span class="upload-text"><strong>Choose files to inspect</strong><span>PDF, EXE, DLL, or another file · up to 10 files</span></span></label>
<input id="sample" type="file" name="sample" multiple required><button type="submit">Scan selected files</button><span class="hint">Up to 10 files · 10 MB each · 25 MB total · files are scanned in memory.</span></form>
<p class="engine-status {status_class}">{escape(clamav_status)} · {"signature scan active" if clamav_online else "start ClamAV to enable signature detection"}</p>{error_html}{result_html}</section>
<footer>Local dashboard at 127.0.0.1 · Files are not saved or executed by MAL-Guard.</footer></main></body></html>"""
    return document.encode("utf-8")


class DashboardHandler(BaseHTTPRequestHandler):
    def send_page(self, content: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path.startswith("/report/"):
            report_id = path.removeprefix("/report/")
            report = REPORTS.get(report_id)
            if report is None:
                self.send_error(404, "Report expired or not found")
                return
            payload = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="mal-guard-report.json"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path != "/":
            self.send_error(404)
            return
        self.send_page(page())

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_page(page(error="Invalid upload size."), 400)
            return
        if length <= 0:
            self.send_page(page(error="Choose a file first."), 400)
            return
        if length > MAX_REQUEST_BYTES:
            self.send_page(page(error="The batch is too large. Keep the total upload under 25 MB."), 413)
            return

        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            self.send_page(page(error="Please use the file upload form."), 400)
            return

        body = self.rfile.read(length)
        message = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
        )
        uploads = [part for part in message.iter_parts() if part.get_param("name", header="content-disposition") == "sample" and part.get_filename()]
        if not uploads:
            self.send_page(page(error="Choose a file first."), 400)
            return
        if len(uploads) > MAX_BATCH_FILES:
            self.send_page(page(error=f"Choose no more than {MAX_BATCH_FILES} files per batch."), 413)
            return
        results: list[dict[str, object]] = []
        for index, uploaded in enumerate(uploads, start=1):
            data = uploaded.get_payload(decode=True) or b""
            if len(data) > MAX_UPLOAD_BYTES:
                self.send_page(page(error=f"A file is larger than 10 MB: {escape(uploaded.get_filename())}"), 413)
                return
            filename = Path(uploaded.get_filename().replace("\\", "/")).name or "uploaded-file"
            kind, findings, risk = inspect_file(filename, data)
            clamav = scan_bytes(data)
            if clamav["status"] == "infected":
                clamav_label = "THREAT DETECTED"
                clamav_message = clamav["message"]
            elif clamav["status"] == "clean":
                clamav_label = "No signature match"
                clamav_message = clamav["message"]
            elif clamav["status"] == "unavailable":
                clamav_label = "Scanner unavailable"
                clamav_message = "Only supplementary heuristics ran. " + clamav["message"]
            else:
                clamav_label = "Scan error"
                clamav_message = clamav["message"]
            results.append({
                "index": index,
                "name": filename,
                "kind": kind,
                "size": f"{len(data):,} bytes",
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "findings": findings,
                "risk": risk,
                "clamav": clamav,
                "clamav_label": clamav_label,
                "clamav_message": clamav_message,
            })

        report_id = secrets.token_urlsafe(18)
        report = {
            "application": "MAL-Guard",
            "report_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "analysis_type": "ClamAV signature scan plus supplementary local static heuristics",
            "warning": "A clean signature scan is not proof a file is safe. Heuristics can miss threats or flag harmless files. No upload was saved or executed.",
            "files": results,
        }
        if len(REPORTS) >= 20:
            REPORTS.pop(next(iter(REPORTS)))
        REPORTS[report_id] = report
        self.send_page(page(results=results, report_url=f"/report/{report_id}"))

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[dashboard] {self.address_string()} - {fmt % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"MAL-Guard dashboard running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop. Uploaded files are not saved or executed.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping MAL-Guard dashboard.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
