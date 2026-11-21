# MAL-Guard

A hybrid malware detection project. The first milestone prepares the Python
development environment and project layout.

## Getting started

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the command-line starter:

```bash
python main.py
```

## Open the dashboard

Start the local dashboard:

```bash
python dashboard/app.py
```

Then open <http://127.0.0.1:8501> in your browser. Choose up to 10 files (up
to 10 MB each and 25 MB total). The dashboard submits every file in memory to
a local ClamAV daemon using its `INSTREAM` protocol. It also reports a SHA-256
hash and supplementary PDF/PE indicators, and lets you download a JSON report.
MAL-Guard never saves or executes uploaded files.

### Enable signature scanning on Fedora

Install ClamAV and its daemon/update packages, update the signatures, then
start the scan service:

```bash
sudo dnf install clamav clamd clamav-freshclam
sudo freshclam
sudo systemctl enable --now clamd@scan
```

The dashboard looks for a local Unix socket at common Fedora paths. If your
ClamAV configuration uses another socket, set `CLAMD_SOCKET_PATH` before
starting MAL-Guard. Keep ClamAV signatures updated. The dashboard reports
`Scanner unavailable` if the daemon cannot be reached and shows that condition
separately from its heuristic findings.

A clean signature scan means ClamAV found no matching signature; it does not
prove a file is safe. The supplementary PDF/PE rules are educational
heuristics, not an antivirus engine. They can miss threats or flag harmless
files. Press `Ctrl+C` to stop the dashboard.

Keep malware samples and other private datasets out of Git. The dataset and
model artifact folders are ignored by default.
