YOU CAN VIEW AND USE PROJECT WEBSITE BY THIS LINK ----
https://deep-packet-inspection-production.up.railway.app/


# DPI Engine — Web Console

A lightweight web application built around an existing native **C++ Deep Packet
Inspection (DPI) engine**. Upload a `.pcap` capture in the browser, and the
C++ binary — not Python, not JavaScript — does all the actual packet parsing
and classification. FastAPI is just the glue that invokes the engine and
hands its output back to a plain HTML/CSS/JS dashboard.

```
Browser  ──upload .pcap──▶  FastAPI  ──subprocess──▶  packet_analyzer (C++17)
   ▲                           │                              │
   │                           │◀── report.json + output.pcap ┘
   └────────── dashboard ◀─────┘
```

> **The C++ engine was not rewritten.** The only change made to
> `analyzer/src/main.cpp` is additive: while the existing packet-reading loop
> runs, a small number of counters are updated and, at the end, a
> `report.json` file and a passthrough `output.pcap` are written. No parsing
> logic, no header decoding, and no existing functions were altered or
> removed. See [Architecture](#architecture) for the exact diff boundary.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Installation (Docker)](#installation-docker)
3. [Installation (Manual / No Docker)](#installation-manual--no-docker)
4. [Usage](#usage)
5. [API Documentation](#api-documentation)
6. [Architecture](#architecture)
7. [Screenshots](#screenshots)
8. [Deployment](#deployment)
9. [Troubleshooting](#troubleshooting)

---

## Project Structure

```
deep-packet-inspection/
│
├── analyzer/                    # Existing C++ DPI engine (core logic untouched)
│   ├── include/                 # Headers: pcap_reader.h, packet_parser.h, types.h, ...
│   ├── src/
│   │   ├── main.cpp             # Entry point — additive report.json/output.pcap hooks only
│   │   ├── pcap_reader.cpp      # Unmodified
│   │   ├── packet_parser.cpp    # Unmodified
│   │   └── ...                  # Other engine variants (multi-threaded, SNI, etc.) — unmodified
│   ├── CMakeLists.txt
│   └── test_dpi.pcap            # Sample capture for quick testing
│
├── backend/
│   ├── app.py                   # FastAPI app: /health, /analyze, /download/*
│   ├── requirements.txt
│   ├── uploads/                 # Scratch space for uploaded files (per-job subfolders)
│   └── reports/                 # Final report.json / output.pcap per job
│
├── frontend/
│   ├── index.html               # Single-page dashboard (Hero / About / Upload / Results / Footer)
│   ├── style.css                # Dark cybersecurity theme, pure CSS
│   └── script.js                # Fetch API, drag & drop, dynamic rendering — vanilla JS only
│
├── Dockerfile                   # Builds the C++ engine + installs FastAPI, runs uvicorn
├── docker-compose.yml           # One-command startup
└── README.md
```

---

## Installation (Docker)

This is the recommended path — it builds the C++ engine and the Python
backend inside one image, with no local toolchain required.

**Prerequisites:** Docker Engine 20.10+ and Docker Compose v2 (`docker compose`, not `docker-compose`).

```bash
git clone <your-repo-url> deep-packet-inspection
cd deep-packet-inspection

docker compose up --build
```

What happens during the build:

1. `python:3.11-slim` base image is pulled.
2. `build-essential`, `cmake`, and `g++` are installed.
3. `analyzer/` is compiled with CMake into `analyzer/build/packet_analyzer`.
4. Python dependencies (`fastapi`, `uvicorn`, `python-multipart`) are installed.
5. The `frontend/` static files are copied in.
6. `uvicorn` starts the FastAPI app on port `8000`.

### Run it

Once the build finishes, the app is already running in the foreground. Open:

```
http://localhost:8000
```

To run in the background instead:

```bash
docker compose up --build -d
```

Check it's healthy:

```bash
curl http://localhost:8000/health
# {"status":"healthy"}
```

View logs / stop:

```bash
docker compose logs -f dpi-web
docker compose down
```

Uploaded files and generated reports persist on the host via the
`backend/uploads/` and `backend/reports/` volume mounts, so they survive
container restarts.

---

## Installation (Manual / No Docker)

Useful for local development or if Docker isn't available.

### Prerequisites

- A C++17 compiler (`g++` or `clang++`) and `cmake` (or plain `g++`, see below)
- Python 3.10+
- `pip`

### 1. Build the C++ engine

Using CMake (matches what Docker does):

```bash
cd analyzer
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cd ..
```

This produces `analyzer/build/packet_analyzer`.

Or, without CMake, compile directly with g++:

```bash
g++ -std=c++17 -O2 -I analyzer/include -o analyzer/build/packet_analyzer \
    analyzer/src/main.cpp \
    analyzer/src/pcap_reader.cpp \
    analyzer/src/packet_parser.cpp
```

### 2. Set up the Python backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd ..
```

### 3. Run the server

From the **project root** (so relative paths to `analyzer/` and `frontend/`
resolve correctly):

```bash
python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```

If your compiled binary lives somewhere other than
`analyzer/build/packet_analyzer`, point the backend at it:

```bash
ANALYZER_BINARY=/absolute/path/to/packet_analyzer \
  python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** in a browser.

---

## Usage

1. Open the app in a browser (`http://localhost:8000`).
2. Scroll to **Analyze** (or click "Upload Capture" in the top bar).
3. Drag a `.pcap` file onto the drop zone, or click **Browse file**.
4. Click **Analyze capture**. A spinner shows while the C++ engine runs.
5. The **Results** section populates with:
   - Total Packets, TCP, UDP, ICMP, HTTP, HTTPS, DNS counts
   - Top Source IP / Top Destination IP
   - Protocol Distribution bar chart
   - The job ID, source filename, and parse-error count
6. Use **Download report.json** / **Download output.pcap** to save the
   engine's raw artifacts. **View console log** shows the exact stdout/stderr
   the C++ binary produced for that run.

A sample capture is included at `analyzer/test_dpi.pcap` if you want to try
the app immediately without your own capture file.

---

## API Documentation

Base URL: `http://localhost:8000`

Interactive Swagger docs are also available at `http://localhost:8000/docs`
(auto-generated by FastAPI).

### `GET /health`

Liveness check.

**Response `200`:**
```json
{ "status": "healthy" }
```

---

### `POST /analyze`

Upload a PCAP file and run it through the C++ engine synchronously.

**Request:** `multipart/form-data`

| Field  | Type | Required | Notes                         |
|--------|------|----------|--------------------------------|
| `file` | File | Yes      | Must have a `.pcap` extension |

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@analyzer/test_dpi.pcap"
```

**Response `200`:**
```json
{
  "job_id": "19b1510b66434ad78357f9230c98942e",
  "filename": "test_dpi.pcap",
  "report": {
    "source_file": "input.pcap",
    "total_packets": 77,
    "total_bytes": 5738,
    "parse_errors": 0,
    "protocol_counts": { "tcp": 73, "udp": 4, "icmp": 0, "other": 0 },
    "application_counts": { "http": 4, "https": 69, "dns": 4 },
    "protocol_distribution": { "TCP": 94.81, "UDP": 5.19, "ICMP": 0.0, "Other": 0.0 },
    "top_source_ip": { "ip": "192.168.1.100", "count": 56 },
    "top_destination_ip": { "ip": "192.168.1.100", "count": 16 }
  },
  "console_log": "... raw stdout/stderr from packet_analyzer ..."
}
```

**Error responses:**

| Status | Cause                                                        |
|--------|---------------------------------------------------------------|
| `400`  | Missing/empty file, or extension is not `.pcap`               |
| `413`  | File exceeds the 300 MB upload limit                           |
| `500`  | Analyzer binary missing, or it exited non-zero (malformed pcap) |
| `504`  | Analysis exceeded the 300s timeout                             |

---

### `GET /download/report`

Downloads the `report.json` from the most recently completed analysis.

```bash
curl -OJ http://localhost:8000/download/report
```

Returns `404` if no analysis has been run yet in this server session.

---

### `GET /download/output`

Downloads the `output.pcap` from the most recently completed analysis (a
passthrough capture of every packet the engine read — openable in
Wireshark).

```bash
curl -OJ http://localhost:8000/download/output
```

Returns `404` if no analysis has been run yet in this server session.

---

## Architecture

### Request flow

```
┌──────────┐   1. POST /analyze (multipart)   ┌────────────┐
│ Browser  │ ───────────────────────────────▶ │  FastAPI   │
│ (vanilla │                                   │  (app.py)  │
│  JS/CSS) │ ◀─────────────────────────────── │            │
└──────────┘   6. JSON report + console_log    └─────┬──────┘
                                                       │ 2. save upload to
                                                       │    backend/uploads/<job_id>/input.pcap
                                                       ▼
                                              3. subprocess.run(
                                                   ["packet_analyzer", "input.pcap"],
                                                   cwd=<job_dir>
                                                 )
                                                       │
                                                       ▼
                                         ┌─────────────────────────────┐
                                         │   packet_analyzer (C++17)   │
                                         │   analyzer/build/           │
                                         │                              │
                                         │  • PcapReader   (unchanged)  │
                                         │  • PacketParser (unchanged)  │
                                         │  • main.cpp: + counters      │
                                         │             + report.json   │
                                         │             + output.pcap    │
                                         └─────────────┬───────────────┘
                                                       │ 4. writes
                                                       │    report.json, output.pcap
                                                       ▼
                                         backend/uploads/<job_id>/
                                                       │ 5. copied to
                                                       ▼
                                         backend/reports/<job_id>/
```

### What changed in the C++ project, precisely

`analyzer/src/main.cpp` gained:

- A `WebReport` namespace (JSON escaping + a `writeReportJson()` writer) —
  new code, does not touch existing classes.
- Inside the existing `while (reader.readNextPacket(...))` loop: a handful
  of counter increments (`stats.tcp_packets++`, etc.) and two `write()`
  calls to persist a passthrough `output.pcap`.
- After the loop: one call to `WebReport::writeReportJson(...)`.

Everything else — `PcapReader`, `PacketParser`, the Ethernet/IPv4/TCP/UDP
header structs, and every other file in `analyzer/` (`dpi_mt.cpp`,
`sni_extractor.cpp`, `rule_manager.cpp`, etc.) is **byte-for-byte
unchanged**. `CMakeLists.txt` was not modified.

### Frontend

Plain HTML/CSS/JS, no bundler, no framework:

- `index.html` — semantic sections (Hero, About, Upload, Results, Footer)
- `style.css` — CSS variables for a dark/blue theme, responsive grid, hover/fade animations
- `script.js` — `fetch()` calls to the API above, drag-and-drop handling, DOM updates, toast notifications

---

## Screenshots

> Replace these placeholders with real screenshots once you have a running
> instance (e.g. `docs/screenshot-hero.png`).

| View | Screenshot |
|------|------------|
| Hero / landing | `docs/screenshot-hero.png` |
| Upload (drag & drop) | `docs/screenshot-upload.png` |
| Results dashboard | `docs/screenshot-results.png` |

---

## Deployment

### Option A — Docker Compose on a single VM

```bash
git clone <your-repo-url>
cd deep-packet-inspection
docker compose up --build -d
```

Put a reverse proxy (nginx, Caddy, Traefik) in front of port `8000` for TLS
termination and a real domain name. Example nginx snippet:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 300M;   # match MAX_UPLOAD_BYTES in backend/app.py
}
```

### Option B — Container registry + orchestrator

```bash
docker build -t your-registry/dpi-engine:latest .
docker push your-registry/dpi-engine:latest
```

Then deploy that image on ECS/Cloud Run/Kubernetes/etc., exposing port
`8000` and mounting persistent volumes at `/app/backend/uploads` and
`/app/backend/reports` if you want uploaded captures/reports to survive
restarts.

### Environment variables

| Variable          | Default                                   | Purpose                                   |
|--------------------|--------------------------------------------|--------------------------------------------|
| `ANALYZER_BINARY`  | `<project_root>/analyzer/build/packet_analyzer` | Path to the compiled C++ engine            |

---

## Troubleshooting

**"Analyzer binary not found"** — The C++ project hasn't been built, or
`ANALYZER_BINARY` points to the wrong path. Rebuild with the commands in
[Installation (Manual)](#1-build-the-c-engine) and confirm the file exists
and is executable (`chmod +x`).

**`docker compose up --build` fails during the cmake step** — Check that
`analyzer/CMakeLists.txt` and `analyzer/src/main.cpp` are present in the
build context (they're copied via `COPY analyzer/ ./analyzer/` in the
Dockerfile).

**Upload succeeds but "report.json" is missing (500 error)** — This means
`packet_analyzer` ran but didn't produce a `report.json` in its working
directory. Check the `console_log` field returned by `/analyze` (or run the
binary manually against the same file) for the underlying error.

**Large PCAPs are slow** — `main.cpp` prints a detailed per-packet summary to
stdout for every packet (this existing behavior was intentionally preserved,
per the "keep console output" requirement). For very large captures this
console output dominates runtime; consider testing with smaller/trimmed
captures, or capturing/discarding stdout if you need faster turnaround.
