"""
FastAPI backend for the Deep Packet Inspection (DPI) web application.

This service is a thin HTTP wrapper around the existing C++ `packet_analyzer`
engine. It does not parse packets itself -- it only:

    1. Accepts an uploaded .pcap file.
    2. Saves it to disk and invokes the compiled C++ binary via subprocess.
    3. Waits for the binary to finish, then reads the report.json /
       output.pcap files that the binary produced.
    4. Serves those artifacts back to the frontend (and makes them
       downloadable).

All actual packet parsing, protocol classification, and statistics are
computed by the C++ engine in `analyzer/`.
"""

import json
import logging
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Paths & configuration
# ---------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"

UPLOAD_DIR = BACKEND_DIR / "uploads"
REPORTS_DIR = BACKEND_DIR / "reports"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Path to the compiled C++ engine. Overridable via env var (used in Docker).
ANALYZER_BINARY = Path(
    os.environ.get(
        "ANALYZER_BINARY",
        str(PROJECT_ROOT / "analyzer" / "build" / "packet_analyzer"),
    )
)

# Safety limits
MAX_UPLOAD_BYTES = 300 * 1024 * 1024  # 300 MB
ANALYSIS_TIMEOUT_SECONDS = 300
ALLOWED_EXTENSIONS = {".pcap"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dpi-backend")

app = FastAPI(
    title="Deep Packet Inspection API",
    description="Web API around a native C++ DPI / packet analysis engine.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory pointer to the most recently completed analysis job. This keeps
# the /download/* endpoints simple (no job id required), matching a
# single-operator lightweight tool. Each entry in JOBS keeps history in case
# a job id is ever needed for debugging.
LATEST_JOB: Optional[dict] = None
JOBS: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_analyzer_available() -> None:
    if not ANALYZER_BINARY.exists():
        raise HTTPException(
            status_code=500,
            detail=(
                f"Analyzer binary not found at '{ANALYZER_BINARY}'. "
                "Build the C++ project first (see README)."
            ),
        )
    if not os.access(ANALYZER_BINARY, os.X_OK):
        raise HTTPException(
            status_code=500,
            detail=f"Analyzer binary at '{ANALYZER_BINARY}' is not executable.",
        )


def _validate_upload(upload: UploadFile) -> None:
    suffix = Path(upload.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Please upload a .pcap file.",
        )


def _save_upload(upload: UploadFile, destination: Path) -> int:
    """Stream the upload to disk, enforcing a max size limit."""
    total = 0
    chunk_size = 1024 * 1024  # 1 MB
    with destination.open("wb") as out_file:
        while True:
            chunk = upload.file.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                out_file.close()
                destination.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
                )
            out_file.write(chunk)
    return total


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    """Simple liveness check."""
    return {"status": "healthy"}


@app.post("/analyze")
def analyze(file: UploadFile = File(...)):
    """
    Accept an uploaded PCAP file, run it through the C++ packet_analyzer
    engine, and return the resulting analysis report as JSON.
    """
    global LATEST_JOB

    _validate_upload(file)
    _ensure_analyzer_available()

    job_id = uuid.uuid4().hex
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    original_name = file.filename or "capture.pcap"
    input_path = job_dir / "input.pcap"

    try:
        size_bytes = _save_upload(file, input_path)
    finally:
        file.file.close()

    if size_bytes == 0:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    logger.info("Job %s: saved '%s' (%d bytes) to %s", job_id, original_name, size_bytes, input_path)

    # Run the C++ engine: ./packet_analyzer input.pcap (cwd = job_dir so the
    # engine's report.json / output.pcap land next to the input file).
    try:
        result = subprocess.run(
            [str(ANALYZER_BINARY), "input.pcap"],
            cwd=str(job_dir),
            capture_output=True,
            text=True,
            timeout=ANALYSIS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail=f"Analysis timed out after {ANALYSIS_TIMEOUT_SECONDS} seconds.",
        )

    if result.returncode != 0:
        logger.error("Job %s: analyzer failed (exit %d)\n%s", job_id, result.returncode, result.stderr)
        raise HTTPException(
            status_code=500,
            detail={
                "message": "The packet analyzer engine failed to process this file.",
                "exit_code": result.returncode,
                "stderr": result.stderr[-4000:],
            },
        )

    report_path = job_dir / "report.json"
    output_pcap_path = job_dir / "output.pcap"

    if not report_path.exists():
        raise HTTPException(
            status_code=500,
            detail="Analyzer completed but did not produce report.json.",
        )

    try:
        report_data = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"report.json is not valid JSON: {exc}")

    # Persist final artifacts under backend/reports/<job_id>/ so uploads/ can
    # be treated as scratch space.
    final_dir = REPORTS_DIR / job_id
    final_dir.mkdir(parents=True, exist_ok=True)
    final_report_path = final_dir / "report.json"
    final_output_path = final_dir / "output.pcap"
    shutil.copyfile(report_path, final_report_path)
    if output_pcap_path.exists():
        shutil.copyfile(output_pcap_path, final_output_path)

    job_record = {
        "job_id": job_id,
        "original_filename": original_name,
        "report_path": final_report_path,
        "output_path": final_output_path if final_output_path.exists() else None,
        "console_log": (result.stdout[-6000:] + "\n" + result.stderr[-2000:]).strip(),
    }
    JOBS[job_id] = job_record
    LATEST_JOB = job_record

    logger.info("Job %s: analysis complete", job_id)

    return JSONResponse(
        content={
            "job_id": job_id,
            "filename": original_name,
            "report": report_data,
            "console_log": job_record["console_log"],
        }
    )


@app.get("/download/report")
def download_report():
    """Download the report.json produced by the most recent analysis."""
    if LATEST_JOB is None or not LATEST_JOB["report_path"].exists():
        raise HTTPException(status_code=404, detail="No analysis report is available yet.")
    return FileResponse(
        path=LATEST_JOB["report_path"],
        media_type="application/json",
        filename="report.json",
    )


@app.get("/download/output")
def download_output():
    """Download the output.pcap produced by the most recent analysis."""
    if LATEST_JOB is None or not LATEST_JOB.get("output_path") or not LATEST_JOB["output_path"].exists():
        raise HTTPException(status_code=404, detail="No output.pcap is available yet.")
    return FileResponse(
        path=LATEST_JOB["output_path"],
        media_type="application/vnd.tcpdump.pcap",
        filename="output.pcap",
    )


# ---------------------------------------------------------------------------
# Static frontend (mounted last so the API routes above take precedence)
# ---------------------------------------------------------------------------

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    logger.warning("Frontend directory not found at %s", FRONTEND_DIR)
