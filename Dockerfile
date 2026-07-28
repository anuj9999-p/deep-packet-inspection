# =============================================================================
# Deep Packet Inspection — web application image
#
# Single-stage build:
#   1. Install system deps (g++, cmake, python3)
#   2. Build the C++ packet_analyzer engine with CMake
#   3. Install Python/FastAPI dependencies
#   4. Copy the frontend and run uvicorn
# =============================================================================
FROM python:3.11-slim

LABEL org.opencontainers.image.title="DPI Engine" \
      org.opencontainers.image.description="Web console for a native C++ deep packet inspection engine"

# ---- System dependencies (g++, cmake, make) --------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Build the C++ engine ---------------------------------------------------
COPY analyzer/ ./analyzer/
RUN cmake -S analyzer -B analyzer/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build analyzer/build --config Release -j"$(nproc)" \
    && test -x analyzer/build/packet_analyzer

# ---- Python backend ----------------------------------------------------------
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
RUN mkdir -p backend/uploads backend/reports

# ---- Frontend (static files served by FastAPI) ------------------------------
COPY frontend/ ./frontend/

ENV ANALYZER_BINARY=/app/analyzer/build/packet_analyzer
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
