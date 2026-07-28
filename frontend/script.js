// =============================================================================
// DPI Engine — frontend logic (vanilla JS, no framework, no build step)
// =============================================================================
(() => {
  "use strict";

  const API_BASE = ""; // same-origin: FastAPI serves both the API and this page

  // ---------------------------------------------------------------------------
  // Elements
  // ---------------------------------------------------------------------------
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const browseBtn = document.getElementById("browseBtn");
  const fileNameEl = document.getElementById("fileName");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const analyzeBtnLabel = document.getElementById("analyzeBtnLabel");
  const progressEl = document.getElementById("progress");

  const resultsEmpty = document.getElementById("resultsEmpty");
  const resultsContent = document.getElementById("resultsContent");

  const statTotal = document.getElementById("statTotal");
  const statTcp = document.getElementById("statTcp");
  const statUdp = document.getElementById("statUdp");
  const statIcmp = document.getElementById("statIcmp");
  const statHttp = document.getElementById("statHttp");
  const statHttps = document.getElementById("statHttps");
  const statDns = document.getElementById("statDns");

  const topSourceIp = document.getElementById("topSourceIp");
  const topSourceCount = document.getElementById("topSourceCount");
  const topDestIp = document.getElementById("topDestIp");
  const topDestCount = document.getElementById("topDestCount");

  const metaFile = document.getElementById("metaFile");
  const metaJob = document.getElementById("metaJob");
  const metaErrors = document.getElementById("metaErrors");

  const distBars = document.getElementById("distBars");

  const downloadReportBtn = document.getElementById("downloadReportBtn");
  const downloadOutputBtn = document.getElementById("downloadOutputBtn");
  const toggleConsoleBtn = document.getElementById("toggleConsoleBtn");
  const consoleLog = document.getElementById("consoleLog");

  const toast = document.getElementById("toast");

  let selectedFile = null;
  let hasResult = false;
  let lastConsoleLog = "";

  // ---------------------------------------------------------------------------
  // Toast notifications
  // ---------------------------------------------------------------------------
  let toastTimer = null;
  function showToast(message, type = "info") {
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.className = "toast is-visible";
    if (type === "success") toast.classList.add("toast--success");
    if (type === "error") toast.classList.add("toast--error");
    toastTimer = setTimeout(() => {
      toast.classList.remove("is-visible");
    }, 4200);
  }

  // ---------------------------------------------------------------------------
  // File selection (browse + drag & drop)
  // ---------------------------------------------------------------------------
  function setSelectedFile(file) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".pcap")) {
      showToast("Only .pcap files are supported.", "error");
      return;
    }
    selectedFile = file;
    fileNameEl.textContent = `${file.name} (${formatBytes(file.size)})`;
    analyzeBtn.disabled = false;
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  browseBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files[0]) {
      setSelectedFile(fileInput.files[0]);
    }
  });

  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("is-dragover");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("is-dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files[0]) {
      setSelectedFile(files[0]);
    }
  });

  // ---------------------------------------------------------------------------
  // Analyze
  // ---------------------------------------------------------------------------
  analyzeBtn.addEventListener("click", async () => {
    if (!selectedFile) return;

    setLoading(true);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        body: formData,
      });

      const payload = await safeJson(response);

      if (!response.ok) {
        const detail = extractErrorDetail(payload, response.statusText);
        throw new Error(detail);
      }

      renderResults(payload);
      showToast("Analysis complete — report generated.", "success");
      document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      console.error(err);
      showToast(err.message || "Analysis failed. See console for details.", "error");
    } finally {
      setLoading(false);
    }
  });

  async function safeJson(response) {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  function extractErrorDetail(payload, fallback) {
    if (!payload) return fallback || "Something went wrong.";
    const detail = payload.detail;
    if (!detail) return fallback || "Something went wrong.";
    if (typeof detail === "string") return detail;
    if (typeof detail === "object") {
      return detail.message ? `${detail.message}` : JSON.stringify(detail);
    }
    return fallback || "Something went wrong.";
  }

  function setLoading(isLoading) {
    analyzeBtn.disabled = isLoading || !selectedFile;
    progressEl.hidden = !isLoading;
    analyzeBtnLabel.textContent = isLoading ? "Analyzing…" : "Analyze capture";
  }

  // ---------------------------------------------------------------------------
  // Render results
  // ---------------------------------------------------------------------------
  function renderResults(payload) {
    const report = payload.report || {};
    const protocolCounts = report.protocol_counts || {};
    const appCounts = report.application_counts || {};
    const distribution = report.protocol_distribution || {};
    const topSrc = report.top_source_ip || {};
    const topDst = report.top_destination_ip || {};

    statTotal.textContent = formatNumber(report.total_packets);
    statTcp.textContent = formatNumber(protocolCounts.tcp);
    statUdp.textContent = formatNumber(protocolCounts.udp);
    statIcmp.textContent = formatNumber(protocolCounts.icmp);
    statHttp.textContent = formatNumber(appCounts.http);
    statHttps.textContent = formatNumber(appCounts.https);
    statDns.textContent = formatNumber(appCounts.dns);

    topSourceIp.textContent = topSrc.ip || "—";
    topSourceCount.textContent = topSrc.count != null ? `${formatNumber(topSrc.count)} packets` : "";
    topDestIp.textContent = topDst.ip || "—";
    topDestCount.textContent = topDst.count != null ? `${formatNumber(topDst.count)} packets` : "";

    metaFile.textContent = payload.filename || "—";
    metaJob.textContent = payload.job_id || "—";
    metaErrors.textContent = formatNumber(report.parse_errors);

    renderDistribution(distribution);

    lastConsoleLog = payload.console_log || "(no console output captured)";
    consoleLog.textContent = lastConsoleLog;
    consoleLog.hidden = true;
    toggleConsoleBtn.textContent = "View console log";

    resultsEmpty.hidden = true;
    resultsContent.hidden = false;
    hasResult = true;
  }

  function formatNumber(value) {
    if (value === undefined || value === null) return "—";
    return Number(value).toLocaleString();
  }

  function renderDistribution(distribution) {
    const order = ["TCP", "UDP", "ICMP", "Other"];
    distBars.innerHTML = "";
    order.forEach((key) => {
      const pct = Number(distribution[key] ?? 0);
      const row = document.createElement("div");
      row.className = "dist__row";
      row.innerHTML = `
        <span class="dist__label">${key}</span>
        <span class="dist__track"><span class="dist__fill" style="width:0%"></span></span>
        <span class="dist__pct">${pct.toFixed(1)}%</span>
      `;
      distBars.appendChild(row);
      requestAnimationFrame(() => {
        row.querySelector(".dist__fill").style.width = `${Math.min(pct, 100)}%`;
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Downloads
  // ---------------------------------------------------------------------------
  async function triggerDownload(url, fallbackName) {
    if (!hasResult) {
      showToast("Run an analysis first.", "error");
      return;
    }
    try {
      const response = await fetch(`${API_BASE}${url}`);
      if (!response.ok) {
        const payload = await safeJson(response);
        throw new Error(extractErrorDetail(payload, "Download failed."));
      }
      const blob = await response.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = fallbackName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
    } catch (err) {
      showToast(err.message || "Download failed.", "error");
    }
  }

  downloadReportBtn.addEventListener("click", () => triggerDownload("/download/report", "report.json"));
  downloadOutputBtn.addEventListener("click", () => triggerDownload("/download/output", "output.pcap"));

  toggleConsoleBtn.addEventListener("click", () => {
    consoleLog.hidden = !consoleLog.hidden;
    toggleConsoleBtn.textContent = consoleLog.hidden ? "View console log" : "Hide console log";
  });

  // ---------------------------------------------------------------------------
  // Hero "live scope" ticker — purely decorative, illustrates the kind of
  // traffic the engine classifies. Not connected to any real capture.
  // ---------------------------------------------------------------------------
  const scopeFeed = document.getElementById("scopeFeed");
  const SAMPLE_LINES = [
    { tag: "TCP", cls: "tag--tcp", text: "192.168.1.100:53728 → 172.217.14.206:443  [SYN]" },
    { tag: "TLS", cls: "tag", text: "ClientHello sni=www.example.com" },
    { tag: "DNS", cls: "tag--dns", text: "192.168.1.100:51230 → 8.8.8.8:53  A? example.com" },
    { tag: "UDP", cls: "tag--udp", text: "192.168.1.104:60122 → 239.255.255.250:1900" },
    { tag: "TCP", cls: "tag--tcp", text: "172.217.14.206:443 → 192.168.1.100:53728  [ACK]" },
    { tag: "HTTP", cls: "tag", text: "GET /health HTTP/1.1  Host: api.internal" },
    { tag: "TCP", cls: "tag--tcp", text: "192.168.1.50:44210 → 140.82.112.3:443  [SYN]" },
    { tag: "DNS", cls: "tag--dns", text: "192.168.1.100:51231 → 8.8.8.8:53  AAAA? github.com" },
  ];
  let scopeIndex = 0;
  const MAX_LINES = 9;

  function pushScopeLine() {
    const sample = SAMPLE_LINES[scopeIndex % SAMPLE_LINES.length];
    scopeIndex++;
    const line = document.createElement("div");
    line.className = "scope__line";
    line.innerHTML = `<span class="${sample.cls}">[${sample.tag}]</span> ${escapeHtml(sample.text)}`;
    scopeFeed.appendChild(line);
    while (scopeFeed.children.length > MAX_LINES) {
      scopeFeed.removeChild(scopeFeed.firstChild);
    }
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  if (scopeFeed) {
    for (let i = 0; i < 6; i++) pushScopeLine();
    setInterval(pushScopeLine, 1400);
  }

  // ---------------------------------------------------------------------------
  // Health check on load (non-blocking, just logs a warning if backend is down)
  // ---------------------------------------------------------------------------
  fetch(`${API_BASE}/health`)
    .then((r) => r.json())
    .then((data) => {
      if (data.status !== "healthy") {
        console.warn("Backend reported unhealthy status:", data);
      }
    })
    .catch(() => {
      console.warn("Could not reach backend /health endpoint.");
    });
})();
