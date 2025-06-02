document.addEventListener("DOMContentLoaded", function () {
  document.getElementById("scanButton").addEventListener("click", startScan);
});

async function startScan() {
  const scanButton = document.getElementById("scanButton");
  const progress = document.getElementById("progress");
  const progressText = document.getElementById("progressText");
  const scanLevel = document.getElementById("scanLevel").value;

  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";
  progress.style.display = "block";

  try {
    const response = await fetch(
      `http://localhost:8000/scan-installed?scan_level=${scanLevel}`
    );
    const data = await response.json();

    updateProgress(data.extensions.length, data.extensions.length);
    displayResults(data.extensions);
  } catch (error) {
    console.error("Scan failed:", error);
    alert("Scan failed. Check console for details.");
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Start Scan";
    progress.style.display = "none";
  }
}

function updateProgress(current, total) {
  document.getElementById("progressText").textContent = `${current}/${total}`;
}

function displayResults(extensions) {
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  extensions.forEach((ext) => {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${ext.extension_id}</td>
      <td>${ext.version}</td>
      <td>${ext.risk_score?.toFixed(1) || "N/A"}</td>
      <td class="${getRiskClass(ext.risk_level)}">${ext.risk_level}</td>
    `;

    tbody.appendChild(row);
  });
}

function getRiskClass(riskLevel) {
  switch (riskLevel?.toLowerCase()) {
    case "high":
      return "risk-high";
    case "medium":
      return "risk-medium";
    case "low":
      return "risk-low";
    default:
      return "";
  }
}
