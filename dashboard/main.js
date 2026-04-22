// =============================
// CONFIG
// =============================
const API_BASE = "http://127.0.0.1:8000";
const DATASET_PATH = "../data/balanced_final_dataset.csv"; // relative to dashboard folder

// =============================
// CSV READER
// =============================
let datasetRows = [];

async function loadDataset() {
  try {
    const res = await fetch(DATASET_PATH);
    const text = await res.text();
    const rows = text.trim().split("\n");
    const header = rows[0].split(",");
    datasetRows = rows.slice(1).map(r => {
      const vals = r.split(",");
      const obj = {};
      header.forEach((h, i) => {
        obj[h.trim()] = isNaN(vals[i]) ? vals[i] : parseFloat(vals[i]);
      });
      return obj;
    });
    console.log(`📚 Loaded dataset: ${datasetRows.length} rows`);
  } catch (err) {
    console.error("❌ Failed to load dataset:", err);
  }
}

// =============================
// FETCH MODEL METRICS
// =============================
async function loadMetrics() {
  const tbody = document.getElementById("metrics-body");
  try {
    const res = await fetch(`${API_BASE}/metrics`);
    const data = await res.json();
    tbody.innerHTML = "";
    data.metrics.forEach((m) => {
      const row = `<tr>
        <td>${m.Model}</td>
        <td>${(m.Accuracy * 100).toFixed(2)}%</td>
        <td>${(m.Precision * 100).toFixed(2)}%</td>
        <td>${(m.Recall * 100).toFixed(2)}%</td>
        <td>${(m["F1-Score"] * 100).toFixed(2)}%</td>
      </tr>`;
      tbody.innerHTML += row;
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger">Error loading metrics: ${err}</td></tr>`;
  }
}

// =============================
// PREDICTION REQUEST
// =============================
async function getPrediction(packet) {
  try {
    const response = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify([packet]), // ✅ send as list
    });

    if (!response.ok) {
      const txt = await response.text();
      console.error("❌ Predict error:", response.status, txt);
      return null;
    }

    const data = await response.json();
    return data.predictions && data.predictions[0]
      ? data.predictions[0]
      : null;
  } catch (err) {
    console.error("❌ Network error:", err);
    return null;
  }
}

// =============================
// DISPLAY LIVE TABLE
// =============================
function addRowToLiveTable(prediction, packet) {
  const tbody = document.getElementById("live-table");

  const rf = prediction["random_forest"] || "-";
  const xgb = prediction["xgboost"] || "-";
  const svm = prediction["svm"] || "-";
  const lr = prediction["logistic_regression"] || "-";

  const color = (val) =>
    String(val).toLowerCase() === "benign"
      ? `<span class='benign'>${val}</span>`
      : `<span class='attack'>${val}</span>`;

  const destPort = packet["Destination Port"]?.toFixed(4) ?? "-";
  const fwdMax = packet["Fwd Packet Length Max"]?.toFixed(4) ?? "-";

  const row = `<tr>
    <td>${prediction.row_index + 1}</td>
    <td>${destPort}</td>
    <td>${fwdMax}</td>
    <td>${color(rf)}</td>
    <td>${color(xgb)}</td>
    <td>${color(svm)}</td>
    <td>${color(lr)}</td>
  </tr>`;

  tbody.insertAdjacentHTML("afterbegin", row);
  while (tbody.rows.length > 15) tbody.deleteRow(-1);
}

// =============================
// LIVE LOOP (REAL DATA FEED)
// =============================
async function liveLoop() {
  if (!datasetRows.length) return;

  // pick a random row from the dataset
  const randomRow = datasetRows[Math.floor(Math.random() * datasetRows.length)];

  // remove Label column before sending
  const { Label, ...packet } = randomRow;

  const prediction = await getPrediction(packet);
  if (prediction) addRowToLiveTable(prediction, packet);
}

// =============================
// INIT
// =============================
loadMetrics();
loadDataset().then(() => {
  console.log("✅ Starting simulated live feed...");
  setInterval(liveLoop, 2500);
});
