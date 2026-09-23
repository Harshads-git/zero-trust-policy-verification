/**
 * Zero Trust Policy Verification Engine (ZTPVE)
 * Main Frontend Application Controller
 */

let sampleTemplates = { valid: [], invalid: [] };
let currentReport = null;

document.addEventListener("DOMContentLoaded", async () => {
  initTabs();
  initVisualizer("cy-container");
  await fetchSystemHealth();
  await loadSampleTemplates();
  await loadVerificationHistory();

  // Load the first valid policy by default into the editor
  if (sampleTemplates.valid.length > 0) {
    loadPolicyIntoEditor(sampleTemplates.valid[0]);
    // Auto-verify initial policy
    verifyCurrentPolicy();
  }
});

// Tab Navigation
function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      tab.classList.add("active");
      const target = document.getElementById(tab.dataset.tab);
      if (target) {
        target.classList.add("active");
        if (tab.dataset.tab === "tab-verify" && cy) {
          setTimeout(() => cy.resize(), 50);
        }
      }
    });
  });
}

// System Health
async function fetchSystemHealth() {
  try {
    const res = await fetch("/health");
    if (res.ok) {
      const data = await res.json();
      document.getElementById("backend-status-indicator").textContent = `Online (${data.storage_backend})`;
    }
  } catch (err) {
    document.getElementById("backend-status-indicator").textContent = "Offline / Error";
    document.getElementById("backend-status-indicator").style.color = "#ef4444";
  }
}

// Load Bundled Sample Policies
async function loadSampleTemplates() {
  try {
    const res = await fetch("/api/policies/samples/templates");
    if (!res.ok) return;
    sampleTemplates = await res.json();

    const select = document.getElementById("sample-policy-select");
    select.innerHTML = '<option value="">-- Load Sample Policy --</option>';

    const optGroupValid = document.createElement("optgroup");
    optGroupValid.label = "Valid Zero Trust Policies";
    sampleTemplates.valid.forEach((p, idx) => {
      const opt = document.createElement("option");
      opt.value = `valid_${idx}`;
      opt.textContent = `[VALID] ${p.policy_name}`;
      optGroupValid.appendChild(opt);
    });
    select.appendChild(optGroupValid);

    const optGroupInvalid = document.createElement("optgroup");
    optGroupInvalid.label = "Flawed Policies (Violation Scenarios)";
    sampleTemplates.invalid.forEach((p, idx) => {
      const opt = document.createElement("option");
      opt.value = `invalid_${idx}`;
      opt.textContent = `[FLAWED] ${p.policy_name}`;
      optGroupInvalid.appendChild(opt);
    });
    select.appendChild(optGroupInvalid);

    select.addEventListener("change", (e) => {
      const val = e.target.value;
      if (!val) return;
      const [type, idx] = val.split("_");
      const policy = sampleTemplates[type][parseInt(idx, 10)];
      if (policy) {
        loadPolicyIntoEditor(policy);
        verifyCurrentPolicy();
      }
    });
  } catch (err) {
    console.error("Error loading templates:", err);
  }
}

function loadPolicyIntoEditor(policy) {
  const editor = document.getElementById("policy-editor");
  editor.value = JSON.stringify(policy, null, 2);
}

// File Upload Handler
function handleFileUpload(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const json = JSON.parse(e.target.result);
      loadPolicyIntoEditor(json);
      verifyCurrentPolicy();
    } catch (err) {
      alert("Invalid JSON file uploaded: " + err.message);
    }
  };
  reader.readAsText(file);
}

// Core Verification Call
async function verifyCurrentPolicy() {
  const editor = document.getElementById("policy-editor");
  const rawText = editor.value.trim();

  let policy;
  try {
    policy = JSON.parse(rawText);
  } catch (err) {
    alert("JSON Parse Error: Please correct policy syntax before verification.\n" + err.message);
    return;
  }

  const verifyBtn = document.getElementById("btn-verify");
  verifyBtn.textContent = "Verifying...";
  verifyBtn.disabled = true;

  try {
    const res = await fetch("/api/policies/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(policy)
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || "Server verification error");
    }

    currentReport = await res.json();
    renderVerificationResults(currentReport);
    await loadVerificationHistory();
  } catch (err) {
    alert("Verification failed: " + err.message);
  } finally {
    verifyBtn.textContent = "Run Formal Verification";
    verifyBtn.disabled = false;
  }
}

// Render Results & Invariants
function renderVerificationResults(report) {
  // Update Metrics Ribbon
  const statusEl = document.getElementById("metric-status");
  statusEl.textContent = report.valid ? "PASSED (VALID)" : "FAILED (VIOLATIONS)";
  statusEl.className = `metric-val ${report.valid ? "val-valid" : "val-invalid"}`;

  document.getElementById("metric-violations").textContent = report.violations_count;
  document.getElementById("metric-states").textContent = report.total_states;
  document.getElementById("metric-transitions").textContent = report.total_transitions;
  document.getElementById("metric-time").textContent = `${report.verification_time_ms} ms`;

  // Render FSM Graph
  if (report.fsm_graph_summary && report.fsm_graph_summary.elements) {
    renderFsmGraph(report.fsm_graph_summary.elements, report.violations);
  }

  // Render Violations Breakdown
  const violationsContainer = document.getElementById("violations-list");
  violationsContainer.innerHTML = "";

  if (report.valid) {
    violationsContainer.innerHTML = `
      <div style="background-color: #064e3b; border: 1px solid #059669; color: #a7f3d0; padding: 14px 18px; border-radius: 4px;">
        <strong>Formal Verification Success:</strong> All Zero Trust safety invariants and Automata reachability properties satisfied. No unauthorized privilege trajectories detected.
      </div>
    `;
  } else {
    report.violations.forEach((v, idx) => {
      const card = document.createElement("div");
      card.className = `violation-card severity-${v.severity}`;
      card.innerHTML = `
        <div class="violation-header">
          <span class="violation-title">#${idx + 1} [${v.severity}] ${v.type}</span>
          <span class="badge" style="background:#451a03; color:#fdba74;">${v.rule_id || v.state || "Structural"}</span>
        </div>
        <p style="margin-bottom: 6px; font-weight: 500;">${escapeHtml(v.message)}</p>
        <p style="font-size: 12px; color: #cbd5e1; margin-bottom: 8px;">${escapeHtml(v.explanation)}</p>
        ${v.witness_path ? `<div class="witness-path-badge">Counterexample Trace: ${v.witness_path.join(" &rarr; ")}</div>` : ""}
        ${v.remediation ? `<div class="remediation-box"><strong>Remediation:</strong> ${escapeHtml(v.remediation)}</div>` : ""}
      `;
      violationsContainer.appendChild(card);
    });
  }
}

// Verification History Table
async function loadVerificationHistory() {
  try {
    const res = await fetch("/api/policies/reports/history?limit=25");
    if (!res.ok) return;
    const history = await res.json();

    const tbody = document.getElementById("history-table-body");
    tbody.innerHTML = "";

    if (history.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #64748b;">No verification logs recorded yet.</td></tr>';
      return;
    }

    history.forEach(item => {
      const row = document.createElement("tr");
      const dateStr = new Date(item.timestamp).toLocaleTimeString();
      row.innerHTML = `
        <td>${dateStr}</td>
        <td><strong>${escapeHtml(item.policy_name)}</strong></td>
        <td><span class="badge" style="background:${item.valid ? '#14532d; color:#86efac' : '#7f1d1d; color:#fecaca'}">${item.valid ? "PASSED" : "FAILED"}</span></td>
        <td>${item.violations_count}</td>
        <td>${item.total_states} Q / ${item.total_transitions} &delta;</td>
        <td>${item.verification_time_ms} ms</td>
      `;
      tbody.appendChild(row);
    });
  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

// Benchmark Runner
async function runEmpiricalBenchmark() {
  const btn = document.getElementById("btn-run-benchmark");
  const output = document.getElementById("benchmark-results-container");
  btn.textContent = "Running Benchmark...";
  btn.disabled = true;
  output.innerHTML = '<p style="color: #38bdf8;">Running synthetic policy scale tests (N = 10, 50, 100, 250, 500 rules)...</p>';

  try {
    const res = await fetch("/api/experiments/benchmark", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify([10, 50, 100, 250, 500])
    });
    const data = await res.json();

    let tableHtml = `
      <table class="data-table" style="margin-top: 12px;">
        <thead>
          <tr>
            <th>Scale (Target N)</th>
            <th>States |Q|</th>
            <th>Transitions |&delta;|</th>
            <th>Verification Time (ms)</th>
            <th>Throughput (rules/sec)</th>
            <th>Violations Flagged</th>
          </tr>
        </thead>
        <tbody>
    `;

    data.measurements.forEach(m => {
      tableHtml += `
        <tr>
          <td><strong>N = ${m.num_rules}</strong></td>
          <td>${m.actual_states}</td>
          <td>${m.actual_transitions}</td>
          <td><strong style="color: #38bdf8;">${m.verification_time_ms} ms</strong></td>
          <td>${m.throughput_rules_per_sec.toLocaleString()}</td>
          <td>${m.violations_detected}</td>
        </tr>
      `;
    });
    tableHtml += `</tbody></table>`;
    output.innerHTML = tableHtml;
  } catch (err) {
    output.innerHTML = `<p style="color: #ef4444;">Benchmark failed: ${err.message}</p>`;
  } finally {
    btn.textContent = "Execute Benchmark Suite";
    btn.disabled = false;
  }
}

// Download Report JSON
function downloadCurrentReport() {
  if (!currentReport) {
    alert("No verification report available to export.");
    return;
  }
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ztpve_report_${currentReport.policy_id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
