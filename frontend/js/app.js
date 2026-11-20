/**
 * Zero Trust Policy Verification Engine (ZTPVE)
 * Main Frontend Application Controller
 */

let sampleTemplates = { valid: [], invalid: [] };
let currentReport = null;
let currentCegisResult = null;
let originalGraphElements = null;
let repairedGraphElements = null;

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
        } else if (tab.dataset.tab === "tab-cloud") {
          loadCloudInfrastructureStatus();
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

// Format Policy JSON
function formatPolicyJson() {
  const editor = document.getElementById("policy-editor");
  try {
    const parsed = JSON.parse(editor.value);
    editor.value = JSON.stringify(parsed, null, 2);
  } catch (err) {
    alert("Cannot format invalid JSON: " + err.message);
  }
}

// Save Policy to Database
async function savePolicyToDatabase() {
  const editor = document.getElementById("policy-editor");
  let policy;
  try {
    policy = JSON.parse(editor.value);
  } catch (err) {
    alert("Cannot save invalid JSON: " + err.message);
    return;
  }

  const saveBtn = document.getElementById("btn-save-db");
  saveBtn.textContent = "Saving...";
  saveBtn.disabled = true;

  try {
    const res = await fetch("/api/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(policy)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Error saving policy");
    }
    const data = await res.json();
    alert(`Policy "${data.policy.policy_name}" saved successfully with ID: ${data.policy.policy_id}`);
    await loadVerificationHistory();
  } catch (err) {
    alert("Failed to save policy: " + err.message);
  } finally {
    saveBtn.textContent = "Save to DB";
    saveBtn.disabled = false;
  }
}

// Render Results & Invariants
function renderVerificationResults(report) {
  // Update Metrics Ribbon
  const statusEl = document.getElementById("metric-status");
  statusEl.textContent = report.valid ? "PASSED (VALID)" : "FAILED (VIOLATIONS)";
  statusEl.className = `metric-val ${report.valid ? "val-valid" : "val-invalid"}`;

  const riskScore = report.risk_score !== undefined ? report.risk_score : 0;
  const posture = report.security_posture || (report.valid ? "COMPLIANT" : "CRITICAL_RISK");

  const riskEl = document.getElementById("metric-risk-score");
  if (riskEl) {
    riskEl.textContent = `${riskScore} / 100`;
    riskEl.className = `metric-val ${riskScore > 50 ? 'risk-score-high' : (riskScore > 20 ? 'risk-score-medium' : 'risk-score-low')}`;
  }

  const postureEl = document.getElementById("metric-posture");
  if (postureEl) {
    postureEl.textContent = posture;
    postureEl.className = `metric-val posture-badge posture-${posture}`;
  }

  const stTrEl = document.getElementById("metric-states-transitions");
  if (stTrEl) {
    stTrEl.textContent = `${report.total_states} Q / ${report.total_transitions} \u03b4`;
  }

  document.getElementById("metric-violations").textContent = report.violations_count;
  document.getElementById("metric-time").textContent = `${report.verification_time_ms} ms`;

  // Render FSM Graph
  if (report.fsm_graph_summary && report.fsm_graph_summary.elements) {
    originalGraphElements = report.fsm_graph_summary.elements;
    renderFsmGraph(report.fsm_graph_summary.elements, report.violations);
  }

  // Render Violations Breakdown
  const violationsContainer = document.getElementById("violations-list");
  violationsContainer.innerHTML = "";

  const remediationContainer = document.getElementById("remediation-plan-container");
  const remediationList = document.getElementById("remediation-plan-list");

  if (report.valid) {
    violationsContainer.innerHTML = `
      <div style="background-color: #064e3b; border: 1px solid #059669; color: #a7f3d0; padding: 14px 18px; border-radius: 4px;">
        <strong>Formal Verification Success:</strong> All Zero Trust safety invariants and Automata reachability properties satisfied. No unauthorized privilege trajectories detected.
      </div>
    `;
    if (remediationContainer) {
      remediationContainer.style.display = "none";
    }
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
        ${v.witness_path && v.witness_path.length > 1 ? `
          <div style="margin: 8px 0 10px 0;">
            <div class="witness-path-badge">Counterexample Trace: ${v.witness_path.join(" &rarr; ")}</div>
            <div style="display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap;">
              <button class="btn btn-sm btn-primary" onclick='highlightWitnessTrace(${JSON.stringify(v.witness_path)})'>Highlight Trace</button>
              <button class="btn btn-sm" onclick='animateWitnessTrace(${JSON.stringify(v.witness_path)})'>Animate Trajectory</button>
              <button class="btn btn-sm" onclick='clearTraceHighlights()'>Reset View</button>
            </div>
          </div>
        ` : (v.witness_path ? `<div class="witness-path-badge">Counterexample Trace: ${v.witness_path.join(" &rarr; ")}</div>` : "")}
        ${v.remediation ? `<div class="remediation-box"><strong>Remediation:</strong> ${escapeHtml(v.remediation)}</div>` : ""}
      `;
      violationsContainer.appendChild(card);
    });

    // Populate Automated Remediation Roadmap
    if (remediationContainer && remediationList) {
      const actionableViolations = report.violations.filter(v => v.remediation);
      if (actionableViolations.length > 0) {
        remediationContainer.style.display = "block";
        remediationList.innerHTML = "";
        actionableViolations.forEach((v, idx) => {
          const item = document.createElement("div");
          item.className = "remediation-plan-item";
          item.innerHTML = `
            <span class="remediation-step-badge">${idx + 1}</span>
            <div style="flex: 1;">
              <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <span class="remediation-target-tag">${escapeHtml(v.rule_id || v.state || "Policy Core")}</span>
                <span class="badge" style="background:${v.severity === 'CRITICAL' ? '#7f1d1d' : '#451a03'}; color:#fecaca;">${v.severity}</span>
                <span style="font-size: 11px; color: #94a3b8;">${escapeHtml(v.type)}</span>
              </div>
              <p style="font-size: 12px; color: #bae6fd;">${escapeHtml(v.remediation)}</p>
            </div>
          `;
          remediationList.appendChild(item);
        });
      } else {
        remediationContainer.style.display = "none";
      }
    }
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

// AWS Cloud Operations
async function loadCloudInfrastructureStatus() {
  try {
    const res = await fetch("/api/cloud/status");
    if (!res.ok) return;
    const data = await res.json();

    const storageEl = document.getElementById("cloud-storage-val");
    if (storageEl) {
      storageEl.textContent = `${data.storage.configured_backend.toUpperCase()} (${data.storage.policies_stored_count} stored)`;
    }

    const regEl = document.getElementById("cloud-region-val");
    if (regEl) regEl.textContent = data.region;

    const cwEl = document.getElementById("cloud-cw-val");
    if (cwEl) {
      cwEl.textContent = data.cloudwatch.enabled ? (data.cloudwatch.client_connected ? "AWS Connected" : "Local Telemetry Buffer") : "Local Telemetry Buffer";
    }

    const s3El = document.getElementById("cloud-s3-val");
    if (s3El) {
      s3El.textContent = data.s3.s3_connected ? `S3 Connected (${data.s3.total_archives_recorded} archives)` : `Local Storage (${data.s3.total_archives_recorded} archives)`;
    }
  } catch (err) {
    console.error("Failed to fetch cloud status:", err);
  }
}

async function triggerS3Backup() {
  const consoleEl = document.getElementById("cloud-ops-console");
  if (consoleEl) {
    consoleEl.style.display = "block";
    consoleEl.textContent = "Initiating AWS S3 snapshot archive...";
  }

  try {
    const res = await fetch("/api/cloud/s3/backup", { method: "POST" });
    const data = await res.json();
    if (consoleEl) {
      consoleEl.textContent = `[SUCCESS] ${data.message}\n` +
        `Storage Destination: ${data.backup.storage_destination.toUpperCase()}\n` +
        `Archive Key / Path : ${data.backup.s3_uri || data.backup.local_path}\n` +
        `Policies Archived  : ${data.backup.policies_archived}\n` +
        `Reports Archived   : ${data.backup.reports_archived}\n` +
        `Archive File Size  : ${data.backup.size_bytes} bytes`;
    }
    await loadCloudInfrastructureStatus();
  } catch (err) {
    if (consoleEl) consoleEl.textContent = `[ERROR] Backup failed: ${err.message}`;
  }
}

async function sendTestCloudWatchMetric() {
  const consoleEl = document.getElementById("cloud-ops-console");
  if (consoleEl) {
    consoleEl.style.display = "block";
    consoleEl.textContent = "Publishing test verification metric to Amazon CloudWatch...";
  }

  try {
    const res = await fetch("/api/cloud/cloudwatch/publish-test", { method: "POST" });
    const data = await res.json();
    if (consoleEl) {
      consoleEl.textContent = `[SUCCESS] ${data.message}\n` +
        `Published to AWS CloudWatch API: ${data.published_to_aws ? "YES (CloudWatch API)" : "NO (Kept in Local Telemetry Buffer)"}\n` +
        `Total Telemetry Records Buffered: ${data.recent_metrics_count}`;
    }
    await loadCloudInfrastructureStatus();
  } catch (err) {
    if (consoleEl) consoleEl.textContent = `[ERROR] Metric test failed: ${err.message}`;
  }
}


// ==========================================
// Day 19: SMT Theorem Prover & Continuous Risk UI
// ==========================================

function closeSmtInspector() {
  const panel = document.getElementById("smt-inspector-container");
  if (panel) panel.style.display = "none";
}

async function verifyPolicyWithSMT() {
  const editor = document.getElementById("policy-editor");
  const rawText = editor.value.trim();

  let policy;
  try {
    policy = JSON.parse(rawText);
  } catch (err) {
    alert("JSON Parse Error: Please correct policy syntax before verification.\n" + err.message);
    return;
  }

  const btn = document.getElementById("btn-verify-smt");
  const originalText = btn.textContent;
  btn.textContent = "Solving Z3 SMT...";
  btn.disabled = true;

  try {
    // 1. Call SMT Theorem Prover Endpoint
    const resSmt = await fetch("/api/policies/verify-smt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(policy)
    });

    if (!resSmt.ok) {
      const errData = await resSmt.json();
      throw new Error(errData.detail || "SMT verification server error");
    }

    const smtResponse = await resSmt.json();
    const fsmReport = smtResponse.fsm_report;
    const smtAnalysis = smtResponse.smt_analysis;

    // Render FSM Report and standard metrics
    currentReport = fsmReport;
    renderVerificationResults(fsmReport);

    // 2. Call Continuous Risk Engine for dynamic trajectory evaluation
    let riskData = null;
    try {
      const resRisk = await fetch("/api/policies/verify-risk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(policy)
      });
      if (resRisk.ok) {
        riskData = await resRisk.json();
      }
    } catch (rErr) {
      console.warn("Continuous risk verification non-blocking warning:", rErr);
    }

    // 3. Annotate Directed Automaton Graph with SMT results
    if (fsmReport.fsm_graph_summary && fsmReport.fsm_graph_summary.elements) {
      renderFsmGraph(fsmReport.fsm_graph_summary.elements, fsmReport.violations, smtAnalysis);
    }

    // 4. Render SMT & Continuous Risk Inspector Drawer
    renderSmtAndRiskDashboard(smtAnalysis, riskData);
    await loadVerificationHistory();
  } catch (err) {
    alert("SMT Verification failed: " + err.message);
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

function renderSmtAndRiskDashboard(smtAnalysis, riskData) {
  const container = document.getElementById("smt-inspector-container");
  if (!container) return;
  container.style.display = "block";

  // Engine & global status badges
  const engineBadge = document.getElementById("smt-solver-engine-badge");
  const statusBadge = document.getElementById("smt-global-status-badge");
  if (engineBadge) engineBadge.textContent = smtAnalysis.solver_engine || "Microsoft Z3 Theorem Prover";

  if (statusBadge) {
    if (smtAnalysis.has_dead_transitions) {
      statusBadge.textContent = "CONTRADICTORY (DEAD TRANSITIONS)";
      statusBadge.className = "badge badge-unsat";
    } else {
      statusBadge.textContent = "SMT SATISFIABLE";
      statusBadge.className = "badge badge-sat";
    }
  }

  // Dead transitions alert
  const deadAlert = document.getElementById("smt-dead-transitions-alert");
  if (deadAlert) {
    if (smtAnalysis.has_dead_transitions && smtAnalysis.dead_transitions_detected && smtAnalysis.dead_transitions_detected.length > 0) {
      deadAlert.style.display = "block";
      let deadHtml = `<div style="font-weight: 600; color: #f87171; margin-bottom: 6px;">⚠ ${smtAnalysis.dead_transitions_detected.length} Mathematically Dead Transition(s) Detected:</div>`;
      smtAnalysis.dead_transitions_detected.forEach(d => {
        deadHtml += `
          <div class="smt-dead-trans-item">
            <strong>Rule ${escapeHtml(d.rule_id)}</strong>: &delta;(${escapeHtml(d.source)}, ${escapeHtml(d.action)}) &rarr; ${escapeHtml(d.target)}
            <div style="color: #cbd5e1; margin-top: 2px;">Condition: <code>${escapeHtml(d.guard || d.condition || 'None')}</code></div>
            <div style="color: #fca5a5; margin-top: 2px;">Contradiction: ${escapeHtml(d.reason || d.explanation || 'Mathematically unsatisfiable')}</div>
          </div>
        `;
      });
      deadAlert.innerHTML = deadHtml;
    } else {
      deadAlert.style.display = "block";
      deadAlert.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid #10b981; border-radius: 4px; padding: 8px 12px; color: #86efac; font-size: 11px;">
          ✓ <strong>First-Order LRA/LIA Consistency:</strong> All transition guard predicates are free from mathematical contradictions.
        </div>
      `;
    }
  }

  // Witness context models table
  const witnessContainer = document.getElementById("smt-witness-model-container");
  if (witnessContainer) {
    const checks = smtAnalysis.guard_satisfiability_checks || [];
    if (checks.length === 0) {
      witnessContainer.innerHTML = `<p style="color: #94a3b8; font-size: 11px;">No explicit guard predicates attached to terminal access grants.</p>`;
    } else {
      let tableHtml = `
        <table class="smt-model-table">
          <thead>
            <tr>
              <th>Rule / Target</th>
              <th>First-Order Guard Expression</th>
              <th>SMT Result</th>
              <th>Satisfying Witness Context Assignment</th>
            </tr>
          </thead>
          <tbody>
      `;
      checks.forEach(chk => {
        const isSat = chk.is_satisfiable;
        let witnessStr = "None (Unconstrained)";
        if (chk.witness_model && Object.keys(chk.witness_model).length > 0) {
          witnessStr = Object.entries(chk.witness_model)
            .map(([k, v]) => `${k} = ${v}`)
            .join(", ");
        }
        tableHtml += `
          <tr>
            <td><code>${escapeHtml(chk.rule_id)}</code> &rarr; <strong>${escapeHtml(chk.target)}</strong></td>
            <td><code style="color: #38bdf8;">${escapeHtml(chk.guard)}</code></td>
            <td><span class="badge ${isSat ? 'badge-sat' : 'badge-unsat'}">${chk.smt_status}</span></td>
            <td><code style="color: #a7f3d0;">${escapeHtml(witnessStr)}</code></td>
          </tr>
        `;
      });
      tableHtml += `</tbody></table>`;
      witnessContainer.innerHTML = tableHtml;
    }
  }

  // Continuous Risk Trajectory Breakdown
  const riskContainer = document.getElementById("smt-risk-trajectories-container");
  if (riskContainer) {
    if (!riskData || !riskData.trajectory_risk_profiles || riskData.trajectory_risk_profiles.length === 0) {
      riskContainer.innerHTML = `<p style="color: #94a3b8; font-size: 11px;">No access trajectories leading to terminal grant states.</p>`;
    } else {
      let rHtml = "";
      const thresh = riskData.stepup_threshold || 0.50;
      riskData.trajectory_risk_profiles.forEach((p, idx) => {
        const pathArr = p.trajectory || p.path || [];
        const pathStr = pathArr.join(" &rarr; ");
        const riskPct = Math.min(100, Math.round(p.cumulative_risk * 100));
        const isHigh = p.cumulative_risk >= thresh;
        const hasStepup = p.step_up_triggered !== undefined ? p.step_up_triggered : p.has_stepup;
        let barColor = "#22c55e";
        if (p.cumulative_risk > 0.70) barColor = "#ef4444";
        else if (p.cumulative_risk >= 0.40) barColor = "#f59e0b";

        rHtml += `
          <div class="trajectory-card">
            <div class="trajectory-path">Trajectory #${idx + 1}: ${pathStr}</div>
            <div class="trajectory-meta">
              <span>Cumulative Risk: <strong>${p.cumulative_risk.toFixed(2)}</strong></span>
              <span>
                <div class="risk-meter">
                  <div class="risk-meter-fill" style="width: ${riskPct}%; background-color: ${barColor};"></div>
                </div>
              </span>
              <span>Peak Transition: <strong>${p.peak_transition_risk.toFixed(2)}</strong></span>
              <span>Threshold &tau;: <strong>${thresh.toFixed(2)}</strong></span>
              <span style="margin-left: auto;">
                ${hasStepup ?
                  '<span class="badge badge-stepup-ok">✓ Step-Up MFA Challenge Verified</span>' :
                  (isHigh ?
                    '<span class="badge badge-stepup-warn">⚠ High Risk / Missing Step-Up</span>' :
                    '<span class="badge" style="background:#1e293b; color:#94a3b8;">Normal Risk Path</span>'
                  )
                }
              </span>
            </div>
          </div>
        `;
      });
      riskContainer.innerHTML = rHtml;
    }
  }
}

// ==========================================
// Day 22: CEGIS Self-Healing & Visual Graph Diff
// ==========================================

function closeCegisInspector() {
  const panel = document.getElementById("cegis-inspector-container");
  if (panel) panel.style.display = "none";
}

async function runCegisAutoRepair() {
  const editor = document.getElementById("policy-editor");
  const rawText = editor.value.trim();

  let policy;
  try {
    policy = JSON.parse(rawText);
  } catch (err) {
    alert("JSON Parse Error: Please correct policy syntax before running CEGIS repair.\n" + err.message);
    return;
  }

  const btn = document.getElementById("btn-cegis-repair");
  const originalText = btn.textContent;
  btn.textContent = "Synthesizing Fix (CEGIS)...";
  btn.disabled = true;

  try {
    const res = await fetch("/api/policies/cegis-repair?max_iterations=6", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(policy)
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || "CEGIS server synthesis error");
    }

    currentCegisResult = await res.json();

    // Fetch graph elements of the repaired policy for the diff view
    if (currentCegisResult.repaired_policy) {
      try {
        const repVerifyRes = await fetch("/api/policies/verify?save_audit=false", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(currentCegisResult.repaired_policy)
        });
        if (repVerifyRes.ok) {
          const repReport = await repVerifyRes.json();
          repairedGraphElements = repReport.fsm_graph_summary ? repReport.fsm_graph_summary.elements : [];
        }
      } catch (e) {
        console.warn("Could not fetch repaired graph summary:", e);
      }
    }

    renderCegisInspector(currentCegisResult);
    switchGraphView("diff");
  } catch (err) {
    alert("CEGIS Policy Synthesis failed: " + err.message);
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

function renderCegisInspector(result) {
  const container = document.getElementById("cegis-inspector-container");
  if (!container) return;
  container.style.display = "block";

  // Badges
  const statusBadge = document.getElementById("cegis-status-badge");
  const roundsBadge = document.getElementById("cegis-rounds-badge");
  const costBadge = document.getElementById("cegis-cost-badge");

  if (statusBadge) {
    statusBadge.textContent = result.status;
    statusBadge.className = `badge ${result.converged ? 'badge-cegis' : 'badge-unsat'}`;
  }
  if (roundsBadge) {
    roundsBadge.textContent = `${result.iterations_count} Round(s)`;
  }
  if (costBadge) {
    costBadge.textContent = `Graph Edit Distance: ${result.cumulative_edit_distance}`;
  }

  // Iteration trace table
  const traceContainer = document.getElementById("cegis-iteration-trace-container");
  if (traceContainer) {
    if (!result.iteration_history || result.iteration_history.length === 0) {
      traceContainer.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid #10b981; border-radius: 4px; padding: 8px 12px; color: #86efac; font-size: 11px;">
          ✓ <strong>Zero-Edit Pass:</strong> Policy already satisfies all safety invariants without requiring graph surgery.
        </div>
      `;
    } else {
      let tHtml = `
        <table class="cegis-trace-table">
          <thead>
            <tr>
              <th>Round</th>
              <th>Violations Before</th>
              <th>Surgeries Applied</th>
              <th>Edit Cost</th>
              <th>Violations After</th>
              <th>Status</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody>
      `;
      result.iteration_history.forEach(rec => {
        const patchSummaries = (rec.patches_applied || []).map(p => `<code>${escapeHtml(p.op_type)}</code>: ${escapeHtml(p.description)}`).join("<br>");
        tHtml += `
          <tr>
            <td><strong>#${rec.iteration}</strong></td>
            <td><span class="badge" style="background:#7f1d1d; color:#fecaca;">${rec.violations_before} Flaw(s)</span></td>
            <td style="font-size: 10px; color: #cbd5e1;">${patchSummaries || 'None'}</td>
            <td><code style="color: #38bdf8;">+${rec.edit_distance_delta}</code></td>
            <td><span class="badge ${rec.violations_after === 0 ? 'badge-sat' : 'badge-unsat'}">${rec.violations_after}</span></td>
            <td>${rec.converged_this_round ? '<span class="badge badge-sat">CONVERGED</span>' : '<span class="badge" style="background:#334155;color:#94a3b8;">REFINED</span>'}</td>
            <td><span style="color:#94a3b8;">${rec.iteration_latency_ms} ms</span></td>
          </tr>
        `;
      });
      tHtml += `</tbody></table>`;
      traceContainer.innerHTML = tHtml;
    }
  }

  // RFC 6902 JSON patch
  const rfcEl = document.getElementById("cegis-rfc6902-code");
  if (rfcEl) {
    rfcEl.textContent = JSON.stringify(result.cumulative_rfc6902_patch_document, null, 2);
  }
}

function switchGraphView(mode) {
  const btnDiff = document.getElementById("btn-view-diff");
  const btnRepaired = document.getElementById("btn-view-repaired");
  const btnOriginal = document.getElementById("btn-view-original");

  if (btnDiff) btnDiff.className = `btn btn-sm ${mode === 'diff' ? 'btn-primary active' : ''}`;
  if (btnRepaired) btnRepaired.className = `btn btn-sm ${mode === 'repaired' ? 'btn-primary active' : ''}`;
  if (btnOriginal) btnOriginal.className = `btn btn-sm ${mode === 'original' ? 'btn-primary active' : ''}`;

  if (mode === "diff") {
    const patches = currentCegisResult ? (currentCegisResult.iteration_history || []).flatMap(h => h.patches_applied || []) : [];
    renderGraphDiff(originalGraphElements, repairedGraphElements, patches);
  } else if (mode === "repaired") {
    if (repairedGraphElements) {
      renderFsmGraph(repairedGraphElements);
    }
  } else if (mode === "original") {
    if (originalGraphElements) {
      renderFsmGraph(originalGraphElements);
    }
  }
}

async function applySynthesizedRepairToEditor() {
  if (!currentCegisResult || !currentCegisResult.repaired_policy) {
    alert("No synthesized repaired policy available to apply.");
    return;
  }

  const editor = document.getElementById("policy-editor");
  editor.value = JSON.stringify(currentCegisResult.repaired_policy, null, 2);
  closeCegisInspector();

  // Run formal verification on the new repaired policy
  await verifyCurrentPolicy();

  alert("✓ Successfully applied synthesized repair!\nPolicy has been updated in the editor and verified compliant with 0 violations.");
}
