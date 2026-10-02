/**
 * FSM Graph Visualizer Module
 * Wraps Cytoscape.js for directed graph rendering, state inspection,
 * and security violation path highlighting.
 */

let cy = null;

function initVisualizer(containerId = "cy-container") {
  const container = document.getElementById(containerId);
  if (!container || typeof cytoscape === "undefined") {
    console.warn("Cytoscape or container not ready yet.");
    return;
  }

  cy = cytoscape({
    container: container,
    elements: [],
    style: [
      {
        selector: "node",
        style: {
          "label": "data(label)",
          "color": "#f8fafc",
          "font-size": "11px",
          "font-family": "SFMono-Regular, Consolas, monospace",
          "text-valign": "center",
          "text-halign": "center",
          "background-color": "#1e293b",
          "border-width": 2,
          "border-color": "#475569",
          "width": 120,
          "height": 40,
          "shape": "round-rectangle",
          "text-wrap": "ellipsis",
          "text-max-width": "110px"
        }
      },
      {
        selector: "node.start-state",
        style: {
          "background-color": "#0369a1",
          "border-color": "#38bdf8",
          "border-width": 3,
          "shape": "ellipse",
          "width": 70,
          "height": 70
        }
      },
      {
        selector: "node.terminal-state",
        style: {
          "border-style": "double",
          "border-width": 4
        }
      },
      {
        selector: "node.granted-state",
        style: {
          "background-color": "#14532d",
          "border-color": "#22c55e",
          "color": "#bbf7d0"
        }
      },
      {
        selector: "node.denied-state",
        style: {
          "background-color": "#7f1d1d",
          "border-color": "#ef4444",
          "color": "#fecaca"
        }
      },
      {
        selector: "node.violation-node",
        style: {
          "background-color": "#991b1b",
          "border-color": "#f87171",
          "border-width": 3
        }
      },
      {
        selector: "edge",
        style: {
          "width": 2,
          "line-color": "#64748b",
          "target-arrow-color": "#64748b",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": "9px",
          "color": "#94a3b8",
          "text-rotation": "autorotate",
          "text-background-opacity": 0.8,
          "text-background-color": "#0f172a",
          "text-background-padding": 2,
          "arrow-scale": 1.1
        }
      },
      {
        selector: "edge.violation-edge",
        style: {
          "line-color": "#ef4444",
          "target-arrow-color": "#ef4444",
          "width": 3
        }
      },
      {
        selector: ".dimmed",
        style: {
          "opacity": 0.2
        }
      },
      {
        selector: "node.trace-highlight-node",
        style: {
          "background-color": "#dc2626",
          "border-color": "#ffffff",
          "border-width": 4,
          "color": "#ffffff",
          "font-weight": "bold",
          "opacity": 1.0,
          "z-index": 999
        }
      },
      {
        selector: "edge.trace-highlight-edge",
        style: {
          "line-color": "#ef4444",
          "target-arrow-color": "#ef4444",
          "width": 5,
          "opacity": 1.0,
          "z-index": 999,
          "arrow-scale": 1.4
        }
      },
      {
        selector: "node.trace-active-step",
        style: {
          "background-color": "#38bdf8",
          "border-color": "#ffffff",
          "border-width": 5,
          "color": "#ffffff",
          "opacity": 1.0,
          "z-index": 1000
        }
      }
    ],
    layout: {
      name: "breadthfirst",
      directed: true,
      padding: 30,
      spacingFactor: 1.3
    }
  });

  // Tap node inspector
  cy.on("tap", "node", function (evt) {
    inspectNode(evt.target);
  });

  // Tap edge inspector
  cy.on("tap", "edge", function (evt) {
    inspectEdge(evt.target);
  });

  // Tap background clears inspector
  cy.on("tap", function (evt) {
    if (evt.target === cy) {
      closeInspector();
    }
  });
}

function inspectNode(node) {
  const panel = document.getElementById("graph-inspector-panel");
  const title = document.getElementById("inspector-title");
  const content = document.getElementById("inspector-content");
  const legendDetails = document.getElementById("node-inspector-details");

  const isStart = node.data("is_start");
  const isTerminal = node.data("is_terminal");
  const isViolation = node.hasClass("violation-node");
  const inEdges = node.incomers("edge");
  const outEdges = node.outgoers("edge");

  if (legendDetails) {
    legendDetails.innerHTML = `State: <strong>${node.id()}</strong> &nbsp;|&nbsp; deg⁻: ${inEdges.length}, deg⁺: ${outEdges.length}`;
  }

  if (!panel || !content) return;

  panel.style.display = "block";
  title.innerHTML = `Automaton State Inspector &mdash; <code style="color:#f8fafc; font-size:13px;">${node.id()}</code>`;

  let inListHtml = "";
  if (inEdges.length > 0) {
    inEdges.forEach(e => {
      const srcId = e.source().id();
      const action = e.data("action") || e.data("label") || "TRANSITION";
      const cond = e.data("condition") ? ` [${escapeHtml(e.data("condition"))}]` : "";
      inListHtml += `<li>&larr; <code>${escapeHtml(srcId)}</code> via <strong>${escapeHtml(action)}</strong>${cond}</li>`;
    });
  } else {
    inListHtml = "<li style='color: #64748b;'>None (Initial state or unreachable)</li>";
  }

  let outListHtml = "";
  if (outEdges.length > 0) {
    outEdges.forEach(e => {
      const tgtId = e.target().id();
      const action = e.data("action") || e.data("label") || "TRANSITION";
      const cond = e.data("condition") ? ` [${escapeHtml(e.data("condition"))}]` : "";
      outListHtml += `<li>&rarr; <code>${escapeHtml(tgtId)}</code> via <strong>${escapeHtml(action)}</strong>${cond}</li>`;
    });
  } else {
    outListHtml = "<li style='color: #64748b;'>None (Terminal state or dead-end)</li>";
  }

  content.innerHTML = `
    <div class="inspector-grid">
      <div class="inspector-field">
        <span class="inspector-field-label">Formal Automaton Type</span>
        <span class="inspector-field-val">
          ${isStart ? '<span class="badge" style="background:#0369a1;color:#bae6fd;">Initial (q₀)</span> ' : ''}
          ${isTerminal ? '<span class="badge" style="background:#14532d;color:#86efac;">Terminal (F)</span> ' : ''}
          ${!isStart && !isTerminal ? '<span class="badge" style="background:#334155;color:#cbd5e1;">Intermediate State</span> ' : ''}
          ${isViolation ? '<span class="badge" style="background:#7f1d1d;color:#fecaca;">Violation Path Traversed</span>' : ''}
        </span>
      </div>
      <div class="inspector-field">
        <span class="inspector-field-label">Automaton Degrees (In / Out)</span>
        <span class="inspector-field-val">deg⁻(q) = <strong>${inEdges.length}</strong> &nbsp;|&nbsp; deg⁺(q) = <strong>${outEdges.length}</strong></span>
      </div>
      <div class="inspector-field">
        <span class="inspector-field-label">Quick Navigation</span>
        <span class="inspector-field-val">
          <button class="btn btn-sm" onclick="focusStateNode('${node.id()}')">Center on Node</button>
        </span>
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 10px;">
      <div>
        <span class="inspector-field-label">Incoming Transitions &delta;⁻(q)</span>
        <ul class="inspector-list">${inListHtml}</ul>
      </div>
      <div>
        <span class="inspector-field-label">Outgoing Transitions &delta;⁺(q)</span>
        <ul class="inspector-list">${outListHtml}</ul>
      </div>
    </div>
  `;
}

function inspectEdge(edge) {
  const panel = document.getElementById("graph-inspector-panel");
  const title = document.getElementById("inspector-title");
  const content = document.getElementById("inspector-content");
  if (!panel || !content) return;

  panel.style.display = "block";
  const ruleId = edge.data("rule_id") || edge.id();
  title.innerHTML = `Transition Inspector &mdash; Rule <code style="color:#f8fafc; font-size:13px;">${escapeHtml(ruleId)}</code>`;

  const src = edge.source().id();
  const tgt = edge.target().id();
  const action = edge.data("action") || edge.data("label") || "TRANSITION";
  const cond = edge.data("condition") || "None (Unconditional)";
  const isViolation = edge.hasClass("violation-edge") || edge.hasClass("trace-highlight-edge");

  content.innerHTML = `
    <div class="inspector-grid">
      <div class="inspector-field">
        <span class="inspector-field-label">Transition Formula</span>
        <span class="inspector-field-val">&delta;(<code>${escapeHtml(src)}</code>, <strong>${escapeHtml(action)}</strong>) &rarr; <code>${escapeHtml(tgt)}</code></span>
      </div>
      <div class="inspector-field">
        <span class="inspector-field-label">Guard Condition</span>
        <span class="inspector-field-val"><code>${escapeHtml(cond)}</code></span>
      </div>
      <div class="inspector-field">
        <span class="inspector-field-label">Rule Identifier</span>
        <span class="inspector-field-val"><code>${escapeHtml(ruleId)}</code></span>
      </div>
      <div class="inspector-field">
        <span class="inspector-field-label">Verification Status</span>
        <span class="inspector-field-val">${isViolation ? '<span class="badge" style="background:#7f1d1d;color:#fecaca;">Part of Counterexample Witness Trace</span>' : '<span class="badge" style="background:#14532d;color:#86efac;">Valid Transition</span>'}</span>
      </div>
    </div>
  `;
}

function closeInspector() {
  const panel = document.getElementById("graph-inspector-panel");
  if (panel) panel.style.display = "none";
}

function focusStateNode(nodeId) {
  if (!cy) return;
  const node = cy.nodes(`[id = "${nodeId}"]`);
  if (node.length > 0) {
    cy.animate({
      center: { eles: node },
      zoom: 1.5,
      duration: 400
    });
  }
}

let activeAnimationTimer = null;

function highlightWitnessTrace(witnessPath) {
  if (!cy || !witnessPath || witnessPath.length === 0) return;
  stopTraceAnimation();

  // Dim everything else
  cy.elements().addClass("dimmed").removeClass("trace-highlight-node trace-highlight-edge trace-active-step");

  // Highlight path nodes
  witnessPath.forEach(stateId => {
    cy.nodes(`[id = "${stateId}"]`).removeClass("dimmed").addClass("trace-highlight-node");
  });

  // Highlight path edges
  for (let i = 0; i < witnessPath.length - 1; i++) {
    const src = witnessPath[i];
    const tgt = witnessPath[i + 1];
    cy.edges(`[source = "${src}"][target = "${tgt}"]`).removeClass("dimmed").addClass("trace-highlight-edge");
  }

  // Focus viewport on witness path
  const targetElements = cy.elements(".trace-highlight-node, .trace-highlight-edge");
  if (targetElements.length > 0) {
    cy.animate({
      fit: {
        eles: targetElements,
        padding: 50
      },
      duration: 500
    });
  }
}

function clearTraceHighlights() {
  if (!cy) return;
  stopTraceAnimation();
  cy.elements().removeClass("dimmed trace-highlight-node trace-highlight-edge trace-active-step");
  cy.fit(undefined, 35);
}

function stopTraceAnimation() {
  if (activeAnimationTimer) {
    clearInterval(activeAnimationTimer);
    activeAnimationTimer = null;
  }
}

function animateWitnessTrace(witnessPath) {
  if (!cy || !witnessPath || witnessPath.length === 0) return;
  highlightWitnessTrace(witnessPath);

  let step = 0;
  stopTraceAnimation();

  activeAnimationTimer = setInterval(() => {
    cy.nodes().removeClass("trace-active-step");
    if (step >= witnessPath.length) {
      step = 0;
    }
    const currState = witnessPath[step];
    const node = cy.nodes(`[id = "${currState}"]`);
    node.addClass("trace-active-step");
    step++;
  }, 650);
}


function renderFsmGraph(elements, violations = []) {
  if (!cy) {
    initVisualizer("cy-container");
  }
  if (!cy) return;

  cy.elements().remove();
  cy.add(elements);

  // Re-apply locked state if active
  if (nodesLocked) {
    cy.nodes().lock();
  }

  // Highlight violating paths
  violations.forEach(v => {
    if (v.witness_path && v.witness_path.length > 1) {
      for (let i = 0; i < v.witness_path.length - 1; i++) {
        const src = v.witness_path[i];
        const tgt = v.witness_path[i + 1];
        cy.edges(`[source = "${src}"][target = "${tgt}"]`).addClass("violation-edge");
      }
    }
    if (v.state) {
      cy.nodes(`[id = "${v.state}"]`).addClass("violation-node");
    }
  });

  applyCurrentLayout(false);
}

let currentLayout = "breadthfirst";
let nodesLocked = false;

function changeGraphLayout(layoutName) {
  currentLayout = layoutName;
  applyCurrentLayout(true);
}

function applyCurrentLayout(animate = true) {
  if (!cy || cy.elements().length === 0) return;

  let layoutOptions = {
    padding: 35,
    animate: animate,
    animationDuration: 400
  };

  if (currentLayout === "breadthfirst") {
    const startNodes = cy.nodes().filter(n => n.data("is_start"));
    layoutOptions = {
      ...layoutOptions,
      name: "breadthfirst",
      directed: true,
      spacingFactor: 1.4,
      roots: startNodes.length > 0 ? startNodes : undefined
    };
  } else if (currentLayout === "cose") {
    layoutOptions = {
      ...layoutOptions,
      name: "cose",
      nodeRepulsion: 6500,
      idealEdgeLength: 100,
      gravity: 0.25,
      numIter: 1000
    };
  } else if (currentLayout === "concentric") {
    layoutOptions = {
      ...layoutOptions,
      name: "concentric",
      concentric: function (node) {
        return node.data("is_start") ? 3 : (node.data("is_terminal") ? 1 : 2);
      },
      levelWidth: () => 1
    };
  } else if (currentLayout === "circle") {
    layoutOptions = {
      ...layoutOptions,
      name: "circle"
    };
  } else if (currentLayout === "grid") {
    layoutOptions = {
      ...layoutOptions,
      name: "grid",
      avoidOverlap: true
    };
  }

  const layout = cy.layout(layoutOptions);
  layout.run();
  if (!animate) {
    cy.fit(undefined, 35);
  }
}

function zoomInGraph() {
  if (cy) {
    cy.zoom({
      level: cy.zoom() * 1.25,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  }
}

function zoomOutGraph() {
  if (cy) {
    cy.zoom({
      level: cy.zoom() * 0.8,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  }
}

function resetGraphZoom() {
  if (cy) {
    cy.fit(undefined, 35);
    cy.center();
  }
}

function toggleNodeLock() {
  if (!cy) return;
  nodesLocked = !nodesLocked;
  if (nodesLocked) {
    cy.nodes().lock();
  } else {
    cy.nodes().unlock();
  }
  const lockBtn = document.getElementById("btn-lock-nodes");
  if (lockBtn) {
    lockBtn.textContent = nodesLocked ? "Unlock" : "Lock";
    lockBtn.style.backgroundColor = nodesLocked ? "#7f1d1d" : "";
  }
}

function exportGraphImage() {
  if (!cy || cy.elements().length === 0) {
    alert("No automaton graph loaded to export.");
    return;
  }
  try {
    const pngData = cy.png({
      full: true,
      bg: "#090d16",
      scale: 2
    });
    const a = document.createElement("a");
    a.href = pngData;
    a.download = `ztpve_automaton_graph_${Date.now()}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } catch (err) {
    alert("Failed to export graph image: " + err.message);
  }
}

