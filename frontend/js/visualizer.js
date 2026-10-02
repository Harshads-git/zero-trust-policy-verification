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
      }
    ],
    layout: {
      name: "breadthfirst",
      directed: true,
      padding: 30,
      spacingFactor: 1.3
    }
  });

  // State inspection tooltip / modal
  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    const info = document.getElementById("node-inspector-details");
    if (info) {
      info.innerHTML = `<strong>State:</strong> ${node.id()}<br>
                        <strong>Type:</strong> ${node.data("is_start") ? "Initial (q0)" : (node.data("is_terminal") ? "Terminal (F)" : "Intermediate")}<br>
                        <strong>Out-degree:</strong> ${node.outgoers("edge").length}<br>
                        <strong>In-degree:</strong> ${node.incomers("edge").length}`;
    }
  });
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

