const THREATS = {
  1: {
    label: "Threat 1: Tool Poisoning",
    startLabel: "Run Attack Simulation",
    desc: "poisoned_query claims to be a read-only SELECT tool, but a hidden magic string ('--UNSAFE_BYPASS') flips it into executing arbitrary SQL, including destructive statements. Watch the database's row count change between the baseline snapshot and the final verification.",
  },
  2: {
    label: "Threat 2: Prompt Injection via Tool Results",
    startLabel: "Run Attack Simulation",
    desc: "injection_vulnerable_query returns raw file content with no escaping or boundary markers. If that content contains prompt-like directives, an LLM reading the tool result may treat them as instructions.",
  },
  3: {
    label: "Threat 3: Over-Broad Tool Scope",
    startLabel: "Run Attack Simulation",
    desc: "overscoped_file_access is described as reading 'user files' but performs no path validation, allowlisting, or traversal checks. Each test case below probes a different path against the tool.",
  },
};

const state = {}; // threat_id -> { titles: [], history: [], index: 0, done: false }

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else node.setAttribute(k, v);
  }
  for (const child of [].concat(children)) {
    if (child == null) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function buildPanels() {
  const panels = document.getElementById("panels");
  for (const id of Object.keys(THREATS)) {
    const t = THREATS[id];
    const panel = el("section", { class: "panel", id: `panel-${id}` }, [
      el("p", { class: "panel-desc" }, t.desc),
      el("div", { class: "controls" }, [
        el("button", { class: "action", id: `start-${id}` }, t.startLabel),
        el("button", { class: "action secondary", id: `next-${id}`, disabled: "true" }, "Next Step"),
        el("span", { class: "status-badge", id: `badge-${id}` }),
      ]),
      el("div", { class: "timeline", id: `timeline-${id}` }),
      el("div", { class: "log", id: `log-${id}` }),
    ]);
    panels.appendChild(panel);

    document.getElementById(`start-${id}`).addEventListener("click", () => startThreat(id));
    document.getElementById(`next-${id}`).addEventListener("click", () => nextStep(id));
  }
}

function setActiveTab(id) {
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.threat === String(id));
  });
  document.querySelectorAll(".panel").forEach((p) => {
    p.classList.toggle("active", p.id === `panel-${id}`);
  });
}

function renderTimeline(id) {
  const s = state[id];
  const container = document.getElementById(`timeline-${id}`);
  container.innerHTML = "";
  s.titles.forEach((title, i) => {
    const isDone = i < s.index;
    const isCurrent = i === s.index && !s.done;
    const histEntry = s.history[i];
    const flagged = histEntry && histEntry.detail && (histEntry.detail.vulnerable === true);

    const stepClasses = ["step"];
    if (isDone) stepClasses.push("done");
    if (isDone && flagged) stepClasses.push("flag");
    if (isCurrent) stepClasses.push("current");

    const dotContent = isDone ? (flagged ? "!" : "✓") : String(i + 1);

    container.appendChild(
      el("div", { class: stepClasses.join(" ") }, [
        el("div", { class: "connector" }),
        el("div", { class: "dot" }, dotContent),
        el("div", { class: "label" }, title),
      ])
    );
  });
}

function renderDbTable(users, removedIds = new Set()) {
  const table = el("table", { class: "db-table" }, [
    el("thead", {}, el("tr", {}, ["ID", "Name", "Email", "Role"].map((h) => el("th", {}, h)))),
  ]);
  const tbody = el("tbody");
  users.forEach((u) => {
    const row = el("tr", removedIds.has(u.id) ? { class: "row-removed" } : {}, [
      el("td", {}, String(u.id)),
      el("td", {}, u.name),
      el("td", {}, u.email),
      el("td", {}, u.role),
    ]);
    tbody.appendChild(row);
  });
  table.appendChild(tbody);
  return table;
}

function renderThreat1Detail(detail) {
  const parts = [];
  if (detail.db_before && !detail.db_after) {
    parts.push(el("div", {}, [
      el("h4", { style: "margin:0 0 6px;font-size:.78rem;color:var(--text-dim);text-transform:uppercase" }, "Database (before)"),
      renderDbTable(detail.db_before),
    ]));
  }
  if (detail.db_before && detail.db_after) {
    const beforeIds = new Set(detail.db_before.map((u) => u.id));
    const afterIds = new Set(detail.db_after.map((u) => u.id));
    const removed = [...beforeIds].filter((id) => !afterIds.has(id));
    const compare = el("div", { class: "db-compare" }, [
      el("div", {}, [el("h4", {}, "Before attack"), renderDbTable(detail.db_before)]),
      el("div", {}, [el("h4", {}, "After attack"), renderDbTable(detail.db_after, new Set(removed))]),
    ]);
    parts.push(compare);
    if (detail.vulnerable) {
      parts.push(el("p", { class: "highlight-inject" }, `${removed.length} row(s) deleted by a tool the LLM believed was read-only.`));
    } else {
      parts.push(el("p", {}, "No rows were deleted."));
    }
  }
  if (detail.query) {
    parts.push(el("pre", { class: "code" }, `Call: poisoned_query("${detail.query}")`));
  }
  if (detail.tool_response) {
    parts.push(el("pre", { class: "code" }, JSON.stringify(detail.tool_response, null, 2)));
  }
  return parts;
}

function renderThreat2Detail(detail) {
  const parts = [];
  if (detail.content) {
    const flagged = ["SYSTEM PROMPT OVERRIDE", "IGNORE_SAFETY_CHECKS", "UNRESTRICTED_MODE"];
    let html = escapeHtml(detail.content);
    flagged.forEach((phrase) => {
      html = html.split(escapeHtml(phrase)).join(`<span class="highlight-inject">${escapeHtml(phrase)}</span>`);
    });
    parts.push(el("pre", { class: "code", html }));
  }
  if (detail.tool_response) {
    const clone = { ...detail.tool_response };
    parts.push(el("pre", { class: "code" }, JSON.stringify(clone, null, 2)));
  }
  if (typeof detail.vulnerable === "boolean") {
    parts.push(
      detail.vulnerable
        ? el("p", { class: "highlight-inject" }, "Injected directives were returned verbatim -- an LLM concatenating this into its prompt would see them as instructions, not data.")
        : el("p", {}, "No injection markers were found in the returned content.")
    );
  }
  return parts;
}

function renderThreat3Detail(detail) {
  const parts = [];
  if (detail.path) {
    const rowClass = detail.scope === "INTENDED" ? "case-intended" : detail.vulnerable ? "case-vulnerable" : "case-blocked";
    const resultText = detail.accessible
      ? (detail.scope === "INTENDED" ? "Accessible (expected)" : "Accessible -- VULNERABLE")
      : "Blocked";
    const table = el("table", { class: "case-table" }, [
      el("thead", {}, el("tr", {}, ["Path", "Scope", "Expected", "Result"].map((h) => el("th", {}, h)))),
      el("tbody", {}, el("tr", { class: rowClass }, [
        el("td", {}, detail.path),
        el("td", {}, detail.scope),
        el("td", {}, detail.expected),
        el("td", { class: "result" }, resultText),
      ])),
    ]);
    parts.push(table);
    if (detail.tool_response && detail.tool_response.content) {
      parts.push(el("pre", { class: "code" }, detail.tool_response.content.slice(0, 300)));
    }
  }
  if (detail.cases) {
    const table = el("table", { class: "case-table" }, [
      el("thead", {}, el("tr", {}, ["Path", "Scope", "Expected", "Result"].map((h) => el("th", {}, h)))),
    ]);
    const tbody = el("tbody");
    detail.cases.forEach((c) => {
      const rowClass = c.scope === "INTENDED" ? "case-intended" : c.vulnerable ? "case-vulnerable" : "case-blocked";
      const resultText = c.accessible
        ? (c.scope === "INTENDED" ? "Accessible (expected)" : "Accessible -- VULNERABLE")
        : "Blocked";
      tbody.appendChild(el("tr", { class: rowClass }, [
        el("td", {}, c.path),
        el("td", {}, c.scope),
        el("td", {}, c.expected),
        el("td", { class: "result" }, resultText),
      ]));
    });
    table.appendChild(tbody);
    parts.push(table);
    if (typeof detail.vulnerable === "boolean") {
      parts.push(
        detail.vulnerable
          ? el("p", { class: "highlight-inject" }, `${detail.vulnerable_count} out-of-scope path(s) were readable with no validation.`)
          : el("p", {}, "All out-of-scope paths were correctly blocked.")
      );
    }
  }
  return parts;
}

const RENDERERS = { 1: renderThreat1Detail, 2: renderThreat2Detail, 3: renderThreat3Detail };

function renderLog(id) {
  const s = state[id];
  const log = document.getElementById(`log-${id}`);
  log.innerHTML = "";
  s.history.forEach((entry) => {
    const flagged = entry.detail && entry.detail.vulnerable === true;
    const blocked = entry.detail && entry.detail.blocked === true;
    const cardClass = ["card"];
    if (flagged) cardClass.push("flag");
    else if (blocked) cardClass.push("ok");

    const card = el("div", { class: cardClass.join(" ") }, [
      el("h3", {}, `Step ${entry.index + 1}: ${entry.title}`),
      el("div", { class: "narrative" }, entry.detail.narrative || ""),
      ...(entry.detail.error ? [el("p", { class: "highlight-inject" }, `Error: ${entry.detail.error}`)] : RENDERERS[id](entry.detail)),
    ]);
    log.appendChild(card);
  });

  const badge = document.getElementById(`badge-${id}`);
  const last = s.history[s.history.length - 1];
  if (s.done && last) {
    const vulnerable = s.history.some((h) => h.detail && h.detail.vulnerable === true);
    badge.textContent = vulnerable ? "VULNERABLE" : "SAFE";
    badge.className = `status-badge ${vulnerable ? "vulnerable" : "safe"}`;
  } else {
    badge.className = "status-badge";
  }
}

async function startThreat(id) {
  const startBtn = document.getElementById(`start-${id}`);
  const nextBtn = document.getElementById(`next-${id}`);
  startBtn.disabled = true;
  startBtn.textContent = "Starting...";
  try {
    const res = await fetch(`/api/threat/${id}/start`, { method: "POST" });
    const data = await res.json();
    if (data.error) {
      alert(data.error);
      return;
    }
    state[id] = { titles: data.titles, history: [], index: 0, done: false };
    renderTimeline(id);
    renderLog(id);
    nextBtn.disabled = false;
  } finally {
    startBtn.disabled = false;
    startBtn.textContent = THREATS[id].startLabel + " (restart)";
  }
}

async function nextStep(id) {
  const nextBtn = document.getElementById(`next-${id}`);
  nextBtn.disabled = true;
  try {
    const res = await fetch(`/api/threat/${id}/next`, { method: "POST" });
    const entry = await res.json();
    const s = state[id];
    s.index = entry.index != null ? entry.index + 1 : s.index;
    s.done = entry.done;
    if (entry.title) s.history.push(entry);
    renderTimeline(id);
    renderLog(id);
  } finally {
    const s = state[id];
    nextBtn.disabled = s.done;
    if (s.done) nextBtn.textContent = "All steps complete";
    else nextBtn.textContent = "Next Step";
  }
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => setActiveTab(btn.dataset.threat));
});

buildPanels();
setActiveTab(1);
