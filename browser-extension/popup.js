// All values from the gateway are written with textContent, never innerHTML:
// user names and reasons are user- or server-controlled strings.

const $ = (id) => document.getElementById(id);

const COLORS = { ALLOW: "#16a34a", SANITIZE: "#f5a524", BLOCK: "#d92d20" };
const RISK_COLORS = { LOW: "#16a34a", MEDIUM: "#f5a524", HIGH: "#ea580c", CRITICAL: "#d92d20" };

function send(type, payload) {
  return chrome.runtime.sendMessage({ type, payload });
}

async function refreshBackend() {
  const result = await send("HEALTH");
  const dot = $("backendStatus").querySelector(".status-dot");
  if (result.ok) {
    const ner = result.data.detectionEngine && result.data.detectionEngine.ner_model_available;
    $("backendText").textContent = ner ? "Connected (NER model loaded)" : "Connected (regex-only mode)";
    dot.classList.remove("offline-dot");
  } else {
    $("backendText").textContent = result.error;
    dot.classList.add("offline-dot");
  }
}

function showSignedIn(user) {
  $("loginCard").hidden = Boolean(user);
  $("userCard").hidden = !user;
  $("testCard").hidden = !user;
  if (user) {
    $("userName").textContent = user.name;
    $("userEmail").textContent = `${user.email} (${user.role})`;
  }
}

function showResult(title, scan, sanitizedPrompt) {
  $("resultCard").hidden = false;
  $("resultTitle").textContent = title;
  $("decision").textContent = scan.decision;
  $("decision").style.background = COLORS[scan.decision] || "#64748b";
  $("riskLevel").textContent = scan.riskLevel;
  $("riskScore").textContent = `${scan.riskScore} / 100`;
  $("scoreBar").style.width = `${scan.riskScore}%`;
  $("scoreBar").style.background = RISK_COLORS[scan.riskLevel] || "#64748b";
  $("replaced").textContent = String(scan.replaced);
  $("reason").textContent = scan.service ? `${scan.reason} (${scan.service})` : scan.reason;
  $("sanitizedBlock").hidden = !sanitizedPrompt;
  $("sanitizedOutput").value = sanitizedPrompt || "";
}

$("loginCard").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("loginError").hidden = true;
  const result = await send("LOGIN", { email: $("email").value.trim(), password: $("password").value });
  $("password").value = "";
  if (!result.ok) {
    $("loginError").textContent = result.error;
    $("loginError").hidden = false;
    return;
  }
  showSignedIn(result.data.user);
});

$("logoutButton").addEventListener("click", async () => {
  await send("LOGOUT");
  $("resultCard").hidden = true;
  showSignedIn(null);
});

$("testCard").addEventListener("submit", async (event) => {
  event.preventDefault();
  const prompt = $("promptInput").value;
  if (!prompt.trim()) return;
  $("inspectButton").disabled = true;
  const result = await send("SCAN_PROMPT", { prompt, service: "Extension popup" });
  $("inspectButton").disabled = false;
  if (!result.ok) {
    $("resultCard").hidden = false;
    $("resultTitle").textContent = "Check failed";
    $("reason").textContent = result.error;
    if (result.status === 401) showSignedIn(null);
    return;
  }
  const data = result.data;
  showResult("Result", {
    decision: data.decision,
    riskLevel: data.riskLevel,
    riskScore: data.riskScore,
    replaced: data.replacements.length,
    reason: data.reason,
  }, data.sanitizedPrompt);
});

(async () => {
  const { user, lastScan } = await chrome.storage.local.get(["user", "lastScan"]);
  showSignedIn(user || null);
  if (user && lastScan) {
    showResult(`Last check: ${new Date(lastScan.at).toLocaleTimeString()}`, lastScan, "");
  }
  refreshBackend();
})();
