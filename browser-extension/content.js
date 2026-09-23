// Runs on supported AI chat websites. When the user submits a prompt (Enter
// or the Send button) the submission is held, the text is checked by the
// gateway, and then it is:
//   ALLOW    -> sent unchanged
//   SANITIZE -> replaced with the placeholder version for the user to review
//   BLOCK    -> not sent
// If the gateway cannot be reached the prompt is held (fail closed).

(() => {
  const SERVICES = {
    "chatgpt.com": "ChatGPT",
    "gemini.google.com": "Google Gemini",
    "copilot.microsoft.com": "Microsoft Copilot",
    "claude.ai": "Claude",
    "www.perplexity.ai": "Perplexity",
  };
  const service = SERVICES[location.hostname] || location.hostname;

  // Most specific first: generic "textarea" also matches hidden helper
  // fields some sites keep in the page.
  const EDITOR_SELECTORS = [
    "#prompt-textarea",
    "rich-textarea [contenteditable='true']",
    "div.ProseMirror[contenteditable='true']",
    "textarea",
    "[contenteditable='true']",
  ];
  const EDITOR_SELECTOR = EDITOR_SELECTORS.join(", ");
  const SEND_SELECTOR = [
    "button[data-testid='send-button']",
    "button[aria-label*='Send' i]",
    "button[aria-label*='Submit' i]",
    "button[type='submit']",
  ].join(", ");

  // Text that has already been checked and may go through on the next submit.
  let approvedText = null;
  let scanning = false;

  function isVisible(element) {
    return element.getClientRects().length > 0 && getComputedStyle(element).visibility !== "hidden";
  }

  // querySelector with a selector list returns the first match in document
  // order, so try each selector in priority order and skip hidden fields.
  function findEditor(from) {
    if (from instanceof Element) {
      const own = from.closest(EDITOR_SELECTOR);
      if (own) return own;
    }
    const scope = (from instanceof Element && from.closest("form")) || document;
    for (const selector of EDITOR_SELECTORS) {
      const match = [...scope.querySelectorAll(selector)].find(isVisible);
      if (match) return match;
    }
    return scope === document ? null : findEditor(null);
  }

  function readText(editor) {
    return ("value" in editor ? editor.value : editor.innerText).trim();
  }

  function writeText(editor, text) {
    editor.focus();
    if (editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement) {
      // React-controlled inputs ignore direct .value writes; use the native setter.
      const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(editor), "value").set;
      setter.call(editor, text);
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }
    // Rich editors (ProseMirror, Quill) apply insertText as a user edit.
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(editor);
    selection.removeAllRanges();
    selection.addRange(range);
    document.execCommand("insertText", false, text);
  }

  function submitEditor(editor) {
    const form = editor.closest("form");
    const button = (form && form.querySelector(SEND_SELECTOR)) || document.querySelector(SEND_SELECTOR);
    if (button && !button.disabled) {
      button.click();
      return;
    }
    editor.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, bubbles: true, cancelable: true }));
  }

  // --- notice banner (shadow DOM so the site's CSS cannot restyle it) ---------
  const host = document.createElement("div");
  host.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:380px;";
  const shadow = host.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      .notice { font: 13px/1.45 system-ui, sans-serif; color: #0f1d35; background: #fff;
        border-left: 5px solid var(--tone); border-radius: 8px; padding: 12px 14px;
        box-shadow: 0 8px 28px rgba(15, 29, 53, 0.25); }
      .notice[hidden] { display: none; }
      strong { display: block; margin-bottom: 4px; }
      ul { margin: 6px 0 0; padding-left: 18px; }
      button { margin-top: 8px; border: 0; background: none; color: #2563eb; cursor: pointer; padding: 0; font: inherit; }
    </style>
    <div class="notice" hidden>
      <strong></strong>
      <div class="body"></div>
      <ul></ul>
      <button type="button">Dismiss</button>
    </div>`;
  const notice = shadow.querySelector(".notice");
  shadow.querySelector("button").addEventListener("click", () => { notice.hidden = true; });

  const TONES = { info: "#2563eb", ok: "#16a34a", warn: "#d97706", block: "#d92d20" };

  function show(tone, title, body, items = []) {
    if (!host.isConnected) document.documentElement.appendChild(host);
    notice.style.setProperty("--tone", TONES[tone]);
    notice.querySelector("strong").textContent = title;
    notice.querySelector(".body").textContent = body;
    const list = notice.querySelector("ul");
    list.replaceChildren(...items.map((text) => {
      const li = document.createElement("li");
      li.textContent = text;
      return li;
    }));
    notice.hidden = false;
  }

  // --- submission interception ---------------------------------------------------
  async function check(editor) {
    const text = readText(editor);
    if (!text) return;
    scanning = true;
    show("info", "Secure AI Gateway", "Checking prompt for sensitive data...");

    let result;
    try {
      result = await chrome.runtime.sendMessage({ type: "SCAN_PROMPT", payload: { prompt: text, service } });
    } catch {
      result = { ok: false, error: "The extension was reloaded. Refresh this page." };
    } finally {
      scanning = false;
    }

    if (!result || !result.ok) {
      show("block", "Prompt held: gateway unavailable", `${result ? result.error : "No response."} Nothing was sent.`);
      return;
    }

    const { decision, sanitizedPrompt, replacements, riskLevel, riskScore, reason } = result.data;
    if (decision === "BLOCK") {
      show("block", `Blocked (${riskLevel}, ${riskScore}/100)`, `${reason} The prompt was not sent. Remove the sensitive values and try again.`);
      return;
    }
    if (decision === "SANITIZE") {
      writeText(editor, sanitizedPrompt);
      approvedText = readText(editor);
      const items = replacements.map((item) => `${item.placeholder} replaced ${item.entity_type.replaceAll("_", " ").toLowerCase()}`);
      show("warn", `Sanitized (${riskLevel}, ${riskScore}/100)`, "Sensitive values were replaced with placeholders. Review the prompt, then send again.", items);
      return;
    }
    // The re-submission below is a synthetic (untrusted) event, which the
    // listeners ignore, so no approval needs to be recorded for it.
    notice.hidden = true;
    submitEditor(editor);
  }

  function intercept(event, editor) {
    const text = readText(editor);
    if (!text) return;
    if (approvedText !== null && text === approvedText) {
      approvedText = null; // one approved submission only
      return;
    }
    event.preventDefault();
    event.stopImmediatePropagation();
    if (!scanning) check(editor);
  }

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing || !event.isTrusted) return;
    const editor = findEditor(event.target);
    if (editor && editor.contains(event.target)) intercept(event, editor);
  }, true);

  document.addEventListener("click", (event) => {
    if (!event.isTrusted || !(event.target instanceof Element)) return;
    const button = event.target.closest(SEND_SELECTOR);
    if (!button) return;
    const editor = findEditor(button.closest("form") || button);
    if (editor) intercept(event, editor);
  }, true);
})();
