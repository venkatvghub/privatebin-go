"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const sections = ["create", "created", "burn-gate", "password-gate", "view"];
  const show = (name) => sections.forEach((s) => ($(s).hidden = s !== name));
  const notice = (msg, info) => { const n = $("notice"); n.textContent = msg || ""; n.hidden = !msg; n.classList.toggle("info", !!info); };

  async function api(method, path, body) {
    const res = await fetch(path, {
      method, credentials: "same-origin", cache: "no-store",
      headers: { "X-Requested-With": "JSONHttpRequest", ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* non-JSON error body */ }
    if (!res.ok || data.status === 1) { const e = new Error(data.message || "request failed (" + res.status + ")"); e.status = res.status; throw e; }
    return data;
  }

  function copyFrom(btnId, getter) {
    $(btnId).onclick = async () => {
      try { await navigator.clipboard.writeText(getter()); notice("Copied.", true); } catch (_) { notice("Copy failed."); }
    };
  }

  async function initCreate(cfg) {
    show("create");
    $("login-link").hidden = !(cfg.authEnabled && !cfg.loggedIn);
    $("send").addEventListener("click", async () => {
      const text = $("message").value;
      if (!text.trim()) { notice("Nothing to send."); return; }
      if (new TextEncoder().encode(text).length > cfg.maxBytes) { notice("Paste too large."); return; }
      $("send").disabled = true; notice("");
      try {
        const { keyB58, body } = await PasteCrypto.encrypt(text, $("format").value, $("burn").checked, $("password").value);
        body.meta = { expire: $("expire").value };
        const r = await api("POST", "/", body);
        $("paste-url").value = location.origin + "/?" + r.id + "#" + keyB58;
        $("delete-url").value = location.origin + "/?pasteid=" + r.id + "&deletetoken=" + r.deletetoken + "#" + keyB58;
        $("new-link").hidden = false;
        show("created");
      } catch (e) {
        if (e.status === 401) { location.href = "/auth/login"; return; }
        notice(e.message);
      } finally { $("send").disabled = false; }
    });
    copyFrom("copy-url", () => $("paste-url").value);
    copyFrom("copy-del", () => $("delete-url").value);
  }

  function render(text, format) {
    const out = $("output");
    out.replaceChildren();
    if (format === "markdown") {
      out.innerHTML = DOMPurify.sanitize(marked.parse(text), { USE_PROFILES: { html: true } });
      out.querySelectorAll("a").forEach((a) => { a.rel = "noopener noreferrer nofollow"; a.target = "_blank"; });
    } else {
      const pre = document.createElement("pre"), code = document.createElement("code");
      code.textContent = text;
      pre.appendChild(code);
      out.appendChild(pre);
      if (format === "syntaxhighlighting") hljs.highlightElement(code);
    }
  }

  async function initView(id, keyB58) {
    $("new-link").hidden = false;
    const delToken = new URLSearchParams(location.search).get("deletetoken");
    let paste, password = "";
    const load = async () => (paste = await api("GET", "/?pasteid=" + id));

    const decryptAndShow = async () => {
      try {
        const { text, format } = await PasteCrypto.decrypt(paste, keyB58, password);
        let raw = false;
        render(text, format);
        $("meta").textContent = paste.meta.time_to_live ? "Expires " + new Date(Date.now() + paste.meta.time_to_live * 1000).toLocaleString() : "";
        $("toggle-raw").onclick = () => { raw = !raw; render(text, raw ? "plaintext" : format); $("toggle-raw").textContent = raw ? "Formatted" : "Raw"; };
        copyFrom("copy-text", () => text);
        $("delete").hidden = !delToken;
        $("delete").onclick = async () => {
          try { await api("GET", "/?pasteid=" + id + "&deletetoken=" + encodeURIComponent(delToken)); show(""); notice("Paste deleted.", true); }
          catch (e) { notice(e.message); }
        };
        notice(paste.adata[3] ? "This paste was destroyed on opening. Save it now." : "", true);
        show("view");
      } catch (_) {
        if (password) notice("Wrong password or key, or corrupted paste.");
        show("password-gate");
      }
    };

    $("password-open").addEventListener("click", () => { password = $("view-password").value; notice(""); decryptAndShow(); });

    try {
      // Reading a burn paste destroys it, so ask first (link previews never reach this JS).
      const meta = await api("GET", "/api/paste/" + id + "/meta");
      if (meta.burn && !delToken) {
        show("burn-gate");
        $("burn-open").addEventListener("click", async () => {
          try { await load(); await decryptAndShow(); } catch (e) { show(""); notice(e.message); }
        });
        return;
      }
      await load();
      await decryptAndShow();
    } catch (e) { show(""); notice(e.message); }
  }

  async function main() {
    let cfg = { authEnabled: false, loggedIn: false, maxBytes: 2097152 };
    try { cfg = await api("GET", "/api/config"); } catch (_) { /* use defaults */ }
    const m = location.search.match(/^\?(?:pasteid=)?([0-9a-f]{16})(?:&|$)/);
    if (m) {
      const key = location.hash.slice(1);
      if (!key) { show(""); notice("This link is missing its decryption key (the part after #)."); return; }
      await initView(m[1], key);
    } else {
      await initCreate(cfg);
    }
  }
  main();
})();
