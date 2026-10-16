"use strict";
(() => {
  const byId = id => document.getElementById(id);
  let token = "", revision = "", rows = [], dirty = false, generation = 0;
  const status = message => { byId("access-status").textContent = message; };
  async function api(method, body) {
    const requestedGeneration = generation;
    const response = await fetch("/api/cloudflare/access", {
      method, cache: "no-store", credentials: "same-origin", redirect: "error",
      headers: { "X-Citadel-Token": token, ...(body ? { "Content-Type": "application/json" } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const data = await response.json();
    if (requestedGeneration !== generation) throw new DOMException("Stale request", "AbortError");
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data;
  }
  function lock() {
    generation++; token = ""; revision = ""; rows = []; dirty = false;
    byId("access-routes").replaceChildren();
    byId("access-token").value = "";
    byId("access-login").hidden = false;
    byId("access-editor").hidden = true;
    status("Locked.");
  }
  function filterRows() {
    const query = byId("access-filter").value.trim().toLowerCase();
    const candidates = byId("access-candidates").checked;
    for (const row of rows) row.card.hidden = (!row.confirmed && !row.input.value.trim() && !candidates)
      || (query && !row.search.includes(query));
  }
  function render(data) {
    revision = data.revision;
    rows = [];
    const list = byId("access-routes");
    list.replaceChildren();
    for (const route of data.routes) {
      const card = document.createElement("section"); card.className = "access-route";
      const heading = document.createElement("h2");
      heading.textContent = route.port ? `Port ${route.port} · ${route.protocol.toUpperCase()} · ${route.path}` : "Not found in the current scan";
      const identity = document.createElement("p"); identity.className = "access-id"; identity.textContent = route.id;
      const evidence = document.createElement("p");
      evidence.textContent = route.status === "ready" ? "Protocol detected. Publication depends on configured access."
        : route.status === "authentication-required" ? "Backend credentials required. The next scan uses the backend bearer configured here."
        : (route.evidence || "Saved access is retained but will not be published until the route is verified.");
      const label = document.createElement("label"); label.textContent = "Access entries (CSV)";
      const input = document.createElement("input"); input.type = "password"; input.autocomplete = "off";
      input.spellcheck = false; input.value = route.entries; input.id = `grant-${route.id}`;
      label.htmlFor = input.id;
      input.addEventListener("input", () => { dirty = true; status("Unsaved changes."); });
      const reveal = document.createElement("button"); reveal.type = "button"; reveal.className = "btn-default"; reveal.textContent = "Show";
      reveal.addEventListener("click", () => {
        input.type = input.type === "password" ? "text" : "password";
        reveal.textContent = input.type === "password" ? "Show" : "Hide";
      });
      card.append(heading, identity, evidence, label, input, reveal); list.append(card);
      rows.push({ id: route.id, input, card, confirmed: route.detected || route.status === "ready",
        search: `${route.port || ""} ${route.protocol || ""} ${route.path || ""} ${route.id}`.toLowerCase() });
    }
    dirty = false;
    byId("access-candidate-count").textContent = `(${rows.filter(row => !row.confirmed && !row.input.value.trim()).length})`;
    filterRows();
    byId("access-empty").hidden = rows.length > 0;
    byId("access-login").hidden = true;
    byId("access-editor").hidden = false;
    status(data.pending ? "Saved access changes are pending a full scan."
      : "Configuration applied during the last successful full scan.");
  }
  byId("access-login").addEventListener("submit", async event => {
    event.preventDefault(); generation++; token = byId("access-token").value;
    try { render(await api("GET")); byId("access-token").value = ""; }
    catch (error) { if (error.name !== "AbortError") { token = ""; status(error.message); } }
  });
  byId("access-save").addEventListener("click", async () => {
    const button = byId("access-save"); button.disabled = true;
    try {
      const saved = Object.fromEntries(rows.map(row => [row.id, row.input.value]));
      const data = await api("PUT", { revision, routes: saved });
      revision = data.revision;
      dirty = rows.some(row => saved[row.id] !== row.input.value);
      status(dirty ? "Saved; additional edits remain unsaved."
        : "Saved. Changes take effect after the next full scan.");
    } catch (error) { if (error.name !== "AbortError") status(error.message); }
    finally { button.disabled = false; }
  });
  byId("access-reload").addEventListener("click", async () => {
    if (dirty && !window.confirm("Discard unsaved changes?")) return;
    try { render(await api("GET")); } catch (error) { if (error.name !== "AbortError") status(error.message); }
  });
  byId("access-filter").addEventListener("input", filterRows);
  byId("access-candidates").addEventListener("change", filterRows);
  byId("access-lock").addEventListener("click", lock);
  window.addEventListener("pagehide", lock);
  window.addEventListener("beforeunload", event => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
})();
