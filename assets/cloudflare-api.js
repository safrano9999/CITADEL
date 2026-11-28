"use strict";
(() => {
  const byId = id => document.getElementById(id);
  let token = "", revision = "", rows = [], dirty = false, generation = 0;
  let editVersion = 0;
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
    for (const row of rows) row.card.hidden = (!row.confirmed && !row.body.rows.length && !candidates)
      || (query && !row.search.includes(query));
  }
  function markChanged() {
    editVersion++;
    dirty = true;
    status("Unsaved changes.");
  }

  function addGrant(body, entry = "", pairedClient = "") {
    const tr = byId("grant-row").content.firstElementChild.cloneNode(true);
    const email = tr.querySelector('[data-field="email"]');
    const client = tr.querySelector('[data-field="client"]');
    const backend = tr.querySelector('[data-field="backend"]');
    const [identity, target = ""] = entry.split(";").map(value => value.trim());
    (identity.includes("@") ? email : client).value = identity;
    if (pairedClient) client.value = pairedClient;
    backend.value = target;
    for (const field of [client, backend]) {
      const copy = field.parentElement.querySelector('[data-action="copy"]');
      const syncCopy = () => { copy.hidden = !field.value.trim(); };
      syncCopy();
      field.addEventListener("input", syncCopy);
      copy.addEventListener("click", async () => {
        const label = field.getAttribute("aria-label");
        try {
          await navigator.clipboard.writeText(field.value.trim());
          if (tr.isConnected) status(label + " copied." + (dirty ? " Unsaved changes." : ""));
        } catch {
          if (tr.isConnected) status("Clipboard unavailable. Use Show to copy the " + label.toLowerCase() + " manually.");
        }
      });
    }
    const generate = tr.querySelector('[data-action="generate"]');
    const removeClient = tr.querySelector('[data-action="delete"]');
    const rotate = tr.querySelector('[data-action="rotate"]');
    function syncClientActions() {
      const populated = Boolean(client.value.trim());
      generate.hidden = populated;
      removeClient.hidden = rotate.hidden = !populated;
    }
    function setClient(value) {
      client.value = value;
      tr.dataset.clientDeleted = String(!value);
      client.dispatchEvent(new Event("input", { bubbles: true }));
      (value ? rotate : generate).focus();
    }
    function generateClient() {
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      setClient(Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join(""));
    }
    generate.addEventListener("click", generateClient);
    rotate.addEventListener("click", generateClient);
    removeClient.addEventListener("click", () => setClient(""));
    client.addEventListener("input", syncClientActions);
    backend.addEventListener("input", () => { delete tr.dataset.clientDeleted; });
    syncClientActions();
    tr.addEventListener("input", markChanged);
    const reveal = tr.querySelector('[data-action="reveal"]');
    reveal.addEventListener("click", () => {
      const show = client.type === "password";
      client.type = backend.type = show ? "text" : "password";
      reveal.textContent = show ? "Hide" : "Show";
      reveal.setAttribute("aria-label", show ? "Hide bearers" : "Show bearers");
      reveal.setAttribute("aria-pressed", String(show));
    });
    tr.querySelector('[data-action="remove"]').addEventListener("click", () => {
      tr.remove();
      markChanged();
    });
    body.append(tr);
    return email;
  }

  function entriesFor(route) {
    const entries = Array.from(route.body.rows).flatMap((tr, index) => {
      const fields = Array.from(tr.querySelectorAll("input"));
      const [email, client, backend] = fields.map(input => input.value.trim());
      if (!email && !client && (!backend || tr.dataset.clientDeleted === "true")) return [];
      if ((!email && !client) || (email && !email.includes("@"))
          || client.includes("@") || fields.some(input => /[,;]/.test(input.value))) {
        const invalid = fields.find(input => /[,;]/.test(input.value))
          || (client.includes("@") ? fields[1] : fields[0]);
        invalid.focus();
        throw new Error(`${route.title}, row ${index + 1}: enter a valid OAuth email or client bearer. Commas and semicolons cannot appear in a field.`);
      }
      return [email, client].filter(Boolean).map(identity => [identity, backend].filter(Boolean).join(";"));
    });
    const value = entries.join(",");
    return value === route.initialValue ? route.original : value;
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
      const editor = byId("grant-table").content.cloneNode(true);
      const body = editor.querySelector("tbody");
      const entries = route.entries.split(",").filter(value => value.trim());
      for (let index = 0; index < entries.length; index++) {
        const [identity, backend] = entries[index].trim().split(";").map(part => part.trim());
        const [next, nextBackend] = (entries[index + 1] || "").split(";").map(part => part.trim());
        const paired = identity.includes("@") && next && !next.includes("@") && backend === nextBackend;
        addGrant(body, entries[index], paired ? next : "");
        if (paired) index++;
      }
      editor.querySelector('[data-action="add"]').addEventListener("click", () => {
        addGrant(body).focus();
        markChanged();
      });
      card.append(heading, identity, evidence, editor);
      list.append(card);
      rows.push({ id: route.id, body, card, title: heading.textContent, original: route.entries,
        initialValue: entries.map(entry => entry.split(";").map(value => value.trim()).join(";")).join(","),
        confirmed: route.detected || route.status === "ready",
        search: `${route.port || ""} ${route.protocol || ""} ${route.path || ""} ${route.id}`.toLowerCase() });
    }
    dirty = false;
    byId("access-candidate-count").textContent = `(${rows.filter(row => !row.confirmed && !row.body.rows.length).length})`;
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
      const savedVersion = editVersion;
      const saved = Object.fromEntries(rows.map(row => [row.id, entriesFor(row)]));
      const data = await api("PUT", { revision, routes: saved });
      revision = data.revision;
      dirty = editVersion !== savedVersion;
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
