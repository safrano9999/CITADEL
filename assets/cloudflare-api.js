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
    if (requestedGeneration !== generation) throw new DOMException("Veraltete Anfrage", "AbortError");
    if (!response.ok) throw new Error(data.detail || `Anfrage fehlgeschlagen (${response.status})`);
    return data;
  }
  function lock() {
    generation++; token = ""; revision = ""; rows = []; dirty = false;
    byId("access-routes").replaceChildren();
    byId("access-token").value = "";
    byId("access-login").hidden = false;
    byId("access-editor").hidden = true;
    status("Gesperrt.");
  }
  function render(data) {
    revision = data.revision;
    rows = [];
    const list = byId("access-routes");
    list.replaceChildren();
    for (const route of data.routes) {
      const card = document.createElement("section"); card.className = "access-route";
      const heading = document.createElement("h2");
      heading.textContent = route.port ? `Port ${route.port} · ${route.protocol.toUpperCase()} · ${route.path}` : "Derzeit nicht im Scan gefunden";
      const identity = document.createElement("p"); identity.className = "access-id"; identity.textContent = route.id;
      const evidence = document.createElement("p");
      evidence.textContent = route.status === "ready" ? "Protokoll erkannt. Veröffentlichung richtet sich nach deinen Freigaben."
        : route.status === "authentication-required" ? "Backend-Zugang erforderlich. Der nächste Scan prüft mit einem hier hinterlegten Backend-Bearer."
        : (route.evidence || "Gespeicherte Zuordnung bleibt erhalten, wird ohne bestätigte Route aber nicht veröffentlicht.");
      const label = document.createElement("label"); label.textContent = "Freigaben (CSV)";
      const input = document.createElement("input"); input.type = "password"; input.autocomplete = "off";
      input.spellcheck = false; input.value = route.entries; input.id = `grant-${route.id}`;
      label.htmlFor = input.id;
      input.addEventListener("input", () => { dirty = true; status("Ungespeicherte Änderungen."); });
      const reveal = document.createElement("button"); reveal.type = "button"; reveal.className = "btn-default"; reveal.textContent = "Anzeigen";
      reveal.addEventListener("click", () => {
        input.type = input.type === "password" ? "text" : "password";
        reveal.textContent = input.type === "password" ? "Anzeigen" : "Verbergen";
      });
      card.append(heading, identity, evidence, label, input, reveal); list.append(card);
      rows.push({ id: route.id, input });
    }
    dirty = false;
    byId("access-empty").hidden = rows.length > 0;
    byId("access-login").hidden = true;
    byId("access-editor").hidden = false;
    status(data.pending ? "Gespeicherte Freigaben warten auf den nächsten vollständigen Scan."
      : "Konfiguration beim letzten erfolgreichen vollständigen Scan übernommen.");
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
      status(dirty ? "Stand gespeichert; weitere Änderungen sind noch ungespeichert."
        : "Gespeichert. Noch nicht aktiv: Übernahme beim nächsten vollständigen Scan.");
    } catch (error) { if (error.name !== "AbortError") status(error.message); }
    finally { button.disabled = false; }
  });
  byId("access-reload").addEventListener("click", async () => {
    if (dirty && !window.confirm("Ungespeicherte Änderungen verwerfen?")) return;
    try { render(await api("GET")); } catch (error) { if (error.name !== "AbortError") status(error.message); }
  });
  byId("access-lock").addEventListener("click", lock);
  window.addEventListener("pagehide", lock);
  window.addEventListener("beforeunload", event => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
})();
