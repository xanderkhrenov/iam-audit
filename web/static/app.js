const eventsEl = document.querySelector("#events");
const reportEl = document.querySelector("#report");
const accessLogEl = document.querySelector("#accessLog");
const filters = document.querySelector("#filters");
const adminEventForm = document.querySelector("#adminEventForm");
const adminResultEl = document.querySelector("#adminResult");

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function paramsFromForm() {
  const params = new URLSearchParams();
  new FormData(filters).forEach((value, key) => {
    if (value) params.set(key, value);
  });
  params.set("limit", "100");
  return params;
}

async function loadEvents() {
  const data = await api(`/api/events?${paramsFromForm()}`);
  eventsEl.innerHTML = data.items.map(renderEvent).join("") || "<p>Событий не найдено</p>";
}

function renderEvent(e) {
  return `<article class="event">
    <div>
      <div class="badge">${e.action} / ${e.decision}</div>
      <div class="meta">${new Date(e.timestamp).toLocaleString()}</div>
    </div>
    <div>
      <strong>${e.subject.display_name || e.subject.id}</strong>
      <span class="meta">через ${e.resource.system} ${e.resource.environment || ""}</span>
      <p>${e.actor.display_name || e.actor.id} -> <code>${e.resource.path}</code></p>
      <p class="meta">ticket ${e.ticket_id || "-"} · correlation ${e.correlation_id || "-"} · hash ${e.hash.slice(0, 16)}...</p>
    </div>
  </article>`;
}

filters.addEventListener("submit", (event) => {
  event.preventDefault();
  loadEvents().catch(showError);
});

document.querySelector("#seedBtn").addEventListener("click", async () => {
  await api("/api/seed", { method: "POST" });
  await loadEvents();
});

document.querySelector("#exportBtn").addEventListener("click", () => {
  location.href = `/api/exports/siem?${paramsFromForm()}`;
});

document.querySelector("#integrityBtn").addEventListener("click", async () => {
  reportEl.textContent = JSON.stringify(await api("/api/integrity"), null, 2);
});

document.querySelectorAll("[data-report]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    reportEl.textContent = JSON.stringify(await api(`/api/reports/${btn.dataset.report}?${paramsFromForm()}`), null, 2);
  });
});

document.querySelector("#accessLogBtn").addEventListener("click", async () => {
  accessLogEl.textContent = JSON.stringify(await api("/api/access-log"), null, 2);
});

adminEventForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(adminEventForm).entries());
  body.fields = parseKeyValueLines(body.fields);
  const created = await api("/api/admin/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  adminResultEl.textContent = JSON.stringify(created, null, 2);
  await loadEvents();
});

function parseKeyValueLines(value) {
  const fields = {};
  value.split("\n").forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    const index = trimmed.indexOf("=");
    if (index <= 0) return;
    fields[trimmed.slice(0, index).trim()] = trimmed.slice(index + 1).trim();
  });
  return fields;
}

function showError(error) {
  reportEl.textContent = error.message;
}

loadEvents().catch(showError);
