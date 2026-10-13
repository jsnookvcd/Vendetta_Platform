// Keyboard triage for the hits queue. Loaded from the same origin so it passes
// the strict CSP. No external dependencies.
(function () {
  "use strict";
  var table = document.getElementById("hitstable");
  if (!table) return;
  var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr[data-hid]"));
  if (!rows.length) return;
  var cur = 0;

  function paint() {
    rows.forEach(function (r, i) { r.classList.toggle("kbd-active", i === cur); });
    var r = rows[cur];
    if (r) r.scrollIntoView({ block: "nearest" });
  }

  function updateCount() {
    var n = table.querySelectorAll(".selrow:checked").length;
    var el = document.getElementById("selcount");
    if (el) el.textContent = n;
  }

  function setStatus(verb) {
    var r = rows[cur];
    if (!r) return;
    var hid = r.getAttribute("data-hid");
    fetch("/hits/" + hid + "/status/" + verb, { method: "POST", headers: { "Accept": "application/json" } })
      .then(function (resp) { return resp.ok ? resp.json() : Promise.reject(resp.status); })
      .then(function (data) {
        var cell = r.querySelector("[data-status]");
        if (cell) {
          cell.textContent = data.status.replace("_", " ");
          cell.className = "state state-" + data.status;
        }
        if (cur < rows.length - 1) { cur++; paint(); }
      })
      .catch(function () { /* leave the row as-is on failure */ });
  }

  function escalate() {
    var r = rows[cur];
    if (!r) return;
    fetch("/hits/" + r.getAttribute("data-hid") + "/escalate", { method: "POST" })
      .then(function () { /* no-op; escalation is a background link to the hub */ });
  }

  document.addEventListener("keydown", function (e) {
    var t = e.target.tagName;
    if (t === "INPUT" || t === "SELECT" || t === "TEXTAREA" || e.metaKey || e.ctrlKey || e.altKey) return;
    switch (e.key) {
      case "j": cur = Math.min(cur + 1, rows.length - 1); paint(); break;
      case "k": cur = Math.max(cur - 1, 0); paint(); break;
      case "o": case "Enter": {
        var href = rows[cur] && rows[cur].getAttribute("data-href");
        if (href) window.location = href; break;
      }
      case "x": {
        var cb = rows[cur] && rows[cur].querySelector(".selrow");
        if (cb) { cb.checked = !cb.checked; updateCount(); } break;
      }
      case "c": setStatus("confirmed"); break;
      case "f": setStatus("false_positive"); break;
      case "r": setStatus("reviewing"); break;
      case "e": escalate(); break;
      default: return;
    }
    e.preventDefault();
  });

  var selall = document.getElementById("selall");
  if (selall) {
    selall.addEventListener("change", function () {
      table.querySelectorAll(".selrow").forEach(function (cb) { cb.checked = selall.checked; });
      updateCount();
    });
  }
  table.addEventListener("change", function (e) {
    if (e.target && e.target.classList.contains("selrow")) updateCount();
  });

  paint();
})();
