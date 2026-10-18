// Live Tor search: poll the queued request and reload the page once the worker
// has finished it. Results are rendered by the server as escaped text; this
// script never inserts markup.
(function () {
  var el = document.getElementById("live-status");
  if (!el) return;
  var id = el.getAttribute("data-id");
  function poll() {
    fetch("/search/live/" + encodeURIComponent(id) + "/status", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) {
        if (!s) { setTimeout(poll, 5000); return; }
        if (s.status === "done" || s.status === "failed") { window.location.reload(); return; }
        el.textContent = s.status === "running" ? "searching over Tor" : "queued for the worker";
        setTimeout(poll, 3000);
      })
      .catch(function () { setTimeout(poll, 5000); });
  }
  setTimeout(poll, 3000);
})();
