// Case board: drag cards between columns and lanes. Every card also has plain form
// buttons, so the board works without this script. After a drop the server applies
// the board rules (timeline entry, workstream status), and the workstream cards,
// board and timeline are re-rendered from the server's HTML.
(function () {
  "use strict";
  var board = document.getElementById("board");
  if (!board) return;
  var drag = null;
  var origin = null;

  function cardAfter(list, y) {
    var cards = Array.prototype.slice.call(list.querySelectorAll(".kcard:not(.dragging)"));
    for (var i = 0; i < cards.length; i++) {
      var box = cards[i].getBoundingClientRect();
      if (y < box.top + box.height / 2) return cards[i];
    }
    return null;
  }

  function openLanes() {
    return Array.prototype.slice.call(document.querySelectorAll("details.lane[open]")).map(function (d) { return d.id; });
  }

  async function refresh(keepOpen) {
    var r = await fetch(location.pathname, { credentials: "same-origin" });
    if (!r.ok) { location.reload(); return; }
    var doc = new DOMParser().parseFromString(await r.text(), "text/html");
    ["ws-grid", "board", "timeline-list", "update-target"].forEach(function (id) {
      var now = document.getElementById(id), next = doc.getElementById(id);
      if (now && next) now.replaceWith(next);
    });
    board = document.getElementById("board");
    // Keep lanes the analyst had open; lanes that just finished still fold up.
    (keepOpen || []).forEach(function (id) {
      var d = document.getElementById(id);
      if (d && !d.classList.contains("lane-done")) d.open = true;
    });
  }

  async function post(url, data) {
    var fd = new FormData();
    Object.keys(data).forEach(function (k) { if (data[k]) fd.append(k, data[k]); });
    var r = await fetch(url, { method: "POST", body: fd, credentials: "same-origin", headers: { "X-Requested-With": "fetch" } });
    return r.ok;
  }

  document.addEventListener("dragstart", function (e) {
    var c = e.target.closest && e.target.closest(".kcard");
    if (!c || !c.draggable) return;
    drag = c;
    origin = { parent: c.parentNode, next: c.nextSibling };
    c.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", c.dataset.task);
  });

  document.addEventListener("dragend", function () {
    if (drag) drag.classList.remove("dragging");
    document.querySelectorAll(".kcol.over").forEach(function (x) { x.classList.remove("over"); });
    drag = null;
  });

  document.addEventListener("dragover", function (e) {
    if (!drag) return;
    var col = e.target.closest && e.target.closest(".kcol");
    if (!col) return;
    e.preventDefault();
    document.querySelectorAll(".kcol.over").forEach(function (x) { if (x !== col) x.classList.remove("over"); });
    col.classList.add("over");
    var list = col.querySelector(".kcards");
    var after = cardAfter(list, e.clientY);
    if (after) list.insertBefore(drag, after); else list.appendChild(drag);
  });

  document.addEventListener("drop", async function (e) {
    if (!drag) return;
    var col = e.target.closest && e.target.closest(".kcol");
    if (!col) return;
    e.preventDefault();
    var card = drag, next = card.nextElementSibling;
    var keep = openLanes();
    var ok = await post(card.dataset.move, {
      status: col.dataset.status,
      workstream: col.dataset.ws,
      before: next && next.classList.contains("kcard") ? next.dataset.task : "",
    });
    if (!ok && origin) origin.parent.insertBefore(card, origin.next);  // put it back
    await refresh(keep);
  });

  // "Log update" on a card: attach the timeline form to that card.
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest("[data-attach]");
    if (!a) return;
    var sel = document.getElementById("update-target");
    var form = document.getElementById("update-form");
    if (!sel || !form) return;
    e.preventDefault();
    sel.value = a.dataset.attach;
    form.scrollIntoView({ behavior: "smooth", block: "center" });
    form.querySelector("textarea").focus({ preventScroll: true });
  });

  // Inputs inside a draggable card cannot be edited in some browsers, so a card
  // stops being draggable while its edit panel is open. toggle does not bubble.
  document.addEventListener("toggle", function (e) {
    var d = e.target;
    if (!d.classList || !d.classList.contains("kedit")) return;
    var c = d.closest(".kcard");
    if (c) c.draggable = !d.open;
  }, true);
})();
