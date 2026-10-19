// Drag and drop for the Kanban boards. A drop posts JSON to /api/cards/<ref>/move
// with the target column and position; the server enforces WIP limits and roles,
// and on any refusal the page reloads to show the board as it really is.
(function () {
  document.querySelectorAll(".kanban").forEach(function (board) {
    if (board.dataset.readonly === "true") return;
    var dragging = null;

    board.addEventListener("dragstart", function (e) {
      var card = e.target.closest(".kcard");
      if (!card) return;
      dragging = card;
      card.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", card.dataset.ref);
    });

    board.addEventListener("dragend", function () {
      if (dragging) dragging.classList.remove("dragging");
      board.querySelectorAll(".kcol.target").forEach(function (c) { c.classList.remove("target"); });
      dragging = null;
    });

    function afterCard(list, y) {
      var cards = Array.prototype.slice.call(list.querySelectorAll(".kcard:not(.dragging)"));
      for (var i = 0; i < cards.length; i++) {
        var r = cards[i].getBoundingClientRect();
        if (y < r.top + r.height / 2) return cards[i];
      }
      return null;
    }

    board.addEventListener("dragover", function (e) {
      var col = e.target.closest(".kcol[data-column]");
      if (!col || !dragging) return;
      e.preventDefault();
      board.querySelectorAll(".kcol.target").forEach(function (c) { if (c !== col) c.classList.remove("target"); });
      col.classList.add("target");
      var list = col.querySelector(".kcards");
      var after = afterCard(list, e.clientY);
      if (after) list.insertBefore(dragging, after); else list.appendChild(dragging);
    });

    board.addEventListener("drop", function (e) {
      var col = e.target.closest(".kcol[data-column]");
      if (!col || !dragging) return;
      e.preventDefault();
      var card = dragging;
      var list = col.querySelector(".kcards");
      var position = Array.prototype.indexOf.call(list.querySelectorAll(".kcard"), card);
      fetch("/api/cards/" + encodeURIComponent(card.dataset.ref) + "/move", {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type": "application/json", "Accept": "application/json"},
        body: JSON.stringify({column: col.dataset.column, position: position})
      }).then(function (r) {
        if (r.ok) {
          board.querySelectorAll(".kcol[data-column]").forEach(function (c) {
            var n = c.querySelectorAll(".kcard").length;
            var counter = c.querySelector(".kcount");
            if (counter) counter.textContent = counter.textContent.replace(/^\d+/, String(n));
          });
          return;
        }
        return r.json().then(function (b) { window.alert(b.detail || "That move was not saved."); location.reload(); });
      }).catch(function () { location.reload(); });
    });

    // A click that ends a drag should not follow the card's link.
    board.addEventListener("click", function (e) {
      var card = e.target.closest(".kcard");
      if (card && card.classList.contains("dragging")) e.preventDefault();
    });
  });

  // Confirm destructive buttons without inline handlers (the CSP forbids them).
  document.querySelectorAll("button.danger, button[data-confirm]").forEach(function (b) {
    b.addEventListener("click", function (e) {
      if (!window.confirm(b.dataset.confirm || "Are you sure?")) e.preventDefault();
    });
  });
})();
