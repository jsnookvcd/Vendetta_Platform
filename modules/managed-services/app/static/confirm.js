// Native confirm() on any form marked data-confirm, so a destructive action
// (isolate, contain, quarantine, kill) is never a single accidental click.
// Static file under the strict CSP (script-src 'self'); the server also refuses
// these in read-only mode, so this is a UX guard, not the safety boundary.
(function () {
  "use strict";
  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (f && f.matches && f.matches("form[data-confirm]")) {
      if (!window.confirm(f.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    }
  }, true);
})();
