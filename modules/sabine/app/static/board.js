// SABINE board: refresh the picture, keep the clock, speak her line when it changes.
(function () {
  var body = document.body;
  var refresh = parseInt(body.dataset.refresh || "30", 10) * 1000;
  var speakMode = body.dataset.speak || "browser";
  var lastLine = document.getElementById("line").textContent.trim();
  var voiceOn = false;
  var muteBtn = document.getElementById("mute");

  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

  function clock() {
    var d = new Date();
    document.getElementById("clock").textContent = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function speak(text) {
    if (!voiceOn || !text) return;
    if (speakMode === "browser") {
      if (!("speechSynthesis" in window)) return;
      var u = new SpeechSynthesisUtterance(text);
      var voices = window.speechSynthesis.getVoices();
      var pick = voices.find(function (v) { return /female|samantha|ava|zira|aria|jenny|karen|moira/i.test(v.name); }) ||
                 voices.find(function (v) { return /^en/i.test(v.lang); });
      if (pick) u.voice = pick;
      u.rate = 1.0; u.pitch = 1.05;
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(u);
      return;
    }
    fetch("/api/speak", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: text }) })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { if (j && j.url) { var a = new Audio(j.url); a.play().catch(function () {}); } })
      .catch(function () {});
  }

  function render(d) {
    var lineEl = document.getElementById("line");
    if (d.line !== lastLine) {
      lineEl.textContent = d.line;
      lineEl.parentElement.classList.remove("fresh"); void lineEl.offsetWidth; lineEl.parentElement.classList.add("fresh");
      lastLine = d.line;
      speak(d.line);
    }
    document.getElementById("t-open").textContent = d.stats.open;
    document.getElementById("t-split").textContent = d.stats.soc + " SOC · " + d.stats.admin + " admin · " + d.stats.services + " services";
    document.getElementById("t-pending").textContent = d.stats.pending;
    if (d.mtta) {
      document.getElementById("t-mtta").textContent = d.mtta.auto;
      document.getElementById("t-mtta-sub").textContent = d.mtta.sub;
    }
    var cyc = document.getElementById("cycle");
    if (d.last_cycle.at) {
      var t = new Date(d.last_cycle.at);
      cyc.textContent = "last cycle " + t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + (d.last_cycle.ok ? "" : " failed");
      cyc.className = "cycle" + (d.last_cycle.ok ? "" : " bad");
    } else { cyc.textContent = "no cycle yet"; }
    var mods = Object.keys(d.modules).sort().map(function (k) {
      var m = d.modules[k];
      return '<span class="dot ' + (m.ok ? "up" : "down") + '" title="' + esc(m.detail) + '"><i></i>' + esc(k) + "</span>";
    }).join("");
    document.getElementById("modules").innerHTML = mods || '<span class="dot"><i></i>nothing in reach</span>';
    document.getElementById("queue").innerHTML = d.queue.length ? d.queue.map(function (w) {
      return '<li><span class="sev ' + esc(w.severity) + '">' + esc(w.severity) + '</span><span class="t">' + esc(w.title) + "</span><span class=\"c\">" + esc(w.client || w.source) + (w.owner ? " · " + esc(w.owner.split("@")[0]) : "") + "</span></li>";
    }).join("") : '<li class="empty">Nothing waiting.</li>';
    document.getElementById("pending").innerHTML = d.pending.length ? d.pending.map(function (p) {
      return '<li><span class="sev ' + (p.risk === "high" ? "critical" : p.risk === "medium" ? "high" : "medium") + '">' + esc(p.risk) + '</span><span class="t">' + esc(p.title) + '</span><span class="c">' + Math.round(p.confidence * 100) + "%</span></li>";
    }).join("") : '<li class="empty">Nothing needs a decision.</li>';
    document.getElementById("recent").innerHTML = d.recent.length ? d.recent.map(function (r) {
      return '<li class="' + (r.ok ? "ok" : "") + '"><span class="sev">' + (r.ok ? "done" : "failed") + '</span><span class="t">' + esc(r.title) + '</span><span class="c">' + esc(r.detail) + "</span></li>";
    }).join("") : '<li class="empty">Nothing yet.</li>';
  }

  function tick() {
    fetch("/api/board", { credentials: "same-origin" })
      .then(function (r) { if (r.status === 401) { location.reload(); } return r.ok ? r.json() : null; })
      .then(function (d) { if (d) render(d); })
      .catch(function () {});
  }

  muteBtn.addEventListener("click", function () {
    voiceOn = !voiceOn;
    muteBtn.textContent = voiceOn ? "voice on" : "voice off";
    muteBtn.classList.toggle("on", voiceOn);
    if (voiceOn) speak(lastLine);
  });

  clock(); setInterval(clock, 15000);
  tick(); setInterval(tick, refresh);
})();
