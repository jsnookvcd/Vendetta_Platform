// Ask SABINE: push to talk (browser speech recognition) and play her answer.
(function () {
  var q = document.querySelector('input[name="question"]');
  var talk = document.getElementById("talk");
  var play = document.getElementById("play");
  var mode = document.body.dataset.speak || "browser";
  var Rec = window.SpeechRecognition || window.webkitSpeechRecognition;

  if (talk) {
    if (!Rec) { talk.disabled = true; talk.title = "This browser cannot listen; type instead."; }
    else {
      var rec = new Rec(); rec.lang = "en-US"; rec.interimResults = true; var listening = false;
      rec.onresult = function (e) { q.value = Array.prototype.map.call(e.results, function (r) { return r[0].transcript; }).join(" "); };
      rec.onend = function () { listening = false; talk.classList.remove("on"); talk.textContent = "Talk"; if (q.value.trim()) talk.form.requestSubmit(); };
      talk.addEventListener("click", function (ev) {
        ev.preventDefault();
        if (listening) { rec.stop(); return; }
        listening = true; talk.classList.add("on"); talk.textContent = "Listening…"; q.value = ""; rec.start();
      });
    }
  }

  if (play) {
    var text = play.dataset.text || "";
    play.addEventListener("click", function () {
      if (mode === "browser") {
        if (!("speechSynthesis" in window)) return;
        var u = new SpeechSynthesisUtterance(text);
        var voices = window.speechSynthesis.getVoices();
        var pick = voices.find(function (v) { return /female|samantha|ava|zira|aria|jenny|karen|moira/i.test(v.name); }) ||
                   voices.find(function (v) { return /^en/i.test(v.lang); });
        if (pick) u.voice = pick; u.pitch = 1.05;
        window.speechSynthesis.cancel(); window.speechSynthesis.speak(u);
        return;
      }
      fetch("/api/speak", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: text }) })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) { if (j && j.url) new Audio(j.url).play(); });
    });
  }
})();
