// Instant unlock button feedback — runs before Qwik loads.
// Uses nodeValue (not textContent) to preserve Qwik's DOM tracking.
(function () {
  function setUnlockText(el, str) {
    if (!el) return;
    // Walk child nodes, find the text node (skip Qwik comment nodes)
    for (var i = 0; i < el.childNodes.length; i++) {
      if (el.childNodes[i].nodeType === 3) {
        el.childNodes[i].nodeValue = str;
        return;
      }
    }
  }

  // pointerdown fires on mouse PRESS — instant, browser paints before click
  document.addEventListener(
    "pointerdown",
    function (e) {
      var t = e.target;
      if (!t || !t.closest) return;
      var btn = t.closest('button[type="submit"]');
      if (!btn) return;
      var form = btn.closest("form");
      if (!form) return;
      var input = form.querySelector('input[type="password"]');
      if (!input || !input.value) return;
      setUnlockText(document.getElementById("unlock-btn-text"), "Unlocking...");
    },
    true
  );

  // Enter key — prevent default, change text, then trigger submit after paint
  document.addEventListener(
    "keydown",
    function (e) {
      if (e.key !== "Enter") return;
      var el = e.target;
      if (!el || !el.closest) return;
      var form = el.closest("form");
      if (!form) return;
      var pwInput = form.querySelector('input[type="password"]');
      if (!pwInput || !pwInput.value) return;
      var text = document.getElementById("unlock-btn-text");
      if (!text) return;

      // Prevent immediate form submit (no paint between keydown and submit)
      e.preventDefault();

      // Change text now
      setUnlockText(text, "Unlocking...");

      // Double-rAF: first rAF runs before paint, second runs AFTER paint.
      // This guarantees the text change is visible before btn.click() fires.
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          var btn = form.querySelector('button[type="submit"]');
          if (btn) btn.click();
        });
      });
    },
    true
  );
})();
