/* ARIA Password Tester — Frontend-Logik
   - Debounced Analyse
   - Rotierende Zeichen-Animation während der Analyse
   - Farbcodierte Ergebnis-Darstellung */

const $ = (id) => document.getElementById(id);

const LEVELS = ["weak", "fair", "good", "strong", "excellent"];
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}";

const els = {
  input:   $("pw"),
  toggle:  $("toggle"),
  scramble:$("scramble"),
  bar:     $("bar"),
  verdict: $("verdict"),
  card:    document.querySelector(".card"),
  length:  $("s-length"),
  entropy: $("s-entropy"),
  score:   $("s-score"),
  hibp:    $("s-hibp"),
  times:   $("times"),
  feedback:$("feedback"),
};

let scrambleTimer = null;
let debounceTimer = null;
let requestSeq = 0;

/* Rotierende Zeichen-Animation (übersprungen bei prefers-reduced-motion) */
function startScramble(text) {
  stopScramble();
  if (REDUCED_MOTION) {
    els.scramble.textContent = "Wird geprüft";
    return;
  }
  let frame = 0;
  scrambleTimer = setInterval(() => {
    frame++;
    const reveal = Math.floor(frame / 3);
    let out = "";
    for (let i = 0; i < text.length; i++) {
      if (i < reveal) out += text[i];
      else out += CHARS[Math.floor(Math.random() * CHARS.length)];
    }
    els.scramble.textContent = out;
  }, 40);
}
function stopScramble() {
  if (scrambleTimer) { clearInterval(scrambleTimer); scrambleTimer = null; }
}

/* Farbcodierung */
function resetLevel() {
  LEVELS.forEach(l => els.card.classList.remove("level-" + l));
}
function applyLevel(level) {
  resetLevel();
  els.card.classList.add("level-" + level);
}

/* Rendering */
function render(data) {
  els.length.textContent  = data.length + " Zeichen";
  els.entropy.textContent = data.entropy_bits + " Bits";
  els.score.textContent   = data.zxcvbn_score + "/4";
  els.hibp.textContent    = data.breached === null
      ? "k. A."
      : data.breached
        ? `geleakt (${data.breach_count.toLocaleString("de-DE")}×)`
        : "sauber";

  const pct = Math.min(100, (data.zxcvbn_score + 1) * 20);
  els.bar.style.width = pct + "%";

  els.verdict.textContent = data.verdict;
  applyLevel(data.verdict_level);

  els.times.innerHTML = "";
  if (!data.crack_times.length) {
    els.times.innerHTML = '<li class="empty">Keine Daten</li>';
  } else {
    for (const t of data.crack_times) {
      const li = document.createElement("li");
      li.innerHTML = `<span class="who">${t.attacker}</span>
                      <span class="val">${t.human}</span>`;
      els.times.appendChild(li);
    }
  }

  els.feedback.innerHTML = "";
  if (!data.feedback.length) {
    els.feedback.innerHTML = '<li class="empty">Keine Hinweise</li>';
  } else {
    for (const f of data.feedback) {
      const li = document.createElement("li");
      li.textContent = f;
      els.feedback.appendChild(li);
    }
  }
}

/* Netzwerk */
async function analyze(pw) {
  const seq = ++requestSeq;
  startScramble(pw || "password");
  try {
    const r = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw }),
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    if (seq !== requestSeq) return;
    render(data);
  } catch (e) {
    els.verdict.textContent = "Fehler bei der Analyse";
    applyLevel("weak");
  } finally {
    if (seq === requestSeq) {
      stopScramble();
      els.scramble.textContent = "Analyse abgeschlossen";
    }
  }
}

/* Events */
els.input.addEventListener("input", () => {
  const v = els.input.value;
  clearTimeout(debounceTimer);
  if (!v) {
    els.scramble.textContent = "";
    els.verdict.textContent = "Noch keine Eingabe";
    els.bar.style.width = "0%";
    resetLevel();
    return;
  }
  debounceTimer = setTimeout(() => analyze(v), 220);
});

els.toggle.addEventListener("click", () => {
  const isPw = els.input.type === "password";
  els.input.type = isPw ? "text" : "password";
  els.toggle.classList.toggle("is-visible", isPw);
  const label = isPw ? "Passwort verbergen" : "Passwort anzeigen";
  els.toggle.setAttribute("aria-label", label);
  els.toggle.setAttribute("aria-pressed", String(isPw));
  els.toggle.title = label;
});

els.input.focus();
