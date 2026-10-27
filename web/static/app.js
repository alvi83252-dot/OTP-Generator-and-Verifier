// Browser side of the time-bomb.
// The bar is drawn here. The server decides whether a code is valid.
// A late submit locks this card even if the local clock disagrees.

const body = document.body;
const card = document.getElementById("timebomb-card");
const otpDisplay = document.getElementById("otp-display");
const barFill = document.getElementById("bar-fill");
const barLabel = document.getElementById("bar-label");
const barHint = document.getElementById("bar-hint");
const lockBanner = document.getElementById("lock-banner");
const otpInput = document.getElementById("otp-input");
const verifyBtn = document.getElementById("verify-btn");
const newBtn = document.getElementById("new-btn");
const attemptCount = document.getElementById("attempt-count");
const statusBox = document.getElementById("status");
const demoForm = document.getElementById("demo-form");

const totpCode = document.getElementById("totp-code");
const totpLeft = document.getElementById("totp-left");
const totpInput = document.getElementById("totp-input");
const totpStatus = document.getElementById("totp-status");
const totpForm = document.getElementById("totp-form");

const hotpCounter = document.getElementById("hotp-counter");
const hotpCode = document.getElementById("hotp-code");
const hotpInput = document.getElementById("hotp-input");
const hotpStatus = document.getElementById("hotp-status");
const hotpForm = document.getElementById("hotp-form");
const hotpShow = document.getElementById("hotp-show");

const vectorBody = document.getElementById("vector-body");
const vectorSummary = document.getElementById("vector-summary");

let token = null;
let issuedAtMs = 0;
let expiresAtMs = 0;
let attempts = 0;
let busy = false;
let barTimer = 0;
let lockTimer = 0;

function showStatus(element, data, extra) {
  element.className = "status status-" + (data.status || "info");
  element.replaceChildren();
  const title = document.createElement("strong");
  title.textContent = data.title || "NOTICE";
  const message = document.createElement("span");
  message.textContent = data.message || "";
  element.append(title, message);
  if (extra) {
    const more = document.createElement("span");
    more.textContent = extra;
    element.append(more);
  }
}

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (_error) {
    return {
      status: "invalid",
      title: "INVALID",
      message: "The server did not return JSON. Is python app.py still running?",
    };
  }
}

function drawBar() {
  if (!expiresAtMs) {
    return;
  }
  const total = Math.max(1, expiresAtMs - issuedAtMs);
  const remaining = Math.max(0, expiresAtMs - Date.now());
  const seconds = remaining <= 0 ? 0 : Math.ceil(remaining / 1000);
  barFill.style.width = (remaining / total) * 100 + "%";
  if (remaining <= 0) {
    barFill.className = "bar-fill is-closed";
    barLabel.textContent = "EXPIRED";
    barHint.textContent =
      "Window closed. Submitting an OTP now locks input for " +
      body.dataset.lockout +
      " seconds.";
    return;
  }
  barLabel.textContent = seconds + "s remaining";
  barHint.textContent = "Window open. You can try more than once before it expires.";
  barFill.className = "bar-fill" + (seconds <= 5 ? " is-low" : seconds <= 15 ? " is-mid" : "");
}

function startBar() {
  window.clearInterval(barTimer);
  drawBar();
  barTimer = window.setInterval(drawBar, 100);
}

function startLock(retryAfter) {
  const seconds = Number(retryAfter || body.dataset.lockout);
  const ends = Date.now() + seconds * 1000;
  token = null;
  window.clearInterval(barTimer);
  window.clearInterval(lockTimer);
  card.classList.remove("is-success");
  card.classList.add("is-locked", "is-flashing");
  window.setTimeout(function () {
    card.classList.remove("is-flashing");
  }, 1200);
  otpInput.disabled = true;
  verifyBtn.disabled = true;
  newBtn.disabled = true;
  lockBanner.hidden = false;
  barFill.style.width = "0%";
  barFill.className = "bar-fill is-closed";
  barLabel.textContent = "EXPIRED";

  function tick() {
    const left = Math.max(0, Math.ceil((ends - Date.now()) / 1000));
    lockBanner.textContent = "LOCKED - input disabled. " + left + "s remaining.";
    if (left <= 0) {
      window.clearInterval(lockTimer);
      card.classList.remove("is-locked", "is-flashing");
      lockBanner.hidden = true;
      newBtn.disabled = false;
      otpInput.value = "";
      otpDisplay.textContent = "------";
      showStatus(statusBox, {
        status: "info",
        title: "LOCKOUT FINISHED",
        message: "Input is enabled again. Generate a new OTP.",
      });
    }
  }

  tick();
  lockTimer = window.setInterval(tick, 200);
}

async function generateOtp() {
  if (card.classList.contains("is-locked") || busy) {
    return;
  }
  busy = true;
  newBtn.disabled = true;
  try {
    const response = await fetch("/api/challenge", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const data = await readJson(response);
    if (response.status === 423 || data.status === "locked") {
      showStatus(statusBox, data);
      startLock(data.retry_after);
      return;
    }
    token = data.token;
    issuedAtMs = data.issued_at * 1000;
    expiresAtMs = data.expires_at * 1000;
    attempts = 0;
    otpDisplay.textContent = data.otp;
    attemptCount.textContent = "Attempts this window: 0";
    otpInput.disabled = false;
    verifyBtn.disabled = false;
    otpInput.value = "";
    card.classList.remove("is-success");
    showStatus(statusBox, {
      status: "info",
      title: "NEW OTP",
      message: data.message || "New code issued.",
    });
    startBar();
    otpInput.focus();
  } catch (_error) {
    showStatus(statusBox, {
      status: "invalid",
      title: "INVALID",
      message: "Could not reach the server.",
    });
  } finally {
    busy = false;
    if (!card.classList.contains("is-locked")) {
      newBtn.disabled = false;
    }
  }
}

async function submitOtp() {
  if (otpInput.disabled || busy) {
    return;
  }
  if (!token) {
    showStatus(statusBox, {
      status: "invalid",
      title: "INVALID",
      message: "Generate an OTP first.",
    });
    return;
  }
  busy = true;
  verifyBtn.disabled = true;
  try {
    const response = await fetch("/api/verify", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ otp: otpInput.value.trim(), token: token }),
    });
    const data = await readJson(response);
    if (data.status === "mismatch") {
      attempts += 1;
      attemptCount.textContent = "Attempts this window: " + attempts;
      const left = Math.max(0, Math.ceil((expiresAtMs - Date.now()) / 1000));
      showStatus(statusBox, data, "Attempt " + attempts + ". " + left + "s left in this window.");
      return;
    }
    if (data.status === "invalid") {
      showStatus(statusBox, data, "This was not counted as an attempt.");
      return;
    }
    if (data.status === "success") {
      token = null;
      otpInput.disabled = true;
      card.classList.add("is-success");
      showStatus(statusBox, data);
      return;
    }
    if (data.status === "expired" || data.status === "locked") {
      showStatus(statusBox, data);
      startLock(data.retry_after);
      return;
    }
    showStatus(statusBox, data);
  } catch (_error) {
    showStatus(statusBox, {
      status: "invalid",
      title: "INVALID",
      message: "Could not reach the server.",
    });
  } finally {
    busy = false;
    if (!otpInput.disabled && !card.classList.contains("is-locked")) {
      verifyBtn.disabled = false;
    }
  }
}

async function refreshTotp() {
  const response = await fetch("/api/totp", { credentials: "same-origin" });
  const data = await readJson(response);
  if (!data.otp) {
    return;
  }
  totpCode.textContent = data.otp;
  totpLeft.textContent = data.seconds_remaining + "s left in this 30-second step. Skew allows one step either side.";
}

async function submitTotp() {
  const response = await fetch("/api/verify-totp", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ otp: totpInput.value.trim() }),
  });
  showStatus(totpStatus, await readJson(response));
}

async function showHotp(quiet) {
  const response = await fetch("/api/hotp", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ counter: hotpCounter.value }),
  });
  const data = await readJson(response);
  if (data.otp) {
    hotpCode.textContent = data.otp;
    if (!quiet) {
      showStatus(hotpStatus, {
        status: "info",
        title: "HOTP",
        message: "Counter " + data.counter + " is showing. Look-ahead is 0.",
      });
    }
    return;
  }
  hotpCode.textContent = "------";
  if (!quiet) {
    showStatus(hotpStatus, data);
  }
}

async function submitHotp() {
  const response = await fetch("/api/verify-hotp", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      otp: hotpInput.value.trim(),
      counter: hotpCounter.value,
    }),
  });
  const data = await readJson(response);
  if (data.status === "success") {
    const next = Number(hotpCounter.value) + 1;
    hotpCounter.value = String(next);
    hotpInput.value = "";
    await showHotp(true);
    showStatus(hotpStatus, data, "Counter advanced to " + next + ".");
    return;
  }
  showStatus(hotpStatus, data);
}

function addCell(row, text, className) {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (className) {
    cell.className = className;
  }
  row.append(cell);
}

async function loadVectors() {
  const response = await fetch("/api/vectors", { credentials: "same-origin" });
  const data = await readJson(response);
  vectorBody.replaceChildren();
  (data.rows || []).forEach(function (row) {
    const tr = document.createElement("tr");
    addCell(tr, row.kind);
    addCell(tr, row.algorithm);
    addCell(tr, row.detail);
    addCell(tr, row.expected);
    addCell(tr, row.actual);
    addCell(tr, row.passed ? "PASS" : "FAIL", row.passed ? "pass" : "fail");
    vectorBody.append(tr);
  });
  const count = data.count || 0;
  vectorSummary.textContent = data.passed
    ? "All " + count + " sample test vectors passed."
    : "One or more sample test vectors failed.";
}

async function resumeLock() {
  const response = await fetch("/api/lock-status", { credentials: "same-origin" });
  const data = await readJson(response);
  if (data.locked) {
    showStatus(statusBox, data);
    startLock(data.retry_after);
    return true;
  }
  return false;
}

demoForm.addEventListener("submit", function (event) {
  event.preventDefault();
  submitOtp();
});
newBtn.addEventListener("click", generateOtp);
totpForm.addEventListener("submit", function (event) {
  event.preventDefault();
  submitTotp();
});
hotpForm.addEventListener("submit", function (event) {
  event.preventDefault();
  submitHotp();
});
hotpShow.addEventListener("click", showHotp);

resumeLock().then(function (locked) {
  if (!locked) {
    generateOtp();
  }
  refreshTotp();
  showHotp();
  loadVectors();
  window.setInterval(refreshTotp, 1000);
});
