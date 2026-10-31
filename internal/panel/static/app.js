"use strict";

const status = document.querySelector("#copy-status");
const toastMessage = status.querySelector("[data-toast-message]");
let toastTimer;
function showToast(message) {
  toastMessage.textContent = message;
  status.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { status.hidden = true; }, 5000);
}
if (toastMessage.textContent.trim()) showToast(toastMessage.textContent);

const presetDialog = document.querySelector("#preset-dialog");
if (presetDialog) {
  document.querySelector("#load-preset").addEventListener("click", () => presetDialog.showModal());
  presetDialog.querySelectorAll("[data-close-preset]").forEach(button => {
    button.addEventListener("click", () => presetDialog.close());
  });
}

document.querySelectorAll("[data-copy], [data-copy-target]").forEach(button => {
  button.addEventListener("click", async () => {
    try {
      const value = button.dataset.copyTarget ? document.querySelector(button.dataset.copyTarget).textContent : button.dataset.copy;
      await navigator.clipboard.writeText(value);
      showToast(button.dataset.copyLabel || "Subscription URL copied");
    } catch {
      showToast("Copy unavailable. Select and copy the text.");
    }
  });
});

const logs = document.querySelector("#server-logs");
if (logs) {
  let pending = false;
  const error = document.querySelector("#logs-error");
  const refresh = async () => {
    if (pending) return;
    pending = true;
    try {
      const response = await fetch(logs.dataset.logsUrl, {cache: "no-store"});
      if (!response.ok) throw new Error();
      const atBottom = logs.scrollTop + logs.clientHeight >= logs.scrollHeight - 10;
      logs.textContent = await response.text();
      if (atBottom) logs.scrollTop = logs.scrollHeight;
      error.hidden = true;
    } catch {
      error.textContent = "Could not refresh logs. Try Refresh.";
      error.hidden = false;
    } finally { pending = false; }
  };
  logs.scrollTop = logs.scrollHeight;
  document.querySelector("#logs-refresh").addEventListener("click", refresh);
  setInterval(() => { if (document.querySelector("#logs-live").checked && !document.hidden) refresh(); }, 3000);
}

document.querySelectorAll("[data-confirm]").forEach(form => {
  form.addEventListener("submit", event => {
    const confirmed = window.confirm(form.dataset.confirm);
    const confirmation = form.querySelector("[data-confirmation]");
    if (confirmation) confirmation.value = confirmed ? "1" : "0";
    if (!confirmed) event.preventDefault();
  });
});

document.querySelectorAll("[data-dirty-form]").forEach(form => {
  let dirty = false;
  form.addEventListener("input", () => { dirty = true; });
  form.addEventListener("submit", () => { dirty = false; });
  window.addEventListener("beforeunload", event => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
});
