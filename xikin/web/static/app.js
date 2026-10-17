(function () {
  "use strict";

  const csrfMeta = document.querySelector('meta[name="csrf"]');
  const csrf = csrfMeta ? csrfMeta.content : "";

  function flash(button) {
    button.classList.add("is-copied");
    const previous = button.getAttribute("title");
    button.setAttribute("title", "Copied");
    window.setTimeout(function () {
      button.classList.remove("is-copied");
      if (previous) {
        button.setAttribute("title", previous);
      } else {
        button.removeAttribute("title");
      }
    }, 1200);
  }

  function copyText(value, button) {
    if (!value) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () { flash(button); });
    }
  }

  function loadInto(targetSelector, url, method, body) {
    const target = typeof targetSelector === "string"
      ? document.querySelector(targetSelector)
      : targetSelector;
    if (!target) return Promise.resolve();
    target.setAttribute("aria-busy", "true");
    const headers = {};
    if (method && method !== "GET") headers["X-CSRF-Token"] = csrf;
    if (body) headers["Content-Type"] = "application/x-www-form-urlencoded";
    return fetch(url, {
      method: method || "GET",
      headers: headers,
      credentials: "same-origin",
      body: body || undefined
    })
      .then(function (response) {
        if (response.status === 401) {
          window.location.href = "/login";
          return null;
        }
        return response.text().then(function (text) {
          if (!response.ok) throw new Error(text || response.statusText);
          return text;
        });
      })
      .then(function (html) {
        if (!html) return;
        const holder = document.createElement("div");
        holder.innerHTML = html;
        const replacement = holder.firstElementChild;
        if (replacement) target.replaceWith(replacement);
      })
      .catch(function (error) {
        target.setAttribute("aria-busy", "false");
        console.error("[xikin]", error);
      });
  }

  function setBusy(button, busy) {
    if (!button) return;
    if (busy) {
      button.dataset.label = button.textContent;
      button.textContent = button.dataset.busy || "Working…";
      button.disabled = true;
    } else {
      button.textContent = button.dataset.label || button.textContent;
      button.disabled = false;
    }
  }

  function activateTab(button) {
    const name = button.dataset.tab;
    document.querySelectorAll("[data-tab]").forEach(function (item) {
      item.classList.toggle("is-active", item === button);
    });
    document.querySelectorAll("[data-panel]").forEach(function (panel) {
      panel.classList.toggle("is-active", panel.dataset.panel === name);
    });
  }

  function handleAction(button) {
    const action = button.dataset.action;
    const target = button.dataset.target;
    if (action === "check-run" || action === "check-run-live") {
      const runId = button.dataset.run;
      if (!runId) return;
      const url = "/partials/runs/" + encodeURIComponent(runId) + "/check"
        + (action === "check-run-live" ? "?live=1" : "");
      setBusy(button, true);
      loadInto(target || "#run-check-panel", url, "POST");
      return;
    }
    const routes = {
      "renew-tor": ["/partials/tor/renew", "POST"],
      "check-engines": ["/partials/engines/check", "POST"],
      "verify-evidence": ["/partials/evidence/verify", "GET"]
    };
    const route = routes[action];
    if (!route) return;
    setBusy(button, true);
    loadInto(target, route[0], route[1]);
  }

  document.addEventListener("click", function (event) {
    const copyButton = event.target.closest("[data-copy]");
    if (copyButton) {
      copyText(copyButton.dataset.copy, copyButton);
      return;
    }
    const tabButton = event.target.closest("[data-tab]");
    if (tabButton) {
      activateTab(tabButton);
      return;
    }
    const selectAll = event.target.closest("[data-select-all]");
    if (selectAll) {
      document.querySelectorAll(selectAll.dataset.selectAll).forEach(function (box) {
        box.checked = selectAll.checked;
      });
      return;
    }
    const actionButton = event.target.closest("[data-action]");
    if (actionButton) handleAction(actionButton);
  });

  document.addEventListener("submit", function (event) {
    const form = event.target.closest("form[data-confirm]");
    if (form && !window.confirm(form.getAttribute("data-confirm"))) {
      event.preventDefault();
    }
  });

  document.addEventListener("submit", function (event) {
    const form = event.target.closest("form[data-ajax='urlcheck']");
    if (!form) return;
    event.preventDefault();
    const button = form.querySelector("button[type='submit']");
    setBusy(button, true);
    const body = new URLSearchParams(new FormData(form)).toString();
    loadInto("#urlcheck-panel", "/partials/urlcheck", "POST", body)
      .finally(function () { setBusy(button, false); });
  });

  function appendLog(log, line) {
    if (!log) return;
    const row = document.createElement("div");
    row.className = "log-line";
    if (line.startsWith("[done]")) row.classList.add("log-ok");
    if (line.startsWith("[error]")) row.classList.add("log-bad");
    row.textContent = line;
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function startLiveStream() {
    const live = document.getElementById("run-live");
    if (!live) return;
    const status = live.dataset.status;
    if (status !== "queued" && status !== "running") return;

    const log = document.getElementById("run-log");
    const bar = document.getElementById("run-progress");
    const label = document.getElementById("run-progress-label");
    const source = new EventSource(live.dataset.events);

    source.onmessage = function (message) {
      try {
        const payload = JSON.parse(message.data);
        appendLog(log, payload.line || "");
        if (bar && typeof payload.progress === "number") {
          bar.style.width = payload.progress + "%";
        }
        if (label && typeof payload.progress === "number") {
          label.textContent = payload.progress + "%";
        }
      } catch (error) {
        /* ignore malformed events */
      }
    };
    source.addEventListener("done", function () {
      source.close();
      window.setTimeout(function () { window.location.reload(); }, 600);
    });
    source.onerror = function () {
      /* EventSource retries automatically; the server closes on completion */
    };
  }

  function init() {
    document.querySelectorAll("[data-autoload]").forEach(function (element) {
      loadInto(element, element.dataset.autoload, "GET");
    });
    document.querySelectorAll("[data-progress]").forEach(function (element) {
      const value = parseInt(element.dataset.progress, 10);
      if (!isNaN(value)) {
        element.style.width = Math.max(0, Math.min(100, value)) + "%";
      }
    });
    document.querySelectorAll("[data-pct]").forEach(function (element) {
      const value = parseInt(element.dataset.pct, 10);
      if (!isNaN(value)) {
        element.style.height = Math.max(2, Math.min(100, value)) + "%";
      }
    });
    startLiveStream();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
