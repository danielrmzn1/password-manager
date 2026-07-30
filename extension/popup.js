"use strict";

/**
 * Popup — pairing UI and credential picker.
 *
 * Holds no token and makes no network requests: every question goes to the
 * service worker, which owns the bridge. The only secret that ever exists in
 * this extension outside the worker is the one username/password the worker
 * hands straight to the content script when the user clicks an entry — it never
 * passes through here.
 */

/** State name -> key in `el` (see collectElements). */
const VIEWS = {
  loading: "viewLoading",
  offline: "viewOffline",
  pair: "viewPair",
  locked: "viewLocked",
  list: "viewList",
};

const el = {};

/** Everything the popup touches, resolved once so a typo is loud, not silent. */
function collectElements() {
  const ids = [
    "badge",
    "view-loading",
    "view-offline",
    "offline-title",
    "offline-body",
    "offline-retry",
    "view-pair",
    "pair-note",
    "code",
    "pair-submit",
    "pair-error",
    "view-locked",
    "locked-retry",
    "view-list",
    "list-host",
    "entries",
    "list-empty",
    "empty-host",
    "form-note",
    "list-error",
    "footer",
    "footer-note",
    "unpair",
  ];

  const missing = [];
  for (const id of ids) {
    const node = document.getElementById(id);
    if (!node) missing.push(id);
    // "offline-retry" -> el.offlineRetry
    el[id.replace(/-([a-z])/g, (m, c) => c.toUpperCase())] = node;
  }
  if (missing.length > 0) {
    console.error("popup.html is missing element(s):", missing.join(", "));
  }
}

/** The active tab, remembered so fill and credentials agree on the target. */
let activeTab = null;
let busy = false;

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/** One request to the service worker. Never rejects: failures come back as `ok:false`. */
function send(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          resolve({
            ok: false,
            kind: "internal",
            error: "The extension's background worker did not respond.",
          });
          return;
        }
        resolve(
          response || {
            ok: false,
            kind: "internal",
            error: "The background worker sent an empty response.",
          },
        );
      });
    } catch (error) {
      resolve({
        ok: false,
        kind: "internal",
        error: "Could not reach the extension's background worker.",
      });
    }
  });
}

async function getActiveTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs && tabs.length > 0 ? tabs[0] : null;
  } catch (error) {
    return null;
  }
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return "";
  }
}

function isFillableUrl(url) {
  if (typeof url !== "string") return false;
  return /^https?:\/\//i.test(url);
}

// ---------------------------------------------------------------------------
// View helpers
// ---------------------------------------------------------------------------

function showView(name) {
  for (const key of Object.keys(VIEWS)) {
    const node = el[VIEWS[key]];
    if (node) node.hidden = key !== name;
  }
}

function setBadge(text, tone) {
  if (!el.badge) return;
  if (!text) {
    el.badge.hidden = true;
    el.badge.textContent = "";
    el.badge.removeAttribute("data-tone");
    return;
  }
  el.badge.hidden = false;
  el.badge.textContent = text;
  if (tone) el.badge.setAttribute("data-tone", tone);
  else el.badge.removeAttribute("data-tone");
}

function setText(node, text) {
  if (!node) return;
  node.textContent = typeof text === "string" ? text : "";
  node.hidden = !text;
}

function setFooter(status) {
  if (!el.footer) return;
  const paired = status && status.paired === true;
  el.footer.hidden = !paired;
  if (!paired) return;

  const bits = [];
  if (status.port) bits.push("127.0.0.1:" + status.port);
  if (status.version) bits.push("app " + status.version);
  if (el.footerNote) el.footerNote.textContent = bits.join(" · ");
  resetUnpairConfirm();
}

function resetUnpairConfirm() {
  if (!el.unpair) return;
  el.unpair.removeAttribute("data-confirm");
  el.unpair.textContent = "Unpair";
}

// ---------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------

async function refresh() {
  showView("loading");
  setBadge("");

  const results = await Promise.all([send({ type: "status" }), getActiveTab()]);
  const status = results[0];
  activeTab = results[1];

  if (!status.ok) {
    renderOffline("Something went wrong", status.error || "Unknown error.");
    setFooter(null);
    return;
  }

  setFooter(status);

  switch (status.state) {
    case "unreachable":
      setBadge("Offline", "off");
      renderOffline(
        "Desktop app not reachable",
        "Nothing answered on 127.0.0.1 ports 8391–8395.",
      );
      return;

    case "disabled":
      setBadge("Bridge off", "warn");
      renderOffline(
        "Browser bridge is switched off",
        "The desktop app is running but is not accepting extension requests.",
      );
      return;

    case "unpaired":
      setBadge("Not paired", "warn");
      renderPair(status);
      return;

    case "locked":
      setBadge("Locked", "warn");
      showView("locked");
      return;

    case "ready":
      setBadge("Unlocked", "ok");
      await renderList();
      return;

    default:
      renderOffline(
        "Unexpected state",
        "The background worker reported a state this popup does not know.",
      );
      return;
  }
}

function renderOffline(title, body) {
  if (el.offlineTitle) el.offlineTitle.textContent = title;
  if (el.offlineBody) el.offlineBody.textContent = body;
  showView("offline");
}

function renderPair(status) {
  let note = "";
  if (status.stale) {
    note =
      "The desktop app no longer recognises this extension — pair it again to carry on.";
  } else if (status.locked) {
    note =
      "Unlock the desktop app first: pairing stores its token inside the vault.";
  }
  setText(el.pairNote, note);
  setText(el.pairError, "");

  showView("pair");

  if (el.code) {
    const digits = el.code.value.replace(/\D+/g, "");
    if (el.pairSubmit) el.pairSubmit.disabled = digits.length !== 6;
    el.code.focus();
  }
}

async function renderList() {
  const url = activeTab && typeof activeTab.url === "string" ? activeTab.url : "";
  const host = hostOf(url);

  setText(el.listError, "");
  setText(el.formNote, "");
  if (el.entries) el.entries.replaceChildren();
  if (el.listEmpty) el.listEmpty.hidden = true;
  if (el.listHost) el.listHost.textContent = host || "this page";
  if (el.emptyHost) el.emptyHost.textContent = host || "this page";
  showView("list");

  if (!isFillableUrl(url)) {
    if (el.listHost) el.listHost.textContent = "this page";
    if (el.listEmpty) el.listEmpty.hidden = true;
    setText(
      el.listError,
      "This kind of page cannot be filled — open a normal http(s) site.",
    );
    return;
  }

  const tabId = activeTab && typeof activeTab.id === "number" ? activeTab.id : null;
  const requests = [send({ type: "credentials", url: url })];
  requests.push(
    tabId === null
      ? Promise.resolve({ ok: false, found: false })
      : send({ type: "detect", tabId: tabId }),
  );

  const answers = await Promise.all(requests);
  const credentials = answers[0];
  const detection = answers[1];

  if (!credentials.ok) {
    // The vault can lock, or the app can go away, between the status check and
    // now — re-render into the right view rather than showing a dead list.
    if (credentials.kind === "locked") {
      setBadge("Locked", "warn");
      showView("locked");
      return;
    }
    if (credentials.kind === "unreachable" || credentials.kind === "disabled") {
      setBadge("Offline", "off");
      renderOffline("Desktop app not reachable", credentials.error);
      return;
    }
    if (credentials.kind === "unpaired" || credentials.kind === "unauthorized") {
      setBadge("Not paired", "warn");
      renderPair({ stale: true, locked: false });
      return;
    }
    setText(el.listError, credentials.error || "Could not read the vault.");
    return;
  }

  const entries = Array.isArray(credentials.entries) ? credentials.entries : [];
  if (entries.length === 0) {
    if (el.listEmpty) el.listEmpty.hidden = false;
  } else {
    renderEntries(entries);
  }

  if (detection && detection.ok === true) {
    if (!detection.found) {
      setText(
        el.formNote,
        "No sign-in form detected here — pick an entry anyway if you know one is hidden on the page.",
      );
    } else if (!detection.hasUsernameField) {
      setText(el.formNote, "Password-only form detected on this page.");
    } else {
      setText(el.formNote, "Sign-in form detected on this page.");
    }
  }
}

function renderEntries(entries) {
  if (!el.entries) return;

  const items = [];
  for (const entry of entries) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "entry";

    const title = document.createElement("span");
    title.className = "entry-title";
    // textContent throughout: vault titles are user data, never markup.
    title.textContent = entry.title || entry.username || "Untitled entry";
    button.appendChild(title);

    const username = document.createElement("span");
    username.className = "entry-user";
    username.textContent = entry.username || "No username saved";
    button.appendChild(username);

    button.addEventListener("click", () => {
      void pick(entry, button);
    });

    const item = document.createElement("li");
    item.appendChild(button);
    items.push(item);
  }
  el.entries.replaceChildren.apply(el.entries, items);
}

/** The user's click here is the confirmation the bridge protocol requires. */
async function pick(entry, button) {
  if (busy) return;
  const tabId = activeTab && typeof activeTab.id === "number" ? activeTab.id : null;
  if (tabId === null) {
    setText(el.listError, "There is no active tab to fill.");
    return;
  }

  busy = true;
  setText(el.listError, "");
  setButtonsDisabled(true);
  const label = button.querySelector(".entry-user");
  const previous = label ? label.textContent : "";
  if (label) label.textContent = "Filling…";

  const result = await send({
    type: "fill",
    id: entry.id,
    tabId: tabId,
    // The origin these candidates were matched against; the service
    // worker refuses to fill if the tab has navigated away from it.
    host: hostOf(activeTab && activeTab.url ? activeTab.url : ""),
  });

  if (result.ok === true) {
    window.close();
    return;
  }

  busy = false;
  setButtonsDisabled(false);
  if (label) label.textContent = previous;

  if (result.kind === "locked") {
    setBadge("Locked", "warn");
    showView("locked");
    return;
  }
  setText(el.listError, result.error || "Could not fill this entry.");
}

function setButtonsDisabled(disabled) {
  if (!el.entries) return;
  const buttons = el.entries.querySelectorAll("button.entry");
  for (const button of buttons) button.disabled = disabled;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

async function submitPair() {
  if (busy || !el.code) return;
  const code = el.code.value.replace(/\D+/g, "");
  if (code.length !== 6) {
    setText(el.pairError, "Enter all six digits of the code.");
    return;
  }

  busy = true;
  if (el.pairSubmit) {
    el.pairSubmit.disabled = true;
    el.pairSubmit.textContent = "Pairing…";
  }
  setText(el.pairError, "");

  const result = await send({ type: "pair", code: code });

  busy = false;
  if (el.pairSubmit) el.pairSubmit.textContent = "Pair";

  if (result.ok === true) {
    el.code.value = "";
    await refresh();
    return;
  }

  if (el.pairSubmit) el.pairSubmit.disabled = false;
  setText(el.pairError, result.error || "Pairing failed.");
  // A rejected code is worth retyping; a wrong one may also have burned an
  // attempt, and the desktop app closes the window after five.
  if (result.kind === "pairing") {
    el.code.value = "";
    if (el.pairSubmit) el.pairSubmit.disabled = true;
    el.code.focus();
  }
}

/** Two-step, so a mis-click cannot drop the pairing. No modal dialogs in popups. */
async function onUnpairClick() {
  if (busy || !el.unpair) return;

  if (el.unpair.getAttribute("data-confirm") !== "true") {
    el.unpair.setAttribute("data-confirm", "true");
    el.unpair.textContent = "Confirm unpair";
    return;
  }

  busy = true;
  el.unpair.textContent = "Unpairing…";
  await send({ type: "unpair" });
  busy = false;
  resetUnpairConfirm();
  await refresh();
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function init() {
  collectElements();

  if (el.code) {
    el.code.addEventListener("input", () => {
      const cleaned = el.code.value.replace(/\D+/g, "").slice(0, 6);
      if (cleaned !== el.code.value) el.code.value = cleaned;
      if (el.pairSubmit) el.pairSubmit.disabled = cleaned.length !== 6;
      setText(el.pairError, "");
    });
    el.code.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        void submitPair();
      }
    });
  }

  if (el.pairSubmit) {
    el.pairSubmit.addEventListener("click", () => {
      void submitPair();
    });
  }
  if (el.offlineRetry) {
    el.offlineRetry.addEventListener("click", () => {
      void refresh();
    });
  }
  if (el.lockedRetry) {
    el.lockedRetry.addEventListener("click", () => {
      void refresh();
    });
  }
  if (el.unpair) {
    el.unpair.addEventListener("click", () => {
      void onUnpairClick();
    });
  }

  void refresh();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
