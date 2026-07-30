"use strict";

/**
 * Service worker — the only place that knows the bridge port and the pairing
 * token, and the only place that talks to the desktop app.
 *
 * Protocol and threat model: `docs/extension-bridge.md`. Server:
 * `src-tauri/src/bridge.rs`.
 *
 * Rules this file exists to enforce:
 *  - The content script never receives or holds the token; it only ever gets a
 *    single username/password for one fill the user explicitly asked for.
 *  - MV3 kills this worker whenever it feels like it, so nothing is cached in
 *    module scope that we cannot rebuild: the port lives in `chrome.storage`
 *    (session, falling back to local) and the token in `chrome.storage.local`.
 *  - Nothing secret is ever logged, not even at debug level.
 */

/** Ports the desktop app may bind, in the order it tries them. */
const PORTS = [8391, 8392, 8393, 8394, 8395];
/** `/health.app` must equal this, so we never talk to some other local server. */
const APP_ID = "password-manager";

const HEALTH_TIMEOUT_MS = 900;
const REQUEST_TIMEOUT_MS = 8000;

const PORT_KEY = "bridgePort";
const TOKEN_KEY = "bridgeToken";
const PAIRED_AT_KEY = "bridgePairedAt";

const UNREACHABLE_MESSAGE =
  "The Password Manager desktop app is not answering on 127.0.0.1.";

/** Message types a content script is allowed to send. Everything else must come
 *  from an extension page (the popup), which has no `sender.tab`. */
const CONTENT_SCRIPT_TYPES = ["detected"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * A failed bridge call. `kind` is what the popup branches on; `message` is
 * shown to the user as-is.
 */
class BridgeError extends Error {
  constructor(kind, message, status) {
    super(message);
    this.name = "BridgeError";
    this.kind = kind;
    this.status = typeof status === "number" ? status : 0;
  }
}

function errorForStatus(status, detail) {
  switch (status) {
    case 400:
      return new BridgeError(
        "bad_request",
        detail || "The desktop app could not read that request.",
        status,
      );
    case 401:
      // Bad/absent token, or an origin that is not the paired extension.
      return new BridgeError(
        "unauthorized",
        "The desktop app does not recognise this extension. Pair it again.",
        status,
      );
    case 403:
      // Pairing-window problem: wrong code, expired, or not started.
      return new BridgeError(
        "pairing",
        detail || "That pairing code was not accepted.",
        status,
      );
    case 404:
      return new BridgeError(
        "not_found",
        "That entry is no longer in the vault.",
        status,
      );
    case 423:
      return new BridgeError(
        "locked",
        "The vault is locked. Unlock the desktop app, then try again.",
        status,
      );
    case 503:
      return new BridgeError(
        "disabled",
        "The browser bridge is switched off in the desktop app's settings.",
        status,
      );
    default:
      return new BridgeError(
        "server",
        detail || "The desktop app returned an error (" + status + ").",
        status,
      );
  }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/**
 * `chrome.storage.session` is memory-only, which is where a discovered port
 * belongs. Older Chromium builds do not have it; `local` is a correct if
 * stickier fallback, because a stale port is always re-verified before use.
 */
function portArea() {
  if (chrome.storage && chrome.storage.session) return chrome.storage.session;
  return chrome.storage.local;
}

async function getCachedPort() {
  try {
    const got = await portArea().get(PORT_KEY);
    const port = got ? got[PORT_KEY] : null;
    return PORTS.indexOf(port) === -1 ? null : port;
  } catch (error) {
    return null;
  }
}

async function setCachedPort(port) {
  try {
    await portArea().set({ [PORT_KEY]: port });
  } catch (error) {
    // Caching is an optimisation; discovery still works without it.
  }
}

async function clearCachedPort() {
  try {
    await portArea().remove(PORT_KEY);
  } catch (error) {
    // Same: nothing to do if the cache cannot be cleared.
  }
}

async function getToken() {
  try {
    const got = await chrome.storage.local.get(TOKEN_KEY);
    const token = got ? got[TOKEN_KEY] : null;
    return typeof token === "string" && token.length > 0 ? token : null;
  } catch (error) {
    return null;
  }
}

async function setToken(token) {
  await chrome.storage.local.set({
    [TOKEN_KEY]: token,
    [PAIRED_AT_KEY]: Date.now(),
  });
}

async function clearToken() {
  try {
    await chrome.storage.local.remove([TOKEN_KEY, PAIRED_AT_KEY]);
  } catch (error) {
    // Nothing better to do; the next authenticated call will fail visibly.
  }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

function timedFetch(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const init = Object.assign({}, options, {
    signal: controller.signal,
    // Loopback, no cookies, no caching, and a redirect is never legitimate here.
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    mode: "cors",
  });
  return fetch(url, init).finally(() => clearTimeout(timer));
}

/**
 * Ask one port whether it is our desktop app.
 *
 * Returns `{ port, version, locked, paired }`, or null for "not us" — a closed
 * port, a timeout, or some other service answering. `locked` fails safe: only
 * an explicit `false` counts as unlocked.
 */
async function probeHealth(port, timeoutMs) {
  let response;
  try {
    response = await timedFetch(
      "http://127.0.0.1:" + port + "/health",
      { method: "GET" },
      timeoutMs,
    );
  } catch (error) {
    return null;
  }
  if (!response.ok) return null;

  let body;
  try {
    body = await response.json();
  } catch (error) {
    return null;
  }
  if (!body || body.app !== APP_ID) return null;

  return {
    port: port,
    version: typeof body.version === "string" ? body.version : "",
    locked: body.locked !== false,
    paired: body.paired === true,
  };
}

/** Walk the port range and remember the first port that answers as our app. */
async function discoverBridge() {
  for (const port of PORTS) {
    const health = await probeHealth(port, HEALTH_TIMEOUT_MS);
    if (health) {
      await setCachedPort(port);
      return health;
    }
  }
  await clearCachedPort();
  return null;
}

/**
 * The cached port, re-verified — a different process may have taken it since,
 * and the app may have moved. Falls back to a full scan.
 */
async function resolveBridge() {
  const cached = await getCachedPort();
  if (cached !== null) {
    const health = await probeHealth(cached, HEALTH_TIMEOUT_MS);
    if (health) return health;
  }
  return discoverBridge();
}

async function readResponse(response) {
  let text = "";
  try {
    text = await response.text();
  } catch (error) {
    text = "";
  }

  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch (error) {
      body = null;
    }
  }

  if (response.ok) return body === null ? {} : body;

  const detail = body && typeof body.error === "string" ? body.error : "";
  throw errorForStatus(response.status, detail);
}

/**
 * One bridge call. `token` null means the endpoint is unauthenticated.
 *
 * A connection failure on the cached port re-runs discovery once, because the
 * desktop app restarting onto a different port is the normal way for that to
 * happen. Throws `BridgeError`.
 */
async function callBridge(path, method, body, token) {
  const headers = {};
  if (token) headers["Authorization"] = "Bearer " + token;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const init = { method: method, headers: headers };
  if (body !== undefined) init.body = JSON.stringify(body);

  let port = await getCachedPort();
  let rediscovered = false;
  if (port === null) {
    const health = await discoverBridge();
    rediscovered = true;
    if (!health) throw new BridgeError("unreachable", UNREACHABLE_MESSAGE);
    port = health.port;
  }

  let response;
  try {
    response = await timedFetch(
      "http://127.0.0.1:" + port + path,
      init,
      REQUEST_TIMEOUT_MS,
    );
  } catch (error) {
    if (rediscovered) throw new BridgeError("unreachable", UNREACHABLE_MESSAGE);
    await clearCachedPort();
    const health = await discoverBridge();
    if (!health) throw new BridgeError("unreachable", UNREACHABLE_MESSAGE);
    try {
      response = await timedFetch(
        "http://127.0.0.1:" + health.port + path,
        init,
        REQUEST_TIMEOUT_MS,
      );
    } catch (retryError) {
      throw new BridgeError("unreachable", UNREACHABLE_MESSAGE);
    }
  }

  return readResponse(response);
}

// ---------------------------------------------------------------------------
// Form detection cache
// ---------------------------------------------------------------------------

/**
 * Last detection report per tab. Best-effort only: it is gone when the worker
 * restarts, so it is never the primary source — the popup's `detect` asks the
 * page live and only falls back to this.
 */
const detectionCache = new Map();
const DETECTION_CACHE_LIMIT = 64;

function rememberDetection(tabId, info) {
  if (typeof tabId !== "number") return;
  if (
    !detectionCache.has(tabId) &&
    detectionCache.size >= DETECTION_CACHE_LIMIT
  ) {
    const oldest = detectionCache.keys().next();
    if (!oldest.done) detectionCache.delete(oldest.value);
  }
  detectionCache.set(tabId, {
    ok: true,
    found: info.found === true,
    hasUsernameField: info.hasUsernameField === true,
    passwordFields:
      typeof info.passwordFields === "number" ? info.passwordFields : 0,
  });
}

if (chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    detectionCache.delete(tabId);
  });
}

// ---------------------------------------------------------------------------
// Talking to the page
// ---------------------------------------------------------------------------

/**
 * Message the tab's content script, injecting it first if it is not there —
 * which is the normal state of every tab that was already open when the
 * extension was installed or reloaded. Allowed by `activeTab`, which the user
 * granted by opening the popup.
 */
async function sendToTab(tabId, message) {
  try {
    return await chrome.tabs.sendMessage(tabId, message);
  } catch (error) {
    let injected = false;
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId, allFrames: false },
        files: ["content.js"],
      });
      injected = true;
    } catch (injectError) {
      injected = false;
    }
    if (!injected) {
      return { ok: false, error: "This page does not allow filling." };
    }
    try {
      return await chrome.tabs.sendMessage(tabId, message);
    } catch (retryError) {
      return { ok: false, error: "This page does not allow filling." };
    }
  }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/**
 * Everything the popup needs to choose a view.
 *
 * `state` is one of: `unreachable`, `disabled`, `unpaired`, `locked`, `ready`.
 *
 * Note the deliberate asymmetry around a locked vault: the desktop app only
 * restores a saved pairing after unlock, so while it is locked `/health.paired`
 * can be false even though our token is perfectly good. A token is therefore
 * only ever discarded on a 401 from an authenticated call made while the vault
 * is unlocked — never on the strength of `paired` alone.
 */
async function handleStatus() {
  const health = await resolveBridge();
  const token = await getToken();

  if (!health) {
    return {
      ok: true,
      state: "unreachable",
      paired: token !== null,
      locked: true,
      port: null,
      version: "",
    };
  }

  const base = {
    ok: true,
    port: health.port,
    version: health.version,
  };

  if (!token) {
    return Object.assign({}, base, {
      state: "unpaired",
      paired: false,
      locked: health.locked,
      // Pairing persists the token under the vault key, so it needs an
      // unlocked vault.
      canPair: !health.locked,
    });
  }

  if (health.locked) {
    return Object.assign({}, base, {
      state: "locked",
      paired: true,
      locked: true,
    });
  }

  // Unlocked and we hold a token: confirm the desktop app still accepts it.
  try {
    const status = await callBridge("/status", "GET", undefined, token);
    if (status && status.locked === true) {
      return Object.assign({}, base, {
        state: "locked",
        paired: true,
        locked: true,
      });
    }
    return Object.assign({}, base, {
      state: "ready",
      paired: true,
      locked: false,
    });
  } catch (error) {
    const kind = error instanceof BridgeError ? error.kind : "server";
    if (kind === "unauthorized") {
      // The desktop app was unpaired, or the vault was recreated. Our token is
      // dead weight; drop it and ask for a fresh pairing.
      await clearToken();
      return Object.assign({}, base, {
        state: "unpaired",
        paired: false,
        locked: false,
        canPair: true,
        stale: true,
      });
    }
    if (kind === "locked") {
      return Object.assign({}, base, {
        state: "locked",
        paired: true,
        locked: true,
      });
    }
    if (kind === "disabled") {
      return Object.assign({}, base, {
        state: "disabled",
        paired: true,
        locked: true,
      });
    }
    if (kind === "unreachable") {
      return {
        ok: true,
        state: "unreachable",
        paired: true,
        locked: true,
        port: null,
        version: "",
      };
    }
    return { ok: false, error: error.message, kind: kind };
  }
}

async function handlePair(rawCode) {
  const code = String(rawCode === undefined || rawCode === null ? "" : rawCode)
    .replace(/\D+/g, "")
    .slice(0, 6);
  if (code.length !== 6) {
    return {
      ok: false,
      kind: "input",
      error: "Enter the 6-digit code shown in the desktop app.",
    };
  }

  const health = await resolveBridge();
  if (!health) {
    return { ok: false, kind: "unreachable", error: UNREACHABLE_MESSAGE };
  }
  if (health.locked) {
    return {
      ok: false,
      kind: "locked",
      error: "Unlock the desktop app before pairing.",
    };
  }

  try {
    // `extension_id` must equal the id in our `Origin` header; the server
    // checks that the two agree.
    const body = await callBridge(
      "/pair",
      "POST",
      { code: code, extension_id: chrome.runtime.id },
      null,
    );
    if (!body || typeof body.token !== "string" || body.token.length === 0) {
      return {
        ok: false,
        kind: "server",
        error: "The desktop app did not return a pairing token.",
      };
    }
    await setToken(body.token);
    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      kind: error instanceof BridgeError ? error.kind : "server",
      error: error.message,
    };
  }
}

async function handleUnpair() {
  const token = await getToken();
  let revoked = false;
  if (token) {
    try {
      await callBridge("/unpair", "POST", undefined, token);
      revoked = true;
    } catch (error) {
      // A 401 means the desktop app had already forgotten us: same outcome.
      revoked = error instanceof BridgeError && error.kind === "unauthorized";
    }
  }
  // Local state is cleared either way — an extension that cannot revoke its
  // token must not keep it.
  await clearToken();
  return { ok: true, revoked: revoked };
}

async function handleCredentials(url) {
  if (typeof url !== "string" || !/^https?:\/\//i.test(url)) {
    return {
      ok: false,
      kind: "unsupported",
      error: "This kind of page cannot be filled.",
    };
  }

  const token = await getToken();
  if (!token) {
    return {
      ok: false,
      kind: "unpaired",
      error: "Pair this extension with the desktop app first.",
    };
  }

  try {
    const body = await callBridge("/credentials", "POST", { url: url }, token);
    const raw = body && Array.isArray(body.entries) ? body.entries : [];
    // Normalised to exactly the three fields the popup renders. The bridge
    // never sends passwords here, and we would not forward them if it did.
    const entries = [];
    for (const entry of raw) {
      if (!entry || typeof entry.id !== "string" || entry.id.length === 0) {
        continue;
      }
      entries.push({
        id: entry.id,
        title: typeof entry.title === "string" ? entry.title : "",
        username: typeof entry.username === "string" ? entry.username : "",
      });
    }
    return { ok: true, entries: entries };
  } catch (error) {
    return {
      ok: false,
      kind: error instanceof BridgeError ? error.kind : "server",
      error: error.message,
    };
  }
}

/**
 * Fetch one credential and hand it straight to the page.
 *
 * The user's click on an entry is the confirmation the protocol requires, so
 * this is only ever reached from the popup. The secret exists in this worker
 * for the length of one message and is never stored, cached or logged.
 */
/** Hostname of `url`, or null if it is not a fillable http(s) URL. */
function hostOfUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.hostname.toLowerCase();
  } catch (_) {
    return null;
  }
}

async function handleFill(id, tabId, expectedHost) {
  if (typeof id !== "string" || id.length === 0) {
    return { ok: false, kind: "input", error: "No entry was selected." };
  }
  if (typeof tabId !== "number") {
    return { ok: false, kind: "input", error: "There is no active tab to fill." };
  }
  if (typeof expectedHost !== "string" || expectedHost.length === 0) {
    return { ok: false, kind: "input", error: "Missing the target site." };
  }

  // Re-check the tab's CURRENT origin before asking for the secret. The
  // credential list was matched against the page that was open when the popup
  // rendered; the tab may have navigated since (a redirect, a slow load, or a
  // hostile page calling location.assign). Filling by tab id alone would hand
  // the password to whatever document now occupies that tab.
  const active = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = (active || []).find((t) => t.id === tabId);
  if (!tab) {
    return {
      ok: false,
      kind: "navigated",
      error: "That tab is no longer the active tab. Open the popup again.",
    };
  }
  const currentHost = hostOfUrl(tab.url || "");
  if (currentHost === null || currentHost !== expectedHost.toLowerCase()) {
    return {
      ok: false,
      kind: "navigated",
      error:
        "This tab changed site since the list was loaded, so nothing was filled. " +
        "Open the popup again.",
    };
  }

  const token = await getToken();
  if (!token) {
    return {
      ok: false,
      kind: "unpaired",
      error: "Pair this extension with the desktop app first.",
    };
  }

  let secret;
  try {
    secret = await callBridge("/fill", "POST", { id: id }, token);
  } catch (error) {
    return {
      ok: false,
      kind: error instanceof BridgeError ? error.kind : "server",
      error: error.message,
    };
  }

  if (!secret || typeof secret.password !== "string") {
    return {
      ok: false,
      kind: "server",
      error: "The desktop app did not return a credential.",
    };
  }

  try {
    const result = await sendToTab(tabId, {
      type: "pm-fill",
      username: typeof secret.username === "string" ? secret.username : "",
      password: secret.password,
    });
    if (!result || result.ok !== true) {
      return {
        ok: false,
        kind: "no_form",
        error:
          (result && result.error) ||
          "No sign-in form was found on this page.",
      };
    }
    return {
      ok: true,
      filledUsername: result.filledUsername === true,
      filledPassword: result.filledPassword === true,
    };
  } finally {
    // Drop the only reference we hold as early as possible.
    secret = null;
  }
}

async function handleDetect(tabId) {
  if (typeof tabId !== "number") {
    return { ok: false, found: false, error: "There is no active tab." };
  }
  const live = await sendToTab(tabId, { type: "pm-detect" });
  if (live && live.ok === true) {
    rememberDetection(tabId, live);
    // Normalised rather than forwarded: this came from a content script, so the
    // popup should never have to guess at the shape.
    return Object.assign({ ok: true }, detectionCache.get(tabId));
  }
  const cached = detectionCache.get(tabId);
  if (cached) return cached;
  return {
    ok: false,
    found: false,
    error: (live && live.error) || "This page cannot be inspected.",
  };
}

// ---------------------------------------------------------------------------
// Message API
// ---------------------------------------------------------------------------

function dispatch(message, sender) {
  switch (message.type) {
    case "status":
      return handleStatus();
    case "pair":
      return handlePair(message.code);
    case "unpair":
      return handleUnpair();
    case "credentials":
      return handleCredentials(message.url);
    case "fill":
      return handleFill(message.id, message.tabId, message.host);
    case "detect":
      return handleDetect(message.tabId);
    case "detected":
      rememberDetection(
        sender && sender.tab ? sender.tab.id : undefined,
        message,
      );
      return Promise.resolve({ ok: true });
    default:
      return Promise.resolve({
        ok: false,
        kind: "unknown",
        error: "Unknown request.",
      });
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") {
    sendResponse({ ok: false, kind: "input", error: "Malformed message." });
    return false;
  }
  // `onMessage` only ever carries messages from this extension (there is no
  // `externally_connectable`), but check anyway.
  if (sender && sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, kind: "denied", error: "Unauthorised sender." });
    return false;
  }
  // A content script may report detection and nothing else. Everything that
  // touches the vault has to come from an extension page, which has no
  // `sender.tab`.
  if (
    sender &&
    sender.tab &&
    CONTENT_SCRIPT_TYPES.indexOf(message.type) === -1
  ) {
    sendResponse({
      ok: false,
      kind: "denied",
      error: "That request cannot come from a page.",
    });
    return false;
  }

  Promise.resolve()
    .then(() => dispatch(message, sender))
    .then((result) => {
      sendResponse(result || { ok: false, error: "No result." });
    })
    .catch((error) => {
      sendResponse({
        ok: false,
        kind: error && error.kind ? error.kind : "unexpected",
        error:
          error && error.message
            ? error.message
            : "The extension hit an unexpected error.",
      });
    });

  // Responding asynchronously: keep the channel open.
  return true;
});
