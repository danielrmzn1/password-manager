"use strict";

/**
 * Content script — finds the sign-in form on the page and fills it when told to.
 *
 * It holds no token and talks to no network: everything arrives from the service
 * worker, and only in response to the user clicking an entry in the popup.
 * Nothing here logs a field value.
 *
 * Runs in the top frame only (see `manifest.json`), so a login form inside a
 * cross-origin iframe is deliberately not filled — the alternative is
 * broadcasting a password to every frame on the page.
 */

(function () {
  // `chrome.scripting` may inject this file into a tab that already has it
  // (that is the recovery path after the extension is reloaded). The isolated
  // world's `window` is shared between those injections, so a flag on it stops
  // us registering a second listener.
  if (window.__passwordManagerBridgeLoaded === true) return;
  window.__passwordManagerBridgeLoaded = true;

  /** How deep to follow open shadow roots when looking for password fields. */
  const MAX_SHADOW_DEPTH = 5;
  /** Debounce for re-reporting detection after the page mutates. */
  const RESCAN_DELAY_MS = 900;

  // -------------------------------------------------------------------------
  // Field inspection
  // -------------------------------------------------------------------------

  /** Normalised input type: unknown or absent types read as "text", as the DOM does. */
  function typeOf(el) {
    const type = typeof el.type === "string" ? el.type : "text";
    return type.toLowerCase();
  }

  function hasAutocompleteToken(el, token) {
    const value = el.getAttribute("autocomplete");
    if (!value) return false;
    return value.toLowerCase().trim().split(/\s+/).indexOf(token) !== -1;
  }

  function isVisible(el) {
    if (!el || !el.isConnected) return false;

    const rect = el.getBoundingClientRect();
    // Catches display:none, collapsed ancestors and the 1px offscreen inputs
    // sites use to bait autofill.
    if (rect.width < 2 || rect.height < 2) return false;

    const style = window.getComputedStyle(el);
    if (!style) return false;
    if (style.display === "none") return false;
    if (style.visibility === "hidden" || style.visibility === "collapse") {
      return false;
    }
    if (Number(style.opacity) === 0) return false;

    return true;
  }

  /** Visible and actually writable. */
  function isFillable(el) {
    if (!el || el.disabled === true || el.readOnly === true) return false;
    if (el.getAttribute("aria-hidden") === "true") return false;
    return isVisible(el);
  }

  /** Fields that are text-like but never a username. */
  function isNoise(el) {
    if (hasAutocompleteToken(el, "one-time-code")) return true;
    const hint = (
      (el.getAttribute("name") || "") +
      " " +
      (el.getAttribute("id") || "") +
      " " +
      (el.getAttribute("role") || "")
    ).toLowerCase();
    return /search|otp|captcha|coupon|promo|voucher/.test(hint);
  }

  function isUsernameCandidate(el) {
    if (!el || el.tagName !== "INPUT") return false;
    const type = typeOf(el);
    if (type !== "text" && type !== "email" && type !== "tel") return false;
    if (isNoise(el)) return false;
    return isFillable(el);
  }

  // -------------------------------------------------------------------------
  // Finding the form
  // -------------------------------------------------------------------------

  /** Collect matches for `selector`, following open shadow roots. */
  function collectDeep(root, selector, out, depth) {
    let matches;
    try {
      matches = root.querySelectorAll(selector);
    } catch (error) {
      return;
    }
    for (const el of matches) out.push(el);

    if (depth >= MAX_SHADOW_DEPTH) return;

    let all;
    try {
      all = root.querySelectorAll("*");
    } catch (error) {
      return;
    }
    for (const el of all) {
      if (el.shadowRoot) collectDeep(el.shadowRoot, selector, out, depth + 1);
    }
  }

  function passwordFields() {
    const found = [];
    collectDeep(document, 'input[type="password"]', found, 0);
    return found.filter(isFillable);
  }

  /**
   * Best username field for `pw` within one scope.
   *
   * Preference: an explicit `autocomplete="username"`, then `autocomplete`
   * mentioning email, then `type="email"`, then the nearest visible text/email/
   * tel input *before* the password field. Fields before the password field win
   * over fields after it at every step.
   *
   * When the password field is not inside this scope at all, only the explicitly
   * marked candidates are eligible — "nearest preceding" is meaningless then and
   * would pick an arbitrary input.
   */
  function pickUsername(scope, pw) {
    let inputs;
    try {
      inputs = Array.prototype.slice.call(scope.querySelectorAll("input"));
    } catch (error) {
      return null;
    }

    const index = inputs.indexOf(pw);
    const beforePw = index === -1 ? [] : inputs.slice(0, index);
    const afterPw = index === -1 ? inputs : inputs.slice(index + 1);

    const preceding = beforePw.filter(isUsernameCandidate).reverse();
    const following = afterPw.filter(isUsernameCandidate);
    const ordered = preceding.concat(following);

    const byAutocomplete = ordered.find((el) =>
      hasAutocompleteToken(el, "username"),
    );
    if (byAutocomplete) return byAutocomplete;

    const byEmailAutocomplete = ordered.find((el) =>
      hasAutocompleteToken(el, "email"),
    );
    if (byEmailAutocomplete) return byEmailAutocomplete;

    const byEmailType = ordered.find((el) => typeOf(el) === "email");
    if (byEmailType) return byEmailType;

    if (index !== -1 && preceding.length > 0) return preceding[0];
    return null;
  }

  /**
   * A password field inside a `<form>` is answered from that form and nowhere
   * else: widening the search would let us type a username into an unrelated
   * field elsewhere on the page (a newsletter box, another form).
   *
   * Only when there is no containing form — the single-page-app case — do we widen
   * to the field's shadow root and then the whole document.
   */
  function findUsernameField(pw) {
    if (pw.form) return pickUsername(pw.form, pw);

    const scopes = [];
    const root = pw.getRootNode ? pw.getRootNode() : null;
    if (root && root !== document && typeof root.querySelectorAll === "function") {
      scopes.push(root);
    }
    scopes.push(document);

    for (const scope of scopes) {
      const found = pickUsername(scope, pw);
      if (found) return found;
    }
    return null;
  }

  /**
   * The pair of fields to act on, or null when the page has no usable password
   * field. With several password fields (change-password and sign-up forms) an
   * explicit `current-password` wins, otherwise the first one.
   */
  function findTarget() {
    const fields = passwordFields();
    if (fields.length === 0) return null;

    const current = fields.find((el) =>
      hasAutocompleteToken(el, "current-password"),
    );
    const password = current || fields[0];

    return {
      password: password,
      username: findUsernameField(password),
      count: fields.length,
    };
  }

  function describe() {
    const target = findTarget();
    if (!target) {
      return { ok: true, found: false, hasUsernameField: false, passwordFields: 0 };
    }
    return {
      ok: true,
      found: true,
      hasUsernameField: target.username !== null,
      passwordFields: target.count,
    };
  }

  // -------------------------------------------------------------------------
  // Filling
  // -------------------------------------------------------------------------

  /**
   * Write a value the way a person would, as far as the page can tell: focus,
   * assign, then real bubbling `input` and `change` events so React, Vue,
   * Angular and friends see the change instead of silently overwriting it.
   */
  function setFieldValue(el, value) {
    try {
      el.focus();
    } catch (error) {
      // Not fatal; the value assignment below is what matters.
    }

    el.value = value;

    try {
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    } catch (error) {
      return false;
    }
    return true;
  }

  /**
   * Fill on instruction. Never called on its own initiative — the popup click is
   * the confirmation. A password-only form (no username field anywhere) is fine:
   * the password still gets filled.
   */
  function fill(username, password) {
    if (typeof password !== "string") {
      return { ok: false, error: "Nothing to fill." };
    }

    const target = findTarget();
    if (!target) {
      return { ok: false, error: "No sign-in form was found on this page." };
    }

    let filledUsername = false;
    if (target.username && typeof username === "string" && username.length > 0) {
      filledUsername = setFieldValue(target.username, username);
    }

    const filledPassword = setFieldValue(target.password, password);
    if (!filledPassword) {
      return { ok: false, error: "The password field could not be filled." };
    }

    // Leave the caret in the password field so Enter submits.
    return {
      ok: true,
      filledUsername: filledUsername,
      filledPassword: true,
      hasUsernameField: target.username !== null,
    };
  }

  // -------------------------------------------------------------------------
  // Messaging
  // -------------------------------------------------------------------------

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message.type !== "string") return false;
    if (sender && sender.id !== chrome.runtime.id) return false;

    if (message.type === "pm-detect") {
      sendResponse(describe());
      return false;
    }

    if (message.type === "pm-fill") {
      const result = fill(message.username, message.password);
      // Drop our reference to the secret straight away.
      message.password = "";
      message.username = "";
      sendResponse(result);
      return false;
    }

    return false;
  });

  let lastReported = null;

  /** Tell the worker whether this page has a sign-in form, so the popup can say so. */
  function report() {
    const info = describe();
    const fingerprint =
      String(info.found) +
      ":" +
      String(info.hasUsernameField) +
      ":" +
      String(info.passwordFields);
    if (fingerprint === lastReported) return;
    lastReported = fingerprint;

    try {
      chrome.runtime.sendMessage(
        {
          type: "detected",
          found: info.found,
          hasUsernameField: info.hasUsernameField,
          passwordFields: info.passwordFields,
        },
        () => {
          // Reading `lastError` stops "unchecked runtime.lastError" noise when
          // the worker is asleep or the extension was just reloaded.
          void chrome.runtime.lastError;
        },
      );
    } catch (error) {
      // The extension context can be invalidated by a reload; nothing to do.
    }
  }

  report();

  /**
   * Cheap gate before a full re-scan: most mutations on a busy page have nothing
   * to do with inputs, and walking the document (plus shadow roots) is the
   * expensive part.
   */
  function touchesInputs(records) {
    for (const record of records) {
      for (const list of [record.addedNodes, record.removedNodes]) {
        for (const node of list) {
          if (node.nodeType !== 1) continue;
          if (node.tagName === "INPUT") return true;
          if (node.shadowRoot) return true;
          if (
            typeof node.querySelector === "function" &&
            node.querySelector("input")
          ) {
            return true;
          }
        }
      }
    }
    return false;
  }

  // Sign-in forms routinely appear after load, so watch for it — debounced, and
  // only actually reporting when the answer changed. Setting `.value` does not
  // mutate the DOM, so filling cannot re-trigger this.
  let rescanTimer = null;
  const observer = new MutationObserver((records) => {
    if (!touchesInputs(records)) return;
    if (rescanTimer !== null) clearTimeout(rescanTimer);
    rescanTimer = setTimeout(() => {
      rescanTimer = null;
      report();
    }, RESCAN_DELAY_MS);
  });

  if (document.documentElement) {
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }
})();
