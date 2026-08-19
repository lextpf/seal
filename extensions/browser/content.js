/* global chrome */

/**
 * seal companion - content script.
 *
 * Classifies the clicked field and reports login navigations to the service worker.
 * Security invariants (do not relax one without re-running the threat model):
 *   M2  chrome.runtime.sendMessage only - no postMessage or 'message' (a page
 *       cannot forge a report)
 *   M3  trusted events only (synthetic events are ignored)
 *   M4  top frame only
 *   M9  user-visible targets only (the visibility gate defeats hidden overlays)
 */

(() => {
    "use strict";

    // M4 - top frame only. The manifest already pins all_frames:false. This is
    // defence in depth against a manifest regression.
    if (window !== window.top) {
        return;
    }

    // Per-click decision traces. Logs land in the page's DevTools console
    // (F12 -> Console), not the service worker console. background.js carries its
    // own separate DEBUG_LOGS.
    const DEBUG_LOGS = false;
    function dbg(...args) {
        if (DEBUG_LOGS) {
            console.log("[seal content]", ...args);
        }
    }

    // Short, readable summary of an Element for debug output.
    function describeElement(el) {
        if (!el) {
            return "<null>";
        }
        if (!(el instanceof Element)) {
            return "<non-Element>";
        }
        const parts = [el.tagName];
        if (el instanceof HTMLInputElement) {
            parts.push("type=" + (el.type || "?"));
            if (el.autocomplete) parts.push("ac=" + el.autocomplete);
        }
        if (el.id) parts.push("#" + el.id);
        if (el.name) parts.push("name=" + el.name);
        const cls = (el.className && typeof el.className === "string")
            ? el.className.split(/\s+/).filter(Boolean).slice(0, 3).join(".")
            : "";
        if (cls) parts.push("." + cls);
        const aria = el.getAttribute && el.getAttribute("aria-label");
        if (aria) parts.push("aria=\"" + aria + "\"");
        if (el.placeholder) parts.push("ph=\"" + el.placeholder + "\"");
        return parts.join(" ");
    }

    const TAG_PASSWORD = "password";  // gitleaks:allow - field-kind label, not a credential
    const TAG_USERNAME = "username";
    const TAG_TEXT = "text";
    const TAG_EMAIL = "email";
    const TAG_OTHER = "other";

    // Opacity floor. Legitimate fade-ins sit at 0.3-0.5 mid-animation; 0.1 is well
    // below that and well above the 0.0-0.01 a hidden overlay uses.
    const MIN_OPACITY = 0.1;

    // Pixel-dimension floor. Zero-size elements are common as accessibility anchors
    // or hidden hot-spots; either way they are not the field the user believes
    // they clicked.
    const MIN_DIMENSION_PX = 2;

    function rectFromDomRect(rect) {
        return {
            left: rect.left,
            top: rect.top,
            right: rect.right,
            bottom: rect.bottom,
            width: rect.right - rect.left,
            height: rect.bottom - rect.top
        };
    }

    function rectIsFinite(rect) {
        return Number.isFinite(rect.left) && Number.isFinite(rect.top) &&
            Number.isFinite(rect.right) && Number.isFinite(rect.bottom) &&
            Number.isFinite(rect.width) && Number.isFinite(rect.height);
    }

    function rectHasMinimumSize(rect) {
        return rect.width >= MIN_DIMENSION_PX && rect.height >= MIN_DIMENSION_PX;
    }

    function intersectRects(a, b) {
        const left = Math.max(a.left, b.left);
        const top = Math.max(a.top, b.top);
        const right = Math.min(a.right, b.right);
        const bottom = Math.min(a.bottom, b.bottom);
        if (right <= left || bottom <= top) {
            return null;
        }
        return {
            left,
            top,
            right,
            bottom,
            width: right - left,
            height: bottom - top
        };
    }

    function viewportRect() {
        const doc = document.documentElement;
        const width = window.innerWidth || (doc && doc.clientWidth) || 0;
        const height = window.innerHeight || (doc && doc.clientHeight) || 0;
        return { left: 0, top: 0, right: width, bottom: height, width, height };
    }

    // Whether this element's overflow settings clip its children.
    function clipsOverflow(style) {
        const clipping = new Set(["hidden", "clip", "auto", "scroll", "overlay"]);
        return clipping.has(style.overflowX) || clipping.has(style.overflowY);
    }

    function pointInRect(point, rect) {
        return point.x >= rect.left && point.x <= rect.right &&
            point.y >= rect.top && point.y <= rect.bottom;
    }

    function centerPoint(rect) {
        return {
            x: Math.floor(rect.left + rect.width / 2),
            y: Math.floor(rect.top + rect.height / 2)
        };
    }

    // A hit counts as `el` itself or one of its own descendants. A click on an
    // <input>'s internal node lands on a different node per engine.
    function relatedHitElement(hit, el) {
        return hit === el || el.contains(hit);
    }

    // Does `el` actually receive the click at `point` (or at the centre of its
    // visible rect)? Rejects an element covered by an overlay. Returns { ok, reason }.
    function hitTestVisibleElement(el, point, visibleRect) {
        const probe = point || centerPoint(visibleRect);
        if (!Number.isFinite(probe.x) || !Number.isFinite(probe.y)) {
            return { ok: false, reason: "hit_point_invalid" };
        }
        if (!pointInRect(probe, visibleRect) || !pointInRect(probe, viewportRect())) {
            return { ok: false, reason: "hit_point_outside_visible_rect" };
        }

        const hits = typeof document.elementsFromPoint === "function"
            ? document.elementsFromPoint(probe.x, probe.y)
            : [document.elementFromPoint(probe.x, probe.y)].filter(Boolean);
        const top = hits.find((hit) => hit instanceof Element) || null;
        if (!top) {
            return { ok: false, reason: "hit_test_empty" };
        }
        if (!relatedHitElement(top, el)) {
            return { ok: false, reason: "hit_test_blocked " + describeElement(top) };
        }
        return { ok: true, reason: "" };
    }

    // The part of `rect` that is really on screen: clipped to the viewport, then to
    // every clipping ancestor. Returns { ok, reason, rect }; not ok when what is left
    // is empty or smaller than MIN_DIMENSION_PX.
    function visibleViewportRect(el, rect) {
        const viewport = viewportRect();
        let visible = intersectRects(rectFromDomRect(rect), viewport);
        if (!visible) {
            return { ok: false, reason: "viewport_intersection_empty" };
        }
        if (!rectHasMinimumSize(visible)) {
            return {
                ok: false,
                reason: "viewport_size " + visible.width.toFixed(1) + "x" +
                    visible.height.toFixed(1)
            };
        }

        let cur = el.parentElement;
        while (cur) {
            const ps = getComputedStyle(cur);
            if (clipsOverflow(ps)) {
                const parentRect = rectFromDomRect(cur.getBoundingClientRect());
                if (!rectIsFinite(parentRect)) {
                    return { ok: false, reason: "transform_invalid ancestor " + cur.tagName };
                }
                visible = intersectRects(visible, parentRect);
                if (!visible) {
                    return { ok: false, reason: "clipped_empty " + cur.tagName };
                }
                if (!rectHasMinimumSize(visible)) {
                    return {
                        ok: false,
                        reason: "clipped_size " + visible.width.toFixed(1) + "x" +
                            visible.height.toFixed(1) + " (" + cur.tagName + ")"
                    };
                }
            }
            cur = cur.parentElement;
        }
        return { ok: true, reason: "", rect: visible };
    }

    // Product of every `opacity(...)` function in a computed `filter` value, or 1
    // when there are none. `filter: opacity(0)` hides an element while style.opacity
    // stays 1, so the M9 opacity gate below would otherwise miss it. Only opacity()
    // folds in: it maps exactly onto CSS opacity semantics, while blur, brightness
    // and drop-shadow are common on legitimate inputs and do not reliably hide a
    // field.
    function filterOpacityFactor(filter) {
        if (!filter || filter === "none") {
            return 1;
        }
        let factor = 1;
        const re = /opacity\(\s*([0-9]*\.?[0-9]+)(%?)\s*\)/gi;
        let m;
        while ((m = re.exec(filter)) !== null) {
            let v = parseFloat(m[1]);
            if (!Number.isFinite(v)) {
                continue;
            }
            if (m[2] === "%") {
                v /= 100;
            }
            factor *= v;
        }
        return factor;
    }

    // M9 visibility gate against hidden-overlay attacks: `el` counts only if the user
    // can see it and reach it. Checks size, display, visibility, pointer-events,
    // effective opacity through ancestors, clipping, and a hit test at `point`, or at
    // the centre of the clipped visible rect when `point` is omitted. The nav-report
    // scans and findUsernameField call it without a point, because they have no click
    // coordinates. Returns { ok, reason }; the reason names the first failing check.
    function isUserVisible(el, point) {
        if (!el || !el.isConnected) {
            return { ok: false, reason: "not_connected" };
        }
        if (!(el instanceof Element)) {
            return { ok: false, reason: "not_an_Element" };
        }

        const rect = el.getBoundingClientRect();
        if (!rectIsFinite(rectFromDomRect(rect))) {
            return { ok: false, reason: "transform_invalid" };
        }
        if (rect.width < MIN_DIMENSION_PX || rect.height < MIN_DIMENSION_PX) {
            return {
                ok: false,
                reason: "zero_size " + rect.width.toFixed(1) + "x" + rect.height.toFixed(1)
            };
        }

        const style = getComputedStyle(el);
        if (style.display === "none") {
            return { ok: false, reason: "display:none" };
        }
        if (style.visibility === "hidden" || style.visibility === "collapse") {
            return { ok: false, reason: "visibility:" + style.visibility };
        }
        if (style.pointerEvents === "none") {
            // Clicks fall through, so the user cannot have believed they clicked it.
            return { ok: false, reason: "pointer-events:none" };
        }

        let effectiveOpacity = 1;
        let cur = el;
        while (cur) {
            const ps = getComputedStyle(cur);
            if (ps.display === "none") {
                return {
                    ok: false,
                    reason: "ancestor display:none (" + cur.tagName + ")"
                };
            }
            if (ps.visibility === "hidden" || ps.visibility === "collapse") {
                return {
                    ok: false,
                    reason: "ancestor visibility:" + ps.visibility + " (" + cur.tagName + ")"
                };
            }
            const opacity = parseFloat(ps.opacity);
            if (Number.isFinite(opacity)) {
                effectiveOpacity *= opacity;
            }
            // Fold `filter: opacity(...)` in as well: it hides an element without
            // touching the opacity property (see filterOpacityFactor).
            effectiveOpacity *= filterOpacityFactor(ps.filter);
            if (effectiveOpacity < MIN_OPACITY) {
                return {
                    ok: false,
                    reason: (cur === el ? "opacity=" : "ancestor opacity=") +
                        effectiveOpacity.toFixed(3) + " (" + cur.tagName + ")"
                };
            }
            cur = cur.parentElement;
        }

        const visible = visibleViewportRect(el, rect);
        if (!visible.ok) {
            return visible;
        }

        const hit = hitTestVisibleElement(el, point, visible.rect);
        if (!hit.ok) {
            return hit;
        }
        return { ok: true, reason: "" };
    }

    // Resolved <label> and aria-labelledby text for an input. Many forms label a
    // generic type=text field only through an external <label>, and without this
    // text the username heuristic misses an obviously labelled field.
    function labelText(el) {
        let s = "";
        try {
            if (el.labels) {
                for (const l of el.labels) {
                    s += " " + (l.textContent || "");
                }
            }
            const labelledBy = el.getAttribute && el.getAttribute("aria-labelledby");
            if (labelledBy) {
                for (const id of labelledBy.split(/\s+/)) {
                    const t = id && document.getElementById(id);
                    if (t) {
                        s += " " + (t.textContent || "");
                    }
                }
            }
        } catch (e) {
            // labels and getElementById can throw on detached nodes; ignore.
        }
        return s.slice(0, 200);  // length cap, so a huge label cannot bloat the work
    }

    // Field kind of an element. Returns { tag, reason }; the reason names the branch
    // that fired, for debug output.
    function classify(el) {
        if (!el) {
            return { tag: TAG_OTHER, reason: "no_element" };
        }

        // <input type=password> is the only high-confidence password signal;
        // no other branch yields TAG_PASSWORD.
        if (el instanceof HTMLInputElement) {
            const type = (el.type || "").toLowerCase();
            if (type === "password") {
                return { tag: TAG_PASSWORD, reason: "input type=password" };
            }
            if (type === "email") {
                return { tag: TAG_EMAIL, reason: "input type=email" };
            }

            // Username heuristics over name, id, autocomplete, aria-label and
            // placeholder, plus resolved <label> and aria-labelledby text. seal
            // weights this low: FusionDecider needs another probe to agree.
            const hay = [
                el.name || "",
                el.id || "",
                el.autocomplete || "",
                el.getAttribute("aria-label") || "",
                el.placeholder || "",
                labelText(el)
            ].join(" ").toLowerCase();
            const m = hay.match(/user|login|account|email|signin/);
            if (m) {
                return {
                    tag: TAG_USERNAME,
                    reason: "input type=" + type + " keyword=\"" + m[0] + "\" hay=\"" + hay + "\""
                };
            }
            if (type === "text" || type === "tel" || type === "search") {
                return {
                    tag: TAG_TEXT,
                    reason: "input type=" + type + " (no username keyword) hay=\"" + hay + "\""
                };
            }
            return { tag: TAG_OTHER, reason: "input type=" + type + " (unclassified)" };
        }

        // contenteditable (rich-text editors, web shells) is common but is
        // rarely a username field.
        if (el.isContentEditable) {
            return { tag: TAG_TEXT, reason: "contenteditable" };
        }

        return { tag: TAG_OTHER, reason: "non-input " + el.tagName };
    }

    // One random token per document lifetime. seal keys its once-per-visit latches
    // on it (the username injects once, the password fills once, then both go inert)
    // and binds each click report to the document it came from. A reload or reopen
    // mints a fresh token and re-enables staging; SPA route churn keeps the same one.
    // 16 bytes -> 32 hex characters, within the bridge's [A-Za-z0-9-]{1,64} cap.
    const VISIT_TOKEN = (() => {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    })();

    // One bridge report per mousedown. Silent on failure (service worker asleep or
    // host down); FusionDecider needs probe agreement anyway, so a missed report
    // leaves the decision to the other probes.
    function reportClick(e) {
        // Collapsible decision trace, one group per click.
        const grouped = DEBUG_LOGS && typeof console.groupCollapsed === "function";
        if (grouped) {
            console.groupCollapsed(
                "[seal content] mousedown at screen(%d,%d) client(%d,%d) button=%d trusted=%s",
                Math.round(e.screenX), Math.round(e.screenY),
                Math.round(e.clientX), Math.round(e.clientY),
                e.button, e.isTrusted
            );
        }
        try {
            dbg("target:", describeElement(e.target));

            // M3 - trusted events only.
            if (!e.isTrusted) {
                dbg("REJECT: event not trusted (synthetic)");
                return;
            }
            if (e.button !== 0) {
                dbg("REJECT: not a left-click (button=" + e.button + ")");
                return;
            }

            // M9 - user-visible targets only.
            const vis = isUserVisible(e.target, { x: e.clientX, y: e.clientY });
            dbg("visibility:", vis.ok ? "ok" : "REJECT -> " + vis.reason);
            if (!vis.ok) {
                return;
            }

            // Cross-check: elementFromPoint has to agree with e.target. An ancestor
            // or descendant relation is allowed, because a click on an <input>'s
            // internal node lands on a different node per engine.
            const topAtPoint = document.elementFromPoint(e.clientX, e.clientY);
            const topRelation = !topAtPoint ? "<null>"
                : topAtPoint === e.target ? "same"
                    : topAtPoint.contains(e.target) ? "top contains target"
                        : e.target.contains(topAtPoint) ? "target contains top"
                            : "unrelated";
            dbg("elementFromPoint:", describeElement(topAtPoint), "-> relation:", topRelation);
            if (topAtPoint && topAtPoint !== e.target &&
                !topAtPoint.contains(e.target) && !e.target.contains(topAtPoint)) {
                dbg("REJECT: hit-test element diverges from event target");
                return;
            }

            const c = classify(e.target);
            dbg("classify ->", c.tag, "(" + c.reason + ")");
            if (c.tag === TAG_OTHER) {
                dbg("REJECT: tag=other (no bridge insert for neutral signal)");
                return;
            }
            if (!window.isSecureContext || location.protocol !== "https:") {
                dbg("REJECT: reason=insecure_click");
                return;
            }

            // The point is what seal matches a later Ctrl+Click against. Send
            // screenX/Y unscaled: seal compares them against the raw screen pixels
            // that its WH_MOUSE_LL hook reports, and neither side converts DPI, so
            // never scale by devicePixelRatio here. The 48 px Chebyshev tolerance
            // (kLookupToleranceRawPx in BrowserBridge::lookup) absorbs the offset
            // between the focus-click and the Ctrl+Click on one input.
            const payload = {
                v: 1,
                x: Math.round(e.screenX),
                y: Math.round(e.screenY),
                tag: c.tag,
                url_host: location.host,
                secure: 1,
                // Per-document token: it binds this cached click authorization to
                // the document it came from, so seal can reject a stale entry that
                // survived a navigation or tab switch at the same location.
                visit: VISIT_TOKEN,
                url_path: location.pathname
            };
            dbg("PAYLOAD -> tag", payload.tag,
                "host_len", location.host.length,
                "path_len", location.pathname.length,
                "(devicePixelRatio=" + window.devicePixelRatio + ")");

            // M2 - chrome.runtime.sendMessage only. The .catch swallows the
            // "Could not establish connection" rejection raised while the service
            // worker sleeps; it wakes on the next sendMessage, so at most one
            // click is lost.
            chrome.runtime.sendMessage(payload).catch((err) => {
                dbg("sendMessage rejected:", err && err.message);
            });
        } finally {
            if (grouped) {
                console.groupEnd();
            }
        }
    }

    // Registered in the capture phase on `document`, which beats a page handler in
    // the bubble phase or on a descendant node. It is still suppressible: a page
    // capture-phase listener on `window` (an ancestor in the propagation path) runs
    // first and can call stopPropagation or stopImmediatePropagation before the event
    // reaches `document`, and so can a `document` capture-phase page listener
    // registered before this one that stops immediate propagation.
    //
    // Suppression denies this click its bridge entry, and both fill paths then fail
    // closed. The staged auto-fill stops at its first gate and is a silent no-op
    // (reason=no_bridge_entry). The manual Ctrl+Click path refuses the fill for any
    // known browser image and asks the user to check the extension
    // (reason=no_bridge_entry_manual); it does not fall back to the on-disk probes.
    // Suppression can stop a fill, but it cannot forge a classification or redirect
    // one.
    document.addEventListener("mousedown", reportClick, true);

    // ---- Navigation reports (zero-gesture staged auto-fill) ----
    // On a secure navigation to a page with a visible login field, tell seal the host
    // so it can pre-arm a uniquely matching record. A nav report carries no secret and
    // no click point: the fill still needs a real click that seal validates OS-side.
    // No user gesture triggers it, so it is https-only, debounced and coalesced.

    // Whether any visible <input type=password> exists (reuses the M9 gate).
    function hasVisiblePasswordField() {
        const fields = document.querySelectorAll('input[type="password"]');
        for (const el of fields) {
            if (isUserVisible(el).ok) {
                return true;
            }
        }
        return false;
    }

    // Whether a visible login identifier field exists (an email-first or multi-step
    // screen with no password field yet). Keys on autocomplete="username" rather than
    // type=email, which newsletter and contact boxes also use, so it stays off
    // non-login fields. A site that omits the token waits for a password field.
    function hasVisibleIdentifierField() {
        const fields = document.querySelectorAll('input[autocomplete~="username"]');
        for (const el of fields) {
            if (el instanceof HTMLInputElement && isUserVisible(el).ok) {
                return true;
            }
        }
        return false;
    }

    let lastNavKey = "";
    let navDebounceTimer = null;

    function reportNavigate() {
        // Secure-context and https gate: never drive an auto-fill on a page whose
        // host is network-spoofable. An attacker's own origin can be https, so this
        // resists downgrade and man-in-the-middle attacks, not phishing.
        if (!window.isSecureContext || location.protocol !== "https:") {
            return;
        }
        const pw = hasVisiblePasswordField();
        const user = hasVisibleIdentifierField();
        // Coalesce on the full field composition, so an email-first step 1
        // (user=1, pw=0) and its password step 2 (pw=1) each fire exactly once,
        // while SPA route churn and the polling fallback do not spam the bridge.
        const key = location.host + "|" + (pw ? "1" : "0") + "|" + (user ? "1" : "0");
        if (key === lastNavKey) {
            return;
        }
        lastNavKey = key;
        if (!pw && !user) {
            return;  // Not a login page, so there is nothing to stage.
        }
        const payload = {
            v: 1,
            kind: "nav",
            url_host: location.host,
            secure: 1,
            form: pw ? 1 : 0,
            user: user ? 1 : 0,
            visit: VISIT_TOKEN
        };
        dbg("NAV PAYLOAD -> host_len", location.host.length,
            "form", payload.form,
            "user", payload.user);
        chrome.runtime.sendMessage(payload).catch((err) => {
            dbg("nav sendMessage rejected:", err && err.message);
        });
    }

    function scheduleNavReport() {
        if (navDebounceTimer !== null) {
            clearTimeout(navDebounceTimer);
        }
        navDebounceTimer = setTimeout(() => {
            navDebounceTimer = null;
            reportNavigate();
        }, 250);
    }

    // History-driven navigations. pushState and replaceState run in the page's own
    // world and cannot be hooked from this isolated world, so the coarse href poll
    // below is the catch-all; popstate and hashchange only make the common case fast.
    window.addEventListener("popstate", scheduleNavReport);
    window.addEventListener("hashchange", scheduleNavReport);

    // Coarse polling fallback: detect href changes (SPA route swaps) without a
    // page-world hook. The coalesce key keeps this to one send per real change.
    let lastHref = location.href;
    setInterval(() => {
        if (location.href !== lastHref) {
            lastHref = location.href;
            scheduleNavReport();
        }
    }, 1000);

    // Initial reports: one at document_end, then two delayed retries to catch login
    // forms that an SPA renders lazily after first paint. All three are coalesced, so
    // at most one report is sent per change of host or field composition.
    scheduleNavReport();
    setTimeout(scheduleNavReport, 1500);
    setTimeout(scheduleNavReport, 3500);

    // Catch login fields that appear or toggle without a URL change: in-place
    // reveals, modal logins, lazy SPA forms. Cheap, because it bails unless a
    // mutation plausibly touched a login field; the 250 ms debounce and the coalesce
    // key then throttle the sends. Loop-safe: username injection sets a property,
    // not an attribute, so it never re-triggers this observer.
    const navObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
            if (m.type === "attributes") {
                // React only to an <input>'s own attribute toggling: a hidden,
                // disabled, type or style reveal of the field itself. This is cheap
                // and ignores the style and class churn of unrelated elements.
                const t = m.target;
                if (t && t.nodeType === 1 && t.tagName === "INPUT") {
                    scheduleNavReport();
                    return;
                }
                continue;
            }
            for (const n of m.addedNodes) {
                if (n.nodeType !== 1) continue;
                const sel = 'input[type="password"],input[autocomplete~="username"]';
                if ((n.matches && n.matches(sel)) ||
                    (n.querySelector && n.querySelector(sel))) {
                    scheduleNavReport();
                    return;
                }
            }
        }
    });
    try {
        navObserver.observe(document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ["type", "style", "hidden", "disabled", "aria-hidden", "autocomplete"]
        });
    } catch (err) {
        dbg("MutationObserver setup failed:", err && err.message);
    }

    // ---- Username injection (seal -> extension reverse channel) ----
    // seal pushes a username back only for a record that strictly matches this exact
    // registered domain; that gate lives in seal. The value goes into the visible
    // username or email field. This is the one place a credential value crosses into
    // the page, and it is the opt-in, strict-domain tradeoff. The password never
    // travels this channel; it is typed locally on a real click.

    // Replace the value of a field and notify JS frameworks. React and Vue observe
    // the native setter plus the input and change events, not a .value assignment.
    function replaceFieldValue(el, value) {
        try {
            const proto = el instanceof HTMLInputElement ? HTMLInputElement.prototype : null;
            const setter = proto && Object.getOwnPropertyDescriptor(proto, "value")
                ? Object.getOwnPropertyDescriptor(proto, "value").set
                : null;
            el.focus();
            if (setter) {
                setter.call(el, value);
            } else {
                el.value = value;
            }
            el.dispatchEvent(new Event("input", { bubbles: true }));
            el.dispatchEvent(new Event("change", { bubbles: true }));
        } catch (err) {
            dbg("replaceFieldValue failed:", err && err.message);
        }
    }

    // First visible username or email field in document order, or null. Only a field
    // that classify() tags as TAG_EMAIL or TAG_USERNAME is eligible, with no generic
    // text fallback, so nothing is written into an unrelated input such as a search
    // box.
    function findUsernameField() {
        const inputs = document.querySelectorAll(
            'input[type="email"], input[type="text"], input[type="tel"], input:not([type])');
        for (const el of inputs) {
            if (!(el instanceof HTMLInputElement)) continue;
            if (!isUserVisible(el).ok) continue;
            const c = classify(el);
            if (c.tag === TAG_EMAIL || c.tag === TAG_USERNAME) {
                return el;
            }
        }
        return null;
    }

    // Defence in depth for seal's once-per-visit guarantee: even if seal re-sends,
    // for example after a restart mid-visit that lost its latches, this document
    // accepts one injection into a found field. Deliberately not set when no field
    // is found yet, because a lazily rendered form still has to be filled.
    let usernameInjected = false;

    function injectUsername(username) {
        // Same secure-context gate as the nav report: never write a credential value
        // into a non-secure page.
        if (!window.isSecureContext || location.protocol !== "https:") {
            return;
        }
        if (usernameInjected) {
            dbg("injectUsername: already injected once this page load");
            return;
        }
        const field = findUsernameField();
        if (!field) {
            dbg("injectUsername: no username field found");
            return;
        }
        usernameInjected = true;
        replaceFieldValue(field, username);
        dbg("injectUsername: filled username field", describeElement(field));
    }

    // Directives from this extension's own service worker only. A page cannot reach
    // this listener; it fires for chrome.tabs.sendMessage sent by the worker.
    chrome.runtime.onMessage.addListener((msg, sender) => {
        if (!sender || sender.id !== chrome.runtime.id) {
            return;  // not from this extension
        }
        if (!msg || msg.v !== 1 || msg.kind !== "fill_username") {
            return;
        }
        // Re-verify that this tab is on the host seal matched, so a stale route or a
        // tab that has since navigated cannot receive another site's username.
        if (msg.url_host !== location.host) {
            dbg("injectUsername: host mismatch (tab is", location.host,
                "msg is", msg.url_host, ")");
            return;
        }
        if (msg.visit !== VISIT_TOKEN) {
            dbg("injectUsername: visit mismatch");
            return;
        }
        if (typeof msg.username === "string" && msg.username.length > 0) {
            injectUsername(msg.username);
        }
    });
})();
