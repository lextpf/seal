/* global chrome */
/*  ============================================================================================  *
 *                                                            ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
 *                                                            ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
 *           ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
 *          :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
 *          +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
 *          +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
 *                 +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇
 *          #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
 *           ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
 *                                                            ⠀⠀⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 *
 *                                  << P A S S   M A N A G E R >>
 *
 *  ============================================================================================  *
 *
 *      A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *      providing on-demand credential management, directory encryption,
 *      webcam QR authentication, and global auto-fill.
 *
 *    ----------------------------------------------------------------------
 *
 *      Repository:   https://github.com/lextpf/seal
 *      License:      MIT
 */

/**
 * seal companion - content script.
 *
 * Classifies the clicked field and reports login navigations to the SW.
 * Security invariants (don't relax without re-running the threat model):
 *   M2  only chrome.runtime.sendMessage - no postMessage/'message' (page can't forge)
 *   M3  trusted events only (synthetic events ignored)
 *   M4  top frame only
 *   M9  user-visible targets only (visibility gate defeats hidden overlays)
 */

(() => {
    "use strict";

    // M4 -- top frame only. Manifest already pins all_frames:false; this
    // is defence in depth against an accidental manifest regression.
    if (window !== window.top) {
        return;
    }

    // Per-click breakdown. Logs land in the PAGE's DevTools console
    // (F12 -> Console), not the SW console.
    const DEBUG_LOGS = false;
    function dbg(...args) {
        if (DEBUG_LOGS) {
            console.log("[seal content]", ...args);
        }
    }

    // Short, parseable summary of an Element for debug output.
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

    // Opacity floor. Legit fade-ins sit at 0.3-0.5 mid-animation; 0.1 is
    // well below that and well above the ~0.0-0.01 a phishing overlay uses.
    const MIN_OPACITY = 0.1;

    // Pixel-dimension floor. Zero-size elements are common as a11y anchors
    // or hidden hot-spots; either way they aren't the field the user thinks
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

    function relatedHitElement(hit, el) {
        return hit === el || el.contains(hit);
    }

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

    // Product of every `opacity(...)` function in a computed `filter` value, or
    // 1 when there are none. `filter: opacity(0)` renders an element fully
    // transparent while leaving style.opacity at 1, so without this an
    // opacity-filtered field would slip through the M9 opacity gate below. Only
    // opacity() is folded in (it maps exactly onto the CSS opacity semantics);
    // other filter functions (blur/brightness/drop-shadow) are common on legit
    // inputs and don't reliably hide a field, so they're left untouched.
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

    // M9 visibility gate vs hidden-overlay attacks. Returns { ok, reason }.
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
            // Clicks fall through, so the user can't think they clicked this.
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
            // Fold `filter: opacity(...)` in too - it hides without touching
            // the opacity property (see filterOpacityFactor).
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

    // Resolved <label> + aria-labelledby text for an input. Many modern forms
    // label a generic type=text field only via an external <label>, so without
    // this the username heuristic misses an obviously-labeled field.
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
            // labels/getElementById can throw on detached nodes; ignore.
        }
        return s.slice(0, 200);  // length-cap so a huge label can't bloat work
    }

    // Returns { tag, reason } so debug logs can show WHICH branch fired.
    function classify(el) {
        if (!el) {
            return { tag: TAG_OTHER, reason: "no_element" };
        }

        // <input type=password> is the only high-confidence Password signal;
        // nothing else ever yields TAG_PASSWORD.
        if (el instanceof HTMLInputElement) {
            const type = (el.type || "").toLowerCase();
            if (type === "password") {
                return { tag: TAG_PASSWORD, reason: "input type=password" };
            }
            if (type === "email") {
                return { tag: TAG_EMAIL, reason: "input type=email" };
            }

            // Username heuristics across name/id/autocomplete/aria/placeholder,
            // plus resolved <label> / aria-labelledby text. Weighted low;
            // FusionDecider requires another probe to agree.
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

        // contenteditable (rich-text editors, web shells) is common but
        // rarely a username field.
        if (el.isContentEditable) {
            return { tag: TAG_TEXT, reason: "contenteditable" };
        }

        return { tag: TAG_OTHER, reason: "non-input " + el.tagName };
    }

    // One random token per DOCUMENT lifetime; seal keys its once-per-visit
    // latches on it (username injects once, password fills once, then inert)
    // and binds each click report to the document it came from. Reload/reopen
    // = fresh token (re-enables staging); SPA churn keeps it. 16 bytes -> 32
    // hex, within the bridge's [A-Za-z0-9-]{1,64} cap.
    const VISIT_TOKEN = (() => {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    })();

    // One bridge report per mousedown. Silent on failure (SW asleep / host
    // down); FusionDecider needs probe agreement anyway, so a missed report
    // just falls through to other probes.
    function reportClick(e) {
        // Collapsible decision-trace group per click.
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

            // Cross-check: elementFromPoint should agree with e.target.
            // Allow ancestor<->descendant relationships - a click on an
            // <input>'s internal node varies by engine.
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

            // screenX/Y already match seal's WH_MOUSE_LL coord space (Qt6 marks
            // seal DPI-aware, so its hook gets logical-pixel coords).
            const payload = {
                v: 1,
                x: Math.round(e.screenX),
                y: Math.round(e.screenY),
                tag: c.tag,
                url_host: location.host,
                secure: 1,
                // Per-document token: binds this cached click authorization to
                // the document it came from, so seal can reject a stale entry
                // that survived a navigation/tab-switch at the same location.
                visit: VISIT_TOKEN,
                url_path: location.pathname
            };
            dbg("PAYLOAD -> tag", payload.tag,
                "host_len", location.host.length,
                "path_len", location.pathname.length,
                "(devicePixelRatio=" + window.devicePixelRatio + ")");

            // M2 -- only chrome.runtime.sendMessage. .catch swallows the
            // "Could not establish connection" rejection when the SW is
            // asleep; it wakes on the next sendMessage and we lose at
            // most one click.
            chrome.runtime.sendMessage(payload).catch((err) => {
                dbg("sendMessage rejected:", err && err.message);
            });
        } finally {
            if (grouped) {
                console.groupEnd();
            }
        }
    }

    // Registered in the capture phase on `document`. This beats a page handler
    // in the bubble phase or on a descendant node, but it is NOT unsuppressable:
    // a page capture-phase listener on `window` (an ancestor in the propagation
    // path) runs first and can stopPropagation/stopImmediatePropagation before
    // the event reaches `document`; so can a `document` capture-phase page
    // listener registered before us that stops immediate propagation. That only
    // DENIES this click's bridge probe vote, which fails safe: with no bridge
    // entry the staged auto-fill is a silent no-op (M5 needs an on-disk probe to
    // agree) and the manual path falls through to the on-disk probes. Suppression
    // cannot forge a classification or redirect a fill.
    document.addEventListener("mousedown", reportClick, true);

    // ---- Navigation reports (zero-gesture staged auto-fill) ----
    // On secure nav to a page with a visible login field, tell seal the host so
    // it can pre-arm a uniquely-matching record. Carries NO secret and NO click
    // point (the fill still needs a real click seal validates OS-side). Not
    // gesture-gated, so: https-only, debounced, coalesced.

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

    // Visible login IDENTIFIER field (email-first / multi-step screen with no
    // password yet). Keys on autocomplete="username" (not type=email, which
    // newsletter/contact boxes use) to stay off non-login fields; sites that
    // omit the token just wait for a password field.
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
        // Secure-context / https gate: never drive an auto-fill on a page whose
        // host is network-spoofable. (An attacker's own origin can be https;
        // this buys resistance to downgrade/MITM, not to phishing.)
        if (!window.isSecureContext || location.protocol !== "https:") {
            return;
        }
        const pw = hasVisiblePasswordField();
        const user = hasVisibleIdentifierField();
        // Coalesce on the FULL field composition so an email-first step 1
        // (user=1,pw=0) and its password step 2 (pw=1) each fire exactly once,
        // while SPA route churn and the polling fallback don't spam the bridge.
        const key = location.host + "|" + (pw ? "1" : "0") + "|" + (user ? "1" : "0");
        if (key === lastNavKey) {
            return;
        }
        lastNavKey = key;
        if (!pw && !user) {
            return;  // Not a login page - nothing to stage.
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

    // History-driven navigations. pushState/replaceState from the page's own
    // world can't be hooked from this isolated world, so a coarse href poll
    // (below) is the reliable catch-all; popstate/hashchange give immediacy.
    window.addEventListener("popstate", scheduleNavReport);
    window.addEventListener("hashchange", scheduleNavReport);

    // Coarse polling fallback: detect href changes (SPA route swaps) without a
    // page-world hook. The coalesce key means this only sends on a real change.
    let lastHref = location.href;
    setInterval(() => {
        if (location.href !== lastHref) {
            lastHref = location.href;
            scheduleNavReport();
        }
    }, 1000);

    // Initial report(s): fire at document_end, then a couple of delayed retries
    // to catch login forms that render lazily (SPA) after first paint. Each is
    // coalesced, so at most one report is actually sent per host/form change.
    scheduleNavReport();
    setTimeout(scheduleNavReport, 1500);
    setTimeout(scheduleNavReport, 3500);

    // MutationObserver: catch login fields that appear/toggle WITHOUT a URL
    // change (in-place reveals, modal logins, lazy SPA forms). Cheap: bail
    // unless a mutation plausibly touched a login field, then the 250ms debounce
    // + coalesce key throttle sends. Loop-safe: injecting sets a property (not
    // an attribute), so it never re-triggers this.
    const navObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
            if (m.type === "attributes") {
                // React only to an <input>'s own attribute toggling (a hidden/
                // disabled/type/style reveal of the field itself) - cheap, and
                // ignores the style/class churn of unrelated elements.
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
    // seal pushes a username back ONLY for records that STRICTLY match this
    // exact registered domain (gated seal-side). Written into the visible
    // username/email field. This is the one place a credential value crosses
    // into the page - the user's opted-in, strict-domain tradeoff. The password
    // is never sent this way; it is still typed locally on a real click.

    // Replace the value of a field and notify JS frameworks (React/Vue read
    // via the native setter + input/change events, not the .value assignment).
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

    // Best visible username/email field, or null. Only a CONFIDENTLY classified
    // username/email field is eligible (no generic text fallback), so nothing
    // gets written into an unrelated input like a search box.
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

    // Defence in depth for seal's once-per-visit guarantee: even if the app
    // side re-sends (e.g. seal restarted mid-visit and lost its latches), this
    // document accepts exactly ONE injection into a found field. Deliberately
    // NOT set when no field is found yet - a lazily rendered form may retry.
    let usernameInjected = false;

    function injectUsername(username) {
        // Same secure-context gate as the nav report: never write a credential
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

    // Receive directives from OUR background service worker only (a page cannot
    // reach this listener; it fires for chrome.tabs.sendMessage from the SW).
    chrome.runtime.onMessage.addListener((msg, sender) => {
        if (!sender || sender.id !== chrome.runtime.id) {
            return;  // not from our extension
        }
        if (!msg || msg.v !== 1 || msg.kind !== "fill_username") {
            return;
        }
        // Re-verify this tab is actually on the host seal matched, so a stale
        // route or a since-navigated tab can't receive another site's username.
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
