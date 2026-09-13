/* global chrome */

/**
 * @brief Classify clicked fields and report login pages from the top frame.
 *
 * M2: use chrome.runtime.sendMessage; accept no page messages.
 * M3: report only trusted events.
 * M4: run only in the top frame.
 * M9: require visible, reachable fields.
 *
 * HTTPS and a secure context are required for reports and username injection.
 * A random token identifies this document. Reload creates a new token; SPA
 * navigation retains it. Username directives must match the host and token.
 * The page can read an injected username; no password enters this channel.
 */

(() => {
    "use strict";

    // M4: enforce the top-frame boundary independently of the manifest.
    if (window !== window.top) {
        return;
    }

    // Debug traces appear in page devtools; background.js has a separate switch.
    const DEBUG_LOGS = false;
    function dbg(...args) {
        if (DEBUG_LOGS) {
            console.log("[seal content]", ...args);
        }
    }


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

    // Allow partially faded inputs while rejecting near-transparent overlays.
    const MIN_OPACITY = 0.1;

    // Exclude zero-size anchors and hidden targets.
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

    // Input internals may hit a descendant node, depending on the browser engine.
    function relatedHitElement(hit, el) {
        return hit === el || el.contains(hit);
    }

    // Reject overlays at the click point, or at the visible center if no point is supplied.
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

    // Clip against the viewport and clipping ancestors. Reject a remaining
    // rectangle smaller than MIN_DIMENSION_PX.
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

    // Multiply CSS filter opacity factors; style.opacity does not include them.
    // Other filters do not reliably indicate a hidden field.
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

    // M9: require visible geometry, ancestor opacity, pointer access, and a hit test.
    // Without a click point, test the clipped center. Return the first failure reason.
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

    // Include external labels so generic text inputs can identify login fields.
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
            // Detached nodes may throw; ignore them.
        }
        return s.slice(0, 200);  // length cap, so a huge label cannot bloat the work
    }

    // The reason identifies the classification branch for debug output.
    function classify(el) {
        if (!el) {
            return { tag: TAG_OTHER, reason: "no_element" };
        }

        // Only input type=password yields TAG_PASSWORD.
        if (el instanceof HTMLInputElement) {
            const type = (el.type || "").toLowerCase();
            if (type === "password") {
                return { tag: TAG_PASSWORD, reason: "input type=password" };
            }
            if (type === "email") {
                return { tag: TAG_EMAIL, reason: "input type=email" };
            }

            // seal requires another probe to corroborate this heuristic.
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

        // Rich-text editors are not reliable username signals.
        if (el.isContentEditable) {
            return { tag: TAG_TEXT, reason: "contenteditable" };
        }

        return { tag: TAG_OTHER, reason: "non-input " + el.tagName };
    }

    // One token per document binds clicks and once-per-visit fills. Reloads create
    // a new token; SPA routes retain it. 16 bytes encode as 32 hex characters.
    const VISIT_TOKEN = (() => {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    })();

    // Send only trusted left clicks on visible fields. Failed delivery adds no new evidence.
    function reportClick(e) {

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


            if (!e.isTrusted) {
                dbg("REJECT: event not trusted (synthetic)");
                return;
            }
            if (e.button !== 0) {
                dbg("REJECT: not a left-click (button=" + e.button + ")");
                return;
            }


            const vis = isUserVisible(e.target, { x: e.clientX, y: e.clientY });
            dbg("visibility:", vis.ok ? "ok" : "REJECT -> " + vis.reason);
            if (!vis.ok) {
                return;
            }

            // Allow ancestor or descendant hits for engine-specific input internals.
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

            // Send screenX/Y unchanged: seal compares raw WH_MOUSE_LL pixels.
            // Never apply devicePixelRatio. The bridge allows 48 px per axis
            // between the focus-click and the completing click.
            const payload = {
                v: 1,
                x: Math.round(e.screenX),
                y: Math.round(e.screenY),
                tag: c.tag,
                url_host: location.host,
                secure: 1,

                visit: VISIT_TOKEN,
                url_path: location.pathname
            };
            dbg("PAYLOAD -> tag", payload.tag,
                "host_len", location.host.length,
                "path_len", location.pathname.length,
                "(devicePixelRatio=" + window.devicePixelRatio + ")");

            // M2: extension messaging only. Ignore rejection while the worker is unavailable.
            chrome.runtime.sendMessage(payload).catch((err) => {
                dbg("sendMessage rejected:", err && err.message);
            });
        } finally {
            if (grouped) {
                console.groupEnd();
            }
        }
    }

    // Capture on document runs before descendant and bubble handlers. A page
    // window-capture handler or earlier document-capture handler can still suppress it.
    // Without a bridge entry, staged auto-fill fails closed (no_bridge_entry) and a
    // Ctrl+Click fill loses only the extension's vote. Suppression cannot forge a report.
    document.addEventListener("mousedown", reportClick, true);

    // Report secure login pages so seal can select one matching record.
    // Password release still requires a trusted click and OS-side checks.


    function hasVisiblePasswordField() {
        const fields = document.querySelectorAll('input[type="password"]');
        for (const el of fields) {
            if (isUserVisible(el).ok) {
                return true;
            }
        }
        return false;
    }

    // Require autocomplete=username on identifier-only pages; type=email also
    // occurs in newsletter and contact forms. Otherwise wait for a password field.
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
        // Require HTTPS and a secure context against network spoofing.
        // This does not establish that the site is trustworthy.
        if (!window.isSecureContext || location.protocol !== "https:") {
            return;
        }
        const pw = hasVisiblePasswordField();
        const user = hasVisibleIdentifierField();
        // Include field composition so username and password steps each report,
        // while repeated observations of the same page do not.
        const key = location.host + "|" + (pw ? "1" : "0") + "|" + (user ? "1" : "0");
        if (key === lastNavKey) {
            return;
        }
        lastNavKey = key;
        if (!pw && !user) {
            return;  // not a login page, so there is nothing to stage.
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

    // The isolated world cannot hook page-world pushState/replaceState.
    // Poll href for those changes; events cover popstate and hashchange.
    window.addEventListener("popstate", scheduleNavReport);
    window.addEventListener("hashchange", scheduleNavReport);


    let lastHref = location.href;
    setInterval(() => {
        if (location.href !== lastHref) {
            lastHref = location.href;
            scheduleNavReport();
        }
    }, 1000);

    // Retry for lazily rendered forms; the composition key suppresses duplicates.
    scheduleNavReport();
    setTimeout(scheduleNavReport, 1500);
    setTimeout(scheduleNavReport, 3500);

    // Observe login fields that appear without navigation. Debounce for 250 ms.
    // The value property write does not directly trigger this attribute observer;
    // page input handlers can still change the DOM and schedule another report.
    const navObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
            if (m.type === "attributes") {
                // Ignore attribute churn outside input elements.
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

    // seal binds username release to a strict domain match. Passwords stay
    // outside this channel and require a click before local typing.

    // Use the native setter and input/change events to notify form frameworks.
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

    // Choose the first visible username or email field. Do not fall back to
    // generic text inputs such as search boxes.
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

    // Accept one injection per document, even after seal restarts.
    // Leave the latch clear if the field has not appeared yet.
    let usernameInjected = false;

    function injectUsername(username) {

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

    // Require this extension's sender ID; ordinary page messages cannot reach this listener.
    chrome.runtime.onMessage.addListener((msg, sender) => {
        if (!sender || sender.id !== chrome.runtime.id) {
            return;  // not from this extension
        }
        if (!msg || msg.v !== 1 || msg.kind !== "fill_username") {
            return;
        }
        // Recheck host and visit before a stale route can deliver another document a username.
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
