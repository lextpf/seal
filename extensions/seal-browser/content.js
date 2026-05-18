// seal companion content script.
//
// Security invariants (do not relax without re-running the threat model):
//   M2: ONLY chrome.runtime.sendMessage. No window.postMessage and no
//       'message' listener -- a page cannot forge a report.
//   M3: every handler early-returns unless e.isTrusted is true. Synthetic
//       page-dispatched events are ignored.
//   M4: top frame only. Cross-origin iframes (ads, widgets, sandboxed
//       embeds) cannot poison the bridge with mismatched (x,y).
//   M9: only user-visible click targets are classified and reported. A
//       zero-size / fully transparent <input type=password> overlaid on a
//       real button would fool both this classifier and seal-side UIA
//       (same render tree). The visibility gate below filters those out
//       before any report leaves.

(() => {
    "use strict";

    // M4 -- top frame only. Manifest already pins all_frames:false; this
    // is defence in depth against an accidental manifest regression.
    if (window !== window.top) {
        return;
    }

    // Per-click breakdown. Logs land in the PAGE's DevTools console
    // (F12 -> Console), not the SW console.
    const DEBUG_LOGS = true;
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

    const TAG_PASSWORD = "password";
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

    // Visibility gate against hidden-overlay attacks. Checks the element's
    // own computed style, then walks ancestors for display:none /
    // visibility:hidden (the two properties that cascade hiding).
    // Ancestor opacity compounding is intentionally NOT walked -- it needs
    // stacking-context math and false-negatives on legitimate pages.
    // Returns { ok, reason } so callers can log the rejection.
    function isUserVisible(el) {
        if (!el || !el.isConnected) {
            return { ok: false, reason: "not_connected" };
        }
        if (!(el instanceof Element)) {
            return { ok: false, reason: "not_an_Element" };
        }

        const rect = el.getBoundingClientRect();
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
        if (parseFloat(style.opacity) < MIN_OPACITY) {
            return { ok: false, reason: "opacity=" + style.opacity };
        }
        if (style.pointerEvents === "none") {
            // Clicks fall through, so the user can't think they clicked this.
            return { ok: false, reason: "pointer-events:none" };
        }

        let cur = el.parentElement;
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
            cur = cur.parentElement;
        }
        return { ok: true, reason: "" };
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

            // Username heuristics across name/id/autocomplete/aria/placeholder.
            // Weighted low; FusionDecider requires another probe to agree.
            const hay = [
                el.name || "",
                el.id || "",
                el.autocomplete || "",
                el.getAttribute("aria-label") || "",
                el.placeholder || ""
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

    // Send one bridge report per mousedown. Silent on failure (SW asleep
    // or host down); FusionDecider's Tier-1 gate already requires probe
    // agreement, so a missing report just falls through to other probes.
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
            const vis = isUserVisible(e.target);
            dbg("visibility:", vis.ok ? "ok" : "REJECT -> " + vis.reason);
            if (!vis.ok) {
                return;
            }

            // Cross-check: elementFromPoint should agree with e.target.
            // Allow ancestor<->descendant relationships -- a click on an
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

            // screenX/Y are already in the DPI-scaled space seal's
            // WH_MOUSE_LL hook reports (Qt6 marks seal DPI-aware, so its
            // Win32 hook receives logical-pixel coords). See git history
            // for the full investigation.
            const payload = {
                v: 1,
                x: Math.round(e.screenX),
                y: Math.round(e.screenY),
                tag: c.tag,
                url_host: location.hostname,
                url_path: location.pathname
            };
            dbg("PAYLOAD ->", JSON.stringify(payload),
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

    // Capture phase fires before any page handler, so a page calling
    // e.stopPropagation() in its own mousedown can't suppress our report.
    document.addEventListener("mousedown", reportClick, true);
})();
