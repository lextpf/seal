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
 * seal companion - background service worker.
 *
 * Connects to the native-messaging host `com.seal.fill`, echoes a per-connection
 * nonce (a framing check, not authentication), and forwards content.js reports to
 * the host as length-prefixed JSON. A signed build has the host and the bridge check
 * each other's Authenticode signer (SEAL_REQUIRE_SIGNED_PEER); an unsigned build has
 * an empty identity and accepts every peer.
 *
 * The host can send back exactly one directive, `fill_username`. A password never
 * crosses this channel. Extension messages are dropped unless sender.id equals this
 * extension's runtime id, this worker registers no *External listeners, and the manifest
 * declares no `externally_connectable`, so another extension cannot reach this worker.
 *
 * Nothing compiles this file. tests/test_ui_secret_boundaries.cpp reads it as text and
 * pins several literals (payload keys, route helpers, DEBUG_LOGS); check that test
 * before you rename or reformat them. M-numbers below refer to the mitigation index in
 * src/BrowserBridge.hpp.
 */

const HOST_NAME = "com.seal.fill";

// Per-event traces for this worker. Logs go to the service worker DevTools console
// (chrome://extensions -> seal companion -> Inspect views: service worker).
// content.js carries its own separate DEBUG_LOGS for page-side logs.
// Set it to true only while you debug: the source-scan test
// BrowserExtensionBoundary.ClicksAreSecureAndUsernameRoutesByVisit greps this exact
// line, so it must read false again before commit.
const DEBUG_LOGS = false;

let port = null;
let reconnectDelayMs = 1000;
// 5 s cap: seal disconnects often (restart, the M8 panic toggle that drops its bridge
// state and closes the pipe, transient OS conditions), and a long backoff would silently
// drop the bridge probe for the next Ctrl+Click.
const RECONNECT_DELAY_MAX_MS = 5_000;
let sessionNonce = null;
// Pending scheduleReconnect timer; the click-time fast path checks this
// to avoid double-scheduling.
let reconnectTimer = null;
// (host, visit) -> the tab and frame that reported that exact document. The visit
// token is random per content.js document; content.js re-verifies it before it
// injects a username.
const navRoutes = new Map();
const MAX_NAV_ROUTES = 256;

function isVisitToken(value) {
    return /^[A-Za-z0-9-]{1,64}$/.test(value);
}

function routeKey(host, visit) {
    return host + "\n" + visit;
}

function rememberNavRoute(host, visit, tabId, frameId) {
    if (!isVisitToken(visit)) {
        return;
    }
    if (navRoutes.size >= MAX_NAV_ROUTES) {
        const oldest = navRoutes.keys().next().value;
        if (oldest !== undefined) {
            navRoutes.delete(oldest);
        }
    }
    navRoutes.set(routeKey(host, visit), { tabId, frameId });
}

// Reclaim entries on tab close so the map can't grow unbounded.
chrome.tabs.onRemoved.addListener((closedTabId) => {
    for (const [key, route] of navRoutes) {
        if (route.tabId === closedTabId) {
            navRoutes.delete(key);
        }
    }
});

function logInfo(...args) {
    // Always on: errors and disconnects. chrome.runtime.id is undefined once this
    // extension context is unloaded, and no console survives it, so skip the log.
    if (chrome.runtime.id) {
        console.log("[seal companion]", ...args);
    }
}

function dbg(...args) {
    if (DEBUG_LOGS && chrome.runtime.id) {
        console.log("[seal companion]", ...args);
    }
}

function connect() {
    dbg("connect(): calling chrome.runtime.connectNative(", HOST_NAME, ")");
    sessionNonce = null;
    try {
        port = chrome.runtime.connectNative(HOST_NAME);
    } catch (err) {
        logInfo("connectNative threw", err);
        scheduleReconnect();
        return;
    }

    port.onMessage.addListener(onHostMessage);
    port.onDisconnect.addListener(() => {
        const err = chrome.runtime.lastError;
        logInfo("host disconnected:", err && err.message);
        port = null;
        sessionNonce = null;
        scheduleReconnect();
    });
}

function scheduleReconnect() {
    if (reconnectTimer !== null) {
        return;  // retry already pending
    }
    const delay = reconnectDelayMs;
    reconnectDelayMs = Math.min(reconnectDelayMs * 2, RECONNECT_DELAY_MAX_MS);
    reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connect();
    }, delay);
}

// Reconnect immediately, bypassing the backoff. Called from the click-report
// fast path: the user is interacting now, so the bridge should be live now.
function kickReconnect() {
    if (port !== null) {
        return;
    }
    if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }
    reconnectDelayMs = 1000;
    connect();
}

function onHostMessage(msg) {
    // Log the kind only; never log the raw object. A fill_username directive holds
    // the plaintext username.
    dbg("host -> extension kind:", msg && (msg.hello ? "handshake" : msg.kind));
    // The first message is the bridge handshake, bearing a per-connection nonce.
    // seal compares the echo byte for byte against the exact string it sent, so the
    // literal below must keep the key order v, hello, nonce and must add no key. Any
    // other shape ends the connection with reason=handshake_mismatch in seal's log
    // (src/BrowserBridge.cpp). The echo proves framing in both directions; it is not
    // authentication.
    if (msg && msg.v === 1 && msg.hello === "seal-bridge" && typeof msg.nonce === "string") {
        sessionNonce = msg.nonce;
        dbg("handshake nonce received; echoing back");
        if (port) {
            try {
                port.postMessage({ v: 1, hello: "seal-bridge", nonce: sessionNonce });
                dbg("handshake echo posted");
            } catch (err) {
                logInfo("handshake echo failed", err);
            }
        }
        reconnectDelayMs = 1000;  // success -> reset backoff
        return;
    }
    // The one reverse directive: seal pushes a username to inject, gated seal-side
    // to a strictly matching domain. Route it to the document that reported this
    // host and visit; content.js re-verifies both before writing into the DOM.
    if (msg && msg.v === 1 && msg.kind === "fill_username" && typeof msg.username === "string") {
        const host = String(msg.url_host || "");
        const visit = String(msg.visit || "");
        if (!isVisitToken(visit)) {
            dbg("fill_username: missing/invalid visit");
            return;
        }
        const route = navRoutes.get(routeKey(host, visit));
        if (route !== undefined) {
            chrome.tabs
                .sendMessage(
                    route.tabId,
                    { v: 1, kind: "fill_username", url_host: host, visit: visit, username: msg.username },
                    { frameId: route.frameId })
                .catch((err) => dbg("fill_username relay failed:", err && err.message));
        } else {
            dbg("fill_username: no known route for host/visit");
        }
        return;
    }

    // Anything else from the host is ignored.
    dbg("ignoring unrecognized host message");
}

// SHA-256 hex digest of a path. The bridge requires exactly 64 hex characters.
async function hashPath(path) {
    const enc = new TextEncoder().encode(path || "");
    const digest = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

// Click and nav reports from content.js, forwarded to the host.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    dbg("content -> bg kind:", msg && msg.kind,
        "from tab", sender && sender.tab ? sender.tab.id : "<none>");
    // Origin checks: this extension only, and a tab-attached sender (content.js) only.
    if (!sender || sender.id !== chrome.runtime.id) {
        dbg("DROP: sender id mismatch (", sender && sender.id, ")");
        return;
    }
    if (!sender.tab) {
        dbg("DROP: sender has no tab");
        return;
    }
    if (!msg || msg.v !== 1) {
        dbg("DROP: bad payload shape (v != 1)");
        return;
    }
    if (!port || !sessionNonce) {
        // No host channel yet. Do not queue the report, because bridge entries are
        // time-windowed; kick the reconnect so the next click lands on a live channel.
        dbg("DROP: no host port yet (port=" + !!port +
            ", nonce=" + !!sessionNonce + "); kicking reconnect");
        kickReconnect();
        return;
    }

    // A nav report describes the page, not a click: it forwards the host and the
    // secure/form/user flags verbatim and carries no path hash and no secret.
    // The bridge validates the schema.
    if (msg.kind === "nav") {
        const navPayload = {
            v: 1,
            kind: "nav",
            url_host: String(msg.url_host || "").slice(0, 253),
            secure: msg.secure ? 1 : 0,
            form: msg.form ? 1 : 0,
            user: msg.user ? 1 : 0
        };
        // Per-document visit token for seal's once-per-visit latches. When it is
        // absent or malformed the key is omitted, never sent empty: the bridge
        // rejects an empty token, an omitted key parses, and seal then stages
        // nothing, which fails closed.
        const visit = String(msg.visit || "");
        if (isVisitToken(visit)) {
            navPayload.visit = visit;
        }
        // Remember the exact document route, so a later fill_username directive
        // cannot be delivered to another page on the same host.
        if (navPayload.visit && sender.tab && typeof sender.tab.id === "number") {
            rememberNavRoute(navPayload.url_host, navPayload.visit, sender.tab.id, sender.frameId || 0);
        }
        dbg("bg -> host (nav):", navPayload);
        try {
            port.postMessage(navPayload);
            dbg("nav postMessage ok");
        } catch (err) {
            logInfo("nav postMessage failed", err);
        }
        return;
    }

    // Hash the path in-extension so the bridge only ever sees the digest.
    hashPath(msg.url_path).then((url_path_hash) => {
        // No browser_pid: the bridge resolves it server-side
        // (GetNamedPipeClientProcessId + parent walk); a client claim would be
        // forgeable, so the wire schema omits it.
        const payload = {
            v: 1,
            x: msg.x | 0,
            y: msg.y | 0,
            tag: String(msg.tag || "other"),
            url_host: String(msg.url_host || "").slice(0, 253),
            secure: msg.secure ? 1 : 0,
            url_path_hash
        };
        // Per-document visit token: it binds this click authorization to its
        // document. When it is absent or malformed the key is omitted, never sent
        // empty: the bridge rejects an empty token, an omitted key parses, and seal
        // falls back to host-only binding for the click.
        const visit = String(msg.visit || "");
        if (isVisitToken(visit)) {
            payload.visit = visit;
        }
        dbg("bg -> host:", payload);
        try {
            port.postMessage(payload);
            dbg("postMessage ok");
        } catch (err) {
            logInfo("postMessage failed", err);
        }
    });
});

// An MV3 service worker suspends after about 30 s idle, which closes the port and
// kills the host, so the next Ctrl+Click is dropped. Awaiting one extension API
// call every 20 s keeps the worker active for as long as it lives, at negligible
// cost.
async function keepServiceWorkerAlive() {
    for (; ;) {
        try {
            await chrome.runtime.getPlatformInfo();
        } catch (err) {
            // Suspended mid-await; the next event respawns the worker.
            logInfo("keep-alive ping rejected", err);
        }
        await new Promise((resolve) => setTimeout(resolve, 20_000));
    }
}

// Reconnection driver of last resort. setTimeout timers freeze in a suspended MV3
// worker, so a seal instance started while the worker sleeps would never be
// reconnected to. chrome.alarms persists and wakes the worker, which re-runs this
// script; this handler is the second retry path. The minimum period is about 30 s,
// so reconnection happens within about 30 s with no user interaction.
const RECONNECT_ALARM = "seal-reconnect";
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === RECONNECT_ALARM && port === null) {
        dbg("reconnect alarm fired; no port -> reconnecting");
        kickReconnect();
    }
});
chrome.alarms.create(RECONNECT_ALARM, { periodInMinutes: 0.5 });

connect();
keepServiceWorkerAlive();
