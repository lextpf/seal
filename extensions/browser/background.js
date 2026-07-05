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
 * seal companion — background service worker.
 *
 * Connects to native-messaging host `com.seal.fill`, echoes a per-connection
 * nonce (framing check, not auth — auth is bridge/host-side), and forwards
 * content-script reports to the host as length-prefixed JSON.
 *
 * One-way flow; inbound messages with sender.id != our runtime id are dropped.
 * No *External listeners and no `externally_connectable`, so cross-extension
 * calls fall through to nothing.
 */

const HOST_NAME = "com.seal.fill";

// Per-event SW traces. Logs go to the SW DevTools console
// (chrome://extensions -> seal companion -> Inspect views: service worker).
const DEBUG_LOGS = true;

let port = null;
let reconnectDelayMs = 1000;
// 5 s cap: seal disconnects often (restart, M8 toggle, transient OS); a long
// backoff would silently drop the bridge probe for the next Ctrl+Click.
const RECONNECT_DELAY_MAX_MS = 5_000;
let sessionNonce = null;
// Pending scheduleReconnect timer; the click-time fast-path checks this
// to avoid double-scheduling.
let reconnectTimer = null;
// host -> last tab that reported a nav there, to route the reverse
// fill_username directive back. Content re-verifies its own hostname before
// injecting, so a stale entry fails closed, never leaks to the wrong site.
const navTabs = new Map();

// Reclaim entries on tab close so the map can't grow unbounded.
chrome.tabs.onRemoved.addListener((closedTabId) => {
    for (const [host, id] of navTabs) {
        if (id === closedTabId) {
            navTabs.delete(host);
        }
    }
});

function logInfo(...args) {
    // Always-on (errors, disconnects). MV3 SWs lack a persistent console;
    // skip when the extension was unloaded.
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

// Reconnect immediately, bypassing backoff. Called from the click-report
// fast path: the user is interacting now, so the bridge should be too.
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
    // Log only the message TYPE -- never the raw object, which for a
    // fill_username directive contains the plaintext username.
    dbg("host -> extension kind:", msg && (msg.hello ? "handshake" : msg.kind));
    // First message is the bridge handshake bearing a per-connection
    // nonce. Echo it back to confirm framing in both directions.
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
    // Reverse directive: seal pushes a username to inject (strict-domain only,
    // gated seal-side). Route to the tab that reported this host; content
    // re-verifies its hostname + secure context, so a stale route fails closed.
    if (msg && msg.v === 1 && msg.kind === "fill_username" && typeof msg.username === "string") {
        const host = String(msg.url_host || "");
        const tabId = navTabs.get(host);
        if (tabId !== undefined) {
            chrome.tabs
                .sendMessage(tabId, { v: 1, kind: "fill_username", url_host: host, username: msg.username })
                .catch((err) => dbg("fill_username relay failed:", err && err.message));
        } else {
            dbg("fill_username: no known tab for host", host);
        }
        return;
    }

    // Anything else from the host is ignored.
    dbg("ignoring unrecognized host message");
}

// SHA-256 hex digest of a path. Bridge requires exactly 64 hex chars.
async function hashPath(path) {
    const enc = new TextEncoder().encode(path || "");
    const digest = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

// Receive click reports from content scripts; forward to host.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    dbg("content -> bg:", msg,
        "from tab", sender && sender.tab ? sender.tab.id : "<none>");
    // Origin checks: own-extension only, tab-attached (content script) only.
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
        // No host channel yet. Don't queue (bridge entries are time-windowed),
        // but kick the reconnect so the NEXT click lands on a live channel.
        dbg("DROP: no host port yet (port=" + !!port +
            ", nonce=" + !!sessionNonce + "); kicking reconnect");
        kickReconnect();
        return;
    }

    // Nav reports: forward host + secure/form flags verbatim, no path hash
    // (page-level, not click-level). Bridge validates the schema. No secret.
    if (msg.kind === "nav") {
        const navPayload = {
            v: 1,
            kind: "nav",
            url_host: String(msg.url_host || "").slice(0, 253),
            secure: msg.secure ? 1 : 0,
            form: msg.form ? 1 : 0,
            user: msg.user ? 1 : 0
        };
        // Per-document visit token for seal's once-per-visit latches. OMITTED
        // (never sent empty) when absent/malformed: the bridge rejects empty, an
        // omitted key parses fine, and seal then stages nothing (fail-closed).
        const visit = String(msg.visit || "");
        if (/^[A-Za-z0-9-]{1,64}$/.test(visit)) {
            navPayload.visit = visit;
        }
        // Remember which tab is on this host so a later fill_username directive
        // can be routed back to it.
        if (sender.tab && typeof sender.tab.id === "number") {
            navTabs.set(navPayload.url_host, sender.tab.id);
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
            url_path_hash
        };
        dbg("bg -> host:", payload);
        try {
            port.postMessage(payload);
            dbg("postMessage ok");
        } catch (err) {
            logInfo("postMessage failed", err);
        }
    });
});

// MV3 SWs suspend after ~30 s idle, closing our port and killing the host,
// which drops the next Ctrl+Click. Workaround: await one extension API call
// every 20 s to keep the SW active while it lives. Cost is negligible.
async function keepServiceWorkerAlive() {
    for (; ;) {
        try {
            await chrome.runtime.getPlatformInfo();
        } catch (err) {
            // Suspended mid-await; the next event will respawn us.
            logInfo("keep-alive ping rejected", err);
        }
        await new Promise((resolve) => setTimeout(resolve, 20_000));
    }
}

// Reliable reconnection driver. setTimeout timers freeze in a suspended MV3
// worker, so seal-started-while-idle would never reconnect. chrome.alarms
// persists and WAKES the worker (re-running this script); the handler is the
// belt-and-suspenders retry. ~30 s min period, so it reconnects within ~30 s
// with no interaction.
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
