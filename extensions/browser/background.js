/* global chrome */
/*/-============================================================================================-\*\

                                                             ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
                                                             ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
            ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
           :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
           +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
           +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
                  +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇          
           #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
            ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
                                                              ⠀ ⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 
                                    << P A S S   M A N A G E R >>
  
\*\-============================================================================================-/*/
/*
 *               A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *               providing on-demand credential management, directory encryption,
 *               webcam QR authentication, and global auto-fill.
 *
 *             +--------------------------------------------------------------------+
 *
 *               Repository:   https://github.com/lextpf/seal
 *               License:      GPL
 */

/**
 * @brief Relay page reports and username directives through the native host.
 *
 * The nonce echo checks framing. The native host and bridge verify signer identity
 * when their own trusted identity is available. Browser ancestry checks still apply
 * in unsigned development builds. Only this extension's content scripts may report.
 * The reverse channel carries usernames only; it routes by host and document token.
 *
 * Reports received before the handshake are dropped. Reconnect does not replay them.
 * Routes remain in memory across native-port reconnects, but worker restart clears them.
 */

const HOST_NAME = "com.seal.fill";

// Debug traces appear in service worker devtools. Keep disabled in committed builds.
const DEBUG_LOGS = false;

let port = null;
let reconnectDelayMs = 1000;
// Cap reconnect delay at 5 s so a bridge restart does not suppress later clicks.
const RECONNECT_DELAY_MAX_MS = 5_000;
let sessionNonce = null;

let reconnectTimer = null;
// (host, visit) identifies the reporting tab and frame. content.js checks both again.
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


chrome.tabs.onRemoved.addListener((closedTabId) => {
    for (const [key, route] of navRoutes) {
        if (route.tabId === closedTabId) {
            navRoutes.delete(key);
        }
    }
});

function logInfo(...args) {
    // Skip logging after extension unload, when chrome.runtime.id is unavailable.
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

// A click bypasses backoff so later reports can reach the bridge promptly.
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
    // Log only the directive kind; fill_username contains plaintext.
    dbg("host -> extension kind:", msg && (msg.hello ? "handshake" : msg.kind));
    // The echo must preserve key order v, hello, nonce with no extra keys.
    // seal compares bytes exactly; this checks framing, not authentication.
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
    // Route only to the document that reported this host and visit.
    // Content.js verifies both before writing the username.
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


    dbg("ignoring unrecognized host message");
}

// The bridge requires a 64-character SHA-256 hex digest.
async function hashPath(path) {
    const enc = new TextEncoder().encode(path || "");
    const digest = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}


chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    dbg("content -> bg kind:", msg && msg.kind,
        "from tab", sender && sender.tab ? sender.tab.id : "<none>");

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
        // Do not queue reports across reconnects; their authorization expires.
        dbg("DROP: no host port yet (port=" + !!port +
            ", nonce=" + !!sessionNonce + "); kicking reconnect");
        kickReconnect();
        return;
    }


    if (msg.kind === "nav") {
        const navPayload = {
            v: 1,
            kind: "nav",
            url_host: String(msg.url_host || "").slice(0, 253),
            secure: msg.secure ? 1 : 0,
            form: msg.form ? 1 : 0,
            user: msg.user ? 1 : 0
        };
        // Omit malformed visit tokens. The bridge rejects empty tokens;
        // an omitted nav token disables staging.
        const visit = String(msg.visit || "");
        if (isVisitToken(visit)) {
            navPayload.visit = visit;
        }

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

    // Raw paths must not cross the native channel.
    hashPath(msg.url_path).then((url_path_hash) => {
        // The bridge resolves browser_pid from the pipe peer and ancestry;
        // a client-supplied PID would be forgeable.
        const payload = {
            v: 1,
            x: msg.x | 0,
            y: msg.y | 0,
            tag: String(msg.tag || "other"),
            url_host: String(msg.url_host || "").slice(0, 253),
            secure: msg.secure ? 1 : 0,
            url_path_hash
        };
        // Omit malformed visit tokens. Staged auto-fill rejects a click entry that has none.
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

// Call an extension API every 20 s to keep the worker and native port active.
async function keepServiceWorkerAlive() {
    for (; ;) {
        try {
            await chrome.runtime.getPlatformInfo();
        } catch (err) {
            // The next extension event restarts a suspended worker.
            logInfo("keep-alive ping rejected", err);
        }
        await new Promise((resolve) => setTimeout(resolve, 20_000));
    }
}

// Alarms survive worker suspension; setTimeout does not. This provides a
// reconnect attempt about every 30 s without user interaction.
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
