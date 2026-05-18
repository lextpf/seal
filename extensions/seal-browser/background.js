// seal companion background service worker. Connects to native-messaging
// host `com.seal.fill`, receives a per-connection nonce on handshake, and
// forwards content-script click reports as length-prefixed JSON.
//
// Security invariants:
//   - One-way flow: nothing is echoed back to content scripts.
//   - Inbound messages with sender.id != our runtime id are dropped
//     (defeats spoofed cross-extension delivery).
//   - The nonce lives only in this worker's memory and is fresh per
//     connection (seal regenerates on every accept), so a captured
//     handshake cannot be replayed.
//   - The nonce echo is a framing sanity check, NOT authentication.
//     Authentication is out-of-band: the bridge does signer / parent /
//     stdio-server checks, and the native host does a matching server-
//     side signer check.
//   - `chrome.runtime.onMessageExternal` / `onConnectExternal` are
//     intentionally not registered; cross-extension calls are silently
//     dropped. `externally_connectable` is also omitted from the manifest
//     to avoid Chrome's "neither matches nor ids" warning -- the deny-all
//     posture relies on listener absence + the sender.id check.

const HOST_NAME = "com.seal.fill";

// Per-event SW traces. Logs go to the SW DevTools console
// (chrome://extensions -> seal companion -> Inspect views: service worker).
const DEBUG_LOGS = true;

let port = null;
let reconnectDelayMs = 1000;
// 5 s cap (down from 60 s). seal disconnects on every restart, every M8
// toggle, and on transient OS conditions; a long tail would silently drop
// the bridge probe for the user's next Ctrl+Click.
const RECONNECT_DELAY_MAX_MS = 5_000;
let sessionNonce = null;
// Pending scheduleReconnect timer; the click-time fast-path checks this
// to avoid double-scheduling.
let reconnectTimer = null;

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
    dbg("host -> extension:", msg);
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
    // Bridge is one-way (seal -> nothing); ignore anything else.
    dbg("ignoring non-handshake host message");
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
        // No host channel yet. Don't queue -- bridge entries are time-
        // windowed -- but kick the reconnect so the NEXT click is more
        // likely to land on a live channel.
        dbg("DROP: no host port yet (port=" + !!port +
            ", nonce=" + !!sessionNonce + "); kicking reconnect");
        kickReconnect();
        return;
    }

    // Hash the path in-extension so the bridge only ever sees the digest.
    hashPath(msg.url_path).then((url_path_hash) => {
        // No browser_pid: the bridge resolves it server-side via
        // GetNamedPipeClientProcessId + parent walk. A client-side claim
        // would be redundant at best and forgeable at worst, so the wire
        // schema deliberately omits it.
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

// MV3 SWs are suspended after ~30 s of inactivity, which closes our
// connectNative port and kills the native host. The host EOFs, we
// reconnect, and the user's next Ctrl+Click is dropped in the gap.
//
// Workaround: await one extension API call every 20 s to keep the SW
// "active". Cost is negligible; the alternative is a flapping host that
// never delivers a report.
async function keepServiceWorkerAlive() {
    while (true) {
        try {
            await chrome.runtime.getPlatformInfo();
        } catch (err) {
            // Suspended mid-await; the next event will respawn us.
            logInfo("keep-alive ping rejected", err);
        }
        await new Promise((resolve) => setTimeout(resolve, 20_000));
    }
}

connect();
keepServiceWorkerAlive();
