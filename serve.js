"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const root = __dirname;
function loadLocalEnvironment(filePath) {
    if (!fs.existsSync(filePath)) {
        return;
    }
    for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
        const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
        if (!match || process.env[match[1]]) {
            continue;
        }
        const value = match[2].replace(/^(["'])(.*)\1$/, "$2");
        process.env[match[1]] = value;
    }
}
loadLocalEnvironment(path.join(root, ".env"));

const port = Number(process.env.PORT || 4173);
const databasePath = process.env.TALANTAPASS_DB ||
    path.join(root, "data", "talantapass.sqlite");
const sessionCookie = "talantapass_admin_session";
const customerSessionCookie = "talantapass_customer_session";
const sessionDurationMs = 8 * 60 * 60 * 1000;
const customerSessionDurationMs = 30 * 24 * 60 * 60 * 1000;
const maxBodyBytes = 64 * 1024;
const loginAttempts = new Map();
const standardTicketCategories = [
    { id: "regular", name: "Regular", price: 500 },
    { id: "vip", name: "VIP", price: 1500 },
    { id: "vvip", name: "VVIP", price: 3000 }
];
const stadiumCapacityLimit = 60000;
const stadiumBlockIds = ["A", "B", "C", "D"];

function standardCategoryId(category) {
    const value = `${category?.id || ""} ${category?.name || ""}`.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (value.includes("vvip") || value.includes("veryveryimportant")) return "vvip";
    if (value.includes("vip") || value.includes("premium")) return "vip";
    return "regular";
}

function standardizeTicketCategories(categories) {
    const normalized = standardTicketCategories.map((category) => ({
        ...category, description: "", allocation: 0, available: true
    }));
    for (const saved of Array.isArray(categories) ? categories : []) {
        const id = standardCategoryId(saved);
        const category = normalized.find((item) => item.id === id);
        category.allocation += Math.max(0, Number(saved.allocation) || 0);
        category.available = category.available && saved.available !== false;
        if (saved.description && !category.description) category.description = String(saved.description).slice(0, 250);
    }
    return normalized;
}

const mimeTypes = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "text/javascript; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".webp": "image/webp"
};

fs.mkdirSync(path.dirname(databasePath), { recursive: true });

const database = new DatabaseSync(databasePath);
database.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS administrators (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS admin_sessions (
        token_hash TEXT PRIMARY KEY,
        administrator_id TEXT NOT NULL REFERENCES administrators(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customers (
        id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        phone TEXT NOT NULL,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customer_sessions (
        token_hash TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS support_messages (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        sender_type TEXT NOT NULL CHECK (sender_type IN ('customer','admin')),
        sender_admin_id TEXT REFERENCES administrators(id) ON DELETE SET NULL,
        body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
        created_at TEXT NOT NULL,
        read_at TEXT,
        CHECK ((sender_type = 'customer' AND sender_admin_id IS NULL) OR sender_type = 'admin')
    );
    CREATE INDEX IF NOT EXISTS support_messages_thread
        ON support_messages(customer_id, created_at, id);
    CREATE INDEX IF NOT EXISTS support_messages_unread
        ON support_messages(customer_id, sender_type, read_at);
    CREATE INDEX IF NOT EXISTS customer_sessions_expiry ON customer_sessions(expires_at);
    CREATE UNIQUE INDEX IF NOT EXISTS customers_phone_unique ON customers(phone);
    CREATE TABLE IF NOT EXISTS customer_bookings (
        id TEXT PRIMARY KEY,
        reference TEXT NOT NULL UNIQUE,
        customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
        event_id TEXT NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
        block_id TEXT CHECK (block_id IS NULL OR block_id IN ('A','B','C','D')),
        category_id TEXT NOT NULL,
        category_name TEXT NOT NULL,
        quantity INTEGER NOT NULL CHECK (quantity > 0 AND quantity <= 10),
        unit_price INTEGER NOT NULL CHECK (unit_price >= 0),
        total_amount INTEGER NOT NULL CHECK (total_amount > 0),
        currency TEXT NOT NULL DEFAULT 'KES',
        status TEXT NOT NULL CHECK (status IN ('PENDING','PAID','FAILED','EXPIRED','LATE_PAYMENT_REFUND_REQUIRED')),
        payment_status TEXT NOT NULL CHECK (payment_status IN ('PENDING','SUCCESSFUL','FAILED','EXPIRED','REFUND_REQUIRED')),
        payment_phone TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT 'MPESA',
        idempotency_key TEXT NOT NULL,
        merchant_request_id TEXT,
        checkout_request_id TEXT UNIQUE,
        mpesa_receipt TEXT UNIQUE,
        hold_expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(customer_id, idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS customer_bookings_active_capacity
        ON customer_bookings(event_id, category_id, status, hold_expires_at);
    CREATE INDEX IF NOT EXISTS customer_bookings_by_customer
        ON customer_bookings(customer_id, created_at);
    CREATE TABLE IF NOT EXISTS issued_tickets (
        id TEXT PRIMARY KEY,
        booking_id TEXT NOT NULL REFERENCES customer_bookings(id) ON DELETE RESTRICT,
        code_digest TEXT NOT NULL UNIQUE,
        code_ciphertext TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS issued_tickets_by_booking ON issued_tickets(booking_id);
    CREATE TABLE IF NOT EXISTS mpesa_callback_receipts (
        checkout_request_id TEXT PRIMARY KEY,
        result_code INTEGER NOT NULL,
        receipt_number TEXT,
        amount INTEGER,
        phone TEXT,
        received_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        home_team TEXT NOT NULL,
        away_team TEXT NOT NULL,
        competition TEXT NOT NULL,
        kickoff TEXT NOT NULL,
        venue TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        banner TEXT NOT NULL DEFAULT '',
        sales_open TEXT NOT NULL,
        sales_close TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('draft', 'published', 'postponed', 'cancelled')),
        categories TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS events_public_listing ON events(status, kickoff);
    CREATE TABLE IF NOT EXISTS stadium_blocks (
        block_id TEXT PRIMARY KEY CHECK (block_id IN ('A','B','C','D')),
        name TEXT NOT NULL,
        capacity INTEGER NOT NULL DEFAULT 0 CHECK (capacity >= 0 AND capacity <= 60000),
        updated_by TEXT REFERENCES administrators(id) ON DELETE SET NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id TEXT PRIMARY KEY,
        administrator_id TEXT REFERENCES administrators(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS admin_audit_logs_recent ON admin_audit_logs(created_at DESC);
    CREATE TABLE IF NOT EXISTS customer_booking_overrides (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        granted_by TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        revoked_by TEXT REFERENCES administrators(id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS booking_overrides_active
        ON customer_booking_overrides(customer_id, event_id, expires_at, revoked_at);
    CREATE TABLE IF NOT EXISTS ticket_email_outbox (
        id TEXT PRIMARY KEY,
        booking_id TEXT NOT NULL UNIQUE REFERENCES customer_bookings(id) ON DELETE RESTRICT,
        status TEXT NOT NULL CHECK (status IN ('PENDING','SENDING','SENT','FAILED')),
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mpesa_b2c_operations (
        id TEXT PRIMARY KEY,
        originator_id TEXT NOT NULL UNIQUE,
        operation_type TEXT NOT NULL CHECK (operation_type IN ('BALANCE','PAYOUT')),
        amount_kes INTEGER,
        recipient_phone TEXT,
        status TEXT NOT NULL CHECK (status IN ('PENDING','SUCCESSFUL','FAILED','UNKNOWN')),
        utility_balance_kes REAL,
        transaction_id TEXT,
        result_description TEXT,
        initiated_by TEXT NOT NULL REFERENCES administrators(id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS mpesa_b2c_operations_recent
        ON mpesa_b2c_operations(operation_type, status, created_at);
`);
const insertStadiumBlock = database.prepare(
    "INSERT OR IGNORE INTO stadium_blocks (block_id, name, capacity, updated_at) VALUES (?, ?, 15000, ?)"
);
for (const blockId of stadiumBlockIds) {
    insertStadiumBlock.run(blockId, `Block ${blockId}`, new Date().toISOString());
}
const configuredBlocks = database.prepare("SELECT capacity FROM stadium_blocks").all();
if (configuredBlocks.length === stadiumBlockIds.length &&
    configuredBlocks.every((block) => Number(block.capacity) === 0)) {
    database.prepare("UPDATE stadium_blocks SET capacity = 15000").run();
}
if (!database.prepare("PRAGMA table_info(customer_booking_overrides)").all()
    .some((column) => column.name === "revoked_by")) {
    database.exec("ALTER TABLE customer_booking_overrides ADD COLUMN revoked_by TEXT REFERENCES administrators(id) ON DELETE RESTRICT");
}
if (!database.prepare("PRAGMA table_info(customer_bookings)").all()
    .some((column) => column.name === "block_id")) {
    database.exec("ALTER TABLE customer_bookings ADD COLUMN block_id TEXT CHECK (block_id IS NULL OR block_id IN ('A','B','C','D'))");
}
database.exec(`CREATE INDEX IF NOT EXISTS customer_bookings_event_block
    ON customer_bookings(event_id, block_id, status, hold_expires_at)`);
database.exec("BEGIN IMMEDIATE");
try {
    const events = database.prepare("SELECT id, categories FROM events").all();
    const updateEventCategories = database.prepare("UPDATE events SET categories = ? WHERE id = ?");
    const updateBookingCategory = database.prepare(
        "UPDATE customer_bookings SET category_id = ? WHERE event_id = ? AND category_id = ?"
    );
    for (const event of events) {
        const oldCategories = JSON.parse(event.categories);
        const categories = standardizeTicketCategories(oldCategories);
        for (const oldCategory of oldCategories) {
            const oldId = String(oldCategory.id || "").toLowerCase();
            const newId = standardCategoryId(oldCategory);
            if (oldId && oldId !== newId) {
                updateBookingCategory.run(newId, event.id, oldId);
            }
        }
        updateEventCategories.run(JSON.stringify(categories), event.id);
    }
    database.exec("COMMIT");
} catch (error) {
    database.exec("ROLLBACK");
    throw error;
}
database.exec(`
    INSERT OR IGNORE INTO ticket_email_outbox
        (id, booking_id, status, attempts, next_attempt_at, created_at, updated_at)
    SELECT lower(hex(randomblob(16))), id, 'PENDING', 0, 0, created_at, updated_at
    FROM customer_bookings WHERE status = 'PAID';
`);

function json(response, status, data, headers = {}) {
    response.writeHead(status, {
        "Cache-Control": "no-store",
        "Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        ...headers
    });
    response.end(JSON.stringify(data));
}

function readBody(request) {
    return new Promise((resolve, reject) => {
        let body = "";
        let bodyBytes = 0;
        let tooLarge = false;
        request.on("data", (chunk) => {
            bodyBytes += chunk.length;
            if (bodyBytes > maxBodyBytes) {
                tooLarge = true;
                body = "";
                return;
            }
            if (tooLarge) {
                return;
            }
            body += chunk;
        });
        request.on("end", () => {
            if (tooLarge) {
                reject(Object.assign(new Error("Request is too large."), { status: 413 }));
                return;
            }
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch {
                reject(Object.assign(new Error("Request body must be valid JSON."), { status: 400 }));
            }
        });
        request.on("error", reject);
    });
}

function ensureSameOrigin(request) {
    const origin = request.headers.origin;
    const host = request.headers.host;
    const localOrigins = new Set([
        `http://127.0.0.1:${port}`,
        `http://localhost:${port}`
    ]);
    const publicOrigin = process.env.PUBLIC_ORIGIN || "";
    const allowedOrigins = new Set([...localOrigins, publicOrigin].filter(Boolean));
    let originHost = "";
    try { originHost = new URL(origin).host.toLowerCase(); } catch { /* invalid Origin */ }
    if (!origin || !host || !allowedOrigins.has(origin) ||
        originHost !== host.toLowerCase()) {
        throw Object.assign(new Error("Request origin was rejected."), { status: 403 });
    }
}

function secureCookieAttribute() {
    return /^https:\/\//i.test(process.env.PUBLIC_ORIGIN || "") ? "; Secure" : "";
}

function getCookie(request, name) {
    const cookies = String(request.headers.cookie || "").split(";");
    const entry = cookies.map((cookie) => cookie.trim())
        .find((cookie) => cookie.startsWith(`${name}=`));
    return entry ? entry.slice(name.length + 1) : "";
}

function hashToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function createSession(administratorId) {
    const token = crypto.randomBytes(32).toString("base64url");
    const expiresAt = Date.now() + sessionDurationMs;
    database.prepare(
        "INSERT INTO admin_sessions (token_hash, administrator_id, expires_at) VALUES (?, ?, ?)"
    ).run(hashToken(token), administratorId, expiresAt);
    return {
        token,
        cookie: `${sessionCookie}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict${secureCookieAttribute()}; Max-Age=${sessionDurationMs / 1000}`
    };
}

function getAdministrator(request) {
    const token = getCookie(request, sessionCookie);
    if (!token) {
        return null;
    }
    const session = database.prepare(`
        SELECT administrators.id, administrators.name, administrators.email
        FROM admin_sessions
        JOIN administrators ON administrators.id = admin_sessions.administrator_id
        WHERE admin_sessions.token_hash = ? AND admin_sessions.expires_at > ?
    `).get(hashToken(token), Date.now());
    return session || null;
}

function getCustomer(request) {
    const token = getCookie(request, customerSessionCookie);
    if (!token) {
        return null;
    }
    return database.prepare(`
        SELECT customers.id, customers.full_name AS fullName,
            customers.email, customers.phone
        FROM customer_sessions
        JOIN customers ON customers.id = customer_sessions.customer_id
        WHERE customer_sessions.token_hash = ? AND customer_sessions.expires_at > ?
    `).get(hashToken(token), Date.now()) || null;
}

function createCustomerSession(customerId, remember = false) {
    const token = crypto.randomBytes(32).toString("base64url");
    const durationMs = remember ? customerSessionDurationMs : sessionDurationMs;
    const expiresAt = Date.now() + durationMs;
    database.prepare(
        "INSERT INTO customer_sessions (token_hash, customer_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
    ).run(hashToken(token), customerId, expiresAt, new Date().toISOString());
    return {
        cookie: `${customerSessionCookie}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict${secureCookieAttribute()}; Max-Age=${durationMs / 1000}`
    };
}

function requireCustomer(request) {
    const customer = getCustomer(request);
    if (!customer) {
        throw Object.assign(new Error("Customer sign-in is required."), { status: 401 });
    }
    return customer;
}

function consumeLoginAttempt(request, key) {
    const address = request.socket.remoteAddress || "unknown";
    const now = Date.now();
    if (loginAttempts.size > 4096) {
        for (const [storedKey, entry] of loginAttempts) {
            if (entry.resetAt <= now) {
                loginAttempts.delete(storedKey);
            }
        }
    }
    const keys = [`${address}:ip`, `${address}:${key}`];
    if (keys.some((attemptKey) => {
        const previous = loginAttempts.get(attemptKey);
        return previous && previous.resetAt > now && previous.count >= 10;
    })) {
        return false;
    }
    for (const attemptKey of keys) {
        const previous = loginAttempts.get(attemptKey);
        const entry = previous && previous.resetAt > now
            ? previous
            : { count: 0, resetAt: now + 15 * 60 * 1000 };
        entry.count += 1;
        loginAttempts.set(attemptKey, entry);
    }
    return true;
}

function clearLoginAttempts(request, key) {
    const address = request.socket.remoteAddress || "unknown";
    loginAttempts.delete(`${address}:ip`);
    loginAttempts.delete(`${address}:${key}`);
}

function customerFromBody(body) {
    const fullName = normalizeText(body.fullName, "Full name", 160);
    const email = normalizeText(body.email, "Email", 254).toLowerCase();
    const phone = normalizeText(body.phone, "Phone number", 24);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        throw Object.assign(new Error("Enter a valid email address."), { status: 400 });
    }
    if (!/^\+254[17]\d{8}$/.test(phone)) {
        throw Object.assign(new Error("Enter a valid Kenyan phone number."), { status: 400 });
    }
    return { fullName, email, phone };
}

function mpesaConfiguration() {
    const environment = process.env.MPESA_ENV === "production" ? "production" : "sandbox";
    let publicOriginValid = false;
    try {
        const publicOrigin = new URL(process.env.PUBLIC_ORIGIN || "");
        publicOriginValid = publicOrigin.protocol === "https:" &&
            publicOrigin.origin === process.env.PUBLIC_ORIGIN;
    } catch { /* missing or invalid public origin */ }
    const configured = Boolean(
        process.env.MPESA_CONSUMER_KEY &&
        process.env.MPESA_CONSUMER_SECRET &&
        process.env.MPESA_SHORTCODE &&
        process.env.MPESA_PASSKEY &&
        publicOriginValid &&
        /^https:\/\//i.test(process.env.MPESA_CALLBACK_URL || "")
    );
    return {
        environment,
        configured,
        baseUrl: environment === "production"
            ? "https://api.safaricom.co.ke"
            : "https://sandbox.safaricom.co.ke"
    };
}

function mpesaB2cConfiguration() {
    const callbackToken = process.env.MPESA_B2C_CALLBACK_TOKEN || "";
    const origin = process.env.PUBLIC_ORIGIN || "";
    const configured = Boolean(
        mpesaConfiguration().configured &&
        process.env.MPESA_B2C_SHORTCODE &&
        process.env.MPESA_B2C_INITIATOR &&
        process.env.MPESA_B2C_SECURITY_CREDENTIAL &&
        callbackToken.length >= 32
    );
    const callback = `${origin}/api/payments/mpesa/b2c?token=${encodeURIComponent(callbackToken)}`;
    return { configured, callback };
}

function mpesaB2cOriginatorId() {
    return `TPB${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
}

let mpesaAccessToken = null;
async function getMpesaAccessToken() {
    const config = mpesaConfiguration();
    if (!config.configured) {
        throw Object.assign(new Error("M-Pesa payment configuration is incomplete."), { status: 503 });
    }
    if (mpesaAccessToken && mpesaAccessToken.expiresAt > Date.now() + 30000) {
        return mpesaAccessToken.value;
    }
    const credentials = Buffer.from(
        `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
    ).toString("base64");
    const response = await fetch(
        `${config.baseUrl}/oauth/v1/generate?grant_type=client_credentials`,
        { headers: { Authorization: `Basic ${credentials}` }, signal: AbortSignal.timeout(15000) }
    );
    if (!response.ok) {
        throw Object.assign(new Error("M-Pesa authentication failed."), { status: 502 });
    }
    const payload = await response.json();
    if (typeof payload.access_token !== "string") {
        throw Object.assign(new Error("M-Pesa did not return an access token."), { status: 502 });
    }
    mpesaAccessToken = {
        value: payload.access_token,
        expiresAt: Date.now() + Number(payload.expires_in || 3600) * 1000
    };
    return mpesaAccessToken.value;
}

function mpesaTimestamp() {
    const parts = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Africa/Nairobi",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hourCycle: "h23"
    }).formatToParts(new Date());
    const values = Object.fromEntries(parts.map(({ type, value }) => [type, value]));
    return `${values.year}${values.month}${values.day}${values.hour}${values.minute}${values.second}`;
}

function mpesaPassword(timestamp) {
    return Buffer.from(
        `${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`
    ).toString("base64");
}

async function mpesaPost(pathname, payload) {
    const config = mpesaConfiguration();
    const token = await getMpesaAccessToken();
    const response = await fetch(`${config.baseUrl}${pathname}`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(20000)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw Object.assign(new Error("M-Pesa rejected the request."), {
            status: 502,
            definitive: response.status >= 400 && response.status < 500
        });
    }
    return result;
}

async function initiateMpesaPayment(booking, phone) {
    const timestamp = mpesaTimestamp();
    const shortcode = process.env.MPESA_SHORTCODE;
    const transactionType = process.env.MPESA_TRANSACTION_TYPE || "CustomerPayBillOnline";
    if (!["CustomerPayBillOnline", "CustomerBuyGoodsOnline"].includes(transactionType)) {
        throw Object.assign(new Error("M-Pesa transaction type is invalid."), { status: 503 });
    }
    return mpesaPost("/mpesa/stkpush/v1/processrequest", {
        BusinessShortCode: shortcode,
        Password: mpesaPassword(timestamp),
        Timestamp: timestamp,
        TransactionType: transactionType,
        Amount: booking.total_amount,
        PartyA: phone,
        PartyB: shortcode,
        PhoneNumber: phone,
        CallBackURL: process.env.MPESA_CALLBACK_URL,
        AccountReference: booking.reference,
        TransactionDesc: "Talanta ticket"
    });
}

async function queryMpesaCheckout(checkoutRequestId) {
    const timestamp = mpesaTimestamp();
    return mpesaPost("/mpesa/stkpushquery/v1/query", {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: mpesaPassword(timestamp),
        Timestamp: timestamp,
        CheckoutRequestID: checkoutRequestId
    });
}

function getTicketEncryptionKey() {
    const encodedKey = process.env.TICKET_ENCRYPTION_KEY || "";
    const key = /^[0-9a-f]{64}$/i.test(encodedKey)
        ? Buffer.from(encodedKey, "hex")
        : Buffer.from(encodedKey, "base64");
    if (key.length !== 32) {
        throw Object.assign(new Error("Ticket encryption key is not configured."), { status: 503 });
    }
    return key;
}

function getTicketDigestKey() {
    const encodedKey = process.env.TICKET_LOOKUP_HMAC_KEY || "";
    const key = /^[0-9a-f]{64}$/i.test(encodedKey)
        ? Buffer.from(encodedKey, "hex")
        : Buffer.from(encodedKey, "base64");
    if (key.length !== 32) {
        throw Object.assign(new Error("Ticket lookup key is not configured."), { status: 503 });
    }
    return key;
}

function ticketConfigurationReady() {
    try {
        getTicketEncryptionKey();
        getTicketDigestKey();
        return true;
    } catch {
        return false;
    }
}

function ticketDigest(code) {
    return crypto.createHmac("sha256", getTicketDigestKey()).update(code).digest("hex");
}

function generateTicketCode() {
    return crypto.randomBytes(16).toString("hex").toUpperCase().match(/.{1,4}/g).join("-");
}

function sealTicketCode(code) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", getTicketEncryptionKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(code, "utf8"), cipher.final()]);
    return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString("base64url")).join(".");
}

function openTicketCode(value) {
    const [encodedIv, encodedTag, encodedCiphertext] = value.split(".");
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm", getTicketEncryptionKey(), Buffer.from(encodedIv, "base64url")
    );
    decipher.setAuthTag(Buffer.from(encodedTag, "base64url"));
    return Buffer.concat([
        decipher.update(Buffer.from(encodedCiphertext, "base64url")), decipher.final()
    ]).toString("utf8");
}

function requireAdministrator(request) {
    const administrator = getAdministrator(request);
    if (!administrator) {
        throw Object.assign(new Error("Administrator sign-in is required."), { status: 401 });
    }
    return administrator;
}

function normalizeText(value, field, maxLength, required = true) {
    const text = typeof value === "string" ? value.trim() : "";
    if ((!text && required) || text.length > maxLength) {
        throw Object.assign(new Error(`${field} is required and must be at most ${maxLength} characters.`), { status: 400 });
    }
    return text;
}

function requireObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw Object.assign(new Error("Request body must be a JSON object."), { status: 400 });
    }
    return value;
}

function normalizeDate(value, field) {
    if (typeof value !== "string" || !value || !Number.isFinite(Date.parse(value))) {
        throw Object.assign(new Error(`${field} must be a valid date and time.`), { status: 400 });
    }
    return new Date(value).toISOString();
}

function configuredStadiumCapacity() {
    return Number(database.prepare("SELECT COALESCE(SUM(capacity), 0) AS total FROM stadium_blocks").get().total);
}

function normalizeEvent(body) {
    requireObject(body);
    const homeTeam = normalizeText(body.homeTeam, "Home team", 80);
    const awayTeam = normalizeText(body.awayTeam, "Away team", 80);
    if (homeTeam.toLowerCase() === awayTeam.toLowerCase()) {
        throw Object.assign(new Error("Home and away teams must be different."), { status: 400 });
    }

    const kickoff = normalizeDate(body.kickoff, "Kickoff");
    const salesOpen = normalizeDate(body.salesOpen, "Sales opening time");
    const salesClose = normalizeDate(body.salesClose, "Sales closing time");
    if (Date.parse(salesOpen) >= Date.parse(salesClose) ||
        Date.parse(salesClose) > Date.parse(kickoff)) {
        throw Object.assign(new Error("Sales must close after opening and no later than kickoff."), { status: 400 });
    }

    const status = String(body.status || "").toLowerCase();
    if (!["draft", "published", "postponed", "cancelled"].includes(status)) {
        throw Object.assign(new Error("Choose a valid event status."), { status: 400 });
    }

    if (!Array.isArray(body.categories) || body.categories.length !== standardTicketCategories.length) {
        throw Object.assign(new Error("Set allocations for Regular, VIP, and VVIP tickets."), { status: 400 });
    }
    const submitted = new Map(body.categories.map((category) => [
        String(category.id || "").trim().toLowerCase(), category
    ]));
    const stadiumCapacity = configuredStadiumCapacity();
    let totalAllocation = 0;
    const categories = standardTicketCategories.map((fixed) => {
        const category = submitted.get(fixed.id);
        if (!category) {
            throw Object.assign(new Error("Ticket categories must be Regular, VIP, and VVIP."), { status: 400 });
        }
        const allocation = Number(category.allocation ?? 0);
        if (!Number.isSafeInteger(allocation) || allocation < 0 || allocation > 60000) {
            throw Object.assign(new Error(`Enter a valid ticket allocation for ${fixed.name} (0 to 60,000).`), { status: 400 });
        }
        totalAllocation += allocation;
        if (totalAllocation > stadiumCapacity) {
            throw Object.assign(new Error(`Total event ticket allocations cannot exceed the ${stadiumCapacity.toLocaleString("en-KE")} seats configured across the stadium blocks.`), { status: 400 });
        }
        return { ...fixed, description: "", allocation, available: category.available !== false };
    });
    if (status === "published" && !categories.some((category) => category.available && category.allocation > 0)) {
        throw Object.assign(new Error("A published event needs at least one available category with a positive ticket allocation."), { status: 400 });
    }

    return {
        homeTeam,
        awayTeam,
        competition: normalizeText(body.competition || "Football", "Competition", 100),
        kickoff,
        venue: normalizeText(body.venue, "Venue", 160),
        description: normalizeText(body.description || "", "Description", 2000, false),
        banner: normalizeText(body.banner || "", "Banner URL", 2000, false),
        salesOpen,
        salesClose,
        status,
        categories
    };
}

function hasBookingOverride(customerId, eventId, now = Date.now()) {
    if (!customerId) return false;
    return Boolean(database.prepare(`
        SELECT 1 FROM customer_booking_overrides
        WHERE customer_id = ? AND event_id = ? AND expires_at > ? AND revoked_at IS NULL
        LIMIT 1
    `).get(customerId, eventId, now));
}

function categoryAvailability(eventRow, category, customerId = null) {
    const now = Date.now();
    const salesOpen = Date.parse(eventRow.sales_open);
    const salesClose = Date.parse(eventRow.sales_close);
    const kickoff = Date.parse(eventRow.kickoff);
    const bookingWindowOpen = eventRow.status === "published" &&
        Number.isFinite(salesOpen) && salesOpen <= now &&
        Number.isFinite(salesClose) && salesClose > now &&
        Number.isFinite(kickoff) && kickoff > now;
    const override = eventRow.status === "published" && Number.isFinite(kickoff) &&
        kickoff > now && hasBookingOverride(customerId, eventRow.id, now);
    const allocation = Number(category.allocation || 0);
    const inventory = database.prepare(`
        SELECT COALESCE(SUM(CASE WHEN status = 'PAID' THEN quantity ELSE 0 END), 0) AS paid,
            COALESCE(SUM(CASE WHEN status = 'PENDING' AND hold_expires_at > ? THEN quantity ELSE 0 END), 0) AS held
        FROM customer_bookings
        WHERE event_id = ? AND category_id = ? AND
            (status = 'PAID' OR (status = 'PENDING' AND hold_expires_at > ?))
    `).get(now, eventRow.id, category.id, now);
    const paid = Number(inventory.paid);
    const held = Number(inventory.held);
    const remainingAfterPaid = Math.max(0, allocation - paid);
    const remaining = Math.max(0, remainingAfterPaid - held);
    const categoryEnabled = Boolean(category.available) && allocation > 0;
    return {
        allocation,
        remaining,
        adminAvailable: Boolean(category.available),
        categoryEnabled,
        soldOut: categoryEnabled && remainingAfterPaid === 0,
        temporarilyHeld: categoryEnabled && remaining === 0 && remainingAfterPaid > 0,
        available: categoryEnabled && remaining > 0 &&
            (bookingWindowOpen || override),
        bookingOverride: Boolean(override)
    };
}

function eventBlockAvailability(eventRow) {
    const now = Date.now();
    const usage = database.prepare(`
        SELECT block_id,
            COALESCE(SUM(CASE WHEN status = 'PAID' THEN quantity ELSE 0 END), 0) AS paid,
            COALESCE(SUM(CASE WHEN status = 'PENDING' AND hold_expires_at > ? THEN quantity ELSE 0 END), 0) AS held
        FROM customer_bookings
        WHERE event_id = ? AND block_id IS NOT NULL AND
            (status = 'PAID' OR (status = 'PENDING' AND hold_expires_at > ?))
        GROUP BY block_id
    `).all(now, eventRow.id, now);
    const usedByBlock = new Map(usage.map((item) => [item.block_id, Number(item.paid) + Number(item.held)]));
    return database.prepare("SELECT block_id AS id, name, capacity FROM stadium_blocks ORDER BY block_id")
        .all().map((block) => {
            const capacity = Number(block.capacity);
            const usageForBlock = usage.find((item) => item.block_id === block.id);
            const paid = Number(usageForBlock?.paid || 0);
            const held = Number(usageForBlock?.held || 0);
            const remainingAfterPaid = Math.max(0, capacity - paid);
            const remaining = Math.max(0, remainingAfterPaid - held);
            return {
                ...block,
                capacity,
                remaining,
                available: remaining > 0,
                soldOut: capacity > 0 && remainingAfterPaid === 0,
                temporarilyHeld: capacity > 0 && remaining === 0 && remainingAfterPaid > 0
            };
        });
}

function eventFromRow(row) {
    const categories = standardizeTicketCategories(JSON.parse(row.categories));
    return {
        id: row.id,
        homeTeam: row.home_team,
        awayTeam: row.away_team,
        title: `${row.home_team} vs ${row.away_team}`,
        competition: row.competition,
        kickoff: row.kickoff,
        venue: row.venue,
        description: row.description,
        banner: row.banner,
        salesOpen: row.sales_open,
        salesClose: row.sales_close,
        status: row.status,
        categories,
        startingPrice: categories.length
            ? Math.min(...categories.map((category) => category.price))
            : null,
        bookingEnabled: false
    };
}

function publicEventFromRow(row, customerId = null) {
    const event = eventFromRow(row);
    const categories = event.categories.map((category) => ({
        ...category,
        ...categoryAvailability(row, category, customerId)
    }));
    const now = Date.now();
    const salesWindowOpen = row.status === "published" &&
        Date.parse(row.sales_open) <= now && Date.parse(row.sales_close) > now &&
        Date.parse(row.kickoff) > now;
    const overrideOpen = categories.some((category) => category.bookingOverride);
    const configuredCategories = categories.filter((category) => category.allocation > 0);
    const allocatedCategories = categories.filter((category) => category.categoryEnabled);
    const blocks = eventBlockAvailability(row);
    const blockSeatsRemaining = blocks.reduce((sum, block) => sum + block.remaining, 0);
    const configuredBlocks = blocks.filter((block) => block.capacity > 0);
    const blocksSoldOut = configuredBlocks.length > 0 && configuredBlocks.every((block) => block.soldOut);
    const blocksTemporarilyHeld = blockSeatsRemaining === 0 &&
        configuredBlocks.some((block) => block.temporarilyHeld);
    const hasRemaining = categories.some((category) => category.remaining > 0 && category.available);
    const bookingEnabled = hasRemaining && blockSeatsRemaining > 0;
    const soldOut = blocksSoldOut || (allocatedCategories.length > 0 &&
        allocatedCategories.every((category) => category.soldOut));
    const bookingReason = bookingEnabled ? "open"
        : soldOut ? "sold_out"
            : configuredCategories.length === 0 ? "allocation_missing"
                : allocatedCategories.length === 0 ? "category_disabled"
            : allocatedCategories.some((category) => category.temporarilyHeld) || blocksTemporarilyHeld ? "payment_in_progress"
                        : !salesWindowOpen && !overrideOpen ? "outside_sales_window" : "category_disabled";
    return {
        ...event,
        categories,
        blocks,
        bookingEnabled,
        soldOut,
        bookingReason
    };
}

function normalizeMpesaPhone(value) {
    const compact = String(value || "").replace(/[\s()-]/g, "");
    if (/^\+254[17]\d{8}$/.test(compact)) return compact.slice(1);
    if (/^254[17]\d{8}$/.test(compact)) return compact;
    if (/^0[17]\d{8}$/.test(compact)) return `254${compact.slice(1)}`;
    throw Object.assign(new Error("Enter a valid Safaricom M-Pesa number."), { status: 400 });
}

function createBookingReference() {
    return `TP${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
}

function issueBookingTickets(booking) {
    const tickets = [];
    for (let index = 0; index < booking.quantity; index += 1) {
        let code = generateTicketCode();
        let digest = ticketDigest(code);
        while (database.prepare("SELECT 1 FROM issued_tickets WHERE code_digest = ?").get(digest)) {
            code = generateTicketCode();
            digest = ticketDigest(code);
        }
        const ticket = {
            id: crypto.randomUUID(),
            booking_id: booking.id,
            code_digest: digest,
            code_ciphertext: sealTicketCode(code),
            created_at: new Date().toISOString()
        };
        database.prepare(`
            INSERT INTO issued_tickets (id, booking_id, code_digest, code_ciphertext, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(ticket.id, ticket.booking_id, ticket.code_digest, ticket.code_ciphertext, ticket.created_at);
        tickets.push(ticket);
        code = "";
    }
    database.prepare(`
        INSERT OR IGNORE INTO ticket_email_outbox
            (id, booking_id, status, attempts, next_attempt_at, created_at, updated_at)
        VALUES (?, ?, 'PENDING', 0, 0, ?, ?)
    `).run(crypto.randomUUID(), booking.id, new Date().toISOString(), new Date().toISOString());
    return tickets;
}

function pdfEscape(value) {
    return String(value).normalize("NFKD")
        .replace(/[^\x20-\x7e]/g, "?")
        .replace(/[()\\]/g, "\\$&");
}

function createTicketPdf(lines) {
    const content = lines.map((line, index) => {
        const fontSize = index === 0 ? 20 : index === 1 ? 15 : 11;
        const y = 790 - index * 31;
        return `BT /F1 ${fontSize} Tf 48 ${y} Td (${pdfEscape(line)}) Tj ET`;
    }).join("\n");
    const objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        `<< /Length ${Buffer.byteLength(content, "ascii")} >>\nstream\n${content}\nendstream`
    ];
    let document = "%PDF-1.4\n";
    const offsets = [0];
    objects.forEach((object, index) => {
        offsets.push(Buffer.byteLength(document, "ascii"));
        document += `${index + 1} 0 obj\n${object}\nendobj\n`;
    });
    const xrefOffset = Buffer.byteLength(document, "ascii");
    document += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const offset of offsets.slice(1)) {
        document += `${String(offset).padStart(10, "0")} 00000 n \n`;
    }
    document += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
    return Buffer.from(document, "ascii");
}

function eventInput(request, id) {
    return readBody(request).then((body) => {
        const event = normalizeEvent(body);
        const now = new Date().toISOString();
        const eventId = id || crypto.randomUUID();
        if (id) {
            const result = database.prepare(`
                UPDATE events SET home_team = ?, away_team = ?, competition = ?,
                    kickoff = ?, venue = ?, description = ?, banner = ?,
                    sales_open = ?, sales_close = ?, status = ?, categories = ?,
                    updated_at = ? WHERE id = ?
            `).run(
                event.homeTeam, event.awayTeam, event.competition, event.kickoff,
                event.venue, event.description, event.banner, event.salesOpen,
                event.salesClose, event.status, JSON.stringify(event.categories), now, id
            );
            if (Number(result.changes) === 0) {
                throw Object.assign(new Error("Event not found."), { status: 404 });
            }
        } else {
            database.prepare(`
                INSERT INTO events (
                    id, home_team, away_team, competition, kickoff, venue,
                    description, banner, sales_open, sales_close, status,
                    categories, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                eventId, event.homeTeam, event.awayTeam, event.competition,
                event.kickoff, event.venue, event.description, event.banner,
                event.salesOpen, event.salesClose, event.status,
                JSON.stringify(event.categories), now, now
            );
        }
        return eventFromRow(database.prepare("SELECT * FROM events WHERE id = ?").get(eventId));
    });
}

function parseAdminPath(pathname) {
    const match = pathname.match(/^\/api\/admin\/events(?:\/([^/]+))?$/);
    return match ? { eventId: match[1] ? decodeURIComponent(match[1]) : null } : null;
}

function readMpesaCallbackMetadata(callback) {
    const items = callback.CallbackMetadata?.Item;
    if (!Array.isArray(items)) return null;
    const values = Object.fromEntries(items
        .filter((item) => item && typeof item.Name === "string")
        .map((item) => [item.Name, item.Value]));
    return {
        amount: Number(values.Amount),
        receipt: typeof values.MpesaReceiptNumber === "string" ? values.MpesaReceiptNumber : "",
        phone: values.PhoneNumber === undefined ? "" : String(values.PhoneNumber)
    };
}

async function reconcileMpesaBooking(checkoutRequestId) {
    const booking = database.prepare(
        "SELECT * FROM customer_bookings WHERE checkout_request_id = ?"
    ).get(checkoutRequestId);
    const callback = database.prepare(
        "SELECT * FROM mpesa_callback_receipts WHERE checkout_request_id = ?"
    ).get(checkoutRequestId);
    if (!booking || !callback || booking.status !== "PENDING") return;

    let verification;
    try {
        verification = await queryMpesaCheckout(checkoutRequestId);
    } catch {
        return;
    }
    const resultCode = Number(verification.ResultCode);
    if (String(verification.ResponseCode) !== "0" || !Number.isInteger(resultCode)) return;

    if (resultCode === 0) {
        const expectedPhone = normalizeMpesaPhone(booking.payment_phone);
        if (callback.result_code !== 0 || callback.amount !== booking.total_amount ||
            callback.phone !== expectedPhone || !callback.receipt_number) {
            return;
        }
    }
    if (Number(callback.result_code) !== resultCode) return;

    database.exec("BEGIN IMMEDIATE");
    try {
        const current = database.prepare(
            "SELECT * FROM customer_bookings WHERE id = ?"
        ).get(booking.id);
        if (!current || current.status !== "PENDING") {
            database.exec("ROLLBACK");
            return;
        }
        if (resultCode !== 0) {
            database.prepare(`
                UPDATE customer_bookings
                SET status = 'FAILED', payment_status = 'FAILED', updated_at = ?
                WHERE id = ? AND status = 'PENDING'
            `).run(new Date().toISOString(), current.id);
            database.exec("COMMIT");
            return;
        }

        const event = database.prepare("SELECT * FROM events WHERE id = ?").get(current.event_id);
        const eventCategories = event ? JSON.parse(event.categories) : [];
        const category = eventCategories.find((item) => item.id === current.category_id);
        const now = Date.now();
        const otherReserved = Number(database.prepare(`
            SELECT COALESCE(SUM(quantity), 0) AS count FROM customer_bookings
            WHERE event_id = ? AND category_id = ? AND id <> ? AND
                (status = 'PAID' OR (status = 'PENDING' AND hold_expires_at > ?))
        `).get(current.event_id, current.category_id, current.id, now).count);
        const withinAllocation = category && category.available !== false &&
            Number(category.allocation || 0) - otherReserved >= current.quantity;
        let withinBlockCapacity = true;
        if (current.block_id) {
            const block = database.prepare("SELECT capacity FROM stadium_blocks WHERE block_id = ?")
                .get(current.block_id);
            const otherBlockReserved = Number(database.prepare(`
                SELECT COALESCE(SUM(quantity), 0) AS count FROM customer_bookings
                WHERE event_id = ? AND block_id = ? AND id <> ? AND
                    (status = 'PAID' OR (status = 'PENDING' AND hold_expires_at > ?))
            `).get(current.event_id, current.block_id, current.id, now).count);
            withinBlockCapacity = block && Number(block.capacity) - otherBlockReserved >= current.quantity;
        }
        const eventStillValid = event && event.status === "published" &&
            Date.parse(event.kickoff) > now;
        const receipt = callback.receipt_number;

        if (!withinAllocation || !withinBlockCapacity || !eventStillValid) {
            database.prepare(`
                UPDATE customer_bookings SET status = 'LATE_PAYMENT_REFUND_REQUIRED',
                    payment_status = 'REFUND_REQUIRED', mpesa_receipt = ?, updated_at = ?
                WHERE id = ?
            `).run(receipt, new Date().toISOString(), current.id);
            database.exec("COMMIT");
            return;
        }

        database.prepare(`
            UPDATE customer_bookings SET status = 'PAID', payment_status = 'SUCCESSFUL',
                mpesa_receipt = ?, updated_at = ? WHERE id = ?
        `).run(receipt, new Date().toISOString(), current.id);
        issueBookingTickets(current);
        database.exec("COMMIT");
        setImmediate(() => deliverTicketEmail(current.id).catch(() => {}));
    } catch (error) {
        database.exec("ROLLBACK");
        if (error.code === "ERR_SQLITE_CONSTRAINT_UNIQUE") return;
        throw error;
    }
}

async function acceptMpesaCallback(body) {
    const callback = body?.Body?.stkCallback;
    if (!callback || typeof callback.CheckoutRequestID !== "string" ||
        !Number.isInteger(Number(callback.ResultCode))) {
        return false;
    }
    const metadata = Number(callback.ResultCode) === 0
        ? readMpesaCallbackMetadata(callback)
        : null;
    const now = new Date().toISOString();
    database.prepare(`
        INSERT INTO mpesa_callback_receipts
            (checkout_request_id, result_code, receipt_number, amount, phone, received_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(checkout_request_id) DO UPDATE SET
            result_code = excluded.result_code,
            receipt_number = COALESCE(excluded.receipt_number, mpesa_callback_receipts.receipt_number),
            amount = COALESCE(excluded.amount, mpesa_callback_receipts.amount),
            phone = COALESCE(excluded.phone, mpesa_callback_receipts.phone),
            received_at = excluded.received_at
    `).run(
        callback.CheckoutRequestID,
        Number(callback.ResultCode),
        metadata?.receipt || null,
        Number.isSafeInteger(metadata?.amount) ? metadata.amount : null,
        metadata?.phone || null,
        now
    );
    await reconcileMpesaBooking(callback.CheckoutRequestID);
    return true;
}

function ticketPdf(ticketId, customerId) {
    const ticket = database.prepare(`
        SELECT tickets.id, tickets.code_ciphertext, bookings.reference, bookings.category_name,
            bookings.unit_price, bookings.total_amount, bookings.payment_phone, bookings.block_id,
            customers.full_name, events.home_team, events.away_team, events.kickoff,
            events.venue, bookings.quantity
        FROM issued_tickets AS tickets
        JOIN customer_bookings AS bookings ON bookings.id = tickets.booking_id
        JOIN customers ON customers.id = bookings.customer_id
        JOIN events ON events.id = bookings.event_id
        WHERE tickets.id = ? AND bookings.customer_id = ? AND bookings.status = 'PAID'
    `).get(ticketId, customerId);
    if (!ticket) return null;
    const phone = ticket.payment_phone.replace(/^254(\d{3})\d{3}(\d{3})$/, "+254$1***$2");
    const kickoff = new Intl.DateTimeFormat("en-KE", {
        dateStyle: "full", timeStyle: "short", timeZone: "Africa/Nairobi"
    }).format(new Date(ticket.kickoff));
    return createTicketPdf([
        "TALANTA STADIUM - OFFICIAL MATCH TICKET",
        `${ticket.venue} | Block ${ticket.block_id || "Unassigned"}`,
        `${ticket.home_team} vs ${ticket.away_team}`,
        `Kickoff: ${kickoff}`,
        `Venue: ${ticket.venue}`,
        `Customer: ${ticket.full_name} | Phone: ${phone}`,
        `Booking reference: ${ticket.reference}`,
        `Stadium block: ${ticket.block_id ? `Block ${ticket.block_id}` : "Not assigned"}`,
        `Category: ${ticket.category_name}`,
        `Amount paid: KES ${ticket.unit_price}`,
        `M-Pesa receipt: ${database.prepare("SELECT mpesa_receipt FROM customer_bookings WHERE reference = ?").get(ticket.reference).mpesa_receipt}`,
        `Ticket number: ${openTicketCode(ticket.code_ciphertext)}`,
        "Single entry only. Ticket number is confidential; present this document at the gate."
    ]);
}

function htmlEscape(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[character]);
}

async function deliverTicketEmail(bookingId) {
    const apiKey = process.env.RESEND_API_KEY || "";
    const from = process.env.TICKET_EMAIL_FROM || "";
    if (!apiKey || !from) return false;

    const delivery = database.prepare(`
        SELECT outbox.*, bookings.reference, bookings.customer_id,
            customers.email, customers.full_name
        FROM ticket_email_outbox AS outbox
        JOIN customer_bookings AS bookings ON bookings.id = outbox.booking_id
        JOIN customers ON customers.id = bookings.customer_id
        WHERE outbox.booking_id = ? AND bookings.status = 'PAID'
    `).get(bookingId);
    if (!delivery || delivery.status === "SENT" || delivery.next_attempt_at > Date.now()) return false;
    if (delivery.status === "SENDING" && Date.now() - Date.parse(delivery.updated_at) < 5 * 60 * 1000) return false;
    const claimed = database.prepare(`
        UPDATE ticket_email_outbox SET status = 'SENDING', attempts = attempts + 1,
            updated_at = ? WHERE id = ? AND status <> 'SENT'
    `).run(new Date().toISOString(), delivery.id);
    if (!Number(claimed.changes)) return false;

    const attempt = Number(delivery.attempts) + 1;
    try {
        const tickets = database.prepare(
            "SELECT id FROM issued_tickets WHERE booking_id = ? ORDER BY created_at, id"
        ).all(bookingId);
        const attachments = tickets.map((ticket, index) => {
            const pdf = ticketPdf(ticket.id, delivery.customer_id);
            if (!pdf) throw new Error("A paid ticket PDF could not be generated.");
            return { filename: `talanta-stadium-ticket-${index + 1}.pdf`, content: pdf.toString("base64") };
        });
        if (!attachments.length) throw new Error("No ticket PDFs are available for email delivery.");
        const event = database.prepare(`
            SELECT home_team, away_team FROM events
            JOIN customer_bookings ON customer_bookings.event_id = events.id
            WHERE customer_bookings.id = ?
        `).get(bookingId);
        const response = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${apiKey}`,
                "Content-Type": "application/json",
                "Idempotency-Key": delivery.id
            },
            body: JSON.stringify({
                from,
                to: [delivery.email],
                reply_to: process.env.TICKET_EMAIL_REPLY_TO || undefined,
                subject: `Your Talanta Stadium ticket${attachments.length === 1 ? "" : "s"} — ${event.home_team} vs ${event.away_team}`,
                html: `<p>Hello ${htmlEscape(delivery.full_name)},</p><p>Your payment is confirmed. Your ${attachments.length} official match ticket PDF${attachments.length === 1 ? " is" : "s are"} attached.</p><p>Booking reference: <strong>${htmlEscape(delivery.reference)}</strong></p><p>You can also download them from your Talanta Stadium customer account.</p>`,
                attachments
            }),
            signal: AbortSignal.timeout(20000)
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(typeof result.message === "string" ? result.message.slice(0, 400) : `Email provider returned HTTP ${response.status}.`);
        database.prepare(`
            UPDATE ticket_email_outbox SET status = 'SENT', last_error = NULL,
                updated_at = ? WHERE id = ?
        `).run(new Date().toISOString(), delivery.id);
        return true;
    } catch (error) {
        const retryAt = Date.now() + Math.min(6 * 60 * 60 * 1000, 30000 * (2 ** Math.min(attempt - 1, 10)));
        database.prepare(`
            UPDATE ticket_email_outbox SET status = ?, next_attempt_at = ?,
                last_error = ?, updated_at = ? WHERE id = ?
        `).run(attempt >= 10 ? "FAILED" : "PENDING", retryAt,
            String(error.message || "Email delivery failed.").slice(0, 500),
            new Date().toISOString(), delivery.id);
        return false;
    }
}

async function retryTicketEmails() {
    const staleBefore = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    database.prepare(`
        UPDATE ticket_email_outbox SET status = 'PENDING', updated_at = ?
        WHERE status = 'SENDING' AND updated_at < ?
    `).run(new Date().toISOString(), staleBefore);
    const due = database.prepare(`
        SELECT booking_id FROM ticket_email_outbox
        WHERE status = 'PENDING' AND next_attempt_at <= ? ORDER BY created_at LIMIT 20
    `).all(Date.now());
    for (const row of due) await deliverTicketEmail(row.booking_id);
}

function mpesaB2cCallbackTokenMatches(candidate) {
    const configured = process.env.MPESA_B2C_CALLBACK_TOKEN || "";
    const left = Buffer.from(String(candidate || ""));
    const right = Buffer.from(configured);
    return right.length >= 32 && left.length === right.length && crypto.timingSafeEqual(left, right);
}

function mpesaResultParameters(result) {
    const parameters = result?.ResultParameters?.ResultParameter;
    if (!Array.isArray(parameters)) return {};
    return Object.fromEntries(parameters
        .filter((item) => item && typeof item.Key === "string")
        .map((item) => [item.Key, item.Value]));
}

async function startMpesaBalanceQuery(administratorId) {
    const config = mpesaB2cConfiguration();
    if (!config.configured) {
        throw Object.assign(new Error("M-Pesa B2C is not fully configured. Add the B2C shortcode, initiator, encrypted security credential, callback token, and public callback domain to .env."), { status: 503 });
    }
    const id = crypto.randomUUID();
    const originatorId = mpesaB2cOriginatorId();
    const timestamp = new Date().toISOString();
    database.prepare(`
        INSERT INTO mpesa_b2c_operations
            (id, originator_id, operation_type, status, initiated_by, created_at, updated_at)
        VALUES (?, ?, 'BALANCE', 'PENDING', ?, ?, ?)
    `).run(id, originatorId, administratorId, timestamp, timestamp);
    try {
        const response = await mpesaPost("/mpesa/accountbalance/v1/query", {
            Initiator: process.env.MPESA_B2C_INITIATOR,
            SecurityCredential: process.env.MPESA_B2C_SECURITY_CREDENTIAL,
            CommandID: "AccountBalance",
            PartyA: process.env.MPESA_B2C_SHORTCODE,
            IdentifierType: "4",
            Remarks: "Talanta Stadium B2C balance query",
            QueueTimeOutURL: config.callback,
            ResultURL: config.callback
        });
        if (String(response.ResponseCode) !== "0") {
            throw Object.assign(new Error("Daraja did not accept the balance query."), { definitive: true });
        }
        return database.prepare("SELECT id, originator_id AS reference, status, created_at AS createdAt FROM mpesa_b2c_operations WHERE id = ?").get(id);
    } catch (error) {
        const responseCode = error.definitive === true;
        database.prepare(`
            UPDATE mpesa_b2c_operations SET status = ?, result_description = ?, updated_at = ? WHERE id = ?
        `).run(responseCode ? "FAILED" : "UNKNOWN",
            String(error.message || "Balance query result is uncertain.").slice(0, 400),
            new Date().toISOString(), id);
        return database.prepare("SELECT id, originator_id AS reference, status, created_at AS createdAt FROM mpesa_b2c_operations WHERE id = ?").get(id);
    }
}

function handleMpesaB2cCallback(body) {
    const result = body?.Result;
    if (!result || typeof result.OriginatorConversationID !== "string" ||
        !Number.isInteger(Number(result.ResultCode))) return false;
    const operation = database.prepare(
        "SELECT * FROM mpesa_b2c_operations WHERE originator_id = ?"
    ).get(result.OriginatorConversationID);
    if (!operation || !["PENDING", "UNKNOWN"].includes(operation.status)) return true;

    const resultCode = Number(result.ResultCode);
    const parameters = mpesaResultParameters(result);
    const balanceRaw = parameters.B2CUtilityAccountAvailableFunds;
    const balance = balanceRaw === undefined ? null : Number(balanceRaw);
    const callbackAt = new Date().toISOString();
    if (operation.operation_type === "BALANCE") {
        const validBalance = Number.isFinite(balance) && balance >= 0;
        database.prepare(`
            UPDATE mpesa_b2c_operations SET status = ?, utility_balance_kes = ?,
                result_description = ?, updated_at = ? WHERE id = ? AND status IN ('PENDING','UNKNOWN')
        `).run(resultCode === 0 && validBalance ? "SUCCESSFUL" : resultCode === 0 ? "UNKNOWN" : "FAILED",
            validBalance ? balance : null,
            String(result.ResultDesc || "M-Pesa balance callback received.").slice(0, 400),
            callbackAt, operation.id);
        return true;
    }

    const transactionAmount = Number(parameters.TransactionAmount);
    const transactionId = typeof result.TransactionID === "string" ? result.TransactionID : null;
    const receiver = String(parameters.ReceiverPartyPublicName || "").split(" - ")[0].trim();
    const confirmed = resultCode === 0 && transactionId &&
        Number.isFinite(transactionAmount) && transactionAmount === Number(operation.amount_kes) &&
        receiver === operation.recipient_phone;
    const status = confirmed ? "SUCCESSFUL" : resultCode === 0 ? "UNKNOWN" : "FAILED";
    database.prepare(`
        UPDATE mpesa_b2c_operations SET status = ?, transaction_id = ?,
            result_description = ?, updated_at = ?
        WHERE id = ? AND status IN ('PENDING','UNKNOWN')
    `).run(status, transactionId,
        String(result.ResultDesc || "M-Pesa B2C result received.").slice(0, 400),
        callbackAt, operation.id);
    return true;
}

function payoutAvailability() {
    const gross = Number(database.prepare(`
        SELECT COALESCE(SUM(total_amount), 0) AS amount FROM customer_bookings
        WHERE status = 'PAID' AND payment_status = 'SUCCESSFUL'
    `).get().amount);
    const paidOut = Number(database.prepare(`
        SELECT COALESCE(SUM(amount_kes), 0) AS amount FROM mpesa_b2c_operations
        WHERE operation_type = 'PAYOUT' AND status = 'SUCCESSFUL'
    `).get().amount);
    const inFlight = Number(database.prepare(`
        SELECT COALESCE(SUM(amount_kes), 0) AS amount FROM mpesa_b2c_operations
        WHERE operation_type = 'PAYOUT' AND status IN ('PENDING','UNKNOWN')
    `).get().amount);
    const dailySentAndReserved = Number(database.prepare(`
        SELECT COALESCE(SUM(amount_kes), 0) AS amount FROM mpesa_b2c_operations
        WHERE operation_type = 'PAYOUT' AND status <> 'FAILED' AND created_at >= ?
    `).get(new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()).amount);
    const balance = database.prepare(`
        SELECT utility_balance_kes, updated_at FROM mpesa_b2c_operations
        WHERE operation_type = 'BALANCE' AND status = 'SUCCESSFUL' AND utility_balance_kes IS NOT NULL
        ORDER BY updated_at DESC, id DESC LIMIT 1
    `).get();
    const pendingBalanceQuery = Number(database.prepare(`
        SELECT COUNT(*) AS count FROM mpesa_b2c_operations
        WHERE operation_type = 'BALANCE' AND status IN ('PENDING','UNKNOWN')
    `).get().count) > 0;
    const fresh = balance && !pendingBalanceQuery && Date.now() - Date.parse(balance.updated_at) <= 5 * 60 * 1000;
    const paidOutAfterSnapshot = balance ? Number(database.prepare(`
        SELECT COALESCE(SUM(amount_kes), 0) AS amount FROM mpesa_b2c_operations
        WHERE operation_type = 'PAYOUT' AND status = 'SUCCESSFUL' AND updated_at >= ?
    `).get(balance.updated_at).amount) : 0;
    const available = fresh ? Math.max(0, Math.floor(Math.min(
        gross - paidOut - inFlight,
        Number(balance.utility_balance_kes) - paidOutAfterSnapshot - inFlight,
        250000,
        500000 - dailySentAndReserved
    ))) : 0;
    return {
        grossPaidKes: gross,
        paidOutKes: paidOut,
        b2cUtilityBalanceKes: balance ? Number(balance.utility_balance_kes) : null,
        balanceUpdatedAt: balance?.updated_at || null,
        balanceFresh: Boolean(fresh),
        pendingBalanceQuery,
        pendingPayoutKes: inFlight,
        dailyLimitRemainingKes: Math.max(0, 500000 - dailySentAndReserved),
        withdrawableKes: available >= 10 ? available : 0
    };
}

async function handleApi(request, response, url) {
    const { pathname } = url;
    const adminEventsPath = parseAdminPath(pathname);
    const addSeatsPath = pathname.match(/^\/api\/admin\/events\/([^/]+)\/seats$/);
    const adminMessageThreadMatch = pathname.match(/^\/api\/admin\/messages\/([^/]+)$/);

    try {
        const externalCallback = pathname === "/api/payments/mpesa/callback" ||
            pathname === "/api/payments/mpesa/b2c";
        if (request.method !== "GET" && !externalCallback) {
            ensureSameOrigin(request);
        }

        if (pathname === "/api/auth/register" && request.method === "POST") {
            if (!consumeLoginAttempt(request, "registration")) {
                return json(response, 429, { success: false, message: "Too many account requests. Try again in 15 minutes." });
            }
            const body = requireObject(await readBody(request));
            if (body.acceptTerms !== true) {
                return json(response, 400, { success: false, message: "Accept the terms to create an account." });
            }
            const customer = customerFromBody(body);
            const password = typeof body.password === "string" ? body.password : "";
            if (password.length < 12 || password.length > 200) {
                return json(response, 400, { success: false, message: "Password must be at least 12 characters." });
            }
            const id = crypto.randomUUID();
            const salt = crypto.randomBytes(16).toString("hex");
            const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");
            const now = new Date().toISOString();
            try {
                database.prepare(`
                    INSERT INTO customers (id, full_name, email, phone, salt, password_hash, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                `).run(id, customer.fullName, customer.email, customer.phone, salt, passwordHash, now, now);
            } catch (error) {
                if (error.code === "ERR_SQLITE_CONSTRAINT_UNIQUE") {
                    return json(response, 409, { success: false, message: "An account with this email or phone already exists." });
                }
                throw error;
            }
            return json(response, 201, { success: true, message: "Account created. Sign in to continue." });
        }

        if (pathname === "/api/auth/login" && request.method === "POST") {
            const body = requireObject(await readBody(request));
            const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
            const password = typeof body.password === "string" ? body.password : "";
            const attemptKey = email.slice(0, 254);
            if (!consumeLoginAttempt(request, attemptKey)) {
                return json(response, 429, { success: false, message: "Too many sign-in attempts. Try again in 15 minutes." });
            }
            const customer = database.prepare(
                "SELECT id, full_name AS fullName, email, phone, salt, password_hash FROM customers WHERE email = ? COLLATE NOCASE"
            ).get(email);
            const salt = customer ? customer.salt : "talantapass-invalid-customer-login";
            const storedHash = customer ? Buffer.from(customer.password_hash, "hex") : Buffer.alloc(64);
            const passwordHash = crypto.scryptSync(password.slice(0, 200), salt, 64);
            if (!customer || password.length === 0 || password.length > 200 || !crypto.timingSafeEqual(storedHash, passwordHash)) {
                return json(response, 401, { success: false, message: "Incorrect email or password." });
            }
            clearLoginAttempts(request, attemptKey);
            const session = createCustomerSession(customer.id, body.remember === true);
            return json(response, 200, {
                success: true,
                user: { id: customer.id, fullName: customer.fullName, email: customer.email, phone: customer.phone }
            }, { "Set-Cookie": session.cookie });
        }

        if (pathname === "/api/auth/me" && request.method === "GET") {
            const customer = getCustomer(request);
            if (!customer) {
                return json(response, 401, { success: false, message: "Customer sign-in is required." });
            }
            return json(response, 200, { success: true, user: customer });
        }

        if (pathname === "/api/auth/profile" && request.method === "PATCH") {
            const customer = requireCustomer(request);
            const body = requireObject(await readBody(request));
            const fullName = normalizeText(body.fullName, "Full name", 160);
            database.prepare("UPDATE customers SET full_name = ?, updated_at = ? WHERE id = ?")
                .run(fullName, new Date().toISOString(), customer.id);
            const updated = getCustomer(request);
            return json(response, 200, { success: true, user: updated });
        }

        if (pathname === "/api/auth/logout" && request.method === "POST") {
            const token = getCookie(request, customerSessionCookie);
            if (token) {
                database.prepare("DELETE FROM customer_sessions WHERE token_hash = ?").run(hashToken(token));
            }
            return json(response, 200, { success: true, signedOut: true }, {
                "Set-Cookie": `${customerSessionCookie}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`
            });
        }

        if (pathname === "/api/my/messages" && request.method === "GET") {
            const customer = requireCustomer(request);
            const now = new Date().toISOString();
            database.prepare(`
                UPDATE support_messages SET read_at = ?
                WHERE customer_id = ? AND sender_type = 'admin' AND read_at IS NULL
            `).run(now, customer.id);
            const messages = database.prepare(`
                SELECT id, sender_type AS sender, body, created_at AS createdAt, read_at AS readAt
                FROM support_messages WHERE customer_id = ?
                ORDER BY created_at DESC, id DESC LIMIT 500
            `).all(customer.id).reverse();
            const unreadCount = Number(database.prepare(`
                SELECT COUNT(*) AS count FROM support_messages
                WHERE customer_id = ? AND sender_type = 'admin' AND read_at IS NULL
            `).get(customer.id).count);
            return json(response, 200, { messages, unreadCount });
        }

        if (pathname === "/api/my/messages" && request.method === "POST") {
            const customer = requireCustomer(request);
            const body = requireObject(await readBody(request));
            const message = normalizeText(body.message, "Message", 2000);
            const id = randomUUID();
            const createdAt = new Date().toISOString();
            database.prepare(`
                INSERT INTO support_messages (id, customer_id, sender_type, body, created_at)
                VALUES (?, ?, 'customer', ?, ?)
            `).run(id, customer.id, message, createdAt);
            return json(response, 201, {
                message: { id, sender: "customer", body: message, createdAt, readAt: null }
            });
        }

        if (pathname === "/api/my/tickets" && request.method === "GET") {
            const customer = requireCustomer(request);
            const tickets = database.prepare(`
                SELECT tickets.id, bookings.reference, bookings.category_name AS category,
                    bookings.block_id AS blockId,
                    bookings.unit_price AS amountPaid, bookings.payment_status AS paymentStatus,
                    events.home_team AS homeTeam, events.away_team AS awayTeam,
                    events.kickoff, events.venue, bookings.status
                FROM issued_tickets AS tickets
                JOIN customer_bookings AS bookings ON bookings.id = tickets.booking_id
                JOIN events ON events.id = bookings.event_id
                WHERE bookings.customer_id = ? AND bookings.status = 'PAID'
                ORDER BY bookings.created_at DESC
            `).all(customer.id).map((ticket) => ({
                ...ticket,
                block: ticket.blockId ? `Block ${ticket.blockId}` : "Not assigned",
                seat: "Unassigned",
                status: "issued",
                downloadUrl: `/api/my/tickets/${encodeURIComponent(ticket.id)}/download`
            }));
            return json(response, 200, { tickets });
        }

        if (pathname === "/api/payments/providers" && request.method === "GET") {
            const config = mpesaConfiguration();
            return json(response, 200, {
                providers: [{
                    id: "mpesa",
                    name: "M-Pesa",
                    available: config.configured && ticketConfigurationReady(),
                    environment: config.environment
                }]
            });
        }

        if (pathname === "/api/bookings" && request.method === "POST") {
            const customer = requireCustomer(request);
            const idempotencyKey = String(request.headers["idempotency-key"] || "").trim();
            if (!/^[A-Za-z0-9_-]{12,100}$/.test(idempotencyKey)) {
                return json(response, 400, { error: "A valid Idempotency-Key header is required." });
            }
            const provider = mpesaConfiguration();
            if (!provider.configured) {
                return json(response, 503, { error: "M-Pesa is not configured. Add the production Daraja values and public HTTPS callback URL to the local .env file." });
            }
            if (!ticketConfigurationReady()) {
                return json(response, 503, { error: "Ticket encryption keys are not configured. Set TICKET_ENCRYPTION_KEY and TICKET_LOOKUP_HMAC_KEY in .env." });
            }
            await getMpesaAccessToken();
            const body = requireObject(await readBody(request));
            const eventId = normalizeText(body.eventId, "Event", 80);
            const categoryId = normalizeText(body.categoryId, "Ticket category", 32).toLowerCase();
            const blockId = normalizeText(body.blockId, "Stadium block", 1).toUpperCase();
            const quantity = Number(body.quantity);
            if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 10) {
                return json(response, 400, { error: "Choose between 1 and 10 tickets." });
            }
            const paymentPhone = normalizeMpesaPhone(body.phone);
            const existing = database.prepare(`
                SELECT reference, block_id AS blockId, status, payment_status AS paymentStatus,
                    total_amount AS totalAmount, hold_expires_at AS expiresAt
                FROM customer_bookings WHERE customer_id = ? AND idempotency_key = ?
            `).get(customer.id, idempotencyKey);
            if (existing) {
                return json(response, 200, {
                    booking: existing,
                    message: existing.status === "PENDING"
                        ? "This payment request is already in progress. Check your phone and do not submit again."
                        : "This idempotent booking request was already processed."
                });
            }

            const now = Date.now();
            const event = database.prepare(
                "SELECT * FROM events WHERE id = ? AND status = 'published'"
            ).get(eventId);
            const salesWindowOpen = event && Date.parse(event.sales_open) <= now &&
                Date.parse(event.sales_close) > now;
            const adminOverride = event && hasBookingOverride(customer.id, eventId, now);
            if (!event || Date.parse(event.kickoff) <= now ||
                (!salesWindowOpen && !adminOverride)) {
                return json(response, 409, { error: "This event is not currently on sale." });
            }
            const categories = JSON.parse(event.categories);
            const category = categories.find((item) => item.id === categoryId);
            if (!category || category.available === false || Number(category.allocation || 0) < 1) {
                return json(response, 409, { error: "This ticket category has no configured allocation." });
            }
            if (!stadiumBlockIds.includes(blockId)) {
                return json(response, 400, { error: "Choose one of the four stadium blocks." });
            }

            const bookingId = crypto.randomUUID();
            const reference = createBookingReference();
            const totalAmount = Number(category.price) * quantity;
            if (!Number.isSafeInteger(totalAmount) || totalAmount < 1) {
                return json(response, 400, { error: "The ticket total must be at least KES 1." });
            }
            const expiresAt = now + 10 * 60 * 1000;
            const createdAt = new Date(now).toISOString();
            database.exec("BEGIN IMMEDIATE");
            try {
                const duplicate = database.prepare(
                    "SELECT reference, block_id AS blockId, status, payment_status AS paymentStatus, total_amount AS totalAmount, hold_expires_at AS expiresAt FROM customer_bookings WHERE customer_id = ? AND idempotency_key = ?"
                ).get(customer.id, idempotencyKey);
                if (duplicate) {
                    database.exec("ROLLBACK");
                    return json(response, 200, { booking: duplicate, message: "This booking request already exists." });
                }
                const active = Number(database.prepare(`
                    SELECT COALESCE(SUM(quantity), 0) AS count FROM customer_bookings
                    WHERE event_id = ? AND category_id = ? AND
                        (status = 'PAID' OR (status = 'PENDING' AND hold_expires_at > ?))
                `).get(eventId, categoryId, now).count);
                if (Number(category.allocation) - active < quantity) {
                    database.exec("ROLLBACK");
                    return json(response, 409, { error: "There are not enough tickets remaining in this category." });
                }
                const block = database.prepare("SELECT capacity FROM stadium_blocks WHERE block_id = ?")
                    .get(blockId);
                if (!block || Number(block.capacity) < 1) {
                    database.exec("ROLLBACK");
                    return json(response, 409, { error: `Block ${blockId} is not configured for this event.` });
                }
                const blockActive = Number(database.prepare(`
                    SELECT COALESCE(SUM(quantity), 0) AS count FROM customer_bookings
                    WHERE event_id = ? AND block_id = ? AND
                        (status = 'PAID' OR (status = 'PENDING' AND hold_expires_at > ?))
                `).get(eventId, blockId, now).count);
                if (Number(block.capacity) - blockActive < quantity) {
                    database.exec("ROLLBACK");
                    return json(response, 409, { error: `There are not enough seats remaining in Block ${blockId}. Choose another block.` });
                }
                database.prepare(`
                    INSERT INTO customer_bookings (
                        id, reference, customer_id, event_id, block_id, category_id, category_name,
                        quantity, unit_price, total_amount, status, payment_status,
                        payment_phone, idempotency_key, hold_expires_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', ?, ?, ?, ?, ?)
                `).run(
                    bookingId, reference, customer.id, eventId, blockId, category.id, category.name,
                    quantity, category.price, totalAmount, paymentPhone, idempotencyKey,
                    expiresAt, createdAt, createdAt
                );
                database.exec("COMMIT");
            } catch (error) {
                database.exec("ROLLBACK");
                throw error;
            }

            let paymentResponse;
            try {
                paymentResponse = await initiateMpesaPayment({
                    reference, total_amount: totalAmount
                }, paymentPhone);
            } catch (error) {
                if (error.definitive) {
                    database.prepare(`
                        UPDATE customer_bookings SET status = 'FAILED', payment_status = 'FAILED', updated_at = ?
                        WHERE id = ? AND status = 'PENDING'
                    `).run(new Date().toISOString(), bookingId);
                    throw error;
                }
                return json(response, 202, {
                    booking: { reference, status: "PENDING", paymentStatus: "PENDING", totalAmount, expiresAt },
                    message: "M-Pesa request status is uncertain. Do not submit another payment; check your phone and refresh this booking shortly."
                });
            }
            if (String(paymentResponse.ResponseCode) !== "0" ||
                typeof paymentResponse.CheckoutRequestID !== "string" ||
                typeof paymentResponse.MerchantRequestID !== "string") {
                database.prepare(`
                    UPDATE customer_bookings SET status = 'FAILED', payment_status = 'FAILED', updated_at = ?
                    WHERE id = ? AND status = 'PENDING'
                `).run(new Date().toISOString(), bookingId);
                return json(response, 502, { error: "M-Pesa did not accept the payment request. No payment was confirmed." });
            }
            database.prepare(`
                UPDATE customer_bookings SET checkout_request_id = ?, merchant_request_id = ?, updated_at = ?
                WHERE id = ?
            `).run(paymentResponse.CheckoutRequestID, paymentResponse.MerchantRequestID, new Date().toISOString(), bookingId);
            if (database.prepare("SELECT 1 FROM mpesa_callback_receipts WHERE checkout_request_id = ?")
                .get(paymentResponse.CheckoutRequestID)) {
                await reconcileMpesaBooking(paymentResponse.CheckoutRequestID);
            }
            const saved = database.prepare(`
                SELECT reference, status, payment_status AS paymentStatus,
                    total_amount AS totalAmount, hold_expires_at AS expiresAt
                FROM customer_bookings WHERE id = ?
            `).get(bookingId);
            return json(response, 201, {
                booking: saved,
                message: "Approve the M-Pesa prompt on your phone. Your tickets are issued after Safaricom confirms payment."
            });
        }

        if (pathname === "/api/payments/mpesa/callback" && request.method === "POST") {
            const body = await readBody(request);
            const accepted = await acceptMpesaCallback(body);
            if (!accepted) return json(response, 400, { Result: "Invalid callback" });
            return json(response, 200, { Result: "Accepted" });
        }

        if (pathname === "/api/payments/mpesa/b2c" && request.method === "POST") {
            if (!mpesaB2cCallbackTokenMatches(url.searchParams.get("token"))) {
                return json(response, 403, { Result: "Rejected" });
            }
            const body = await readBody(request);
            if (!handleMpesaB2cCallback(body)) return json(response, 400, { Result: "Invalid callback" });
            return json(response, 200, { Result: "Accepted" });
        }

        if (pathname === "/api/my/bookings" && request.method === "GET") {
            const customer = requireCustomer(request);
            const bookings = database.prepare(`
                SELECT reference, category_name AS category, quantity,
                    unit_price AS unitPrice, total_amount AS totalAmount, currency,
                    block_id AS blockId, status, payment_status AS paymentStatus, hold_expires_at AS expiresAt,
                    created_at AS createdAt
                FROM customer_bookings WHERE customer_id = ? ORDER BY created_at DESC LIMIT 100
            `).all(customer.id);
            return json(response, 200, { bookings });
        }

        const bookingStatusMatch = pathname.match(/^\/api\/my\/bookings\/([^/]+)$/);
        if (bookingStatusMatch && request.method === "GET") {
            const customer = requireCustomer(request);
            const reference = decodeURIComponent(bookingStatusMatch[1]);
            const booking = database.prepare(`
                SELECT reference, category_name AS category, quantity,
                    unit_price AS unitPrice, total_amount AS totalAmount, currency,
                    block_id AS blockId, status, payment_status AS paymentStatus, hold_expires_at AS expiresAt
                FROM customer_bookings WHERE customer_id = ? AND reference = ?
            `).get(customer.id, reference);
            if (!booking) return json(response, 404, { error: "Booking not found." });
            return json(response, 200, { booking });
        }

        const ticketDownloadMatch = pathname.match(/^\/api\/my\/tickets\/([^/]+)\/download$/);
        if (ticketDownloadMatch && request.method === "GET") {
            const customer = requireCustomer(request);
            let pdf;
            try {
                pdf = ticketPdf(decodeURIComponent(ticketDownloadMatch[1]), customer.id);
            } catch (error) {
                if (error.status) return json(response, error.status, { error: error.message });
                throw error;
            }
            if (!pdf) return json(response, 404, { error: "Paid ticket not found." });
            response.writeHead(200, {
                "Cache-Control": "private, no-store",
                "Content-Type": "application/pdf",
                "Content-Disposition": "attachment; filename=talanta-stadium-ticket.pdf",
                "X-Content-Type-Options": "nosniff"
            });
            return response.end(pdf);
        }

        if (pathname === "/api/admin/session" && request.method === "GET") {
            const administrator = getAdministrator(request);
            return json(response, 200, {
                authenticated: Boolean(administrator),
                administrator: administrator
                    ? { id: administrator.id, name: administrator.name, email: administrator.email }
                    : null,
                setupRequired: Number(database.prepare("SELECT COUNT(*) AS count FROM administrators").get().count) === 0
            });
        }

        if (pathname === "/api/admin/stadium/blocks" && request.method === "GET") {
            requireAdministrator(request);
            const blocks = database.prepare(
                "SELECT block_id AS id, name, capacity FROM stadium_blocks ORDER BY block_id"
            ).all();
            const configuredCapacity = blocks.reduce((sum, block) => sum + Number(block.capacity), 0);
            return json(response, 200, {
                capacityLimit: stadiumCapacityLimit,
                configuredCapacity,
                unassignedCapacity: stadiumCapacityLimit - configuredCapacity,
                blocks
            });
        }

        if (pathname === "/api/admin/stadium/blocks" && request.method === "PUT") {
            const administrator = requireAdministrator(request);
            const body = requireObject(await readBody(request));
            if (!Array.isArray(body.blocks) || body.blocks.length !== stadiumBlockIds.length) {
                return json(response, 400, { error: "Configure all four stadium blocks." });
            }
            const submitted = new Map(body.blocks.map((block) => [String(block.id || "").toUpperCase(), Number(block.capacity)]));
            let total = 0;
            for (const blockId of stadiumBlockIds) {
                const capacity = submitted.get(blockId);
                if (!Number.isSafeInteger(capacity) || capacity < 0 || capacity > stadiumCapacityLimit) {
                    return json(response, 400, { error: `Enter a valid seat capacity for Block ${blockId}.` });
                }
                total += capacity;
            }
            if (total > stadiumCapacityLimit) {
                return json(response, 400, { error: "The four block capacities cannot exceed 60,000 seats." });
            }
            const now = Date.now();
            for (const blockId of stadiumBlockIds) {
                const overbookedEvent = database.prepare(`
                    SELECT events.home_team, events.away_team, SUM(bookings.quantity) AS assigned
                    FROM customer_bookings AS bookings
                    JOIN events ON events.id = bookings.event_id
                    WHERE bookings.block_id = ? AND
                        (bookings.status = 'PAID' OR (bookings.status = 'PENDING' AND bookings.hold_expires_at > ?))
                    GROUP BY bookings.event_id
                    HAVING SUM(bookings.quantity) > ?
                    LIMIT 1
                `).get(blockId, now, submitted.get(blockId));
                if (overbookedEvent) {
                    return json(response, 409, {
                        error: `Block ${blockId} cannot be reduced below ${Number(overbookedEvent.assigned).toLocaleString("en-KE")} tickets already assigned to ${overbookedEvent.home_team} vs ${overbookedEvent.away_team}.`
                    });
                }
            }
            const events = database.prepare("SELECT id, home_team, away_team, categories FROM events").all();
            const overCapacityEvent = events.find((event) => {
                const eventAllocation = JSON.parse(event.categories).reduce(
                    (sum, category) => sum + Number(category.allocation || 0), 0
                );
                return eventAllocation > total;
            });
            if (overCapacityEvent) {
                return json(response, 409, {
                    error: `Block capacity cannot be reduced below the ${Number(JSON.parse(overCapacityEvent.categories).reduce((sum, category) => sum + Number(category.allocation || 0), 0)).toLocaleString("en-KE")} tickets allocated to ${overCapacityEvent.home_team} vs ${overCapacityEvent.away_team}. Reduce that event's allocations first.`
                });
            }
            const update = database.prepare(`
                UPDATE stadium_blocks SET capacity = ?, updated_by = ?, updated_at = ? WHERE block_id = ?
            `);
            const updatedAt = new Date().toISOString();
            database.exec("BEGIN IMMEDIATE");
            try {
                for (const blockId of stadiumBlockIds) {
                    update.run(submitted.get(blockId), administrator.id, updatedAt, blockId);
                }
                database.exec("COMMIT");
            } catch (error) {
                database.exec("ROLLBACK");
                throw error;
            }
            const blocks = database.prepare(
                "SELECT block_id AS id, name, capacity FROM stadium_blocks ORDER BY block_id"
            ).all();
            database.prepare(`
                INSERT INTO admin_audit_logs (id, administrator_id, action, details, created_at)
                VALUES (?, ?, ?, ?, ?)
            `).run(randomUUID(), administrator.id, "stadium.blocks.updated", JSON.stringify({ blocks }), updatedAt);
            return json(response, 200, {
                capacityLimit: stadiumCapacityLimit,
                configuredCapacity: total,
                unassignedCapacity: stadiumCapacityLimit - total,
                blocks
            });
        }

        if (pathname === "/api/admin/audit" && request.method === "GET") {
            requireAdministrator(request);
            const entries = database.prepare(`
                SELECT logs.id, admins.name AS actor, logs.action, logs.details, logs.created_at AS createdAt
                FROM admin_audit_logs AS logs
                LEFT JOIN administrators AS admins ON admins.id = logs.administrator_id
                ORDER BY logs.created_at DESC
                LIMIT 200
            `).all();
            return json(response, 200, { entries });
        }

        if (pathname === "/api/admin/dashboard" && request.method === "GET") {
            requireAdministrator(request);
            const totalEvents = Number(database.prepare("SELECT COUNT(*) AS count FROM events").get().count);
            const publishedEvents = Number(database.prepare(
                "SELECT COUNT(*) AS count FROM events WHERE status = 'published' AND kickoff > ?"
            ).get(new Date().toISOString()).count);
            const totalCustomers = Number(database.prepare("SELECT COUNT(*) AS count FROM customers").get().count);
            const ticketsIssued = Number(database.prepare("SELECT COUNT(*) AS count FROM issued_tickets").get().count);
            return json(response, 200, {
                metrics: { totalEvents, publishedEvents, totalCustomers, ticketsIssued }
            });
        }

        if (pathname === "/api/admin/revenue" && request.method === "GET") {
            requireAdministrator(request);
            const paid = database.prepare(`
                SELECT COUNT(*) AS paidBookings,
                    COALESCE(SUM(total_amount), 0) AS grossPaidKes,
                    COALESCE(SUM(quantity), 0) AS paidTickets
                FROM customer_bookings WHERE status = 'PAID' AND payment_status = 'SUCCESSFUL'
            `).get();
            const pending = Number(database.prepare(
                "SELECT COUNT(*) AS count FROM customer_bookings WHERE status = 'PENDING'"
            ).get().count);
            const byProvider = database.prepare(`
                SELECT provider, SUM(total_amount) AS amountKes, COUNT(*) AS bookings
                FROM customer_bookings WHERE status = 'PAID' AND payment_status = 'SUCCESSFUL'
                GROUP BY provider ORDER BY amountKes DESC
            `).all().map((row) => ({ ...row, amountKes: Number(row.amountKes), bookings: Number(row.bookings) }));
            const byCategory = database.prepare(`
                SELECT category_name AS category, SUM(total_amount) AS amountKes,
                    SUM(quantity) AS tickets
                FROM customer_bookings WHERE status = 'PAID' AND payment_status = 'SUCCESSFUL'
                GROUP BY category_name ORDER BY amountKes DESC
            `).all().map((row) => ({ ...row, amountKes: Number(row.amountKes), tickets: Number(row.tickets) }));
            const b2cConfigured = mpesaB2cConfiguration().configured;
            const payout = payoutAvailability();
            const recentOperations = database.prepare(`
                SELECT id, operation_type AS type, amount_kes AS amountKes,
                    recipient_phone AS recipientPhone, status, transaction_id AS transactionId,
                    result_description AS resultDescription, created_at AS createdAt, updated_at AS updatedAt
                FROM mpesa_b2c_operations ORDER BY created_at DESC LIMIT 10
            `).all();
            const withdrawalStatus = !b2cConfigured
                ? "M-Pesa B2C payout credentials and public callback are not configured."
                : !payout.balanceFresh
                    ? "Refresh the B2C utility balance. It must be confirmed within the last five minutes before withdrawal."
                    : payout.withdrawableKes < 10
                        ? "No amount of at least KES 10 is currently available within verified ticket sales and B2C limits."
                        : `Available amount is capped by confirmed ticket sales, the B2C utility balance, and Safaricom limits. Balance checked ${payout.balanceUpdatedAt}.`;
            return json(response, 200, {
                verified: {
                    paidBookings: Number(paid.paidBookings),
                    paidTickets: Number(paid.paidTickets),
                    grossPaidKes: Number(paid.grossPaidKes),
                    pendingPayments: pending
                },
                byProvider,
                byCategory,
                payoutConfigured: b2cConfigured,
                ...payout,
                withdrawableKes: b2cConfigured && payout.balanceFresh ? payout.withdrawableKes : null,
                withdrawalStatus,
                recentOperations
            });
        }

        if (pathname === "/api/admin/payments" && request.method === "GET") {
            requireAdministrator(request);
            const payments = database.prepare(`
                SELECT bookings.reference, bookings.provider, bookings.category_name AS category,
                    bookings.quantity, bookings.total_amount AS amountKes,
                    bookings.status AS bookingStatus, bookings.payment_status AS paymentStatus,
                    bookings.mpesa_receipt AS receipt, bookings.created_at AS createdAt,
                    customers.full_name AS customerName, customers.email AS customerEmail,
                    events.home_team AS homeTeam, events.away_team AS awayTeam
                FROM customer_bookings AS bookings
                JOIN customers ON customers.id = bookings.customer_id
                JOIN events ON events.id = bookings.event_id
                ORDER BY bookings.created_at DESC LIMIT 500
            `).all();
            return json(response, 200, { payments });
        }

        if (pathname === "/api/admin/revenue/balance" && request.method === "POST") {
            const administrator = requireAdministrator(request);
            const operation = await startMpesaBalanceQuery(administrator.id);
            return json(response, operation.status === "FAILED" ? 502 : 202, {
                operation,
                message: operation.status === "PENDING"
                    ? "M-Pesa balance query submitted; waiting for Safaricom's callback."
                    : "Balance query result is uncertain. Check the operation status before retrying."
            });
        }

        const payoutOperationMatch = pathname.match(/^\/api\/admin\/revenue\/operations\/([^/]+)$/);
        if (payoutOperationMatch && request.method === "GET") {
            requireAdministrator(request);
            const operation = database.prepare(`
                SELECT id, operation_type AS type, amount_kes AS amountKes,
                    recipient_phone AS recipientPhone, status, transaction_id AS transactionId,
                    result_description AS resultDescription, utility_balance_kes AS utilityBalanceKes,
                    created_at AS createdAt, updated_at AS updatedAt
                FROM mpesa_b2c_operations WHERE id = ?
            `).get(decodeURIComponent(payoutOperationMatch[1]));
            if (!operation) return json(response, 404, { error: "M-Pesa operation not found." });
            return json(response, 200, { operation });
        }

        if (pathname === "/api/admin/revenue/withdraw-mpesa" && request.method === "POST") {
            const administrator = requireAdministrator(request);
            if (!mpesaB2cConfiguration().configured) {
                return json(response, 503, { error: "M-Pesa B2C is not configured." });
            }
            const body = requireObject(await readBody(request));
            const phone = normalizeMpesaPhone(body.phone);
            const operationId = crypto.randomUUID();
            const originatorId = mpesaB2cOriginatorId();
            const now = new Date().toISOString();
            let amount;
            database.exec("BEGIN IMMEDIATE");
            try {
                const active = Number(database.prepare(`
                    SELECT COUNT(*) AS count FROM mpesa_b2c_operations
                    WHERE operation_type = 'PAYOUT' AND status IN ('PENDING','UNKNOWN')
                `).get().count);
                if (active) {
                    database.exec("ROLLBACK");
                    return json(response, 409, { error: "A prior B2C withdrawal is still unresolved. Wait for its callback before starting another." });
                }
                const availability = payoutAvailability();
                if (!availability.balanceFresh) {
                    database.exec("ROLLBACK");
                    return json(response, 409, { error: "Refresh the B2C balance and wait for Safaricom's confirmation before withdrawing." });
                }
                amount = availability.withdrawableKes;
                if (!Number.isSafeInteger(amount) || amount < 10) {
                    database.exec("ROLLBACK");
                    return json(response, 409, { error: "No withdrawable amount is currently available." });
                }
                database.prepare(`
                    INSERT INTO mpesa_b2c_operations
                        (id, originator_id, operation_type, amount_kes, recipient_phone,
                         status, initiated_by, created_at, updated_at)
                    VALUES (?, ?, 'PAYOUT', ?, ?, 'PENDING', ?, ?, ?)
                `).run(operationId, originatorId, amount, phone, administrator.id, now, now);
                database.exec("COMMIT");
            } catch (error) {
                database.exec("ROLLBACK");
                throw error;
            }

            try {
                const config = mpesaB2cConfiguration();
                const responseFromProvider = await mpesaPost("/mpesa/b2c/v3/paymentrequest", {
                    OriginatorConversationID: originatorId,
                    InitiatorName: process.env.MPESA_B2C_INITIATOR,
                    SecurityCredential: process.env.MPESA_B2C_SECURITY_CREDENTIAL,
                    CommandID: "BusinessPayment",
                    Amount: amount,
                    PartyA: process.env.MPESA_B2C_SHORTCODE,
                    PartyB: phone,
                    Remarks: `Talanta Stadium withdrawal ${originatorId}`,
                    QueueTimeOutURL: config.callback,
                    ResultURL: config.callback
                });
                if (String(responseFromProvider.ResponseCode) !== "0" ||
                    responseFromProvider.OriginatorConversationID !== originatorId) {
                    database.prepare(`
                        UPDATE mpesa_b2c_operations SET status = 'FAILED',
                            result_description = ?, updated_at = ? WHERE id = ? AND status = 'PENDING'
                    `).run("Daraja rejected the B2C payout request.", new Date().toISOString(), operationId);
                    return json(response, 502, { error: "Daraja did not accept the withdrawal request." });
                }
            } catch (error) {
                const status = error.definitive ? "FAILED" : "UNKNOWN";
                database.prepare(`
                    UPDATE mpesa_b2c_operations SET status = ?, result_description = ?, updated_at = ?
                    WHERE id = ? AND status = 'PENDING'
                `).run(status, String(error.message || "B2C result is uncertain.").slice(0, 400),
                    new Date().toISOString(), operationId);
                const operation = database.prepare(
                    "SELECT id, amount_kes AS amountKes, recipient_phone AS recipientPhone, status FROM mpesa_b2c_operations WHERE id = ?"
                ).get(operationId);
                return json(response, 202, {
                    operation,
                    message: status === "UNKNOWN"
                        ? "Withdrawal status is uncertain. It remains reserved; do not retry until Safaricom reports its result."
                        : "Safaricom rejected the withdrawal request."
                });
            }
            const operation = database.prepare(`
                SELECT id, amount_kes AS amountKes, recipient_phone AS recipientPhone,
                    status, created_at AS createdAt FROM mpesa_b2c_operations WHERE id = ?
            `).get(operationId);
            return json(response, 202, {
                operation,
                message: `Withdrawal request for KES ${amount.toLocaleString("en-KE")} was accepted for processing; final status arrives by callback.`
            });
        }

        if (pathname === "/api/admin/customers" && request.method === "GET") {
            requireAdministrator(request);
            const query = (url.searchParams.get("q") || "").trim().slice(0, 100);
            const search = `%${query}%`;
            const customers = database.prepare(`
                SELECT id, full_name AS fullName, email, phone, created_at AS createdAt
                FROM customers
                WHERE ? = '' OR full_name LIKE ? OR email LIKE ? OR phone LIKE ?
                ORDER BY created_at DESC LIMIT 100
            `).all(query, search, search, search);
            return json(response, 200, { customers, limit: 100 });
        }

        if (pathname === "/api/admin/messages" && request.method === "GET") {
            requireAdministrator(request);
            const query = (url.searchParams.get("q") || "").trim().slice(0, 100);
            const search = `%${query}%`;
            const customers = database.prepare(`
                SELECT customers.id, customers.full_name AS fullName, customers.email, customers.phone,
                    (SELECT body FROM support_messages
                     WHERE customer_id = customers.id ORDER BY created_at DESC, id DESC LIMIT 1) AS latestMessage,
                    (SELECT sender_type FROM support_messages
                     WHERE customer_id = customers.id ORDER BY created_at DESC, id DESC LIMIT 1) AS latestSender,
                    (SELECT created_at FROM support_messages
                     WHERE customer_id = customers.id ORDER BY created_at DESC, id DESC LIMIT 1) AS lastMessageAt,
                    (SELECT COUNT(*) FROM support_messages
                     WHERE customer_id = customers.id AND sender_type = 'customer' AND read_at IS NULL) AS unreadCount
                FROM customers
                WHERE ? = '' OR customers.full_name LIKE ? OR customers.email LIKE ? OR customers.phone LIKE ?
                ORDER BY COALESCE(lastMessageAt, customers.created_at) DESC
                LIMIT 100
            `).all(query, search, search, search);
            return json(response, 200, { customers, limit: 100 });
        }

        if (adminMessageThreadMatch && request.method === "GET") {
            requireAdministrator(request);
            const customerId = decodeURIComponent(adminMessageThreadMatch[1]);
            const customer = database.prepare(`
                SELECT id, full_name AS fullName, email, phone
                FROM customers WHERE id = ?
            `).get(customerId);
            if (!customer) return json(response, 404, { error: "Customer account not found." });
            const now = new Date().toISOString();
            database.prepare(`
                UPDATE support_messages SET read_at = ?
                WHERE customer_id = ? AND sender_type = 'customer' AND read_at IS NULL
            `).run(now, customerId);
            const messages = database.prepare(`
                SELECT id, sender_type AS sender, body, created_at AS createdAt, read_at AS readAt
                FROM support_messages WHERE customer_id = ?
                ORDER BY created_at DESC, id DESC LIMIT 500
            `).all(customerId).reverse();
            return json(response, 200, { customer, messages });
        }

        if (adminMessageThreadMatch && request.method === "POST") {
            const administrator = requireAdministrator(request);
            const customerId = decodeURIComponent(adminMessageThreadMatch[1]);
            const customer = database.prepare("SELECT id FROM customers WHERE id = ?").get(customerId);
            if (!customer) return json(response, 404, { error: "Customer account not found." });
            const body = requireObject(await readBody(request));
            const message = normalizeText(body.message, "Message", 2000);
            const id = randomUUID();
            const createdAt = new Date().toISOString();
            database.prepare(`
                INSERT INTO support_messages
                    (id, customer_id, sender_type, sender_admin_id, body, created_at)
                VALUES (?, ?, 'admin', ?, ?, ?)
            `).run(id, customerId, administrator.id, message, createdAt);
            database.prepare(`
                INSERT INTO admin_audit_logs (id, administrator_id, action, details, created_at)
                VALUES (?, ?, 'support.message_sent', ?, ?)
            `).run(id, administrator.id, JSON.stringify({ customerId, messageId: id }), createdAt);
            return json(response, 201, {
                message: { id, sender: "admin", body: message, createdAt, readAt: null }
            });
        }

        if (pathname === "/api/admin/booking-overrides" && request.method === "POST") {
            const administrator = requireAdministrator(request);
            const body = requireObject(await readBody(request));
            const email = normalizeText(body.email, "Customer email", 254).toLowerCase();
            const eventId = normalizeText(body.eventId, "Event", 80);
            const hours = Number(body.hours);
            if (!Number.isSafeInteger(hours) || hours < 1 || hours > 72) {
                return json(response, 400, { error: "Override duration must be between 1 and 72 hours." });
            }
            const customer = database.prepare("SELECT id, email FROM customers WHERE email = ? COLLATE NOCASE").get(email);
            if (!customer) return json(response, 404, { error: "Customer account not found." });
            const event = database.prepare("SELECT id, kickoff, status FROM events WHERE id = ?").get(eventId);
            if (!event || event.status !== "published" || Date.parse(event.kickoff) <= Date.now()) {
                return json(response, 409, { error: "Override requires a published event that has not started." });
            }
            const createdAt = Date.now();
            const expiresAt = Math.min(createdAt + hours * 60 * 60 * 1000, Date.parse(event.kickoff));
            const overrideId = crypto.randomUUID();
            database.prepare(`
                INSERT INTO customer_booking_overrides
                    (id, customer_id, event_id, granted_by, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(overrideId, customer.id, event.id, administrator.id,
                expiresAt, new Date(createdAt).toISOString());
            return json(response, 201, {
                override: { id: overrideId, customerEmail: customer.email, eventId, expiresAt },
                message: `Booking access granted until ${new Date(expiresAt).toISOString()}.`
            });
        }

        if (pathname === "/api/admin/booking-overrides/revoke" && request.method === "POST") {
            const administrator = requireAdministrator(request);
            const body = requireObject(await readBody(request));
            const customerEmail = normalizeText(body.email, "Customer email", 254).toLowerCase();
            const eventId = normalizeText(body.eventId, "Event", 80);
            const result = database.prepare(`
                UPDATE customer_booking_overrides SET revoked_at = ?, revoked_by = ?
                WHERE customer_id = (SELECT id FROM customers WHERE email = ? COLLATE NOCASE)
                    AND event_id = ? AND revoked_at IS NULL AND expires_at > ?
            `).run(Date.now(), administrator.id, customerEmail, eventId, Date.now());
            return json(response, 200, { revoked: Number(result.changes) });
        }

        if (pathname === "/api/admin/bootstrap" && request.method === "POST") {
            if (Number(database.prepare("SELECT COUNT(*) AS count FROM administrators").get().count) !== 0) {
                return json(response, 409, { error: "Administrator setup has already been completed." });
            }
            const body = requireObject(await readBody(request));
            const name = normalizeText(body.name, "Name", 120);
            const email = normalizeText(body.email, "Email", 254).toLowerCase();
            const password = typeof body.password === "string" ? body.password : "";
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                return json(response, 400, { error: "Enter a valid email address." });
            }
            if (password.length < 12 || password.length > 200) {
                return json(response, 400, { error: "Password must be at least 12 characters." });
            }

            const id = crypto.randomUUID();
            const salt = crypto.randomBytes(16).toString("hex");
            const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");
            database.exec("BEGIN IMMEDIATE");
            try {
                if (Number(database.prepare("SELECT COUNT(*) AS count FROM administrators").get().count) !== 0) {
                    database.exec("ROLLBACK");
                    return json(response, 409, { error: "Administrator setup has already been completed." });
                }
                database.prepare(`
                    INSERT INTO administrators (id, name, email, salt, password_hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                `).run(id, name, email, salt, passwordHash, new Date().toISOString());
                database.exec("COMMIT");
            } catch (error) {
                database.exec("ROLLBACK");
                if (error.code === "ERR_SQLITE_CONSTRAINT_UNIQUE") {
                    return json(response, 409, { error: "An administrator with that email already exists." });
                }
                throw error;
            }
            const session = createSession(id);
            return json(response, 201, { administrator: { id, name, email } }, {
                "Set-Cookie": session.cookie
            });
        }

        if (pathname === "/api/admin/login" && request.method === "POST") {
            const body = requireObject(await readBody(request));
            const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
            const password = typeof body.password === "string" ? body.password : "";
            if (password.length === 0 || password.length > 200) {
                return json(response, 401, { error: "Email or password is incorrect." });
            }
            const administrator = database.prepare(
                "SELECT id, name, email, salt, password_hash FROM administrators WHERE email = ?"
            ).get(email);
            const salt = administrator ? administrator.salt : "talantapass-invalid-login";
            const storedHash = administrator
                ? Buffer.from(administrator.password_hash, "hex")
                : Buffer.alloc(64);
            const passwordHash = crypto.scryptSync(password, salt, 64);
            if (!administrator || !crypto.timingSafeEqual(storedHash, passwordHash)) {
                return json(response, 401, { error: "Email or password is incorrect." });
            }
            const session = createSession(administrator.id);
            return json(response, 200, {
                administrator: { id: administrator.id, name: administrator.name, email: administrator.email }
            }, { "Set-Cookie": session.cookie });
        }

        if (pathname === "/api/admin/logout" && request.method === "POST") {
            const token = getCookie(request, sessionCookie);
            if (token) {
                database.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").run(hashToken(token));
            }
            return json(response, 200, { signedOut: true }, {
                "Set-Cookie": `${sessionCookie}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`
            });
        }

        if (addSeatsPath && request.method === "POST") {
            const administrator = requireAdministrator(request);
            const eventId = decodeURIComponent(addSeatsPath[1]);
            const body = requireObject(await readBody(request));
            const categoryId = String(body.categoryId || "").trim().toLowerCase();
            const seatsToAdd = Number(body.seats);
            if (!standardTicketCategories.some((category) => category.id === categoryId)) {
                return json(response, 400, { error: "Choose Regular, VIP, or VVIP." });
            }
            if (!Number.isSafeInteger(seatsToAdd) || seatsToAdd < 1) {
                return json(response, 400, { error: "Enter a positive whole number of seats to add." });
            }
            database.exec("BEGIN IMMEDIATE");
            try {
                const row = database.prepare("SELECT * FROM events WHERE id = ?").get(eventId);
                if (!row) {
                    database.exec("ROLLBACK");
                    return json(response, 404, { error: "Event not found." });
                }
                const categories = standardizeTicketCategories(JSON.parse(row.categories));
                const category = categories.find((item) => item.id === categoryId);
                const currentTotal = categories.reduce((sum, item) => sum + Number(item.allocation || 0), 0);
                const stadiumCapacity = configuredStadiumCapacity();
                const availableCapacity = Math.max(0, stadiumCapacity - currentTotal);
                if (seatsToAdd > availableCapacity) {
                    database.exec("ROLLBACK");
                    return json(response, 409, {
                        error: `Only ${availableCapacity.toLocaleString("en-KE")} unallocated stadium seats remain. Increase block capacity first if more space is available.`
                    });
                }
                category.allocation = Number(category.allocation || 0) + seatsToAdd;
                const updatedAt = new Date().toISOString();
                database.prepare("UPDATE events SET categories = ?, updated_at = ? WHERE id = ?")
                    .run(JSON.stringify(categories), updatedAt, eventId);
                database.prepare(`
                    INSERT INTO admin_audit_logs (id, administrator_id, action, details, created_at)
                    VALUES (?, ?, ?, ?, ?)
                `).run(randomUUID(), administrator.id, "event.seats.added", JSON.stringify({
                    eventId, categoryId, seatsAdded: seatsToAdd, newAllocation: category.allocation
                }), updatedAt);
                database.exec("COMMIT");
            } catch (error) {
                database.exec("ROLLBACK");
                throw error;
            }
            const updatedRow = database.prepare("SELECT * FROM events WHERE id = ?").get(eventId);
            const updatedEvent = eventFromRow(updatedRow);
            updatedEvent.categories = updatedEvent.categories.map((item) => ({
                ...item,
                ...categoryAvailability(updatedRow, item)
            }));
            return json(response, 200, { event: updatedEvent });
        }

        if (adminEventsPath) {
            requireAdministrator(request);
            if (request.method === "GET" && !adminEventsPath.eventId) {
                const events = database.prepare("SELECT * FROM events ORDER BY kickoff ASC")
                    .all().map((row) => {
                        const event = eventFromRow(row);
                        event.categories = event.categories.map((category) => ({
                            ...category,
                            ...categoryAvailability(row, category)
                        }));
                        return event;
                    });
                return json(response, 200, { events });
            }
            if (request.method === "POST" && !adminEventsPath.eventId) {
                const event = await eventInput(request, null);
                return json(response, 201, { event });
            }
            if (request.method === "PUT" && adminEventsPath.eventId) {
                const event = await eventInput(request, adminEventsPath.eventId);
                return json(response, 200, { event });
            }
            if (request.method === "DELETE" && adminEventsPath.eventId) {
                const result = database.prepare("DELETE FROM events WHERE id = ?").run(adminEventsPath.eventId);
                if (Number(result.changes) === 0) {
                    return json(response, 404, { error: "Event not found." });
                }
                return json(response, 200, { deleted: true });
            }
            return json(response, 405, { error: "Method not allowed." }, {
                Allow: adminEventsPath.eventId ? "PUT, DELETE" : "GET, POST"
            });
        }

        if (pathname === "/api/events" && request.method === "GET") {
            const now = new Date().toISOString();
            const customer = getCustomer(request);
            const events = database.prepare(`
                SELECT * FROM events
                WHERE status = 'published' AND kickoff > ?
                ORDER BY kickoff ASC
            `).all(now).map((row) => {
                const event = publicEventFromRow(row, customer?.id || null);
                return {
                    ...event,
                    status: "PUBLISHED",
                    isSoldOut: event.soldOut
                };
            });
            return json(response, 200, { events });
        }

        const publicEventMatch = pathname.match(/^\/api\/events\/([^/]+)$/);
        if (publicEventMatch && request.method === "GET") {
            const id = decodeURIComponent(publicEventMatch[1]);
            const customer = getCustomer(request);
            const row = database.prepare(
                "SELECT * FROM events WHERE id = ? AND status = 'published'"
            ).get(id);
            if (!row) {
                return json(response, 404, { error: "Published event not found." });
            }
            const event = publicEventFromRow(row, customer?.id || null);
            return json(response, 200, {
                ...event,
                status: "upcoming"
            });
        }

        return json(response, 404, { error: "API endpoint not found." });
    } catch (error) {
        if (error.status) {
            return json(response, error.status, { error: error.message });
        }
        console.error("API request failed:", error);
        return json(response, 500, { error: "The server could not complete the request." });
    }
}

const server = http.createServer(async (request, response) => {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "same-origin");

    let url;
    try {
        url = new URL(request.url, `http://${request.headers.host || "127.0.0.1"}`);
    } catch {
        response.writeHead(400).end("Invalid URL");
        return;
    }

    if (url.pathname.startsWith("/api/")) {
        await handleApi(request, response, url);
        return;
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
        response.writeHead(405, { Allow: "GET, HEAD" }).end("Method not allowed");
        return;
    }

    let pathname;
    try {
        pathname = decodeURIComponent(url.pathname);
    } catch {
        response.writeHead(400).end("Invalid URL");
        return;
    }

    if (pathname === "/") {
        pathname = "/index.html";
    }

    const filePath = path.resolve(root, `.${pathname}`);
    const relativePath = path.relative(root, filePath);
    if (relativePath === ".." ||
        relativePath.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relativePath)) {
        response.writeHead(403).end("Forbidden");
        return;
    }
    const topLevel = relativePath.split(path.sep)[0].toLowerCase();
    if (topLevel === ".env" || topLevel === ".git" || topLevel === "data" || topLevel === "backend") {
        response.writeHead(404).end("Not found");
        return;
    }

    fs.stat(filePath, (error, stats) => {
        if (error || !stats.isFile()) {
            response.writeHead(404).end("Not found");
            return;
        }
        response.writeHead(200, {
            "Cache-Control": "no-cache",
            "Content-Type": mimeTypes[path.extname(filePath).toLowerCase()] ||
                "application/octet-stream"
        });
        if (request.method === "HEAD") {
            response.end();
            return;
        }
        fs.createReadStream(filePath).pipe(response);
    });
});

server.listen(port, "127.0.0.1", () => {
    console.log(`Talanta Stadium customer site: http://127.0.0.1:${port}/`);
    console.log(`Talanta Stadium administration: http://127.0.0.1:${port}/admin.html`);
    console.log(`SQLite database: ${databasePath}`);
    retryTicketEmails().catch(() => {});
});

const ticketEmailRetryTimer = setInterval(() => {
    retryTicketEmails().catch(() => {});
}, 60 * 1000);
ticketEmailRetryTimer.unref();

function shutdown() {
    clearInterval(ticketEmailRetryTimer);
    server.close(() => {
        database.close();
        process.exit(0);
    });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
