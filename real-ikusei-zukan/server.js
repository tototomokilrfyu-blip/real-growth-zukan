"use strict";
const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const ROOT = __dirname;
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 4173);
const NODE_ENV = process.env.NODE_ENV || "development";
const API_KEY = process.env.STEPS_API_KEY || "";
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const REQUIRE_HTTPS = process.env.REQUIRE_HTTPS === "1";
const TIME_ZONE = process.env.APP_TIME_ZONE || "Asia/Tokyo";
const DATA_FILE = path.resolve(process.env.STEP_DATA_FILE || path.join(ROOT, "steps-data.json"));
const MAX_STEPS = 100000;
const MAX_BODY_BYTES = 1024;
const origins = new Set((process.env.CORS_ORIGINS || "").split(",").map(x => x.trim()).filter(Boolean));

function isLoopback(host) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}
if (!Number.isInteger(PORT) || PORT < 0 || PORT > 65535) throw new Error("PORT must be a valid port number.");
if ([...origins].some(origin => origin === "*" || !/^https:\/\//i.test(origin))) throw new Error("CORS_ORIGINS must contain exact HTTPS origins only.");
if (!isLoopback(HOST) && API_KEY.length < 32) throw new Error("A 32-character STEPS_API_KEY is required when binding outside localhost.");
if (NODE_ENV === "production" && (API_KEY.length < 32 || !TRUST_PROXY || !REQUIRE_HTTPS)) throw new Error("Production requires STEPS_API_KEY, TRUST_PROXY=1, and REQUIRE_HTTPS=1 behind an HTTPS proxy.");

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(body), "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extraHeaders });
  res.end(body);
}
function dateKey(date = new Date()) {
  return new Intl.DateTimeFormat("en-CA", { timeZone: TIME_ZONE, year: "numeric", month: "2-digit", day: "2-digit" }).format(date);
}
function isHttps(req) { return Boolean(req.socket.encrypted) || (TRUST_PROXY && req.headers["x-forwarded-proto"] === "https"); }
function ownOrigin(req) { const protocol = isHttps(req) ? "https" : "http"; const host = req.headers.host || ""; return host ? protocol + "://" + host : ""; }
function applyCors(req, res) {
  const origin = req.headers.origin;
  res.setHeader("Vary", "Origin");
  if (!origin) return;
  if (origin !== ownOrigin(req) && !origins.has(origin)) throw new HttpError(403, "Origin is not allowed.");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "600");
}
function sameOriginRead(req) {
  if (req.headers["sec-fetch-site"] === "same-origin") return true;
  return Boolean(req.headers.origin && req.headers.origin === ownOrigin(req));
}
function hasApiKey(req) {
  if (!API_KEY) return NODE_ENV !== "production" && isLoopback(HOST);
  const header = req.headers.authorization || "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) return false;
  const actual = Buffer.from(header.slice(prefix.length));
  const expected = Buffer.from(API_KEY);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
async function readJson(req) {
  const mediaType = (req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (mediaType !== "application/json" && !mediaType.endsWith("+json")) throw new HttpError(415, "Content-Type must be application/json.");
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, "Request body is too large.");
    chunks.push(chunk);
  }
  let value;
  try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new HttpError(400, "Request body must contain valid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "JSON body must be an object.");
  if (!Object.prototype.hasOwnProperty.call(value, "steps")) throw new HttpError(400, "steps is required.");
  if (typeof value.steps !== "number" || !Number.isFinite(value.steps) || !Number.isInteger(value.steps) || value.steps < 0) throw new HttpError(422, "steps must be a non-negative integer.");
  if (value.steps > MAX_STEPS) throw new HttpError(422, "steps is above the accepted daily limit.");
  return value.steps;
}
async function readDatabase() {
  try {
    const raw = JSON.parse(await fs.readFile(DATA_FILE, "utf8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid store");
    const records = {};
    for (const [date, item] of Object.entries(raw)) {
      if (/^\d{4}-\d{2}-\d{2}$/.test(date) && item && item.date === date && Number.isInteger(item.steps) && item.steps >= 0 && item.steps <= MAX_STEPS && typeof item.receivedAt === "string") records[date] = item;
    }
    return records;
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw new Error("store unavailable");
  }
}
async function writeDatabase(records) {
  const keep = Object.fromEntries(Object.entries(records).sort(([a], [b]) => a.localeCompare(b)).slice(-366));
  const temp = DATA_FILE + "." + process.pid + ".tmp";
  await fs.mkdir(path.dirname(DATA_FILE), { recursive: true });
  await fs.writeFile(temp, JSON.stringify(keep), { encoding: "utf8", mode: 0o600 });
  await fs.rename(temp, DATA_FILE);
  return keep;
}
async function serveFile(res, name) {
  const mime = { "index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8" }[name];
  try {
    const body = await fs.readFile(path.join(ROOT, name));
    res.writeHead(200, { "Content-Type": mime, "Content-Length": body.length, "Cache-Control": name === "index.html" ? "no-cache" : "no-cache", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'" });
    res.end(body);
  } catch { sendJson(res, 404, { success: false, error: "Not found." }); }
}
async function handle(req, res) {
  try {
    const url = new URL(req.url, ownOrigin(req) || "http://localhost");
    if (REQUIRE_HTTPS && !isHttps(req)) throw new HttpError(426, "HTTPS is required.");
    if (url.pathname === "/api/steps") {
      applyCors(req, res);
      if (req.method === "OPTIONS") { res.writeHead(204, { "Cache-Control": "no-store" }); return res.end(); }
      if (req.method === "POST") {
        if (!hasApiKey(req)) throw new HttpError(401, "A valid API key is required.");
        const steps = await readJson(req);
        const date = dateKey();
        const db = await readDatabase();
        db[date] = { date, steps, receivedAt: new Date().toISOString() };
        const saved = await writeDatabase(db);
        return sendJson(res, 200, { success: true, date, steps, receivedAt: saved[date].receivedAt });
      }
      if (req.method === "GET") {
        if (!sameOriginRead(req)) throw new HttpError(403, "Same-origin access is required.");
        const date = url.searchParams.get("date") || dateKey();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new HttpError(400, "date must use YYYY-MM-DD format.");
        const db = await readDatabase();
        const record = db[date] || null;
        return sendJson(res, 200, { success: true, date, steps: record ? record.steps : null, receivedAt: record ? record.receivedAt : null, record, developmentTestEnabled: NODE_ENV !== "production" && !API_KEY && isLoopback(HOST) });
      }
      res.setHeader("Allow", "GET, POST, OPTIONS");
      throw new HttpError(405, "Method not allowed.");
    }
    if (req.method === "GET" && ["/", "/index.html"].includes(url.pathname)) return serveFile(res, "index.html");
    if (req.method === "GET" && ["/app.js", "/style.css"].includes(url.pathname)) return serveFile(res, url.pathname.slice(1));
    throw new HttpError(404, "Not found.");
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    if (status === 500) console.error("Request failed.");
    if (!res.headersSent) sendJson(res, status, { success: false, error: error instanceof HttpError ? error.message : "The request could not be completed." });
    else res.destroy();
  }
}
const server = http.createServer((req, res) => { handle(req, res); });
server.listen(PORT, HOST, () => {
  const address = server.address();
  console.log(JSON.stringify({ event: "listening", host: HOST, port: address.port, environment: NODE_ENV }));
});
