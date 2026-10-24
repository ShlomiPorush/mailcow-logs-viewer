#!/usr/bin/env node
/*
 * mailcow-logs for agents: connect with a code a person approves (OAuth device flow, RFC 8628), then read and act on
 * mailcow Logs Viewer through its REST API, within what the person allowed.
 *
 * One of three versions with one contract: mailcow-logs.mjs (Node 20+), mailcow-logs.ps1 (Windows PowerShell 5.1+)
 * and mailcow-logs.sh (POSIX sh and curl). Same commands, same JSON output and error codes, same files and the same
 * lock, so they can run side by side on one computer. Tokens never appear in the output.
 *
 * The refresh token rotates on every use, and the server ends the connection when one is used twice. So every
 * change to the connection's file and every request that spends a one-time secret runs under one lock, the
 * access token is reused until a minute before it runs out, and a refresh whose answer was lost is retried once.
 *
 * An action (an endpoint whose kind is act, whatever its HTTP method) is never sent twice: when its answer is lost
 * or the server failed after it may have started, the answer is outcome_unknown. Kinds come from the server's own
 * list (agent/endpoints), kept per connection; an endpoint not on the list counts as an action.
 */
import { execFileSync } from "node:child_process"
import { createHash, randomBytes } from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

// Filled in with the mailcow Logs Viewer address when the file is downloaded from it.
const DEFAULT_URL = "__MAILCOW_LOGS_URL__"
const CLIENT_ID = "mailcow-logs-cli"
const SCOPE =
  "status:read status:write messages:read outbound:read outbound:write quarantine:read quarantine:write " +
  "security:read security:write rspamd:read rspamd:write dmarc:read dmarc:write domains:read domains:write " +
  "mailboxes:read mailboxes:write logs:read settings:read"
const WAIT_SECONDS = Number(process.env.MAILCOW_LOGS_WAIT_SECONDS) || 90
// A pending code is dropped locally only this long after its expiry: until then the server decides
// (an approved code can be collected for a few minutes after it expires)
const STALE_CODE_SECONDS = 600
const LOCK_WAIT_MS = Number(process.env.MAILCOW_LOGS_LOCK_WAIT_MS) || 20_000
const OAUTH_TIMEOUT_MS = 15_000
// The server answers an API call within 60 s (or says the outcome is unknown).
const API_TIMEOUT_MS = Number(process.env.MAILCOW_LOGS_TEST_API_TIMEOUT_MS) || 75_000
// RFC 8628: 5 seconds between polls unless the server says otherwise (tests shorten it).
const POLL_SECONDS = Number(process.env.MAILCOW_LOGS_TEST_POLL_SECONDS) || 5
// A refresh is retried only once it cannot be in flight any more: twice the request timeout (tests shorten it).
const REFRESH_GRACE = Number(process.env.MAILCOW_LOGS_TEST_REFRESH_GRACE ?? 30)
// Wait before the one retry of a call the server refused as busy (tests shorten it).
const BUSY_WAIT_MS = Number(process.env.MAILCOW_LOGS_TEST_BUSY_WAIT_MS ?? 2000)
const KINDS_MAX_AGE = 3600
const SECRET = /^[A-Za-z0-9._~+/=-]{1,4096}$/
// Every value in a connection file: no quote, backslash or control character, so the shell version reads it too.
// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point
const PLAIN = /^[^"\\\u0000-\u001f\u007f]*$/
const PATH_CHARS = /^[A-Za-z0-9._~!$&'()*+,;=:@/?%-]+$/
const TEMPLATE = /^\/api\/[A-Za-z0-9._~{}:/-]*$/
const UNKNOWN_OUTCOME = "The action may have run. Read its state before trying again."
const FIELDS = [
  ["v", "n"],
  ["issuer", "s"],
  ["label", "s"],
  ["generation", "s"],
  ["refreshToken", "s"],
  ["accessToken", "s"],
  ["accessExpiresAt", "n"],
  ["scope", "s"],
  ["refreshStartedAt", "n"],
  ["refreshRetried", "n"],
  ["deviceCode", "s"],
  ["userCode", "s"],
  ["link", "s"],
  ["deviceExpiresAt", "n"],
  ["interval", "n"],
  ["nextPollAt", "n"],
  ["toRevoke", "s"],
]
const win = process.platform === "win32"

class Fail extends Error {
  constructor(code, message, extra = {}) {
    super(message)
    this.code = code
    this.extra = extra
  }
}

const now = () => Math.floor(Date.now() / 1000)
const hex = (n) => randomBytes(n).toString("hex")
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const print = (value) => process.stdout.write(`${JSON.stringify(value)}\n`)
const host = () => (win ? process.env.COMPUTERNAME || os.hostname() : os.hostname())
const sameHost = (h) => String(h).toLowerCase() === host().toLowerCase()
// Windows tools by their full path: in Git Bash, for one, whoami is a different program.
const system32 = (exe) => path.join(process.env.SystemRoot || "C:\\Windows", "System32", exe)

const HELP = `mailcow-logs: use mailcow Logs Viewer after a person approves it.

  connect [--replace]   Ask to connect; prints a link and a code to show the person.
  connect --wait        Wait up to ${WAIT_SECONDS} s for the approval; run again while it answers still_waiting.
  access                What this connection may view or act on, and until when.
  endpoints [area]      The API calls this connection may make, with their kind (read or act).
  get <path>            GET /api/<path>, for example: get 'messages?limit=20'
  post|put|patch|delete <path> [--json <body> | --json-file <file>]
  status                Whether this agent is connected (no secrets).
  disconnect            End this agent's connection.

  --url <address>       The mailcow Logs Viewer address (or MAILCOW_LOGS_URL).`

async function main() {
  const args = process.argv.slice(2)
  const command = args.shift() ?? "help"
  const opts = { positional: [] }
  while (args.length) {
    const a = args.shift()
    if (a === "--url") opts.url = args.shift()
    else if (a === "--replace") opts.replace = true
    else if (a === "--wait") opts.wait = true
    else if (a === "--json") opts.json = args.shift()
    else if (a === "--json-file") opts.jsonFile = args.shift()
    else opts.positional.push(a)
  }
  if (command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(`${HELP}\n`)
    return
  }
  if (Number(process.versions.node.split(".")[0]) < 20)
    throw new Fail("node_too_old", "Node 20 or later is needed. Use mailcow-logs.ps1 or mailcow-logs.sh instead.")
  const ctx = context(opts.url)
  const first = opts.positional[0]
  if (command === "status") return status(ctx)
  if (command === "connect") return opts.wait ? waitForApproval(ctx) : connect(ctx, Boolean(opts.replace))
  if (command === "access") return api(ctx, "GET", "agent/access")
  if (command === "endpoints") {
    if (first !== undefined && !/^[a-z_]{1,40}$/.test(first)) throw new Fail("bad_path", "Give an area name, for example: security")
    return api(ctx, "GET", first === undefined ? "agent/endpoints" : `agent/endpoints?area=${first}`)
  }
  if (command === "get") return api(ctx, "GET", first)
  if (["post", "put", "patch"].includes(command)) return api(ctx, command.toUpperCase(), first, body(opts, "{}"))
  if (command === "delete") return api(ctx, "DELETE", first, body(opts, undefined))
  if (command === "disconnect") return disconnect(ctx)
  throw new Fail("unknown_command", `Unknown command "${command}". Run: mailcow-logs help`)
}

function body(opts, fallback) {
  if (opts.jsonFile !== undefined) {
    try {
      return fs.readFileSync(opts.jsonFile, "utf8")
    } catch {
      throw new Fail("bad_body", `Cannot read ${opts.jsonFile}.`)
    }
  }
  return opts.json ?? fallback
}

/** The app's address, this agent's identity (the folder it is installed in) and where its connection is kept. */
function context(urlOption) {
  const raw = urlOption || process.env.MAILCOW_LOGS_URL || (DEFAULT_URL.startsWith("__") ? "" : DEFAULT_URL)
  if (!raw)
    throw new Fail("no_url", "No mailcow Logs Viewer address. Pass --url https://<its address> or set MAILCOW_LOGS_URL.")
  let url
  try {
    url = new URL(raw)
  } catch {
    throw new Fail("insecure_url", `"${raw}" is not an address.`)
  }
  const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
    throw new Fail("insecure_url", "The address must start with https:// (http only for this computer).")
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== ""))
    throw new Fail("insecure_url", "Use the address alone, for example https://logs.example.com.")
  const issuer = url.origin
  const install = installDir()
  const dir = credentialsDir()
  const key = createHash("sha256")
    .update(`${issuer}\n${installId(install)}`)
    .digest("hex")
    .slice(0, 32)
  return {
    issuer,
    install,
    dir,
    file: path.join(dir, `${key}.json`),
    lock: path.join(dir, `${key}.lock`),
    kinds: path.join(dir, `${key}.kinds`),
    label: label(install),
  }
}

/** The skill's folder: one connection per place the skill is installed (one agent). */
function installDir() {
  return path.resolve(path.dirname(path.dirname(fileURLToPath(import.meta.url))))
}

/**
 * This install's id, kept in the skill's folder (`.install-id`), so every version agrees on it however each one
 * spells the folder's path (short 8.3 names, links, letter case). Published in one step: written aside, then
 * linked into place, which fails if another process got there first.
 */
function installId(install) {
  const file = path.join(install, ".install-id")
  const read = () => {
    try {
      const id = fs.readFileSync(file, "utf8").trim()
      return /^[0-9a-f]{32}$/.test(id) ? id : null
    } catch {
      return null
    }
  }
  const existing = read()
  if (existing) return existing
  const tmp = `${file}.${hex(6)}`
  try {
    fs.writeFileSync(tmp, `${hex(16)}\n`, { flag: "wx" })
    fs.linkSync(tmp, file)
  } catch {
    // Another process published one first, or the folder cannot be written.
  } finally {
    fs.rmSync(tmp, { force: true })
  }
  const id = read()
  if (!id) throw new Fail("cannot_save", `Cannot write in ${install}. The agent's id is kept there; allow writing it.`)
  return id
}

/** What the agent is called on the approval page and in Settings: which agent, on which computer. */
function label(install) {
  if (process.env.MAILCOW_LOGS_AGENT_NAME) return process.env.MAILCOW_LOGS_AGENT_NAME.slice(0, 60)
  let agent = "Agent"
  for (const part of install.split(/[\\/]/)) {
    const p = part.toLowerCase()
    if (p.startsWith(".claude")) {
      agent = p === ".claude" ? "Claude Code" : `Claude Code (${p})`
      break
    }
    if (p.startsWith(".codex")) {
      agent = p === ".codex" ? "Codex" : `Codex (${p})`
      break
    }
    if (p.startsWith(".cursor")) {
      agent = "Cursor"
      break
    }
  }
  return `${agent} on ${host()}`.slice(0, 60)
}

function credentialsDir() {
  const override = process.env.MAILCOW_LOGS_CREDENTIALS
  if (win) {
    const appData = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming")
    const dir = path.resolve(override || path.join(appData, "mailcow-logs"))
    const home = path.resolve(process.env.USERPROFILE || os.homedir()).toLowerCase()
    const lower = dir.toLowerCase()
    if (lower !== home && !lower.startsWith(`${home}\\`))
      throw new Fail(
        "insecure_credentials",
        `Keep the mailcow-logs folder inside your user profile (${home}), not ${dir}.`,
      )
    return dir
  }
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
  return path.resolve(override || path.join(base, "mailcow-logs"))
}

let secured = false
/** Creates the folder if needed and checks that only this user can read it; never loosens or fixes it silently. */
function secureDir(dir) {
  if (secured) return
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  } catch {
    throw new Fail("cannot_save", `Cannot create ${dir}. Allow this agent to write there.`)
  }
  const st = fs.lstatSync(dir)
  if (st.isSymbolicLink() || !st.isDirectory())
    throw new Fail("insecure_credentials", `${dir} must be a plain folder, not a link.`)
  if (win) {
    // Mode bits are no ACL on Windows: the folder is limited to this user, SYSTEM and Administrators.
    try {
      const sid = /"(S-1-[0-9-]+)"\s*$/.exec(
        execFileSync(system32("whoami.exe"), ["/user", "/fo", "csv", "/nh"]).toString().trim(),
      )
      if (!sid) throw new Error("no SID")
      execFileSync(
        system32("icacls.exe"),
        [
          dir,
          "/inheritance:r",
          "/grant:r",
          `*${sid[1]}:(OI)(CI)F`,
          "*S-1-5-18:(OI)(CI)F",
          "*S-1-5-32-544:(OI)(CI)F",
          "/Q",
        ],
        { stdio: "ignore" },
      )
      // The owner may always change an ACL, so the folder and its files must be this user's. (Only now: taking
      // ownership needs the full control just granted. No /C, which would hide a failure behind exit code 0.)
      icacls([dir, "/setowner", `*${sid[1]}`, "/T", "/Q"])
      // Granting does not remove other entries: read the folder's and its files' ACLs back and allow no one else.
      const saved = path.join(dir, `.acl-${hex(4)}`)
      try {
        icacls([dir, "/save", saved, "/T", "/Q"])
        const other = othersAllowed(fs.readFileSync(saved).toString("utf16le"), sid[1])
        if (other) throw new Fail("insecure_credentials", `Others can open ${dir} (${other}). Remove their access.`)
      } finally {
        fs.rmSync(saved, { force: true })
      }
    } catch (e) {
      if (e instanceof Fail) throw e
      throw new Fail("insecure_credentials", `Could not limit ${dir} to your user (icacls failed).`)
    }
  } else {
    if (st.uid !== process.getuid())
      throw new Fail("insecure_credentials", `${dir} belongs to another user. Use a folder of your own.`)
    if (st.mode & 0o077) throw new Fail("insecure_credentials", `Others can open ${dir}. Run: chmod 700 '${dir}'`)
  }
  secured = true
}

/** icacls over the folder and its files; tried again while other commands add or replace files in it. */
function icacls(args) {
  for (let i = 0; ; i++) {
    try {
      execFileSync(system32("icacls.exe"), args, { stdio: "ignore" })
      return
    } catch (e) {
      if (i >= 4) throw e
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100 + Math.random() * 200)
    }
  }
}

/**
 * What in saved ACLs (icacls /save: one SDDL line per object) lets anyone but this user, SYSTEM and Administrators
 * in. Anything but plain allow and deny entries (conditional or callback ones) counts too: refused, not guessed.
 */
function othersAllowed(saved, userSid) {
  const allowed = new Set([userSid, "SY", "BA", "S-1-5-18", "S-1-5-32-544"])
  // SDDL writes the built-in Administrator account (RID 500) as LA, so a user who is that account shows as LA.
  if (/^S-1-5-21-[0-9-]+-500$/.test(userSid)) allowed.add("LA")
  for (const line of saved.split(/\r?\n/)) {
    const at = line.indexOf("D:")
    if (at < 0) continue
    const dacl = line.slice(at + 2).split(/S:/)[0]
    let depth = 0
    let ace = ""
    for (const ch of dacl) {
      if (ch === "(") {
        depth++
        if (depth > 1) return "a conditional entry"
        ace = ""
      } else if (ch === ")") {
        depth--
        const [type, , , , , sid] = ace.split(";")
        if (!["A", "D", "OA", "OD"].includes(type)) return `an entry of type ${type}`
        if ((type === "A" || type === "OA") && !allowed.has(sid)) return sid
      } else if (depth === 1) ace += ch
    }
  }
  return null
}

function checkFile(file) {
  const st = fs.lstatSync(file)
  if (st.isSymbolicLink() || !st.isFile()) throw new Fail("insecure_credentials", `${file} must be a plain file.`)
  if (!win) {
    if (st.uid !== process.getuid()) throw new Fail("insecure_credentials", `${file} belongs to another user.`)
    if (st.mode & 0o077) throw new Fail("insecure_credentials", `Others can read ${file}. Run: chmod 600 '${file}'`)
  }
}

function readRecord(ctx) {
  let text
  try {
    checkFile(ctx.file)
    text = fs.readFileSync(ctx.file, "utf8")
  } catch (e) {
    if (e.code === "ENOENT") return null
    throw e
  }
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Fail("insecure_credentials", `${ctx.file} is damaged. Delete it and connect again.`)
  }
  const rec = {}
  for (const [k, type] of FIELDS) rec[k] = type === "n" ? Number(parsed[k]) || 0 : String(parsed[k] ?? "")
  return rec
}

function emptyRecord(ctx) {
  const rec = {}
  for (const [k, type] of FIELDS) rec[k] = type === "n" ? 0 : ""
  return { ...rec, v: 1, issuer: ctx.issuer, label: ctx.label }
}

function serialize(rec) {
  const parts = FIELDS.map(([k, type]) => {
    if (type === "n") return `"${k}":${Math.max(0, Math.floor(Number(rec[k]) || 0))}`
    const value = String(rec[k] ?? "")
    if (!PLAIN.test(value))
      throw new Fail("unexpected_answer", `mailcow Logs Viewer sent a value that cannot be stored (${k}).`)
    return `"${k}":"${value}"`
  })
  return `{${parts.join(",")}}\n`
}

/** Writes a file of the connection in one step: a private temp file, synced, renamed over the old one. */
function writePrivate(ctx, file, text) {
  secureDir(ctx.dir)
  const tmp = `${file}.${hex(6)}.tmp`
  let fd
  try {
    fd = fs.openSync(tmp, "wx", 0o600)
    fs.writeSync(fd, text)
    fs.fsyncSync(fd)
  } catch (e) {
    if (e instanceof Fail) throw e
    throw new Fail("cannot_save", `Cannot write in ${ctx.dir}. Allow this agent to write there.`)
  } finally {
    if (fd !== undefined) fs.closeSync(fd)
  }
  renameOver(tmp, file)
}

const writeRecord = (ctx, rec) => writePrivate(ctx, ctx.file, serialize(rec))

function renameOver(from, to) {
  // On Windows an open handle (an antivirus scan) can refuse the rename for a moment.
  const until = Date.now() + 5_000
  for (;;) {
    try {
      fs.renameSync(from, to)
      return
    } catch (e) {
      if (!win || !["EPERM", "EBUSY", "EACCES"].includes(e.code) || Date.now() > until) {
        fs.rmSync(from, { force: true })
        throw new Fail("cannot_save", `Cannot replace ${to}.`)
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100)
    }
  }
}

function removeRecord(ctx) {
  fs.rmSync(ctx.file, { force: true })
  fs.rmSync(ctx.kinds, { force: true })
}

/* The lock: a file created exclusively, naming its holder. Never taken from a live holder, however old. */

function readLock(file) {
  try {
    const text = fs.readFileSync(file, "utf8")
    const held = JSON.parse(text)
    return typeof held?.token === "string" ? held : { empty: true, mtime: fs.statSync(file).mtimeMs }
  } catch (e) {
    if (e.code === "ENOENT") return null
    try {
      return { empty: true, mtime: fs.statSync(file).mtimeMs }
    } catch {
      return null
    }
  }
}

function alive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    // The holder runs as this user, so a process of another user with that number means the holder is gone.
    return win && e.code === "EPERM"
  }
}

async function hook(point) {
  const at = process.env[`MAILCOW_LOGS_TEST_HOLD_${point.toUpperCase().replace(/-/g, "_")}`]
  if (!at) return
  fs.writeFileSync(`${at}.reached`, String(process.pid))
  for (let i = 0; i < 1200 && !fs.existsSync(`${at}.go`); i++) await sleep(50)
}

/** Takes the lock; `own` is a lock this process held before, which counts as taken if it is back in place. */
async function acquire(ctx, own) {
  secureDir(ctx.dir)
  const token = hex(16)
  const line = JSON.stringify({ pid: process.pid, host: host(), token, startedAt: now() })
  const deadline = Date.now() + LOCK_WAIT_MS
  for (;;) {
    let fd
    try {
      fd = fs.openSync(ctx.lock, "wx", 0o600)
      fs.writeSync(fd, line)
      fs.closeSync(fd)
      await hook("locked")
      return token
    } catch (e) {
      if (fd !== undefined) fs.closeSync(fd)
      // Windows refuses for a moment to create a file whose name is still being deleted (a lock just released).
      const deleting = win && (e.code === "EPERM" || e.code === "EACCES") && Date.now() < deadline
      if (deleting) {
        await sleep(50 + Math.random() * 100)
        continue
      }
      if (e.code !== "EEXIST") throw new Fail("cannot_save", `Cannot create a lock in ${ctx.dir}.`)
    }
    const held = readLock(ctx.lock)
    // Another process moved this one's lock away by mistake and has put it back.
    if (own && held && !held.empty && held.token === own) return own
    // A holder that died between creating the lock and writing its name leaves it empty; that takes a moment.
    const dead = held?.empty
      ? Date.now() - held.mtime > 60_000
      : held && sameHost(held.host) && !alive(Number(held.pid))
    if (dead) {
      await hook("break-observed")
      if (await breakLock(ctx, held)) continue
    }
    if (Date.now() > deadline) {
      const old = held && !held.empty && now() - Number(held.startedAt) > 600
      throw new Fail(
        "busy",
        old
          ? `Another mailcow-logs command has held ${ctx.lock} for over 10 minutes. If none is running, delete that file.`
          : "Another mailcow-logs command is using this connection. Nothing was sent; run it again.",
      )
    }
    await sleep(100 + Math.random() * 200)
  }
}

/**
 * Removes a dead holder's lock. Moving it away is atomic, so of two that try only one moves it; if what was moved
 * is not the dead lock (another process had just taken a fresh one), it goes back unless a newer one is there.
 */
async function breakLock(ctx, held) {
  const moved = `${ctx.lock}.${hex(6)}.dead`
  try {
    fs.renameSync(ctx.lock, moved)
  } catch {
    return true
  }
  await hook("break-moved")
  const got = readLock(moved)
  if (got && (held.empty ? got.empty : got.token === held.token)) {
    fs.rmSync(moved, { force: true })
    return true
  }
  try {
    fs.linkSync(moved, ctx.lock)
  } catch {
    // A newer lock is there already.
  }
  fs.rmSync(moved, { force: true })
  return false
}

const mine = (ctx, token) => readLock(ctx.lock)?.token === token

function release(ctx, token) {
  if (mine(ctx, token)) fs.rmSync(ctx.lock, { force: true })
}

async function withLock(ctx, fn, own) {
  const token = await acquire(ctx, own)
  try {
    return await fn(token)
  } finally {
    release(ctx, token)
  }
}

/** Before spending a one-time secret: the lock must still be ours, or nothing is sent. */
function assertMine(ctx, token) {
  if (!mine(ctx, token))
    throw new Fail("busy", "Another mailcow-logs command took over this connection. Run it again.")
}

/* Requests */

const NOT_SENT = new Set([
  "ENOTFOUND",
  "EAI_AGAIN",
  "ECONNREFUSED",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
  "CERT_HAS_EXPIRED",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "ERR_TLS_CERT_ALTNAME_INVALID",
])

async function request(ctx, method, url, { form, bearer, json, timeout = OAUTH_TIMEOUT_MS } = {}) {
  const headers = { accept: "application/json" }
  let payload
  if (form) {
    headers["content-type"] = "application/x-www-form-urlencoded"
    payload = new URLSearchParams(form).toString()
  } else if (json !== undefined) {
    headers["content-type"] = "application/json"
    payload = json
  }
  if (bearer) headers.authorization = `Bearer ${bearer}`
  let res
  try {
    // No redirects: a secret never follows one to another address.
    res = await fetch(url, {
      method,
      headers,
      body: payload,
      redirect: "manual",
      signal: AbortSignal.timeout(timeout),
    })
  } catch (e) {
    const code = e?.cause?.code ?? e?.code
    throw new Fail("unreachable", `Cannot reach ${ctx.issuer} (${code ?? e?.name ?? "network error"}).`, {
      sent: !NOT_SENT.has(code),
    })
  }
  let text
  try {
    text = await res.text()
  } catch {
    // The answer started and broke off: the app got the request and may have acted on it.
    throw new Fail("unreachable", `The answer from ${ctx.issuer} broke off.`, { sent: true })
  }
  let parsed = null
  try {
    parsed = JSON.parse(text)
  } catch {}
  return { status: res.status, text, json: parsed }
}

const oauth = (ctx, p, form) =>
  request(ctx, "POST", `${ctx.issuer}${p}`, { form: { ...form, client_id: CLIENT_ID } })

function httpFail(r, what) {
  const body = r.json !== null && typeof r.json === "object" ? r.json : null
  const detail =
    body?.error_description || body?.message || (typeof body?.detail === "string" ? body.detail : "") || body?.error
  return new Fail(`http_${r.status}`, `${what} failed (${r.status}${detail ? `: ${detail}` : ""}).`, { body })
}

function tokensFrom(r) {
  const t = r.json ?? {}
  const scope = typeof t.scope === "string" ? t.scope : ""
  const ok = (v) => typeof v === "string" && SECRET.test(v)
  if (!ok(t.access_token) || !ok(t.refresh_token) || !PLAIN.test(scope))
    throw new Fail("unexpected_answer", "mailcow Logs Viewer answered without usable tokens.")
  return {
    refreshToken: t.refresh_token,
    accessToken: t.access_token,
    accessExpiresAt: now() + Math.max(0, Math.floor(Number(t.expires_in) || 0)),
    scope,
  }
}

async function revokePending(ctx, rec) {
  if (!rec.toRevoke) return rec
  const left = []
  for (const token of rec.toRevoke.split(" ").filter(Boolean)) {
    const r = await oauth(ctx, "/oauth/revoke", { token, token_type_hint: "refresh_token" }).catch(() => null)
    if (r?.status !== 200) left.push(token)
  }
  const next = { ...rec, toRevoke: left.join(" ") }
  if (next.toRevoke !== rec.toRevoke) writeRecord(ctx, next)
  return next
}

/* Commands */

function status(ctx) {
  const rec = readRecord(ctx)
  print({
    status: rec?.refreshToken ? "connected" : rec?.deviceCode ? "pending" : "not_connected",
    url: ctx.issuer,
    label: rec?.label || ctx.label,
    ...(rec?.refreshToken ? { scope: rec.scope, accessExpiresIn: Math.max(0, rec.accessExpiresAt - now()) } : {}),
  })
}

async function connect(ctx, replace) {
  // Before any code exists: can it keep a connection here, and is the app there?
  secureDir(ctx.dir)
  const probe = path.join(ctx.dir, `.probe-${hex(4)}`)
  try {
    fs.writeFileSync(probe, "", { flag: "wx", mode: 0o600 })
    fs.rmSync(probe)
  } catch {
    throw new Fail("cannot_save", `Cannot write in ${ctx.dir}. Allow this agent to write there.`)
  }
  const meta = await request(ctx, "GET", `${ctx.issuer}/.well-known/oauth-authorization-server`)
  if (meta.status !== 200 || meta.json?.issuer !== ctx.issuer)
    throw new Fail(
      "unreachable",
      `${ctx.issuer} does not answer as mailcow Logs Viewer with agent access on (${meta.status}). Check the address, and that agent access is on in Settings > Agents.`,
    )

  const result = await withLock(ctx, async (lock) => {
    let rec = readRecord(ctx) ?? emptyRecord(ctx)
    rec = await revokePending(ctx, rec)
    if (rec.refreshToken && !replace) return { status: "already_connected", label: rec.label, scope: rec.scope }
    // The open code again, unless asked for a new one (--replace: the link did not work for the person).
    if (rec.deviceCode && rec.deviceExpiresAt - now() > 30 && !replace) return pending(rec)
    assertMine(ctx, lock)
    const r = await oauth(ctx, "/oauth/device", {
      scope: SCOPE,
      resource: `${ctx.issuer}/api`,
      client_label: ctx.label,
    })
    if (r.status !== 200) throw httpFail(r, "Asking to connect")
    const d = r.json ?? {}
    const link = String(d.verification_uri_complete ?? "")
    if (!SECRET.test(String(d.device_code)) || !/^[A-Z0-9-]{4,20}$/.test(String(d.user_code)) || !PLAIN.test(link))
      throw new Fail("unexpected_answer", "mailcow Logs Viewer answered without a code.")
    if (!link.startsWith(`${ctx.issuer}/`))
      throw new Fail("unexpected_answer", "The approval link is not on mailcow Logs Viewer.")
    const interval = Math.max(POLL_SECONDS, Math.floor(Number(d.interval) || POLL_SECONDS))
    rec = {
      ...rec,
      label: ctx.label,
      deviceCode: d.device_code,
      userCode: d.user_code,
      link,
      deviceExpiresAt: now() + Math.max(60, Math.floor(Number(d.expires_in) || 600)),
      interval,
      nextPollAt: now() + interval,
    }
    writeRecord(ctx, rec)
    return pending(rec)
  })
  print(result)
}

function pending(rec) {
  return {
    status: "pending",
    link: rec.link,
    code: rec.userCode,
    expiresIn: Math.max(0, rec.deviceExpiresAt - now()),
    next: "End your turn with a reply that shows the person the link and the code and asks them to reply once they approve. When they reply, run: mailcow-logs connect --wait",
  }
}

function clearPending(rec) {
  return { ...rec, deviceCode: "", userCode: "", link: "", deviceExpiresAt: 0, interval: 0, nextPollAt: 0 }
}

async function waitForApproval(ctx) {
  const until = Date.now() + WAIT_SECONDS * 1000
  for (;;) {
    const step = await withLock(ctx, async (lock) => {
      let rec = readRecord(ctx)
      if (!rec?.deviceCode) {
        if (rec?.refreshToken) return { done: { status: "connected", label: rec.label, scope: rec.scope } }
        throw new Fail("not_connected", "No connection is being made. Run: mailcow-logs connect")
      }
      const t = now()
      // The server decides when a code has ended: one approved at the last minute can
      // still be collected for a while after. Only a code long past that is dropped here.
      if (rec.deviceExpiresAt + STALE_CODE_SECONDS <= t) {
        writeRecord(ctx, clearPending(rec))
        throw new Fail("expired", "The code expired before it was approved. Run: mailcow-logs connect")
      }
      if (rec.nextPollAt > t) return { wait: rec.nextPollAt - t }
      assertMine(ctx, lock)
      let r
      try {
        r = await oauth(ctx, "/oauth/token", {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: rec.deviceCode,
        })
      } catch (e) {
        if (e.code === "unreachable") {
          rec.nextPollAt = t + rec.interval
          writeRecord(ctx, rec)
        }
        throw e
      }
      if (r.status === 200) {
        const tokens = tokensFrom(r)
        // Connecting again (--replace): the old connection is ended once the new one is stored.
        const old = rec.refreshToken && rec.refreshToken !== tokens.refreshToken ? rec.refreshToken : ""
        rec = {
          ...clearPending(rec),
          ...tokens,
          generation: hex(8),
          refreshStartedAt: 0,
          refreshRetried: 0,
          toRevoke: [rec.toRevoke, old].filter(Boolean).join(" "),
        }
        writeRecord(ctx, rec)
        fs.rmSync(ctx.kinds, { force: true })
        rec = await revokePending(ctx, rec)
        return { done: { status: "connected", label: rec.label, scope: rec.scope } }
      }
      const error = r.json?.error
      if (error === "authorization_pending" || error === "slow_down") {
        if (error === "slow_down") rec.interval += 5
        rec.nextPollAt = t + rec.interval
        writeRecord(ctx, rec)
        return { wait: rec.interval }
      }
      if (error === "access_denied") {
        writeRecord(ctx, clearPending(rec))
        throw new Fail("denied", "The person did not approve the connection.")
      }
      if (error === "expired_token" || error === "invalid_grant") {
        writeRecord(ctx, clearPending(rec))
        throw new Fail("expired", "The code is no longer valid. Run: mailcow-logs connect")
      }
      throw httpFail(r, "Waiting for the approval")
    })
    if (step.done) return print(step.done)
    if (Date.now() + step.wait * 1000 > until)
      return print({ status: "still_waiting", next: "Not approved yet. Run again: mailcow-logs connect --wait" })
    await sleep(step.wait * 1000)
  }
}

const usable = (rec) => rec.accessToken && rec.accessExpiresAt - now() > 60 && !rec.refreshStartedAt

/** A live access token: the stored one while it lasts, else one refresh under the lock. */
async function accessToken(ctx, stale) {
  const first = readRecord(ctx)
  if (!first?.refreshToken) throw new Fail("not_connected", "Not connected. Run: mailcow-logs connect")
  if (!stale && usable(first)) return first.accessToken
  return withLock(ctx, async (lock) => {
    let rec = readRecord(ctx)
    if (!rec?.refreshToken) throw new Fail("not_connected", "Not connected. Run: mailcow-logs connect")
    rec = await revokePending(ctx, rec)
    // Another command refreshed while this one waited for the lock.
    if (usable(rec) && rec.accessToken !== stale) return rec.accessToken
    const before = { refreshStartedAt: rec.refreshStartedAt, refreshRetried: rec.refreshRetried }
    // A refresh that started moments ago may still be on its way (its holder lost the lock): never send it twice.
    if (rec.refreshStartedAt && now() - rec.refreshStartedAt < REFRESH_GRACE)
      throw new Fail(
        "busy",
        "Another mailcow-logs command is refreshing this connection. Nothing was sent; run it again.",
      )
    if (rec.refreshStartedAt) {
      // The last refresh got no answer; it may or may not have reached the app. Trying once more either continues
      // the connection or ends it there, which also ends the new token nobody received.
      if (rec.refreshRetried)
        throw new Fail(
          "connection_ended",
          "Two refreshes got no answer, so this connection cannot be trusted. Run: mailcow-logs connect --replace",
        )
      rec.refreshRetried = 1
    }
    rec.refreshStartedAt = now()
    writeRecord(ctx, rec)
    assertMine(ctx, lock)
    await hook("before-refresh")
    let r
    try {
      r = await oauth(ctx, "/oauth/token", {
        grant_type: "refresh_token",
        refresh_token: rec.refreshToken,
        resource: `${ctx.issuer}/api`,
      })
    } catch (e) {
      // Nothing left the computer: the token is as good as before.
      if (e.code === "unreachable" && e.extra.sent === false) writeRecord(ctx, { ...rec, ...before })
      throw e
    }
    if (r.status === 200) {
      const next = { ...rec, ...tokensFrom(r), refreshStartedAt: 0, refreshRetried: 0 }
      await hook("before-write")
      if (!mine(ctx, lock)) {
        // The lock was taken while this one waited for the app: keep the new tokens anyway, under a fresh lock.
        await withLock(ctx, async () => writeRecord(ctx, next), lock)
      } else writeRecord(ctx, next)
      return next.accessToken
    }
    if (r.json?.error === "invalid_grant") {
      // An old connection still to be ended (after --replace) keeps its place until the app confirms it.
      if (rec.toRevoke) writeRecord(ctx, { ...emptyRecord(ctx), label: rec.label, toRevoke: rec.toRevoke })
      else removeRecord(ctx)
      throw new Fail(
        "connection_ended",
        "This connection has ended (disconnected in Settings, its time ran out, sign-in settings changed, or its token was used twice). Run: mailcow-logs connect",
      )
    }
    // The app answered with an error before spending the token (a 4xx); a 5xx may have come after.
    if (r.status < 500) writeRecord(ctx, { ...rec, ...before })
    throw httpFail(r, "Refreshing the connection")
  })
}

/** The full path of an API call (with its query) and the URL to send it to. */
function apiTarget(ctx, p) {
  let value = String(p ?? "")
  const bad = "Give a path of the API, for example: messages?limit=20 (percent-encode anything else)"
  if (value.startsWith("/api/")) value = value.slice(4)
  // The same characters in every version (the shell version passes the path to curl as it is).
  // Encoded dots too: a server or proxy that decodes them would take the token out of the API.
  if (!PATH_CHARS.test(value) || value.includes("://") || value.startsWith("//") || /%2e/i.test(value))
    throw new Fail("bad_path", bad)
  const pathOnly = value.split("?")[0]
  if (pathOnly.split("/").some((s) => s === "." || s === "..")) throw new Fail("bad_path", bad)
  const url = new URL(`${ctx.issuer}/api${value.startsWith("/") ? "" : "/"}${value}`)
  if (url.origin !== ctx.issuer || !url.pathname.startsWith("/api/") || url.pathname.length <= 5)
    throw new Fail("bad_path", bad)
  return { url: url.toString(), path: url.pathname }
}

/* Kinds: whether a call is a read or an action, from the server's own list of this connection's calls. */

function readKinds(ctx, rec) {
  let text
  try {
    text = fs.readFileSync(ctx.kinds, "utf8")
  } catch {
    return null
  }
  const lines = text.split(/\r?\n/)
  const head = (lines.shift() ?? "").split(" ")
  if (head[0] !== "mailcow-logs-kinds" || head[1] !== "1" || head[2] !== rec.generation) return null
  if (now() - Number(head[3] || 0) > KINDS_MAX_AGE) return null
  const list = []
  for (const line of lines) {
    const [method, template, kind] = line.split(" ")
    if (/^[A-Z]{3,7}$/.test(method ?? "") && TEMPLATE.test(template ?? "") && (kind === "read" || kind === "act"))
      list.push({ method, template, kind })
  }
  return list
}

function writeKinds(ctx, rec, data) {
  const list = Array.isArray(data?.endpoints) ? data.endpoints : null
  if (!list || !rec?.generation) return
  const lines = [`mailcow-logs-kinds 1 ${rec.generation} ${now()}`]
  for (const e of list) {
    const method = String(e?.method ?? "")
    const template = String(e?.path ?? "")
    const kind = e?.kind === "read" ? "read" : "act"
    if (/^[A-Z]{3,7}$/.test(method) && TEMPLATE.test(template)) lines.push(`${method} ${template} ${kind}`)
  }
  try {
    writePrivate(ctx, ctx.kinds, `${lines.join("\n")}\n`)
  } catch {
    // Only a cache: without it every call counts as an action.
  }
}

function templateMatches(template, p) {
  const t = template.split("/")
  const s = p.split("/")
  for (let i = 0; i < t.length; i++) {
    if (/^\{[^}]*:path\}$/.test(t[i])) return i === t.length - 1 && s.length > i && s.slice(i).join("") !== ""
    if (i >= s.length) return false
    if (/^\{[^}]*\}$/.test(t[i])) {
      if (s[i] === "") return false
    } else if (t[i] !== s[i]) return false
  }
  return t.length === s.length
}

/** "read" or "act". An endpoint the list does not hold, or no list, counts as an action. */
async function kindOf(ctx, method, p) {
  if (method === "GET" && (p === "/api/agent/access" || p === "/api/agent/endpoints")) return "read"
  const rec = readRecord(ctx)
  if (!rec?.refreshToken) return "act"
  let list = readKinds(ctx, rec)
  if (!list) {
    try {
      const r = await send(ctx, "GET", apiTarget(ctx, "agent/endpoints").url, undefined, "read")
      if (r.status === 200) {
        writeKinds(ctx, rec, r.json)
        list = readKinds(ctx, rec)
      }
    } catch {
      // Without the list every call counts as an action.
    }
  }
  if (!list) return "act"
  const hits = list.filter((e) => e.method === method && templateMatches(e.template, p))
  if (!hits.length) return "act"
  return hits.some((e) => e.kind === "act") ? "act" : "read"
}

/**
 * One API call with its retries: a refresh and one retry after a 401 (the server checks the token before the
 * route runs), one retry after a 429 busy (nothing started), and for a read one retry after a network failure.
 * An action is never sent again once it may have reached the app.
 */
async function send(ctx, method, url, json, kind) {
  let token = await accessToken(ctx)
  let refreshed = false
  let busyRetried = false
  let netRetried = false
  for (;;) {
    let r
    try {
      r = await request(ctx, method, url, { bearer: token, json, timeout: API_TIMEOUT_MS })
    } catch (e) {
      if (e.code !== "unreachable") throw e
      if (kind === "act") {
        if (e.extra.sent === false) throw e
        throw new Fail("outcome_unknown", UNKNOWN_OUTCOME)
      }
      if (netRetried) throw e
      netRetried = true
      continue
    }
    if (r.status === 401 && !refreshed) {
      refreshed = true
      token = await accessToken(ctx, token)
      continue
    }
    if (r.status === 429 && r.json?.error === "busy" && !busyRetried) {
      busyRetried = true
      await sleep(BUSY_WAIT_MS)
      continue
    }
    if (kind === "act" && r.status >= 500) throw new Fail("outcome_unknown", UNKNOWN_OUTCOME, { status: r.status })
    return r
  }
}

/** The answer as JSON text on one line: a JSON answer as it is (its line breaks are only spacing), text as a string. */
function dataText(r) {
  if (r.json !== null) return r.text.replace(/[\r\n]/g, "").trim()
  return JSON.stringify(r.text)
}

const failedAnswer = (data) =>
  data !== null && typeof data === "object" && !Array.isArray(data) && (data.success === false || data.status === "error")

async function api(ctx, method, p, json) {
  const target = apiTarget(ctx, p)
  if (json !== undefined) {
    try {
      JSON.parse(json)
    } catch {
      throw new Fail("bad_body", "The body is not JSON.")
    }
  }
  const kind = await kindOf(ctx, method, target.path)
  const r = await send(ctx, method, target.url, json, kind)
  if (r.status >= 200 && r.status < 300) {
    if (method === "GET" && target.path === "/api/agent/endpoints" && !target.url.includes("?"))
      writeKinds(ctx, readRecord(ctx), r.json)
    const data = dataText(r)
    if (failedAnswer(r.json)) {
      process.stdout.write(
        `{"error":"failed","message":${JSON.stringify(`${method} ${p} answered that it failed.`)},"status":${r.status},"data":${data}}\n`,
      )
      process.exitCode = 1
      return
    }
    process.stdout.write(`{"status":${r.status},"data":${data}}\n`)
    return
  }
  const body = r.json !== null && typeof r.json === "object" && !Array.isArray(r.json) ? r.json : null
  // The app's own refusals for agents carry a code and a message: passed on as they are.
  if (body && typeof body.error === "string" && /^[a-z_]{1,40}$/.test(body.error) && typeof body.message === "string")
    throw new Fail(body.error, body.message, { status: r.status })
  throw httpFail(r, `${method} ${p}`)
}

async function disconnect(ctx) {
  const result = await withLock(ctx, async (lock) => {
    const rec = readRecord(ctx)
    if (!rec) return { status: "not_connected" }
    assertMine(ctx, lock)
    const tokens = [rec.refreshToken, ...rec.toRevoke.split(" ")].filter(Boolean)
    const left = []
    for (const token of tokens) {
      const r = await oauth(ctx, "/oauth/revoke", { token, token_type_hint: "refresh_token" }).catch(() => null)
      if (r?.status !== 200) left.push(token)
    }
    if (left.length) {
      writeRecord(ctx, { ...rec, refreshToken: "", accessToken: "", accessExpiresAt: 0, toRevoke: left.join(" ") })
      throw new Fail(
        "disconnect_failed",
        "mailcow Logs Viewer did not confirm the disconnect. Run it again, or disconnect this agent in Settings > Agents.",
      )
    }
    removeRecord(ctx)
    return { status: "disconnected" }
  })
  print(result)
}

main().catch((e) => {
  if (e instanceof Fail) {
    print({
      error: e.code,
      message: e.message,
      ...(e.extra.status !== undefined ? { status: e.extra.status } : {}),
      ...(e.extra.body !== undefined && e.extra.body !== null ? { body: e.extra.body } : {}),
    })
  } else {
    print({ error: "failed", message: String(e?.message ?? e) })
  }
  process.exitCode = 1
})
