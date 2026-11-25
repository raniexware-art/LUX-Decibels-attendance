const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, "store.json");
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SCRYPT_COST = 32768;
const COOKIE_NAME = "attendance_session";
const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
};

function emptyStore() {
  return { admins: [], employees: [], attendance: [], leaves: [] };
}

function readStore(filePath) {
  try {
    const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (!Array.isArray(data.admins) || !Array.isArray(data.employees) || !Array.isArray(data.attendance)) {
      throw new Error("Data file has an invalid structure.");
    }
    if (!Array.isArray(data.leaves)) data.leaves = [];
    return data;
  } catch (error) {
    if (error.code === "ENOENT") return emptyStore();
    throw error;
  }
}

function saveStore(filePath, store) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const temporaryPath = `${filePath}.tmp`;
  fs.writeFileSync(temporaryPath, JSON.stringify(store, null, 2), { mode: 0o600 });
  fs.renameSync(temporaryPath, filePath);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64, { N: SCRYPT_COST, maxmem: 64 * 1024 * 1024 });
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

function verifyPassword(password, storedHash) {
  const [saltHex, hashHex] = storedHash.split(":");
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, "hex"), expected.length, { N: SCRYPT_COST, maxmem: 64 * 1024 * 1024 });
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map((part) => {
    const separator = part.indexOf("=");
    if (separator < 0) return ["", ""];
    return [part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim())];
  }).filter(([key]) => key));
}

function safeUser(user) {
  return user && { role: user.role, id: user.id, name: user.name };
}

function createAppServer({ dataFile = DATA_FILE } = {}) {
  const sessions = new Map();
  let store = readStore(dataFile);

  function getSession(req, res) {
    const cookies = parseCookies(req.headers.cookie);
    let session = sessions.get(cookies[COOKIE_NAME]);
    if (!session || session.expiresAt <= Date.now()) {
      if (session) sessions.delete(cookies[COOKIE_NAME]);
      session = { id: crypto.randomBytes(32).toString("hex"), csrf: crypto.randomBytes(24).toString("hex"), user: null, expiresAt: Date.now() + SESSION_TTL_MS };
      sessions.set(session.id, session);
      setSessionCookie(res, session.id);
    }
    return session;
  }

  function setSessionCookie(res, sessionId) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    res.setHeader("Set-Cookie", `${COOKIE_NAME}=${sessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${secure}`);
  }

  function rotateSession(session, user, res) {
    sessions.delete(session.id);
    const replacement = { id: crypto.randomBytes(32).toString("hex"), csrf: crypto.randomBytes(24).toString("hex"), user, expiresAt: Date.now() + SESSION_TTL_MS };
    sessions.set(replacement.id, replacement);
    setSessionCookie(res, replacement.id);
    return replacement;
  }

  function sendJson(res, status, body) {
    res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
    res.end(JSON.stringify(body));
  }

  function sendError(res, status, message) {
    sendJson(res, status, { error: message });
  }

  function requireUser(session, role, res) {
    if (!session.user) {
      sendError(res, 401, "Please log in to continue.");
      return false;
    }
    if (role && session.user.role !== role) {
      sendError(res, 403, "You do not have permission to do that.");
      return false;
    }
    return true;
  }

  async function readJson(req) {
    const contentType = req.headers["content-type"] || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      const error = new Error("Send this request as JSON.");
      error.status = 415;
      throw error;
    }
    let body = "";
    for await (const chunk of req) {
      body += chunk;
      if (Buffer.byteLength(body) > 1024 * 32) {
        const error = new Error("Request is too large.");
        error.status = 413;
        throw error;
      }
    }
    try {
      return JSON.parse(body);
    } catch {
      const error = new Error("Request body must be valid JSON.");
      error.status = 400;
      throw error;
    }
  }

  function requireCsrf(req, session, res) {
    const token = req.headers["x-csrf-token"];
    if (typeof token !== "string" || token.length !== session.csrf.length || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(session.csrf))) {
      sendError(res, 403, "Refresh the page and try again.");
      return false;
    }
    return true;
  }

  async function handleApi(req, res, session, url) {
    if (req.method === "GET" && url.pathname === "/api/session") {
      return sendJson(res, 200, { firstRun: store.admins.length === 0, user: safeUser(session.user), csrfToken: session.csrf });
    }

    if (req.method === "POST" && url.pathname === "/api/setup") {
      if (!requireCsrf(req, session, res)) return;
      if (store.admins.length > 0) return sendError(res, 409, "Admin setup has already been completed.");
      const body = await readJson(req);
      const username = typeof body.username === "string" ? body.username.trim() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return sendError(res, 400, "Username must be 3–40 letters, numbers, dots, underscores, or hyphens.");
      if (password.length < 10 || password.length > 128) return sendError(res, 400, "Use a password between 10 and 128 characters.");
      const admin = { id: crypto.randomUUID(), username, passwordHash: hashPassword(password), name: username };
      store.admins.push(admin);
      saveStore(dataFile, store);
      session = rotateSession(session, { role: "admin", id: admin.id, name: admin.name }, res);
      return sendJson(res, 201, { user: safeUser(session.user) });
    }

    if (req.method === "POST" && url.pathname === "/api/login") {
      if (!requireCsrf(req, session, res)) return;
      const body = await readJson(req);
      const role = body.role;
      const identifier = typeof body.identifier === "string" ? body.identifier.trim() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!["admin", "employee"].includes(role) || !identifier || !password) return sendError(res, 400, "Enter your login details.");
      const user = role === "admin"
        ? store.admins.find((admin) => admin.username.toLowerCase() === identifier.toLowerCase() && verifyPassword(password, admin.passwordHash))
        : store.employees.find((employee) => employee.employeeId.toLowerCase() === identifier.toLowerCase() && verifyPassword(password, employee.passwordHash));
      if (!user) return sendError(res, 401, "The ID or password is incorrect.");
      const authenticated = role === "admin"
        ? { role: "admin", id: user.id, name: user.name }
        : { role: "employee", id: user.id, name: user.name };
      session = rotateSession(session, authenticated, res);
      return sendJson(res, 200, { user: safeUser(session.user) });
    }

    if (req.method === "POST" && url.pathname === "/api/admin/recover") {
      if (!requireCsrf(req, session, res)) return;
      const body = await readJson(req);
      const username = typeof body.username === "string" ? body.username.trim() : "";
      const recoveryCode = typeof body.recoveryCode === "string" ? body.recoveryCode : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!username || !recoveryCode || password.length < 10 || password.length > 128) {
        return sendError(res, 400, "Enter your username, recovery code, and a password between 10 and 128 characters.");
      }
      const admin = store.admins.find((item) => item.username.toLowerCase() === username.toLowerCase());
      if (!admin || typeof admin.recoveryHash !== "string" || !verifyPassword(recoveryCode, admin.recoveryHash)) {
        return sendError(res, 401, "The username or recovery code is incorrect.");
      }
      admin.passwordHash = hashPassword(password);
      admin.recoveryHash = null;
      saveStore(dataFile, store);
      session = rotateSession(session, { role: "admin", id: admin.id, name: admin.name }, res);
      return sendJson(res, 200, { user: safeUser(session.user) });
    }

    if (req.method === "POST" && url.pathname === "/api/logout") {
      if (!requireCsrf(req, session, res)) return;
      sessions.delete(session.id);
      const replacement = rotateSession(session, null, res);
      return sendJson(res, 200, { user: null, csrfToken: replacement.csrf });
    }

    if (url.pathname.startsWith("/api/") && req.method !== "GET" && !requireCsrf(req, session, res)) return;

    if (req.method === "GET" && url.pathname === "/api/employees") {
      if (!requireUser(session, "admin", res)) return;
      const employees = store.employees.map((employee) => {
        const latest = store.attendance.filter((event) => event.employeeId === employee.id).at(-1);
        return { id: employee.id, employeeId: employee.employeeId, name: employee.name, checkedIn: latest?.type === "check-in" };
      });
      return sendJson(res, 200, { employees });
    }

    if (req.method === "POST" && url.pathname === "/api/employees") {
      if (!requireUser(session, "admin", res)) return;
      const body = await readJson(req);
      const employeeId = typeof body.employeeId === "string" ? body.employeeId.trim() : "";
      const name = typeof body.name === "string" ? body.name.trim() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!/^[a-zA-Z0-9._-]{1,40}$/.test(employeeId)) return sendError(res, 400, "Employee ID must be 1–40 letters, numbers, dots, underscores, or hyphens.");
      if (name.length < 1 || name.length > 80) return sendError(res, 400, "Name must be between 1 and 80 characters.");
      if (password.length < 10 || password.length > 128) return sendError(res, 400, "Use a password between 10 and 128 characters.");
      if (store.employees.some((employee) => employee.employeeId.toLowerCase() === employeeId.toLowerCase())) {
        return sendError(res, 409, "That employee ID is already in use.");
      }
      const employee = { id: crypto.randomUUID(), employeeId, name, passwordHash: hashPassword(password) };
      store.employees.push(employee);
      saveStore(dataFile, store);
      return sendJson(res, 201, { employee: { id: employee.id, employeeId, name: employee.name } });
    }

    if (req.method === "DELETE" && /^\/api\/employees\/[^/]+$/.test(url.pathname)) {
      if (!requireUser(session, "admin", res)) return;
      const employeeId = url.pathname.split("/")[3];
      const employee = store.employees.find((item) => item.id === employeeId);
      if (!employee) return sendError(res, 404, "Employee account not found.");

      store.employees = store.employees.filter((item) => item.id !== employeeId);
      store.attendance = store.attendance.filter((item) => item.employeeId !== employeeId);
      store.leaves = store.leaves.filter((item) => item.employeeId !== employeeId);
      for (const [sessionId, employeeSession] of sessions) {
        if (employeeSession.user?.role === "employee" && employeeSession.user.id === employeeId) {
          sessions.delete(sessionId);
        }
      }
      saveStore(dataFile, store);
      return sendJson(res, 200, { employee: { id: employee.id, employeeId: employee.employeeId, name: employee.name } });
    }

    if (req.method === "PATCH" && /^\/api\/employees\/[^/]+\/password$/.test(url.pathname)) {
      if (!requireUser(session, "admin", res)) return;
      const body = await readJson(req);
      const password = typeof body.password === "string" ? body.password : "";
      if (password.length < 10 || password.length > 128) return sendError(res, 400, "Use a password between 10 and 128 characters.");
      const employeeId = url.pathname.split("/")[3];
      const employee = store.employees.find((item) => item.id === employeeId);
      if (!employee) return sendError(res, 404, "Employee account not found.");
      employee.passwordHash = hashPassword(password);
      saveStore(dataFile, store);
      return sendJson(res, 200, { employee: { id: employee.id, employeeId: employee.employeeId, name: employee.name } });
    }

    if (req.method === "POST" && url.pathname === "/api/admin/recovery-code") {
      if (!requireUser(session, "admin", res)) return;
      const admin = store.admins.find((item) => item.id === session.user.id);
      if (!admin) return sendError(res, 404, "Admin account not found.");
      const recoveryCode = crypto.randomBytes(24).toString("base64url");
      admin.recoveryHash = hashPassword(recoveryCode);
      saveStore(dataFile, store);
      return sendJson(res, 201, { recoveryCode });
    }

    if (req.method === "GET" && url.pathname === "/api/attendance") {
      if (url.searchParams.get("lateCheckIns") === "true") {
        if (!requireUser(session, "admin", res)) return;
        const events = store.attendance
          .filter((event) => event.type === "check-in" && event.reason)
          .sort((a, b) => b.at.localeCompare(a.at))
          .map((event) => {
            const employee = store.employees.find((item) => item.id === event.employeeId);
            return { ...event, employeeName: employee?.name || "Former employee", employeeCode: employee?.employeeId || "" };
          });
        return sendJson(res, 200, { events });
      }
      if (!requireUser(session, null, res)) return;
      const employeeId = session.user.role === "employee" ? session.user.id : url.searchParams.get("employeeId");
      if (session.user.role === "admin" && employeeId) {
        const events = store.attendance.filter((event) => event.employeeId === employeeId);
        return sendJson(res, 200, { events });
      }
      if (session.user.role === "admin") {
        const today = new Date().toISOString().slice(0, 10);
        const events = store.attendance.filter((event) => event.at.startsWith(today)).map((event) => {
          const employee = store.employees.find((item) => item.id === event.employeeId);
          return { ...event, employeeName: employee?.name || "Former employee", employeeCode: employee?.employeeId || "" };
        });
        return sendJson(res, 200, { events });
      }
      return sendJson(res, 200, { events: store.attendance.filter((event) => event.employeeId === employeeId).slice(-10).reverse() });
    }

    if (req.method === "POST" && url.pathname === "/api/attendance") {
      if (!requireUser(session, "employee", res)) return;
      const body = await readJson(req);
      if (!["check-in", "check-out"].includes(body.type)) return sendError(res, 400, "Choose check-in or check-out.");
      const previous = store.attendance.filter((event) => event.employeeId === session.user.id).at(-1);
      const currentlyCheckedIn = previous?.type === "check-in";
      if ((body.type === "check-in" && currentlyCheckedIn) || (body.type === "check-out" && !currentlyCheckedIn)) {
        return sendError(res, 409, body.type === "check-in" ? "You are already checked in." : "You need to check in before checking out.");
      }
      const event = { id: crypto.randomUUID(), employeeId: session.user.id, type: body.type, at: new Date().toISOString() };
      if (body.type === "check-in" && typeof body.reason === "string" && body.reason.trim()) {
        if (body.reason.trim().length > 500) return sendError(res, 400, "The late check-in reason must be 500 characters or fewer.");
        event.reason = body.reason.trim();
      }
      store.attendance.push(event);
      saveStore(dataFile, store);
      return sendJson(res, 201, { event });
    }

    if (req.method === "GET" && url.pathname === "/api/leaves") {
      if (!requireUser(session, null, res)) return;
      const leaves = store.leaves
        .filter((leave) => session.user.role === "admin" || leave.employeeId === session.user.id)
        .map((leave) => {
          const employee = store.employees.find((item) => item.id === leave.employeeId);
          return {
            ...leave,
            employeeName: employee?.name || "Former employee",
            employeeCode: employee?.employeeId || "",
          };
        })
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return sendJson(res, 200, { leaves });
    }

    if (req.method === "POST" && url.pathname === "/api/leaves") {
      if (!requireUser(session, "employee", res)) return;
      const body = await readJson(req);
      const type = typeof body.type === "string" ? body.type.trim() : "";
      const startDate = typeof body.startDate === "string" ? body.startDate : "";
      const endDate = typeof body.endDate === "string" ? body.endDate : "";
      const reason = typeof body.reason === "string" ? body.reason.trim() : "";
      if (!["Casual", "Sick", "Earned", "Other"].includes(type)) return sendError(res, 400, "Choose a valid leave type.");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(startDate) || !/^\d{4}-\d{2}-\d{2}$/.test(endDate)) {
        return sendError(res, 400, "Choose valid start and end dates.");
      }
      const startTimestamp = new Date(`${startDate}T00:00:00Z`);
      const endTimestamp = new Date(`${endDate}T00:00:00Z`);
      if (Number.isNaN(startTimestamp.getTime()) || Number.isNaN(endTimestamp.getTime()) ||
          startTimestamp.toISOString().slice(0, 10) !== startDate ||
          endTimestamp.toISOString().slice(0, 10) !== endDate) {
        return sendError(res, 400, "Choose valid start and end dates.");
      }
      if (startDate > endDate) return sendError(res, 400, "The end date cannot be before the start date.");
      if (reason.length < 3 || reason.length > 300) return sendError(res, 400, "Reason must be between 3 and 300 characters.");
      const overlaps = store.leaves.some((leave) =>
        leave.employeeId === session.user.id &&
        ["pending", "approved"].includes(leave.status) &&
        startDate <= leave.endDate &&
        endDate >= leave.startDate
      );
      if (overlaps) return sendError(res, 409, "You already have a pending or approved leave for these dates.");
      const leave = {
        id: crypto.randomUUID(),
        employeeId: session.user.id,
        type,
        startDate,
        endDate,
        reason,
        status: "pending",
        createdAt: new Date().toISOString(),
        reviewedAt: null,
      };
      store.leaves.push(leave);
      saveStore(dataFile, store);
      return sendJson(res, 201, { leave });
    }

    if ((req.method === "DELETE" && /^\/api\/leaves\/[^/]+$/.test(url.pathname)) ||
        (req.method === "PATCH" && /^\/api\/leaves\/[^/]+\/cancel$/.test(url.pathname))) {
      if (!requireUser(session, "employee", res)) return;
      const leaveId = url.pathname.split("/")[3];
      const leave = store.leaves.find((item) => item.id === leaveId);
      if (!leave || leave.employeeId !== session.user.id) {
        return sendError(res, 404, "Leave request not found.");
      }
      if (!["pending", "approved"].includes(leave.status)) {
        return sendError(res, 409, "This leave request cannot be cancelled.");
      }
      leave.status = "cancelled";
      leave.cancelledAt = new Date().toISOString();
      saveStore(dataFile, store);
      return sendJson(res, 200, { leave });
    }

    if (req.method === "PATCH" && /^\/api\/leaves\/[^/]+\/status$/.test(url.pathname)) {
      if (!requireUser(session, "admin", res)) return;
      const body = await readJson(req);
      if (!["approved", "rejected"].includes(body.status)) return sendError(res, 400, "Choose approved or rejected.");
      const leaveId = url.pathname.split("/")[3];
      const leave = store.leaves.find((item) => item.id === leaveId);
      if (!leave) return sendError(res, 404, "Leave request not found.");
      leave.status = body.status;
      leave.reviewedAt = new Date().toISOString();
      saveStore(dataFile, store);
      return sendJson(res, 200, { leave });
    }

    if (req.method === "GET" && url.pathname === "/api/reports/monthly") {
      if (!requireUser(session, null, res)) return;
      const month = url.searchParams.get("month") || new Date().toISOString().slice(0, 7);
      if (!/^\d{4}-\d{2}$/.test(month)) return sendError(res, 400, "Month must use YYYY-MM format.");
      const monthNumber = Number(month.slice(5, 7));
      if (monthNumber < 1 || monthNumber > 12) return sendError(res, 400, "Month must use YYYY-MM format.");
      const employeeId = session.user.role === "employee"
        ? session.user.id
        : url.searchParams.get("employeeId");
      const employees = store.employees.filter((employee) => !employeeId || employee.id === employeeId);
      const monthStart = `${month}-01`;
      const monthDate = new Date(`${month}-01T00:00:00Z`);
      const monthEnd = new Date(Date.UTC(monthDate.getUTCFullYear(), monthDate.getUTCMonth() + 1, 0)).toISOString().slice(0, 10);
      const report = employees.map((employee) => {
        const attendance = store.attendance
          .filter((event) => event.employeeId === employee.id && event.at.slice(0, 7) === month)
          .sort((a, b) => a.at.localeCompare(b.at));
        const presentDates = new Set(attendance.filter((event) => event.type === "check-in").map((event) => event.at.slice(0, 10)));
        let activeCheckIn = null;
        let workingMs = 0;
        for (const event of attendance) {
          const timestamp = new Date(event.at).getTime();
          if (event.type === "check-in") activeCheckIn = timestamp;
          else if (activeCheckIn !== null) {
            workingMs += Math.max(0, timestamp - activeCheckIn);
            activeCheckIn = null;
          }
        }
        const employeeLeaves = store.leaves.filter((leave) => leave.employeeId === employee.id);
        const approvedLeaves = employeeLeaves.filter((leave) =>
          leave.status === "approved" && leave.startDate <= monthEnd && leave.endDate >= monthStart
        );
        const approvedDates = new Set();
        for (const leave of approvedLeaves) {
          let date = leave.startDate < monthStart ? monthStart : leave.startDate;
          while (date <= leave.endDate && date <= monthEnd) {
            approvedDates.add(date);
            const next = new Date(`${date}T00:00:00Z`);
            next.setUTCDate(next.getUTCDate() + 1);
            date = next.toISOString().slice(0, 10);
          }
        }
        return {
          employeeId: employee.id,
          employeeCode: employee.employeeId,
          employeeName: employee.name,
          presentDays: presentDates.size,
          workingMs,
          approvedLeaveDays: approvedDates.size,
          pendingLeaveCount: employeeLeaves.filter((leave) =>
            leave.status === "pending" && leave.startDate <= monthEnd && leave.endDate >= monthStart
          ).length,
          leaves: employeeLeaves
            .filter((leave) => leave.startDate <= monthEnd && leave.endDate >= monthStart)
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
          attendance: attendance,
        };
      });
      return sendJson(res, 200, { month, monthStart, monthEnd, report });
    }

    return sendError(res, 404, "Not found.");
  }

  const server = http.createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    const url = new URL(req.url, "http://localhost");
    try {
      if (url.pathname.startsWith("/api/")) {
        return await handleApi(req, res, getSession(req, res), url);
      }
      if (req.method !== "GET" && req.method !== "HEAD") return sendError(res, 405, "Method not allowed.");
      const relativePath = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
      if (!["index.html", "styles.css", "app.js", "lux-decibels-logo.png", "logowhit.png"].includes(relativePath)) return sendError(res, 404, "Not found.");
      const filePath = path.join(ROOT, relativePath);
      const content = fs.readFileSync(filePath);
      res.writeHead(200, { "Content-Type": MIME_TYPES[path.extname(filePath)], "Cache-Control": "no-cache" });
      return res.end(req.method === "HEAD" ? undefined : content);
    } catch (error) {
      console.error("Request failed:", error);
      return sendError(res, error.status || 500, error.status ? error.message : "Something went wrong. Please try again.");
    }
  });

  return server;
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || "127.0.0.1";
  const server = createAppServer();
  server.listen(port, host, () => {
    console.log(`Attendance app running at http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${port}`);
    if (host === "0.0.0.0") {
      const addresses = Object.values(os.networkInterfaces())
        .flat()
        .filter((address) => address && address.family === "IPv4" && !address.internal)
        .map((address) => address.address);
      for (const address of addresses) {
        console.log(`Phone on the same Wi-Fi: http://${address}:${port}`);
      }
    }
  });
}

module.exports = { createAppServer };
