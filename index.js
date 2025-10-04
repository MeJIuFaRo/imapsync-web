
"use strict";

/*
  OpenThreat IMAPSync server
  - /sync       : full synchronization (WS log stream + progress)
  - /check-sync : credentials check (--justlogin) via the same WS pipeline with 10s timeout
  - /cancel     : cancel running job via abort file
  
  Timeout logic:
  - Check Credentials: 10 seconds absolute timeout
  - Start Sync: inactivity timeout (resets on each log line)
*/

const express = require("express");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const url = require("url");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

const jobs = new Map();

/** Utilities */
function makeJobId() {
  return crypto.randomBytes(12).toString("hex");
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

// Функция создания директории для логов
function createLogDirectory(host1, user1, host2, user2) {
    const sanitize = (str) => str.replace(/[^a-zA-Z0-9._-]/g, '_');
    const dirName = `${sanitize(host1)}_${sanitize(user1)}_${sanitize(host2)}_${sanitize(user2)}`;
    const logDir = path.join('/tmp/logs', dirName);
    
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
    }
    
    return logDir;
}

// Функция создания имени лог-файла
function createLogFileName() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    
    return `${year}-${month}-${day}_${hours}-${minutes}-${seconds}.log`;
}

/** Fanout */
function broadcast(job, entry) {
  const payload = typeof entry === "string" ? entry : JSON.stringify(entry);
  for (const s of job.sockets) {
    if (s.readyState === 1) s.send(payload);
  }
}

/** Overall progress snapshot */
function sendProgress(job) {
  const p = job.progress || {};
  const evt = { type: "progress" };
  if (typeof p.copied === "number") evt.copied = p.copied;
  if (typeof p.total === "number") evt.total = p.total;
  if (typeof p.percentage === "number") evt.percentage = clamp(p.percentage, 0, 100);
  broadcast(job, evt);
}

/** Reset inactivity timeout for sync jobs */
function resetInactivityTimeout(job) {
  if (!job.inactivityTimeoutEnabled) return;
  
  // Clear existing timeout
  if (job.inactivityTimer) {
    clearTimeout(job.inactivityTimer);
  }
  
  // Set new timeout
  const INACTIVITY_TIMEOUT_MS = Number(process.env.INACTIVITY_TIMEOUT_MS || 2 * 60 * 60 * 1000); // 2 hours default
  
  job.inactivityTimer = setTimeout(() => {
    const j = jobs.get(job.id);
    if (j && j.child && j.status === "running") {
      const timeoutMinutes = Math.round(INACTIVITY_TIMEOUT_MS / 60000);
      const warn = `\n[SERVER] Job ${job.id} has been inactive for ${timeoutMinutes} minutes, initiating graceful abort...\n`;
      j.buffer.push(warn);
      broadcast(j, warn);
      if (j.logStream) j.logStream.write(warn);
      
      console.log(`Job ${job.id} timed out due to inactivity (${timeoutMinutes} minutes)`);
      
      // Используем abort file для graceful shutdown
      if (j.abortFilePath) {
        try {
          fs.writeFileSync(j.abortFilePath, `Inactivity timeout at ${new Date().toISOString()}\nJob ID: ${job.id}\nInactive for: ${timeoutMinutes} minutes\n`);
          j.cancelled = true;
          console.log(`Abort file created due to inactivity timeout: ${j.abortFilePath}`);
        } catch (e) {
          console.error(`Failed to create abort file on inactivity timeout: ${e.message}`);
          // Fallback к kill
          killImapsyncProcess(j, "inactivity timeout");
        }
      } else {
        killImapsyncProcess(j, "inactivity timeout");
      }
    }
  }, INACTIVITY_TIMEOUT_MS);
  
  job.lastActivityTime = Date.now();
}

/** Parser for imapsync output: derive overall progress */
function attachImapSyncParsers(job) {
  job.progress = job.progress || { copied: 0, total: undefined, percentage: undefined };
  job._progressMode = "unknown"; // "unknown" | "per-folder" | "global"

  // Per-folder fallback state
  job.folders = job.folders || new Map(); // name -> { total, selected, duplicates }
  function ensureFolder(name) {
    if (!job.folders.has(name)) job.folders.set(name, { total: undefined, selected: 0, duplicates: 0 });
    return job.folders.get(name);
  }
  function recalcFromFolders() {
    let total = 0, done = 0, haveTotals = true;
    for (const f of job.folders.values()) {
      if (typeof f.total === "number") {
        total += f.total;
        const fd = Math.min((Number(f.selected) || 0) + (Number(f.duplicates) || 0), f.total);
        done += fd;
      } else {
        haveTotals = false;
      }
    }
    if (haveTotals && total > 0) {
      job.progress.total = total;
      job.progress.copied = done;
      job.progress.percentage = Math.round((done / total) * 100);
      job._progressMode = job._progressMode === "global" ? "global" : "per-folder";
      sendProgress(job);
    }
  }

  // Regexes
  const reMsgsLeft = /(\d+)\s*\/\s*(\d+)\s+msgs\s+left/i;         // "108/109 msgs left"
  const reMsgsDone = /(\d+)\s*\/\s*(\d+)\s+msgs\s+done/i;         // "X/Y msgs done"
  const reFolderTotal = /^Host1:\s+folder\s+\[(.+?)\]\s+has\s+(\d+)\s+messages\s+in\s+total/i;
  const reFolderSelected = /^Host2:\s+folder\s+\[(.+?)\]\s+selected\s+(\d+)\s+messages,\s+duplicates\s+(\d+)/i;

  job.onLine = (line) => {
    // 1) Global: X/Y msgs left
    let m = line.match(reMsgsLeft);
    if (m) {
      const left = Number(m[1]);
      const total = Number(m[2]);
      if (Number.isFinite(left) && Number.isFinite(total) && total > 0 && left >= 0 && left <= total) {
        const done = total - left;
        job.progress.total = total;
        job.progress.copied = done;
        job.progress.percentage = Math.round((done / total) * 100);
        job._progressMode = "global";
        sendProgress(job);
      }
      return;
    }

    // 2) Alternative: X/Y msgs done
    m = line.match(reMsgsDone);
    if (m) {
      const done = Number(m[1]);
      const total = Number(m[2]);
      if (Number.isFinite(done) && Number.isFinite(total) && total > 0 && done >= 0 && done <= total) {
        job.progress.total = total;
        job.progress.copied = done;
        job.progress.percentage = Math.round((done / total) * 100);
        job._progressMode = "global";
        sendProgress(job);
      }
      return;
    }

    // 3) Fallback per-folder — only when global not active
    if (job._progressMode !== "global") {
      let t = line.match(reFolderTotal);
      if (t) {
        const name = t[1];
        const total = Number(t[2]);
        const f = ensureFolder(name);
        if (Number.isFinite(total)) {
          f.total = total;
          recalcFromFolders();
        }
        return;
      }

      let s = line.match(reFolderSelected);
      if (s) {
        const name = s[1];
        const selected = Number(s[2]);
        const duplicates = Number(s[3]);
        const f = ensureFolder(name);
        if (Number.isFinite(selected)) f.selected = selected;
        if (Number.isFinite(duplicates)) f.duplicates = duplicates;
        recalcFromFolders();
        return;
      }
    }
  };
}

/** Kill imapsync process gracefully */
function killImapsyncProcess(job, reason = "timeout") {
  if (!job.child || job.status !== "running") {
    return;
  }

  const msg = `\n[SERVER] Terminating imapsync process (reason: ${reason})...\n`;
  job.buffer.push(msg);
  broadcast(job, msg);
  if (job.logStream) {
    job.logStream.write(msg);
  }

  try {
    job.child.kill("SIGTERM");
    console.log(`Sent SIGTERM to job ${job.id} (${reason})`);
    
    // Если через 5 секунд не завершился - SIGKILL
    setTimeout(() => {
      if (job.status === "running" && job.child) {
        try {
          job.child.kill("SIGKILL");
          const killMsg = `[SERVER] Process did not terminate, sent SIGKILL\n`;
          if (job.logStream) {
            job.logStream.write(killMsg);
          }
          console.log(`Sent SIGKILL to job ${job.id} (${reason})`);
        } catch (_) {}
      }
    }, 5000);
  } catch (err) {
    const errMsg = `[SERVER] Failed to kill process: ${err.message}\n`;
    job.buffer.push(errMsg);
    broadcast(job, errMsg);
    if (job.logStream) {
      job.logStream.write(errMsg);
    }
  }
}

/** Start imapsync (full sync) with abort file monitoring and inactivity timeout */
function startImapSync(job, payload) {
  const { host1, user1, pass1, host2, user2, pass2, debug, nosslcheck } = payload || {};
  if (!host1 || !user1 || !pass1 || !host2 || !user2 || !pass2) {
    throw new Error("Missing required credentials");
  }

  // Создаём директорию для логов
  const logDir = createLogDirectory(host1, user1, host2, user2);
  const logFileName = createLogFileName();
  const logFilePath = path.join(logDir, logFileName);
  
  // Путь к abort-файлу в той же директории что и логи
  const abortFilePath = path.join(logDir, 'abort.txt');
  
  // Создаём поток для записи в файл
  const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
  job.logStream = logStream;
  job.logFilePath = logFilePath;
  job.logDir = logDir;
  job.abortFilePath = abortFilePath;
  
  // Enable inactivity timeout for sync jobs
  job.inactivityTimeoutEnabled = true;
  
  // Записываем заголовок в лог
  const INACTIVITY_TIMEOUT_MS = Number(process.env.INACTIVITY_TIMEOUT_MS || 2 * 60 * 60 * 1000);
  const timeoutMinutes = Math.round(INACTIVITY_TIMEOUT_MS / 60000);
  
  const logHeader = `=== IMAP Sync Started at ${new Date().toISOString()} ===\n` +
                   `Source: ${user1}@${host1}\n` +
                   `Destination: ${user2}@${host2}\n` +
                   `Log directory: ${logDir}\n` +
                   `Log file: ${logFilePath}\n` +
                   `Abort file: ${abortFilePath}\n` +
                   `Inactivity timeout: ${timeoutMinutes} minutes\n` +
                   `${'='.repeat(60)}\n\n`;
  logStream.write(logHeader);

  const args = [
    "--host1", host1,
    "--user1", user1,
    "--password1", pass1,
    "--host2", host2,
    "--user2", user2,
    "--password2", pass2,
    "--ssl1",
    "--ssl2",
    "--automap",
    "--noresyncflags",
    "--allowsizemismatch",
    "--skipemptyfolders",
  ];

  if (nosslcheck === "on" || nosslcheck === true) {
    args.push("--nosslcheck");
  }
  if (debug === "on" || debug === true) {
    args.push("--debug");
  }

  const child = spawn("imapsync", args, { stdio: ["ignore", "pipe", "pipe"] });
  job.child = child;
  job.status = "running";

  attachImapSyncParsers(job);
  
  // Start inactivity timeout
  resetInactivityTimeout(job);

  // Мониторинг abort-файла каждые 2 секунды
  job.abortCheckInterval = setInterval(() => {
    if (fs.existsSync(abortFilePath)) {
      const msg = `\n[SERVER] Abort file detected: ${abortFilePath}\n[SERVER] Sending SIGTERM for graceful shutdown...\n\n`;
      job.buffer.push(msg);
      broadcast(job, msg);
      if (job.logStream) {
        job.logStream.write(msg);
      }
      
      clearInterval(job.abortCheckInterval);
      job.abortCheckInterval = null;
      
      // Clear inactivity timeout
      if (job.inactivityTimer) {
        clearTimeout(job.inactivityTimer);
        job.inactivityTimer = null;
      }
      
      killImapsyncProcess(job, "user cancellation");
    }
  }, 2000);

  // Periodic keepalive to reduce idle WS timeouts
  job.keepaliveTimer = setInterval(() => {
    broadcast(job, { type: "keepalive", ts: Date.now() });
  }, 20000);

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");

  function safeParseLine(line) {
    try {
      if (job.onLine) job.onLine(line);
    } catch (e) {
      const warn = `[server] parser error: ${e.message}\n`;
      job.buffer.push(warn);
      broadcast(job, warn);
      if (job.logStream) job.logStream.write(warn);
    }
  }

  let stdoutBuf = "";
  child.stdout.on("data", (chunk) => {
    // Reset inactivity timeout on each log line
    resetInactivityTimeout(job);
    
    stdoutBuf += chunk;
    let idx;
    while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
      const line = stdoutBuf.slice(0, idx + 1);
      stdoutBuf = stdoutBuf.slice(idx + 1);
      job.buffer.push(line);
      broadcast(job, line);
      safeParseLine(line);
      if (job.logStream) job.logStream.write(line);
    }
  });

  let stderrBuf = "";
  child.stderr.on("data", (chunk) => {
    // Reset inactivity timeout on each log line
    resetInactivityTimeout(job);
    
    stderrBuf += chunk;
    let idx;
    while ((idx = stderrBuf.indexOf("\n")) >= 0) {
      const line = stderrBuf.slice(0, idx + 1);
      stderrBuf = stderrBuf.slice(idx + 1);
      job.buffer.push(line);
      broadcast(job, line);
      safeParseLine(line);
      if (job.logStream) job.logStream.write(`[ERROR] ${line}`);
    }
  });

  child.on("error", (err) => {
    const msg = `[server] Failed to start imapsync: ${err.message}\n`;
    job.buffer.push(msg);
    broadcast(job, msg);
    if (job.logStream) job.logStream.write(msg);
  });

  child.on("close", (code, signal) => {
    clearInterval(job.keepaliveTimer);
    job.keepaliveTimer = null;
    
    if (job.abortCheckInterval) {
      clearInterval(job.abortCheckInterval);
      job.abortCheckInterval = null;
    }
    
    if (job.inactivityTimer) {
      clearTimeout(job.inactivityTimer);
      job.inactivityTimer = null;
    }

    const duration = Date.now() - job.createdAt;
    const durationMin = Math.round(duration / 60000);
    
    const wasCancelled = job.cancelled === true;
    const footer = `\n${'='.repeat(60)}\n` +
                  `=== Sync ${wasCancelled ? 'CANCELLED' : 'Completed'} at ${new Date().toISOString()} ===\n` +
                  `Exit code: ${code}\n` +
                  `Signal: ${signal || 'none'}\n` +
                  `Duration: ${durationMin} minutes\n` +
                  `${'='.repeat(60)}\n`;
    
    if (job.logStream) {
      job.logStream.write(footer);
      job.logStream.end();
    }
    
    // Удаляем abort-файл после завершения (если он был создан)
    try {
      if (fs.existsSync(job.abortFilePath)) {
        fs.unlinkSync(job.abortFilePath);
        console.log(`Removed abort file: ${job.abortFilePath}`);
      }
    } catch (e) {
      console.warn(`Failed to remove abort file: ${e.message}`);
    }
    
    console.log(`imapsync process exited with code ${code}`);
    console.log(`Log saved to: ${logFilePath}`);

    job.status = "finished";
    broadcast(job, { 
      type: "done", 
      code: Number(code), 
      signal: signal || null,
      cancelled: wasCancelled
    });

    // Close all sockets after done
    for (const s of job.sockets) {
      try {
        s.close(1000, "done");
      } catch (_) {}
    }
  });
}

/** Start imapsync --justlogin (check mode) with 10s timeout */
function startImapJustLogin(job, payload) {
  const { host1, user1, pass1, host2, user2, pass2, debug, nosslcheck } = payload || {};
  if (!host1 || !user1 || !pass1 || !host2 || !user2 || !pass2) {
    throw new Error("Missing required credentials");
  }

  const args = [
    "--host1", host1,
    "--user1", user1,
    "--password1", pass1,
    "--host2", host2,
    "--user2", user2,
    "--password2", pass2,
    "--ssl1",
    "--ssl2",
    "--justlogin",
  ];

  if (nosslcheck === "on" || nosslcheck === true) {
    args.push("--nosslcheck");
  }
  if (debug === "on" || debug === true) {
    args.push("--debug");
  }

  const child = spawn("imapsync", args, { stdio: ["ignore", "pipe", "pipe"] });
  job.child = child;
  job.status = "running";

  attachImapSyncParsers(job);

  // 10 second timeout for credential check
  const CHECK_TIMEOUT = 10000; // 10 seconds
  job.checkTimeoutTimer = setTimeout(() => {
    if (job.status === "running") {
      const msg = `\n[SERVER] Credential check timeout (10 seconds) - terminating process...\n`;
      job.buffer.push(msg);
      broadcast(job, msg);
      console.log(`Check timeout for job ${job.id}`);
      
      killImapsyncProcess(job, "check timeout");
      
      // Mark as timeout failure
      job.timedOut = true;
    }
  }, CHECK_TIMEOUT);

  // keepalive WS
  job.keepaliveTimer = setInterval(() => {
    broadcast(job, { type: "keepalive", ts: Date.now() });
  }, 20000);

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");

  function safeParseLine(line) {
    try {
      if (job.onLine) job.onLine(line);
    } catch (e) {
      const warn = `[server] parser error: ${e.message}\n`;
      job.buffer.push(warn);
      broadcast(job, warn);
    }
  }

  let stdoutBuf = "";
  child.stdout.on("data", (chunk) => {
    stdoutBuf += chunk;
    let idx;
    while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
      const line = stdoutBuf.slice(0, idx + 1);
      stdoutBuf = stdoutBuf.slice(idx + 1);
      job.buffer.push(line);
      broadcast(job, line);
      safeParseLine(line);
    }
  });

  let stderrBuf = "";
  child.stderr.on("data", (chunk) => {
    stderrBuf += chunk;
    let idx;
    while ((idx = stderrBuf.indexOf("\n")) >= 0) {
      const line = stderrBuf.slice(0, idx + 1);
      stderrBuf = stderrBuf.slice(idx + 1);
      job.buffer.push(line);
      broadcast(job, line);
      safeParseLine(line);
    }
  });

  child.on("error", (err) => {
    const msg = `[server] Failed to start imapsync: ${err.message}\n`;
    job.buffer.push(msg);
    broadcast(job, msg);
  });

  child.on("close", (code, signal) => {
    // Clear timeout timer
    if (job.checkTimeoutTimer) {
      clearTimeout(job.checkTimeoutTimer);
      job.checkTimeoutTimer = null;
    }

    clearInterval(job.keepaliveTimer);
    job.keepaliveTimer = null;

    job.status = "finished";
    
    // If timed out, return error code
    const finalCode = job.timedOut ? 124 : Number(code); // 124 = timeout exit code
    
    broadcast(job, { 
      type: "done", 
      code: finalCode, 
      signal: signal || null,
      timedOut: job.timedOut || false
    });

    // Close WS
    for (const s of job.sockets) {
      try {
        s.close(1000, "done");
      } catch (_) {}
    }
  });
}

/** POST /sync */
app.post("/sync", (req, res) => {
  try {
    const jobId = makeJobId();
    const job = {
      id: jobId,
      createdAt: Date.now(),
      buffer: [],
      sockets: new Set(),
      status: "pending",
      progress: { copied: 0, total: undefined, percentage: undefined },
      cancelled: false,
      inactivityTimeoutEnabled: false,
      inactivityTimer: null,
      lastActivityTime: null,
    };
    jobs.set(jobId, job);

    startImapSync(job, req.body);

    res.json({ 
      jobId,
      logFile: job.logFilePath,
      logDir: job.logDir
    });
  } catch (err) {
    res.status(400).json({ error: err.message || "Bad Request" });
  }
});

/** POST /check-sync */
app.post("/check-sync", (req, res) => {
  try {
    const jobId = makeJobId();
    const job = {
      id: jobId,
      createdAt: Date.now(),
      buffer: [],
      sockets: new Set(),
      status: "pending",
      progress: { copied: 0, total: undefined, percentage: undefined },
      timedOut: false,
    };
    jobs.set(jobId, job);

    startImapJustLogin(job, req.body);

    res.json({ jobId });
  } catch (err) {
    res.status(400).json({ error: err.message || "Bad Request" });
  }
});

/** POST /cancel - Cancel running job gracefully */
app.post("/cancel", (req, res) => {
  const { jobId } = req.body;
  
  if (!jobId) {
    return res.status(400).json({ error: "jobId is required" });
  }
  
  const job = jobs.get(jobId);
  
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }
  
  if (job.status !== "running") {
    return res.status(400).json({ error: `Job is not running (status: ${job.status})` });
  }
  
  // Создаём abort-файл для graceful shutdown
  if (job.abortFilePath) {
    try {
      const abortMessage = `Cancelled by user at ${new Date().toISOString()}\nJob ID: ${jobId}\n`;
      fs.writeFileSync(job.abortFilePath, abortMessage);
      job.cancelled = true;
      
      const msg = `\n[CLIENT] Cancellation requested - abort file created: ${job.abortFilePath}\n`;
      const msg2 = `[CLIENT] imapsync will be terminated gracefully...\n\n`;
      job.buffer.push(msg);
      job.buffer.push(msg2);
      broadcast(job, msg);
      broadcast(job, msg2);
      if (job.logStream) {
        job.logStream.write(msg);
        job.logStream.write(msg2);
      }
      
      console.log(`Abort file created for job ${jobId}: ${job.abortFilePath}`);
      
      res.json({ 
        success: true, 
        message: "Abort file created - process will terminate gracefully",
        jobId: jobId,
        abortFile: job.abortFilePath
      });
    } catch (err) {
      console.error(`Failed to create abort file: ${err.message}`);
      res.status(500).json({ 
        error: `Failed to create abort file: ${err.message}` 
      });
    }
  } else {
    // Fallback: kill process directly if no abort file path
    try {
      killImapsyncProcess(job, "user cancellation");
      job.cancelled = true;
      res.json({ 
        success: true, 
        message: "SIGTERM sent to process (no abort file available)",
        jobId: jobId
      });
    } catch (err) {
      res.status(500).json({ 
        error: `Failed to kill process: ${err.message}` 
      });
    }
  }
});

/** (Optional legacy) POST /check — JSON check */
app.post("/check", async (req, res) => {
  try {
    const { host1, user1, pass1, host2, user2, pass2, debug, nosslcheck } = req.body || {};
    if (!host1 || !user1 || !pass1 || !host2 || !user2 || !pass2) {
      return res.status(400).json({ error: "Missing required credentials" });
    }

    const args = [
      "--host1", host1, "--user1", user1, "--password1", pass1,
      "--host2", host2, "--user2", user2, "--password2", pass2,
      "--ssl1", "--ssl2",
      "--justlogin"
    ];
    if (nosslcheck === "on" || nosslcheck === true) args.push("--nosslcheck");
    if (debug === "on" || debug === true) args.push("--debug");

    const child = spawn("imapsync", args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (ch) => { out += ch; });
    child.stderr.on("data", (ch) => { out += ch; });

    child.on("error", (err) => {
      res.status(500).json({ ok: false, error: `Failed to start imapsync: ${err.message}` });
    });

    child.on("close", (code) => {
      const host1Fail = /Host1:.*FAIL/i.test(out);
      const host2Fail = /Host2:.*FAIL/i.test(out);
      const ok = !host1Fail && !host2Fail && (code === 0 || code === null);

      if (ok) {
        res.json({ ok: true, output: out, host1Fail: false, host2Fail: false });
      } else {
        res.status(400).json({ ok: false, output: out, host1Fail, host2Fail });
      }
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || "Internal error" });
  }
});

/** (Optional) POST /check-stream — SSE streaming */
app.post("/check-stream", async (req, res) => {
  try {
    const { host1, user1, pass1, host2, user2, pass2, debug, nosslcheck } = req.body || {};
    if (!host1 || !user1 || !pass1 || !host2 || !user2 || !pass2) {
      res.status(400).set("Content-Type", "text/plain; charset=utf-8");
      return res.end("Missing required credentials");
    }

    // SSE headers
    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");

    const args = [
      "--host1", host1, "--user1", user1, "--password1", pass1,
      "--host2", host2, "--user2", user2, "--password2", pass2,
      "--ssl1", "--ssl2",
      "--justlogin"
    ];
    if (nosslcheck === "on" || nosslcheck === true) args.push("--nosslcheck");
    if (debug === "on" || debug === true) args.push("--debug");

    const child = spawn("imapsync", args, { stdio: ["ignore", "pipe", "pipe"] });

    let out = "";
    let stdoutBuffer = "";
    let stderrBuffer = "";

    const sendEvent = (event, data) => {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");

    // Stream lines in full (buffer until newline)
    child.stdout.on("data", (chunk) => {
      out += chunk;
      stdoutBuffer += chunk;
      let idx;
      while ((idx = stdoutBuffer.indexOf("\n")) >= 0) {
        const line = stdoutBuffer.slice(0, idx + 1);
        stdoutBuffer = stdoutBuffer.slice(idx + 1);
        sendEvent("line", { line });
      }
    });

    child.stderr.on("data", (chunk) => {
      out += chunk;
      stderrBuffer += chunk;
      let idx;
      while ((idx = stderrBuffer.indexOf("\n")) >= 0) {
        const line = stderrBuffer.slice(0, idx + 1);
        stderrBuffer = stderrBuffer.slice(idx + 1);
        sendEvent("line", { line });
      }
    });

    child.on("error", (err) => {
      sendEvent("line", { line: `[server] Failed to start imapsync: ${err.message}\n` });
      sendEvent("end", { ok: false, host1Fail: true, host2Fail: true });
      res.end();
    });

    child.on("close", (code) => {
      // Flush remaining partials (if no trailing newline)
      if (stdoutBuffer.length) sendEvent("line", { line: stdoutBuffer + "\n" });
      if (stderrBuffer.length) sendEvent("line", { line: stderrBuffer + "\n" });

      const host1Fail = /Host1:.*FAIL/i.test(out);
      const host2Fail = /Host2:.*FAIL/i.test(out);
      const ok = !host1Fail && !host2Fail && (code === 0 || code === null);

      sendEvent("end", { ok, host1Fail, host2Fail });
      res.end();
    });

    // Client disconnected -> stop child
    req.on("close", () => {
      try { child.kill("SIGTERM"); } catch (_) {}
    });

  } catch (err) {
    if (!res.headersSent) {
      res.status(500).set("Content-Type", "text/plain; charset=utf-8");
    }
    res.end(err.message || "Internal error");
  }
});

/** WS upgrade */
server.on("upgrade", (request, socket, head) => {
  const { query } = url.parse(request.url, true);
  const jobId = query.job;

  if (!jobId || !jobs.has(jobId)) {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit("connection", ws, request, jobId);
  });
});

/** WS connection */
wss.on("connection", (ws, request, jobId) => {
  const job = jobs.get(jobId);
  if (!job) {
    ws.close(1008, "Invalid job");
    return;
  }

  job.sockets.add(ws);

  // Flush buffered logs to the new client
  if (Array.isArray(job.buffer) && job.buffer.length) {
    for (const entry of job.buffer) {
      ws.send(typeof entry === "string" ? entry : String(entry));
    }
    job.buffer.length = 0;
  }

  // Send current progress snapshot
  sendProgress(job);

  ws.on("message", (data) => {
    // Optional: client pings
    try {
      const parsed = JSON.parse(String(data));
      if (parsed && parsed.type === "ping") {
        // no-op
      }
    } catch (_) {
      // ignore non-JSON
    }
  });

  ws.on("close", () => {
    job.sockets.delete(ws);
  });
});

/** Graceful shutdown */
function shutdown() {
  console.log("Shutting down gracefully...");
  for (const [jobId, job] of jobs) {
    if (job.child && job.status === "running") {
      // Используем abort file для graceful shutdown
      if (job.abortFilePath) {
        try {
          fs.writeFileSync(job.abortFilePath, `Server shutdown at ${new Date().toISOString()}\nJob ID: ${jobId}\n`);
          job.cancelled = true;
          console.log(`Abort file created for shutdown: ${job.abortFilePath}`);
        } catch (e) {
          console.warn(`Failed to create abort file on shutdown: ${e.message}`);
        }
      }
      killImapsyncProcess(job, "server shutdown");
    }
    if (job.inactivityTimer) {
      clearTimeout(job.inactivityTimer);
      job.inactivityTimer = null;
    }
    if (job.logStream) {
      job.logStream.write(`\n[SHUTDOWN] Server shutdown at ${new Date().toISOString()}\n`);
      job.logStream.end();
    }
    for (const ws of job.sockets) {
      try { ws.close(1001, "server shutdown"); } catch (_) {}
    }
  }
  
  // Даём время для graceful shutdown
  setTimeout(() => {
    server.close(() => {
      console.log("Server closed");
      process.exit(0);
    });
  }, 2000);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

/** Start server */
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  const INACTIVITY_TIMEOUT_MS = Number(process.env.INACTIVITY_TIMEOUT_MS || 2 * 60 * 60 * 1000);
  const timeoutMinutes = Math.round(INACTIVITY_TIMEOUT_MS / 60000);
  console.log(`Inactivity timeout for sync jobs: ${timeoutMinutes} minutes`);
});
