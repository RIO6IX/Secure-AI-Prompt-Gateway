const { app, BrowserWindow, shell } = require("electron");
const { spawn } = require("node:child_process");
const http = require("node:http");
const path = require("node:path");

const FRONTEND_URL = "http://localhost:3000";
const BACKEND_READY_URL = "http://127.0.0.1:8000/ready";
const LOCAL_PROJECT_ROOT = "C:\\Users\\user\\OneDrive\\Desktop\\Secure AI Prompt Gateway\\Dashboard";

const childProcesses = [];

function requestOk(url) {
  return new Promise((resolve) => {
    const request = http.get(url, (response) => {
      response.resume();
      resolve(response.statusCode >= 200 && response.statusCode < 500);
    });
    request.on("error", () => resolve(false));
    request.setTimeout(2500, () => {
      request.destroy();
      resolve(false);
    });
  });
}

async function waitFor(url, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await requestOk(url)) return true;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return false;
}

function projectRoot() {
  return process.env.SECURE_GATEWAY_PROJECT_ROOT || LOCAL_PROJECT_ROOT;
}

function startProcess(command, args, cwd) {
  const child = spawn(command, args, {
    cwd,
    shell: false,
    windowsHide: true,
    stdio: "ignore",
    env: {
      ...process.env,
      OLLAMA_MODEL: process.env.OLLAMA_MODEL || "qwen2.5:3b",
      OLLAMA_BASE_URL: process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434",
    },
  });
  childProcesses.push(child);
}

async function ensureLocalStack() {
  const root = projectRoot();
  const backendReady = await requestOk(BACKEND_READY_URL);
  if (!backendReady) {
    startProcess("python", ["-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000"], path.join(root, "python_gateway"));
  }

  const frontendReady = await requestOk(FRONTEND_URL);
  if (!frontendReady) {
    startProcess("npm.cmd", ["run", "dev"], root);
  }

  const [backendStarted, frontendStarted] = await Promise.all([
    waitFor(BACKEND_READY_URL, 30000),
    waitFor(FRONTEND_URL, 45000),
  ]);

  return backendStarted && frontendStarted;
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1500,
    height: 930,
    minWidth: 1100,
    minHeight: 720,
    backgroundColor: "#f8fbff",
    title: "Secure AI Prompt Gateway",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  return win;
}

async function boot() {
  const win = createWindow();
  win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent("<h2 style='font-family:Arial;padding:32px'>Starting Secure AI Prompt Gateway...</h2>")}`);
  const ready = await ensureLocalStack();
  if (ready) {
    await win.loadURL(FRONTEND_URL);
  } else {
    await win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(`
      <main style="font-family:Arial;padding:32px;line-height:1.5">
        <h1>Secure AI Prompt Gateway could not start</h1>
        <p>Check that Python, Node.js, and the project folder are available.</p>
        <p>Project path: ${projectRoot()}</p>
      </main>
    `)}`);
  }
}

app.whenReady().then(boot);

app.on("window-all-closed", () => {
  for (const child of childProcesses) {
    try {
      child.kill();
    } catch {
      // Ignore shutdown races.
    }
  }
  if (process.platform !== "darwin") app.quit();
});
