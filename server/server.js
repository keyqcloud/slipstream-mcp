#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const API_URL = process.env.SLIPSTREAM_API_URL || "https://slipstream-api.keyq.io";
const TOKEN = process.env.SLIPSTREAM_TOKEN;
const DEBUG = process.env.SLIPSTREAM_DEBUG === "1";

if (!TOKEN) {
  console.error("Error: SLIPSTREAM_TOKEN environment variable is required.\n");
  console.error("To get a token:");
  console.error("  1. Go to https://slipstream.keyq.io/settings");
  console.error("  2. Scroll to 'API Tokens'");
  console.error("  3. Create a token and copy the pat_... value\n");
  console.error("Then set it:");
  console.error('  export SLIPSTREAM_TOKEN="pat_your_token_here"');
  process.exit(1);
}

function debug(...args) {
  if (DEBUG) console.error("[slipstream-mcp]", ...args);
}

// ─── Dangerous command detection ─────────────────

const DANGEROUS_PATTERNS = [
  { pattern: /\brm\s+(-[rf]+\s+)?\//, label: "rm with absolute path" },
  { pattern: /\brm\s+-rf\b/, label: "recursive force delete" },
  { pattern: /\bmkfs\b/, label: "filesystem format" },
  { pattern: /\bdd\s+.*of=\/dev\//, label: "disk overwrite" },
  { pattern: /\b(shutdown|reboot|halt|poweroff)\b/, label: "system shutdown/reboot" },
  { pattern: /\b(DROP|TRUNCATE|DELETE\s+FROM)\b/i, label: "destructive SQL" },
  { pattern: />\s*\/dev\/sd[a-z]/, label: "write to raw disk" },
  { pattern: /\bchmod\s+777\b/, label: "world-writable permissions" },
  { pattern: /\bchown\s+-R\s+.*\/\s*$/, label: "recursive chown on root" },
  { pattern: /\b:(){ :|:& };:/, label: "fork bomb" },
  { pattern: /\bcurl\b.*\|\s*(sudo\s+)?bash/, label: "pipe curl to bash" },
  { pattern: /\biptables\s+-F\b/, label: "flush firewall rules" },
  { pattern: /\bsystemctl\s+(stop|disable)\s+(sshd|ssh|networking|firewalld)\b/, label: "disable critical service" },
];

function detectDangerousCommand(command) {
  const warnings = [];
  for (const { pattern, label } of DANGEROUS_PATTERNS) {
    if (pattern.test(command)) {
      warnings.push(label);
    }
  }
  return warnings;
}

// ─── API helpers with retry ──────────────────────

async function apiRequest(method, path, body, retries = 2) {
  const url = `${API_URL}${path}`;
  debug(`${method} ${path}`);

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const opts = {
        method,
        headers: {
          Authorization: `Bearer ${TOKEN}`,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      };

      const resp = await fetch(url, opts);

      if (resp.status === 401) {
        throw new Error("Authentication failed. Your token may be invalid or revoked. Create a new one at https://slipstream.keyq.io/settings");
      }

      if (resp.status === 403) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || "Permission denied. Check your permissions in the Slipstream dashboard.");
      }

      if (resp.status === 429) {
        throw new Error("Rate limit exceeded. Wait a moment and try again.");
      }

      if (resp.status >= 500 && attempt < retries) {
        debug(`Server error ${resp.status}, retrying in ${(attempt + 1) * 1000}ms...`);
        await new Promise((r) => setTimeout(r, (attempt + 1) * 1000));
        continue;
      }

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`API error ${resp.status}: ${text}`);
      }

      return resp.json();
    } catch (e) {
      if (e.message.includes("Authentication") || e.message.includes("Permission") || e.message.includes("Rate limit")) {
        throw e; // Don't retry auth/permission/rate errors
      }
      if (attempt < retries) {
        debug(`Request failed: ${e.message}, retrying...`);
        await new Promise((r) => setTimeout(r, (attempt + 1) * 1000));
        continue;
      }
      throw e;
    }
  }
}

const apiGet = (path) => apiRequest("GET", path);
const apiPost = (path, body) => apiRequest("POST", path, body);

async function getDeviceTags(deviceId) {
  try {
    const tags = await apiGet(`/tags/device/${deviceId}`);
    return tags.map((t) => t.name);
  } catch {
    return [];
  }
}

async function pollExecResult(execId, timeoutSecs = 30) {
  const maxWaitMs = (timeoutSecs + 5) * 1000; // timeout + 5s buffer
  const start = Date.now();
  let interval = 300; // Start fast, slow down

  while (Date.now() - start < maxWaitMs) {
    const result = await apiGet(`/exec/${execId}`);
    if (result.status === "completed" || result.status === "failed" || result.status === "timeout") {
      return result;
    }
    await new Promise((r) => setTimeout(r, interval));
    interval = Math.min(interval * 1.5, 2000); // Back off to 2s max
  }
  return { status: "timeout", stdout: "", stderr: "Client-side polling timed out waiting for result" };
}

// ─── MCP Server ──────────────────────────────────

const server = new McpServer({
  name: "slipstream",
  version: "0.1.0",
});

// Tool: list devices
server.tool(
  "list_devices",
  "List all devices in your Slipstream organization with their online status, tags, and capabilities. Use this first to find device IDs before running commands.",
  {},
  async () => {
    try {
      const profile = await apiGet("/account/me");
      const orgs = profile.orgs || [];

      if (orgs.length === 0) {
        return { content: [{ type: "text", text: "No organizations found. Sign up at https://slipstream.keyq.io/signup" }] };
      }

      let allDevices = [];
      for (const org of orgs) {
        const devices = await apiGet(`/devices?org_id=${org.org_id}`);

        // Batch fetch tags (parallel)
        const tagResults = await Promise.all(devices.map((d) => getDeviceTags(d.id)));

        for (let i = 0; i < devices.length; i++) {
          const d = devices[i];
          allDevices.push({
            id: d.id,
            name: d.name,
            hostname: d.hostname,
            os: d.os,
            arch: d.arch,
            online: !!d.is_online,
            org: org.org_name,
            agent_version: d.agent_version,
            capabilities: d.capabilities,
            tags: tagResults[i],
          });
        }
      }

      if (allDevices.length === 0) {
        return { content: [{ type: "text", text: "No devices found. Install the agent: https://slipstream.keyq.io/download" }] };
      }

      const text = allDevices
        .map((d) => {
          let line = `${d.online ? "●" : "○"} [${d.id}] ${d.name} (${d.os}/${d.arch}) — ${d.online ? "online" : "offline"}`;
          if (d.tags.length > 0) line += ` [${d.tags.join(", ")}]`;
          if (d.capabilities) line += ` — capabilities: ${d.capabilities}`;
          return line;
        })
        .join("\n");

      return { content: [{ type: "text", text: `Devices:\n${text}` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error listing devices: ${e.message}` }], isError: true };
    }
  }
);

// Tool: execute command
server.tool(
  "execute_command",
  "Execute a shell command on a remote Slipstream device. Returns stdout, stderr, and exit code. The command runs in a shell (sh -c on Linux/macOS, cmd /C on Windows). Requires exec:command permission — grant it in the Slipstream dashboard under Team > Permissions.",
  {
    device_id: z.coerce.number().describe("Device ID (use list_devices to find IDs)"),
    command: z.string().max(10000).describe("Shell command to execute (max 10,000 chars)"),
    timeout_secs: z.coerce.number().min(1).max(30).optional().default(30).describe("Timeout in seconds (1-30, default 30)"),
  },
  async ({ device_id, command, timeout_secs }) => {
    try {
      // Check for dangerous commands
      const warnings = detectDangerousCommand(command);
      let warningText = "";
      if (warnings.length > 0) {
        warningText = `\n⚠️  CAUTION: This command involves: ${warnings.join(", ")}. Verify it is correct before relying on the output.\n`;
      }

      debug(`Executing on device ${device_id}: ${command.slice(0, 100)}...`);

      const exec = await apiPost(`/exec/devices/${device_id}`, {
        command,
        timeout_secs: Math.min(timeout_secs || 30, 30),
      });

      debug(`Exec ID: ${exec.exec_id}, polling...`);
      const result = await pollExecResult(exec.exec_id, timeout_secs);

      if (result.status === "completed") {
        let text = warningText;
        if (result.stdout) text += result.stdout;
        if (result.stderr) text += (text && result.stdout ? "\n" : "") + `[stderr] ${result.stderr}`;
        text += `\n[exit_code: ${result.exit_code}, duration: ${result.duration_ms}ms, device: ${device_id}]`;
        return { content: [{ type: "text", text: text || "(no output)" }] };
      } else if (result.status === "timeout") {
        return {
          content: [{ type: "text", text: `${warningText}Command timed out after ${timeout_secs}s. The command may still be running on the device. For long-running commands, consider backgrounding: nohup your_command > /tmp/output.log 2>&1 &` }],
          isError: true,
        };
      } else {
        return {
          content: [{ type: "text", text: `${warningText}Command failed: ${result.stderr || result.status}` }],
          isError: true,
        };
      }
    } catch (e) {
      return { content: [{ type: "text", text: `Error executing command: ${e.message}` }], isError: true };
    }
  }
);

// Tool: get exec history
server.tool(
  "exec_history",
  "Get recent command execution history for a device. Shows the last 10 commands with their status, exit codes, and timing.",
  {
    device_id: z.coerce.number().describe("Device ID"),
  },
  async ({ device_id }) => {
    try {
      const results = await apiGet(`/exec/devices/${device_id}/history`);

      if (results.length === 0) {
        return { content: [{ type: "text", text: "No execution history for this device." }] };
      }

      const text = results
        .slice(0, 10)
        .map((r) => {
          const status = r.status === "completed"
            ? (r.exit_code === 0 ? "ok" : `exit ${r.exit_code}`)
            : r.status;
          const time = new Date(r.created_at).toLocaleString();
          const user = r.user_name ? ` by ${r.user_name}` : "";
          return `[${status}] ${r.command.slice(0, 80)}${r.command.length > 80 ? "..." : ""} — ${time}${user} (${r.duration_ms || 0}ms)`;
        })
        .join("\n");

      return { content: [{ type: "text", text: `Recent executions on device ${device_id}:\n${text}` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error fetching history: ${e.message}` }], isError: true };
    }
  }
);

// Tool: device info
server.tool(
  "device_info",
  "Get detailed information about a specific device including tags, capabilities, OS, architecture, and connection status.",
  {
    device_id: z.coerce.number().describe("Device ID"),
  },
  async ({ device_id }) => {
    try {
      const profile = await apiGet("/account/me");
      const orgs = profile.orgs || [];

      for (const org of orgs) {
        const devices = await apiGet(`/devices?org_id=${org.org_id}`);
        const device = devices.find((d) => d.id === device_id);
        if (device) {
          const tags = await getDeviceTags(device_id);
          return {
            content: [{
              type: "text",
              text: [
                `Device: ${device.name}`,
                `ID: ${device.id}`,
                `Hostname: ${device.hostname || "unknown"}`,
                `OS: ${device.os || "unknown"} (${device.arch || "unknown"})`,
                `Status: ${device.is_online ? "● Online" : "○ Offline"}`,
                `Agent Version: ${device.agent_version || "unknown"}`,
                `Capabilities: ${device.capabilities || "unknown"}`,
                `Organization: ${org.org_name}`,
                `Tags: ${tags.length > 0 ? tags.join(", ") : "none"}`,
                device.last_seen_at ? `Last Seen: ${new Date(device.last_seen_at).toLocaleString()}` : null,
                device.created_at ? `Registered: ${new Date(device.created_at).toLocaleString()}` : null,
              ].filter(Boolean).join("\n"),
            }],
          };
        }
      }

      return { content: [{ type: "text", text: `Device ${device_id} not found. Use list_devices to see available devices.` }], isError: true };
    } catch (e) {
      return { content: [{ type: "text", text: `Error fetching device info: ${e.message}` }], isError: true };
    }
  }
);

// Start server
debug("Starting Slipstream MCP server...");
debug(`API: ${API_URL}`);
debug(`Token: ${TOKEN.slice(0, 12)}...`);

const transport = new StdioServerTransport();
await server.connect(transport);
