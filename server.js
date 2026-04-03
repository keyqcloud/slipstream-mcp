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
  "Execute a shell command on a remote Slipstream device. Returns stdout, stderr, and exit code. The command runs in a shell (sh -c on Linux/macOS, cmd /C on Windows). Requires exec:command permission. IMPORTANT: On Windows, use 'powershell -Command \"Start-Process <app>\"' to launch GUI apps (not 'start'). On Linux, use 'DISPLAY=:0 nohup <app> > /dev/null 2>&1 & echo launched'. Always capture_screen after launching to verify before retrying.",
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

// ─── GUI Control Tools ───────────────────────────

async function pollScreenCapture(captureId, maxWaitMs = 20000) {
  const start = Date.now();
  let interval = 300;
  while (Date.now() - start < maxWaitMs) {
    const result = await apiGet(`/screen/${captureId}`);
    if (result.status === "completed" || result.status === "failed" || result.status === "timeout") {
      return result;
    }
    await new Promise((r) => setTimeout(r, interval));
    interval = Math.min(interval * 1.5, 1500);
  }
  return { status: "timeout" };
}

// Tool: capture screen
server.tool(
  "capture_screen",
  "Take a screenshot of a remote device's screen. Returns the image so you can see what's on the display. Use this before and after GUI actions to understand the current state. Tip: to open applications, prefer execute_command (e.g. 'DISPLAY=:0 nohup firefox &') over clicking small taskbar icons. Requires remote:view permission.",
  {
    device_id: z.coerce.number().describe("Device ID (use list_devices to find IDs)"),
  },
  async ({ device_id }) => {
    try {
      // Try up to 2 attempts (retry once on timeout)
      for (let attempt = 0; attempt < 2; attempt++) {
        debug(`Capturing screen on device ${device_id} (attempt ${attempt + 1})...`);
        const capture = await apiPost(`/screen/devices/${device_id}/capture`, {});
        const result = await pollScreenCapture(capture.capture_id);

        if (result.status === "completed" && result.image_base64) {
          return {
            content: [
              {
                type: "image",
                data: result.image_base64,
                mimeType: "image/jpeg",
              },
              {
                type: "text",
                text: `Screenshot captured: ${result.width}x${result.height} pixels (device ${device_id})`,
              },
            ],
          };
        } else if (result.status === "timeout" && attempt === 0) {
          debug("First capture timed out, retrying...");
          continue;
        } else if (result.status === "timeout") {
          return { content: [{ type: "text", text: "Screenshot timed out after retry. The device may not have a display or screen capture may not be available." }], isError: true };
        } else {
          return { content: [{ type: "text", text: `Screenshot failed: ${result.status}` }], isError: true };
        }
      }
      return { content: [{ type: "text", text: "Screenshot failed after retries." }], isError: true };
    } catch (e) {
      return { content: [{ type: "text", text: `Error capturing screen: ${e.message}` }], isError: true };
    }
  }
);

// Tool: mouse click
server.tool(
  "mouse_click",
  "Click at a specific position on the remote device's screen. Use capture_screen first to see the screen and determine coordinates. Coordinates are absolute pixel positions. Requires remote:control permission.",
  {
    device_id: z.coerce.number().describe("Device ID"),
    x: z.coerce.number().describe("X coordinate (pixels from left)"),
    y: z.coerce.number().describe("Y coordinate (pixels from top)"),
    button: z.enum(["left", "right", "middle"]).optional().default("left").describe("Mouse button"),
    double_click: z.coerce.boolean().optional().default(false).describe("Double-click instead of single click"),
  },
  async ({ device_id, x, y, button, double_click }) => {
    try {
      const buttonNum = button === "right" ? 2 : button === "middle" ? 1 : 0;
      const action = double_click
        ? { type: "MouseDoubleClick", x, y }
        : { type: "MouseClick", x, y, button: buttonNum };

      await apiPost(`/screen/devices/${device_id}/input`, { action });
      const clickType = double_click ? "Double-clicked" : "Clicked";
      return { content: [{ type: "text", text: `${clickType} ${button || "left"} at (${x}, ${y}) on device ${device_id}. Use capture_screen to see the result.` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// Tool: type text
server.tool(
  "type_text",
  "Type text on the remote device as if using the keyboard. The text is typed at the current cursor position. Use mouse_click first to focus the right input field. Requires remote:control permission.",
  {
    device_id: z.coerce.number().describe("Device ID"),
    text: z.string().max(5000).describe("Text to type"),
  },
  async ({ device_id, text }) => {
    try {
      await apiPost(`/screen/devices/${device_id}/input`, {
        action: { type: "TypeText", text },
      });
      return { content: [{ type: "text", text: `Typed "${text.slice(0, 100)}${text.length > 100 ? "..." : ""}" on device ${device_id}. Use capture_screen to see the result.` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// Tool: key press
server.tool(
  "key_press",
  "Press a keyboard key or key combination on the remote device. Supports special keys (Return, Tab, Escape, F1-F12, ArrowUp/Down/Left/Right) and modifier combinations (ctrl+c, alt+tab, cmd+s). Requires remote:control permission.",
  {
    device_id: z.coerce.number().describe("Device ID"),
    key: z.string().describe("Key to press (e.g. 'Return', 'Tab', 'Escape', 'F5', 'a', 'ArrowDown')"),
    ctrl: z.coerce.boolean().optional().default(false).describe("Hold Ctrl"),
    alt: z.coerce.boolean().optional().default(false).describe("Hold Alt"),
    shift: z.coerce.boolean().optional().default(false).describe("Hold Shift"),
    meta: z.coerce.boolean().optional().default(false).describe("Hold Meta/Cmd/Win"),
  },
  async ({ device_id, key, ctrl, alt, shift, meta }) => {
    try {
      await apiPost(`/screen/devices/${device_id}/input`, {
        action: {
          type: "KeyPress",
          key,
          modifiers: { ctrl, alt, shift, meta },
        },
      });
      const mods = [ctrl && "Ctrl", alt && "Alt", shift && "Shift", meta && "Meta"].filter(Boolean);
      const combo = mods.length > 0 ? `${mods.join("+")}+${key}` : key;
      return { content: [{ type: "text", text: `Pressed ${combo} on device ${device_id}. Use capture_screen to see the result.` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// Tool: scroll
server.tool(
  "scroll",
  "Scroll at a specific position on the remote device's screen. Positive delta_y scrolls down, negative scrolls up. Requires remote:control permission.",
  {
    device_id: z.coerce.number().describe("Device ID"),
    x: z.coerce.number().describe("X coordinate to scroll at"),
    y: z.coerce.number().describe("Y coordinate to scroll at"),
    delta_y: z.coerce.number().describe("Scroll amount (positive = down, negative = up, typical: 3 or -3)"),
  },
  async ({ device_id, x, y, delta_y }) => {
    try {
      await apiPost(`/screen/devices/${device_id}/input`, {
        action: { type: "Scroll", x, y, delta_x: 0, delta_y },
      });
      const direction = delta_y > 0 ? "down" : "up";
      return { content: [{ type: "text", text: `Scrolled ${direction} at (${x}, ${y}) on device ${device_id}. Use capture_screen to see the result.` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// Tool: drag (mouse down, move, mouse up)
server.tool(
  "drag",
  "Click and drag from one position to another on the remote device's screen. Useful for moving windows, dragging files, selecting text, moving chess pieces, etc. Requires remote:control permission.",
  {
    device_id: z.coerce.number().describe("Device ID"),
    from_x: z.coerce.number().describe("Starting X coordinate"),
    from_y: z.coerce.number().describe("Starting Y coordinate"),
    to_x: z.coerce.number().describe("Ending X coordinate"),
    to_y: z.coerce.number().describe("Ending Y coordinate"),
    button: z.enum(["left", "right"]).optional().default("left").describe("Mouse button to drag with"),
  },
  async ({ device_id, from_x, from_y, to_x, to_y, button }) => {
    try {
      const buttonNum = button === "right" ? 2 : 0;

      // Mouse down at start
      await apiPost(`/screen/devices/${device_id}/input`, {
        action: { type: "MouseDown", x: from_x, y: from_y, button: buttonNum },
      });

      // Small delay for the press to register
      await new Promise((r) => setTimeout(r, 100));

      // Move to destination
      await apiPost(`/screen/devices/${device_id}/input`, {
        action: { type: "MouseMove", x: to_x, y: to_y },
      });

      // Small delay for the move to register
      await new Promise((r) => setTimeout(r, 100));

      // Mouse up at destination
      await apiPost(`/screen/devices/${device_id}/input`, {
        action: { type: "MouseUp", x: to_x, y: to_y, button: buttonNum },
      });

      return { content: [{ type: "text", text: `Dragged from (${from_x}, ${from_y}) to (${to_x}, ${to_y}) on device ${device_id}. Use capture_screen to see the result.` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// ─── UI Automation Tools ─────────────────────────

// Tool: find UI elements
server.tool(
  "find_elements",
  "Find UI elements on a remote device's screen by name and/or role. Returns elements with their names, roles, and positions. Use this to discover what's on screen before clicking. Much more reliable than coordinate-based clicking for buttons, links, and text fields. Windows only (uses UI Automation API).",
  {
    device_id: z.coerce.number().describe("Device ID"),
    name: z.string().optional().describe("Search by element name/text (partial match, case-insensitive)"),
    role: z.string().optional().describe("Filter by role: button, link, textfield, checkbox, menuitem, text, window, tab, listitem"),
    window_title: z.string().optional().describe("Limit search to a specific window by title"),
  },
  async ({ device_id, name, role, window_title }) => {
    try {
      debug(`Finding elements on device ${device_id}: name=${name}, role=${role}`);
      const query = await apiPost(`/screen/devices/${device_id}/find-elements`, {
        name: name || null,
        role: role || null,
        window_title: window_title || null,
      });

      // Poll for result (reuses screen capture polling)
      const result = await pollScreenCapture(query.query_id);

      if (result.status === "completed" && result.image_base64) {
        // image_base64 contains the JSON-encoded element list
        try {
          const elements = JSON.parse(result.image_base64);
          if (elements.length === 0) {
            return { content: [{ type: "text", text: `No elements found matching name="${name || "*"}", role="${role || "*"}". Try broader criteria or use capture_screen to see the current state.` }] };
          }
          const text = elements.map((e, i) => {
            const pos = e.bounding_rect ? `(${e.bounding_rect[0]}, ${e.bounding_rect[1]})` : "";
            return `[${i}] "${e.name}" (${e.role}) ${pos}${e.is_enabled ? "" : " [disabled]"}`;
          }).join("\n");
          return { content: [{ type: "text", text: `Found ${elements.length} elements:\n${text}\n\nUse click_element with name and role to click one.` }] };
        } catch {
          return { content: [{ type: "text", text: result.image_base64 }] };
        }
      } else {
        return { content: [{ type: "text", text: "Element search timed out. The device may not support UI Automation (Windows only)." }], isError: true };
      }
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// Tool: click UI element by name/role
server.tool(
  "click_element",
  "Click a UI element on a remote device by its name and/or role. Much more reliable than coordinate-based clicking — finds the element in the accessibility tree and clicks its center. Use find_elements first to discover available elements. Windows only (uses UI Automation API).",
  {
    device_id: z.coerce.number().describe("Device ID"),
    name: z.string().optional().describe("Element name/text to click (partial match)"),
    role: z.string().optional().describe("Element role: button, link, textfield, checkbox, menuitem"),
    window_title: z.string().optional().describe("Limit to a specific window"),
    index: z.coerce.number().optional().default(0).describe("If multiple matches, click the Nth one (0-based)"),
  },
  async ({ device_id, name, role, window_title, index }) => {
    try {
      debug(`Clicking element on device ${device_id}: name=${name}, role=${role}`);
      await apiPost(`/screen/devices/${device_id}/click-element`, {
        name: name || null,
        role: role || null,
        window_title: window_title || null,
        index: index || 0,
      });
      return { content: [{ type: "text", text: `Clicked element "${name || "*"}" (${role || "*"}) on device ${device_id}. Use capture_screen to verify.` }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// Start server
debug("Starting Slipstream MCP server...");
debug(`API: ${API_URL}`);
debug(`Token: ${TOKEN.slice(0, 12)}...`);

const transport = new StdioServerTransport();
await server.connect(transport);
