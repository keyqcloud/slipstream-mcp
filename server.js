#!/usr/bin/env node
/**
 * Slipstream MCP (stdio) — a thin bridge to the hosted remote MCP.
 *
 * Rather than re-declaring every tool here (which drifts from the hosted server
 * in api/src/routes/mcp.ts), this connects to the hosted streamable-HTTP MCP as a
 * client and transparently re-exposes its tools over stdio. The hosted endpoint is
 * the single source of truth: any tool added there shows up here automatically —
 * no per-tool code, no drift.
 *
 * Env:
 *   SLIPSTREAM_TOKEN     (required) Slipstream personal access token (pat_...)
 *   SLIPSTREAM_API_URL   (optional) default https://slipstream-api.keyq.io
 *   SLIPSTREAM_DEBUG=1   (optional) log bridge activity to stderr
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const API_URL = (process.env.SLIPSTREAM_API_URL || "https://slipstream-api.keyq.io").replace(/\/$/, "");
const TOKEN = process.env.SLIPSTREAM_TOKEN;
const DEBUG = process.env.SLIPSTREAM_DEBUG === "1";
const debug = (...a) => { if (DEBUG) console.error("[slipstream-mcp]", ...a); };

if (!TOKEN) {
  console.error("Error: SLIPSTREAM_TOKEN is required. Create a personal access token in the Slipstream web app (Settings -> API tokens) and set SLIPSTREAM_TOKEN.");
  process.exit(1);
}

let VERSION = "0.0.0";
try {
  const pkg = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "package.json"), "utf8"));
  VERSION = pkg.version || VERSION;
} catch { /* best-effort */ }

async function main() {
  // 1. Connect to the hosted remote MCP as a client (the single source of truth).
  const upstream = new Client({ name: "slipstream-mcp-bridge", version: VERSION }, { capabilities: {} });
  const upstreamTransport = new StreamableHTTPClientTransport(new URL(`${API_URL}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
  });
  debug(`connecting to hosted MCP at ${API_URL}/mcp`);
  await upstream.connect(upstreamTransport);
  debug("connected");

  // 2. Expose a local stdio server that forwards the tool list + calls upstream.
  const server = new Server({ name: "slipstream", version: VERSION }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const { tools } = await upstream.listTools();
    debug(`listTools -> ${tools.length} tools`);
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    debug(`callTool ${req.params.name}`);
    return await upstream.callTool({
      name: req.params.name,
      arguments: req.params.arguments || {},
    });
  });

  await server.connect(new StdioServerTransport());
  debug("stdio bridge ready");
}

main().catch((err) => {
  console.error("Fatal:", err?.message || err);
  process.exit(1);
});
