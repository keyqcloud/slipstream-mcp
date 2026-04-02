# @keyqinc/slipstream-mcp

MCP server for [Slipstream](https://slipstream.keyq.io) — manage remote devices and execute commands directly from Claude.

[![npm version](https://img.shields.io/npm/v/@keyqinc/slipstream-mcp.svg)](https://www.npmjs.com/package/@keyqinc/slipstream-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is Slipstream?

[Slipstream](https://slipstream.keyq.io) is a cross-platform remote desktop, terminal, and device management tool. This MCP server lets you interact with your Slipstream devices directly from Claude — list devices, execute commands, and monitor your infrastructure through natural language.

## Installation

### Claude Desktop (Recommended)

Download the [Desktop Extension](https://slipstream-api.keyq.io/download/latest/slipstream.mcpb) and double-click to install.

### Claude Code (CLI)

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "slipstream": {
      "command": "npx",
      "args": ["-y", "@keyqinc/slipstream-mcp"],
      "env": {
        "SLIPSTREAM_TOKEN": "pat_your_token_here"
      }
    }
  }
}
```

Or add via CLI:

```bash
claude mcp add slipstream -- npx -y @keyqinc/slipstream-mcp -e SLIPSTREAM_TOKEN=pat_your_token_here
```

### Getting Your API Token

1. Sign up at [slipstream.keyq.io](https://slipstream.keyq.io/signup)
2. Go to [Settings → API Tokens](https://slipstream.keyq.io/settings)
3. Create a token and copy the `pat_...` value

### Enabling Command Execution

Remote command execution requires explicit permission:

1. Go to [Team](https://slipstream.keyq.io/team) → click your user → Permissions
2. Enable **Remote Command Execution** (`exec:command`)

## Tools

### `list_devices`

List all devices with online status, tags, and capabilities.

```
> List my Slipstream devices

● [9] raspberrypi (linux/aarch64) — online [Production] — capabilities: terminal,files,remote
○ [10] ws1 (windows/x86_64) — offline — capabilities: terminal,files,remote
```

### `execute_command`

Run a shell command on a remote device. Supports pipes, redirects, loops, and multi-command chains.

```
> Run "df -h" on device 9

Filesystem      Size  Used Avail Use% Mounted on
/dev/mmcblk0p2   29G  8.2G   19G  31% /

[exit_code: 0, duration: 22ms, device: 9]
```

```
> Check nginx status and last 5 error log lines on device 15

systemctl status nginx && tail -5 /var/log/nginx/error.log
```

### `device_info`

Get detailed information about a device including tags, capabilities, and connection status.

```
> Tell me about device 9

Device: raspberrypi (linux)
ID: 9
Hostname: raspberrypi
OS: linux (aarch64)
Status: ● Online
Agent Version: 0.1.0
Capabilities: terminal,files,remote
Organization: KeyQ, Inc.
Tags: Production, KeyQ
```

### `exec_history`

View recent command executions on a device.

```
> Show recent commands on device 9

[ok] uname -a — 4/1/2026, 10:08:22 AM (18ms)
[ok] df -h — 4/1/2026, 10:12:45 AM (22ms)
```

## Security

- **Permission-gated**: `exec:command` permission required (not granted by default)
- **Audit logged**: Every command logged with user, device, command text, and result
- **Rate limited**: 60 commands/minute per device
- **Timeout enforced**: 30-second max execution time
- **Output capped**: 1MB per stream (stdout/stderr)
- **Dangerous command detection**: Flags destructive commands (rm -rf, DROP TABLE, shutdown, etc.)
- **Credential isolation**: Agent strips sensitive env vars from command environment
- **Revocable tokens**: Personal API tokens can be revoked instantly from the dashboard

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SLIPSTREAM_TOKEN` | Yes | Personal API token (`pat_...`) |
| `SLIPSTREAM_API_URL` | No | API URL (default: `https://slipstream-api.keyq.io`) |
| `SLIPSTREAM_DEBUG` | No | Set to `1` for debug logging |

## Requirements

- Node.js 18+
- A [Slipstream](https://slipstream.keyq.io) account (free tier available)
- At least one device with the [Slipstream agent](https://slipstream.keyq.io/download) installed

## Links

- [Slipstream Dashboard](https://slipstream.keyq.io)
- [Download Agent](https://slipstream.keyq.io/download)
- [Documentation](https://slipstream.keyq.io/docs)
- [KeyQ, Inc.](https://keyq.cloud)

## License

MIT — see [LICENSE](LICENSE)
