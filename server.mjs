#!/usr/bin/env node
// gha-shield-mcp — Model Context Protocol server exposing the 13-rule workflow
// security scanner as a tool that Claude Desktop, Cursor, or any other MCP
// client can call.
//
// Protocol: JSON-RPC 2.0 over stdio. Implements `initialize`, `tools/list`,
// and `tools/call`. No streaming, no sampling, no roots — single tool, single
// response per call.
//
// Install (Claude Desktop config):
//   {
//     "mcpServers": {
//       "gha-shield": { "command": "npx", "args": ["-y","gha-shield-mcp"] }
//     }
//   }

import { createInterface } from "node:readline";
import { stdin, stdout, stderr } from "node:process";
import { runFreeRules } from "./rules.js";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "gha-shield-mcp", version: "1.0.0" };

function reply(id, result) {
  stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
function replyError(id, code, message) {
  stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}
function log(msg) {
  stderr.write(`[gha-shield-mcp] ${msg}\n`);
}

const TOOLS = [
  {
    name: "scan_workflow_yaml",
    description:
      "Scan a GitHub Actions workflow YAML string for 13 categorized security issues " +
      "(unpinned actions, pull_request_target + PR-ref checkout, command injection via ${{ … }}, " +
      "missing permissions, curl|bash, hardcoded provider keys in env:, untrusted action receiving GITHUB_TOKEN, " +
      "schedule with broad permissions, workflow_run + untrusted checkout, secrets in if:, " +
      "continue-on-error on auth/test steps, gist/raw downloads without checksum, jobs without timeout-minutes). " +
      "Returns an array of findings, each with id, severity (crit|high|med|low), title, and location.",
    inputSchema: {
      type: "object",
      properties: {
        yaml: {
          type: "string",
          description: "Contents of a single GitHub Actions workflow YAML file.",
        },
      },
      required: ["yaml"],
    },
  },
];

function handle(req) {
  const { id, method, params } = req;
  switch (method) {
    case "initialize":
      reply(id, {
        protocolVersion: PROTOCOL_VERSION,
        serverInfo: SERVER_INFO,
        capabilities: { tools: { listChanged: false } },
      });
      return;

    case "notifications/initialized":
      // No reply expected for notifications.
      return;

    case "tools/list":
      reply(id, { tools: TOOLS });
      return;

    case "tools/call": {
      const name = params?.name;
      const args = params?.arguments ?? {};
      if (name !== "scan_workflow_yaml") {
        replyError(id, -32601, `Unknown tool: ${name}`);
        return;
      }
      const yaml = args.yaml;
      if (typeof yaml !== "string") {
        replyError(id, -32602, "Argument 'yaml' must be a string");
        return;
      }
      const findings = runFreeRules(yaml).filter((f) => f.id !== "empty");
      const counts = { crit: 0, high: 0, med: 0, low: 0, info: 0 };
      for (const f of findings) counts[f.severity]++;
      const summary = `${findings.length} finding(s) — ${counts.crit} crit · ${counts.high} high · ${counts.med} med · ${counts.low} low`;
      const text =
        findings.length === 0
          ? `gha-shield: 0 findings. The workflow looks clean against the 13 free-tier rules.`
          : `${summary}\n\n` +
            findings
              .map(
                (f) =>
                  `[${f.severity.toUpperCase()}] ${f.id} — ${f.title}\n  ${f.location}` +
                  (f.fix ? `\n  fix: ${f.fix.split("\n")[0]}` : ""),
              )
              .join("\n\n");
      reply(id, {
        content: [{ type: "text", text }],
        structuredContent: { findings, counts, summary },
      });
      return;
    }

    case "ping":
      reply(id, {});
      return;

    default:
      replyError(id, -32601, `Method not found: ${method}`);
  }
}

log("server ready");
const rl = createInterface({ input: stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (!line.trim()) return;
  let req;
  try { req = JSON.parse(line); }
  catch (e) { log(`parse error: ${e.message}`); return; }
  try { handle(req); }
  catch (e) {
    log(`handler error: ${e.message}`);
    if (req.id !== undefined) replyError(req.id, -32603, e.message);
  }
});
rl.on("close", () => process.exit(0));
