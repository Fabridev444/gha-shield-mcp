# gha-shield-mcp

Model Context Protocol server exposing the [gha-shield](https://github.com/Fabridev444/gha-shield) 13-rule GitHub Actions workflow security scanner as a tool that Claude Desktop, Cursor, Continue, and any other MCP-compatible client can invoke.

## Install

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (or the equivalent on your OS):

```json
{
  "mcpServers": {
    "gha-shield": {
      "command": "npx",
      "args": ["-y", "github:Fabridev444/gha-shield-mcp"]
    }
  }
}
```

Restart Claude Desktop. The tool `scan_workflow_yaml` will appear available.

### Cursor / Continue / other MCP clients

Point the client at `npx -y github:Fabridev444/gha-shield-mcp` as the stdio command.

## Use

Once the server is connected, ask your AI client:

> Scan this workflow YAML for security issues:
> ```yaml
> name: ci
> on: [push]
> jobs:
>   build:
>     runs-on: ubuntu-latest
>     steps:
>       - uses: actions/checkout@v3
>       - run: echo ${{ github.event.pull_request.title }}
> ```

The client invokes the `scan_workflow_yaml` tool and gets back a categorized report.

## What it catches

13 rules — see the [main gha-shield README](https://github.com/Fabridev444/gha-shield) and the [REAL-WORLD-AUDITS.md](https://github.com/Fabridev444/gha-shield/blob/main/REAL-WORLD-AUDITS.md) corpus (143 workflow files, 325 findings across 6 OSS repos).

## License

MIT-pending. The 13 free-tier rules + harness will be MIT once the V2 paid features of gha-shield ship.

## Tip jar

The maintainer accepts USDC tips on Solana to `634UtV9dWq8G7ciosqx1pcKkBK4kNkNod9yvoM8ujSdM`. Every tip funds another rule.
