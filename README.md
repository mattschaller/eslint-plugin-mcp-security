# eslint-plugin-mcp

[![CI](https://github.com/mattschaller/eslint-plugin-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/mattschaller/eslint-plugin-mcp/actions/workflows/ci.yml)

ESLint rules for Model Context Protocol servers. Security, correctness, and best practices — like `eslint-plugin-react` for the MCP ecosystem.

v1 focuses on security: catches the credential-harvesting patterns deployed by [SANDWORM_MODE/McpInject](https://socket.dev/blog/sandworm-mode), path traversal (CWE-22), command injection (CWE-78), and the CVE-2025-6514 / CVE-2026-25536 patterns that runtime Zod validation alone cannot prevent. Correctness and best-practice rules are on the roadmap.

## Install

```bash
npm install --save-dev eslint-plugin-mcp
```

## Configure (ESLint 9 flat config)

```javascript
// eslint.config.js
import mcp from 'eslint-plugin-mcp';

export default [
  mcp.configs.recommended,
  // ...your other configs
];
```

That's it. All security rules are enabled at `error` severity.

## Rules

### Security

| Rule | What it catches | Severity |
|------|----------------|----------|
| [`no-credential-pattern-in-description`](docs/rules/no-credential-pattern-in-description.md) | Tool descriptions referencing `~/.ssh`, `~/.aws`, `.env`, and other credential paths — the exact pattern used by SANDWORM_MODE/McpInject to trick AI agents into exfiltrating secrets | error |
| [`no-exec-with-external-input`](docs/rules/no-exec-with-external-input.md) | `exec`, `execSync`, `spawn`, and other shell execution functions inside `.tool()` handlers — the CVE-2025-6514 pattern (mcp-remote RCE via unvalidated input to `execSync`) | error |
| [`no-path-traversal-in-handler`](docs/rules/no-path-traversal-in-handler.md) | `readFile`, `writeFile`, `createReadStream`, `unlink`, `readdir`, and other fs operations inside `.tool()` handlers — 82% of MCP servers are vulnerable to path traversal (CWE-22, Endor Labs) | error |
| [`no-eval-in-handler`](docs/rules/no-eval-in-handler.md) | `eval()`, `new Function()`, and `vm` module execution inside `.tool()` handlers — 67% of MCP implementations have code injection vulnerabilities (CWE-94) | error |
| [`no-mcpserver-reuse`](docs/rules/no-mcpserver-reuse.md) | `new McpServer()` inside HTTP request handlers or loops — per-request instantiation causing resource exhaustion and state confusion (CVE-2026-25536) | error |

### Roadmap

- **Correctness** — `no-duplicate-tool-names`, `require-zod-validation`, `no-sync-in-tool-handler`
- **Best practices** — `prefer-resource-templates`, handler return type validation

## Why this exists

The MCP SDK has 97M monthly npm downloads and two published CVEs in 2026. Every MCP starter template relies on runtime Zod validation only — there is no dev-time static analysis for MCP server code. The SDK's own [RFC #716](https://github.com/modelcontextprotocol/specification/discussions/716) acknowledges that "current ESLint rules are very basic and do not provide enough value or strictness."

Meanwhile, SANDWORM_MODE (Feb 2026) demonstrated that malicious MCP servers can register innocuous-looking tools (`lint_check`, `scan_dependencies`) whose descriptions contain prompt injections that silently read `~/.ssh/id_rsa`, `~/.aws/credentials`, and `.env` files through the AI agent. This plugin catches those patterns before the code ships.

## License

MIT
