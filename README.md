# eslint-plugin-mcp-security

[![CI](https://github.com/mattschaller/eslint-plugin-mcp-security/actions/workflows/ci.yml/badge.svg)](https://github.com/mattschaller/eslint-plugin-mcp-security/actions/workflows/ci.yml)

Static analysis for MCP server security. 13 rules covering the [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/), [SANDWORM_MODE/McpInject](https://socket.dev/blog/sandworm-mode), and real CVEs (CVE-2025-6514, CVE-2026-25536) — the security layer that runtime Zod validation alone cannot provide.

82% of MCP server implementations have path traversal vulnerabilities. 67% have code injection. This plugin catches those patterns before the code ships.

## Install

```bash
npm install --save-dev eslint-plugin-mcp-security
```

## Configure (ESLint 9 flat config)

```javascript
// eslint.config.js
import mcpSecurity from 'eslint-plugin-mcp-security';

export default [
  mcpSecurity.configs.recommended,
  // ...your other configs
];
```

That's it. All security rules are enabled — critical rules at `error`, heuristic rules at `warn`.

## Rules

| Rule | What it catches | OWASP MCP | Severity |
|------|----------------|-----------|----------|
| [`no-credential-paths-in-descriptions`](docs/rules/no-credential-paths-in-descriptions.md) | Tool descriptions referencing `~/.ssh`, `~/.aws`, `.env` — the SANDWORM_MODE/McpInject credential harvesting pattern | Tool Poisoning | error |
| [`no-shell-injection-in-tools`](docs/rules/no-shell-injection-in-tools.md) | `exec`, `execSync`, `spawn` inside `.tool()` handlers — the CVE-2025-6514 pattern | Command Injection | error |
| [`no-path-traversal-in-resources`](docs/rules/no-path-traversal-in-resources.md) | `readFile`, `writeFile`, `unlink` inside `.tool()` and `.resource()` handlers — CWE-22 | Path Traversal | error |
| [`no-eval-in-handler`](docs/rules/no-eval-in-handler.md) | `eval()`, `new Function()`, `vm` module inside `.tool()` handlers — CWE-94 | Code Injection | error |
| [`no-mcpserver-reuse`](docs/rules/no-mcpserver-reuse.md) | `new McpServer()` / `.connect()` inside HTTP handlers or loops — CVE-2026-25536 | Server Misuse | error |
| [`no-duplicate-tool-names`](docs/rules/no-duplicate-tool-names.md) | Multiple `.tool()` calls with the same name — silent handler overwrites | Tool Poisoning | error |
| [`require-tool-input-schema`](docs/rules/require-tool-input-schema.md) | `.tool()` calls missing a Zod schema argument — unvalidated inputs | Input Validation | error |
| [`no-hardcoded-secrets-in-server`](docs/rules/no-hardcoded-secrets-in-server.md) | API keys, tokens, connection strings hardcoded in source — credential exposure | Secrets Management | error |
| [`no-unvalidated-tool-input`](docs/rules/no-unvalidated-tool-input.md) | Handlers accessing parameters without an input schema — injection risk | Input Validation | error |
| [`no-sensitive-data-in-tool-result`](docs/rules/no-sensitive-data-in-tool-result.md) | `process.env` access and credential file reads in handlers — data leakage | Data Leakage | error |
| [`no-dynamic-tool-registration`](docs/rules/no-dynamic-tool-registration.md) | Non-literal tool names/descriptions — runtime tool injection | Tool Poisoning | warn |
| [`no-unscoped-tool-permissions`](docs/rules/no-unscoped-tool-permissions.md) | `process.exit()`, recursive delete in handlers — denial of service | Excessive Permissions | warn |
| [`require-auth-check-in-handler`](docs/rules/require-auth-check-in-handler.md) | Handlers with no auth/verify/session identifiers — missing authorization | Auth Bypass | warn |

## CVE Coverage

| CVE | Description | Rules |
|-----|-------------|-------|
| CVE-2025-6514 | mcp-remote RCE via unvalidated input to `execSync` | `no-shell-injection-in-tools`, `no-unvalidated-tool-input` |
| CVE-2026-25536 | Per-request McpServer instantiation causing resource exhaustion | `no-mcpserver-reuse` |

## Migration from v0.1.x

Three rules were renamed in v0.2.0. Update your config if you reference them explicitly:

```diff
- mcp-security/no-credential-pattern-in-description
+ mcp-security/no-credential-paths-in-descriptions

- mcp-security/no-exec-with-external-input
+ mcp-security/no-shell-injection-in-tools

- mcp-security/no-path-traversal-in-handler
+ mcp-security/no-path-traversal-in-resources
```

If you use `mcpSecurity.configs.recommended`, no changes are needed — the config uses the new names automatically.

## Why this exists

The MCP SDK has 97M monthly npm downloads and two published CVEs in 2026. Every MCP starter template relies on runtime Zod validation only — there is no dev-time static analysis for MCP server code. The SDK's own [RFC #716](https://github.com/modelcontextprotocol/specification/discussions/716) acknowledges that "current ESLint rules are very basic and do not provide enough value or strictness."

Meanwhile, SANDWORM_MODE (Feb 2026) demonstrated that malicious MCP servers can register innocuous-looking tools (`lint_check`, `scan_dependencies`) whose descriptions contain prompt injections that silently read `~/.ssh/id_rsa`, `~/.aws/credentials`, and `.env` files through the AI agent. This plugin catches those patterns before the code ships.

## License

MIT
