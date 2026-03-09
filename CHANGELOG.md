# Changelog

## 0.2.2

- Add CVE-2025-6514 code example and polymorphic engine differentiator to docs

## 0.2.0

- Add 8 new security rules (5 → 13 rules):
  - `no-duplicate-tool-names`
  - `no-dynamic-tool-registration`
  - `no-hardcoded-secrets-in-server`
  - `no-unvalidated-tool-input`
  - `no-sensitive-data-in-tool-result`
  - `no-unscoped-tool-permissions`
  - `require-auth-check-in-handler`
  - `require-tool-input-schema`
- Rename 3 rules for consistency, add shared patterns/helpers
- Fix `no-mcpserver-reuse` to allow per-request pattern
- Rewrite README with CVE coverage table and OWASP MCP Top 10 mapping

## 0.1.4

- Fix publish workflow to match working OIDC pattern

## 0.1.3

- Rename release workflow to publish.yml

## 0.1.2

- Fix release workflow to trigger on release published

## 0.1.1

- Switch release workflow to OIDC trusted publishing
- Add automated npm publish on version tags

## 0.1.0

- Initial release with 5 security rules:
  - `no-credential-paths-in-descriptions`
  - `no-shell-injection-in-tools`
  - `no-path-traversal-in-resources`
  - `no-eval-in-handler`
  - `no-mcpserver-reuse`
- MIT license and CI workflow
