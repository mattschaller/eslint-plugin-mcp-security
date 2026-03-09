# Contributing to eslint-plugin-mcp-security

## Development Setup

```bash
git clone https://github.com/mattschaller/eslint-plugin-mcp-security
cd eslint-plugin-mcp-security
npm install
npm run build
npm test
```

## Adding a New Rule

1. Create the rule file in `src/rules/security/<rule-name>.ts`
2. Create the test file in `tests/rules/security/<rule-name>.test.ts`
3. Register the rule in `src/index.ts` (both `rules` object and `recommended` config)
4. Add the rule to the table in `README.md`
5. Add a violation example to `example/bad-server.ts`

### Rule Structure

Use `ESLintUtils.RuleCreator` from `@typescript-eslint/utils`. Import shared helpers from `src/utils/mcp-ast-helpers.ts` and shared constants from `src/utils/patterns.ts`.

Every rule needs:
- A `name` matching the filename
- A `meta.type` (`'problem'` for errors, `'suggestion'` for recommendations)
- A `meta.docs.description` explaining what it catches
- A `meta.messages` object with descriptive error messages including CWE/CVE references
- At least 4 valid and 4 invalid test cases

### Test Conventions

- Use `@typescript-eslint/rule-tester` with `vitest`
- Include both valid and invalid cases
- Test edge cases: different `.tool()` signatures (2-arg, 3-arg, 4-arg), arrow vs function expressions, nested functions
- Verify error `messageId` and `data` in invalid cases

## Running Tests

```bash
npm test            # run once
npm run test:watch  # watch mode
```

## Build

```bash
npm run build       # tsc -p tsconfig.build.json
```

## Smoke Test

```bash
npx eslint example/bad-server.ts
```

This should report violations from all rules against the intentionally vulnerable example server.
