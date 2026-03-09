import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-duplicate-tool-names.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-duplicate-tool-names', rule, {
  valid: [
    // Two tools with different names
    {
      code: `
        server.tool("get-data", "Fetch data", async () => {});
        server.tool("set-data", "Set data", async () => {});
      `,
    },
    // Single tool
    {
      code: `server.tool("ping", async () => {})`,
    },
    // Not a .tool() call
    {
      code: `
        server.resource("config", async () => {});
        server.resource("config", async () => {});
      `,
    },
    // Dynamic names (can't statically check)
    {
      code: `
        server.tool(getName(), async () => {});
        server.tool(getName(), async () => {});
      `,
    },
  ],
  invalid: [
    // Same name registered twice
    {
      code: `
        server.tool("get-data", "Fetch data v1", async () => {});
        server.tool("get-data", "Fetch data v2", async () => {});
      `,
      errors: [{ messageId: 'duplicateToolName', data: { name: 'get-data' } }],
    },
    // Three registrations of same name
    {
      code: `
        server.tool("ping", async () => {});
        server.tool("ping", async () => {});
        server.tool("ping", async () => {});
      `,
      errors: [
        { messageId: 'duplicateToolName', data: { name: 'ping' } },
        { messageId: 'duplicateToolName', data: { name: 'ping' } },
      ],
    },
    // Duplicate among distinct tools
    {
      code: `
        server.tool("alpha", async () => {});
        server.tool("beta", async () => {});
        server.tool("alpha", async () => {});
      `,
      errors: [{ messageId: 'duplicateToolName', data: { name: 'alpha' } }],
    },
    // 4-arg form with schema — same name
    {
      code: `
        server.tool("run", "Run v1", { cmd: z.string() }, async () => {});
        server.tool("run", "Run v2", { cmd: z.string() }, async () => {});
      `,
      errors: [{ messageId: 'duplicateToolName', data: { name: 'run' } }],
    },
  ],
});
