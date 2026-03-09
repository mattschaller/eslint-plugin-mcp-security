import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/require-tool-input-schema.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('require-tool-input-schema', rule, {
  valid: [
    // 3-arg form with schema object
    {
      code: `server.tool("get-data", { id: z.string() }, async (params) => {})`,
    },
    // 4-arg form with description + schema
    {
      code: `server.tool("get-data", "Fetch data", { id: z.string() }, async (params) => {})`,
    },
    // Not a .tool() call
    {
      code: `server.resource("config", async () => {})`,
    },
    // Non-method tool call
    {
      code: `tool("get-data", async (params) => {})`,
    },
  ],
  invalid: [
    // 2-arg form: name + handler (no schema)
    {
      code: `server.tool("ping", async () => {})`,
      errors: [{ messageId: 'missingSchema', data: { name: 'ping' } }],
    },
    // 3-arg form: name + description + handler (no schema)
    {
      code: `server.tool("get-data", "Fetch data", async (params) => {})`,
      errors: [{ messageId: 'missingSchema', data: { name: 'get-data' } }],
    },
    // Template literal name, no schema
    {
      code: 'server.tool(`list-items`, "List items", async () => {})',
      errors: [{ messageId: 'missingSchema' }],
    },
    // Multiple tools without schemas
    {
      code: `
        server.tool("a", async () => {});
        server.tool("b", "desc", async () => {});
      `,
      errors: [
        { messageId: 'missingSchema', data: { name: 'a' } },
        { messageId: 'missingSchema', data: { name: 'b' } },
      ],
    },
  ],
});
