import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-unvalidated-tool-input.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-unvalidated-tool-input', rule, {
  valid: [
    // Handler with schema — validated
    {
      code: `server.tool("get-data", { id: z.string() }, async (params) => {
        return params.id;
      })`,
    },
    // 4-arg form with schema
    {
      code: `server.tool("get-data", "Fetch data", { id: z.string() }, async (params) => {
        return params.id;
      })`,
    },
    // No params — handler doesn't access input
    {
      code: `server.tool("ping", async () => {
        return { content: [{ type: "text", text: "pong" }] };
      })`,
    },
    // No params, with description
    {
      code: `server.tool("ping", "Health check", async () => {})`,
    },
    // Not a .tool() call
    {
      code: `server.resource("config", async (uri) => {})`,
    },
  ],
  invalid: [
    // 2-arg form: name + handler with params (no schema)
    {
      code: `server.tool("get-data", async (params) => {
        return params.id;
      })`,
      errors: [{ messageId: 'unvalidatedInput', data: { name: 'get-data' } }],
    },
    // 3-arg form: name + description + handler with params (no schema)
    {
      code: `server.tool("get-data", "Fetch data", async (params) => {
        return params.id;
      })`,
      errors: [{ messageId: 'unvalidatedInput', data: { name: 'get-data' } }],
    },
    // Destructured params, no schema
    {
      code: `server.tool("run", "Execute", async ({ cmd }) => {
        exec(cmd);
      })`,
      errors: [{ messageId: 'unvalidatedInput', data: { name: 'run' } }],
    },
    // FunctionExpression handler with params, no schema
    {
      code: `server.tool("run", "Execute", async function(params) {
        exec(params.cmd);
      })`,
      errors: [{ messageId: 'unvalidatedInput', data: { name: 'run' } }],
    },
  ],
});
