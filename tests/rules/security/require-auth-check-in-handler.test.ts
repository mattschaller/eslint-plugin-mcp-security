import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/require-auth-check-in-handler.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('require-auth-check-in-handler', rule, {
  valid: [
    // Handler with auth check
    {
      code: `server.tool("get-data", "Fetch data", async (params) => {
        await authenticate(params.token);
        return getData();
      })`,
    },
    // Handler referencing context (auth-related identifier)
    {
      code: `server.tool("get-data", "Fetch data", async (params, context) => {
        return getData(context);
      })`,
    },
    // Handler with verifyToken call
    {
      code: `server.tool("action", "Do action", async (params) => {
        verifyToken(params.authToken);
        return doAction();
      })`,
    },
    // Handler with session check
    {
      code: `server.tool("profile", "Get profile", async (params) => {
        const session = getSession();
        return session.user;
      })`,
    },
    // Handler that checks permissions
    {
      code: `server.tool("admin", "Admin action", async (params) => {
        checkPermission(params.role);
        return adminAction();
      })`,
    },
    // Not a .tool() call
    {
      code: `server.resource("data", async () => {
        return getData();
      })`,
    },
  ],
  invalid: [
    // Handler with no auth identifiers
    {
      code: `server.tool("get-data", "Fetch data", async (params) => {
        const result = fetchData(params.id);
        return { content: [{ type: "text", text: result }] };
      })`,
      errors: [{ messageId: 'missingAuthCheck', data: { name: 'get-data' } }],
    },
    // Simple handler, no auth
    {
      code: `server.tool("ping", async () => {
        return { content: [{ type: "text", text: "pong" }] };
      })`,
      errors: [{ messageId: 'missingAuthCheck', data: { name: 'ping' } }],
    },
    // Handler with unrelated identifiers
    {
      code: `server.tool("calc", "Calculate", async (params) => {
        const sum = params.a + params.b;
        return { content: [{ type: "text", text: String(sum) }] };
      })`,
      errors: [{ messageId: 'missingAuthCheck', data: { name: 'calc' } }],
    },
    // FunctionExpression, no auth
    {
      code: `server.tool("run", "Run task", async function(params) {
        doWork(params.input);
      })`,
      errors: [{ messageId: 'missingAuthCheck', data: { name: 'run' } }],
    },
    // 4-arg form, no auth
    {
      code: `server.tool("delete", "Delete item", { id: z.string() }, async (params) => {
        deleteItem(params.id);
      })`,
      errors: [{ messageId: 'missingAuthCheck', data: { name: 'delete' } }],
    },
  ],
});
