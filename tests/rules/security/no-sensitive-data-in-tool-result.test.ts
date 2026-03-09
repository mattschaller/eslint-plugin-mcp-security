import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-sensitive-data-in-tool-result.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-sensitive-data-in-tool-result', rule, {
  valid: [
    // No env access in handler
    {
      code: `server.tool("get-data", "Fetch data", async () => {
        return { content: [{ type: "text", text: "ok" }] };
      })`,
    },
    // process.env outside handler
    {
      code: `
        const port = process.env.PORT;
        server.tool("ping", async () => {
          return { content: [{ type: "text", text: "pong" }] };
        })
      `,
    },
    // readFileSync on a normal path inside handler
    {
      code: `server.tool("read", "Read file", async (params) => {
        readFileSync("/tmp/data.txt");
      })`,
    },
    // Not a .tool() call
    {
      code: `server.resource("config", async () => {
        const key = process.env.API_KEY;
      })`,
    },
  ],
  invalid: [
    // process.env.SECRET_KEY in handler
    {
      code: `server.tool("get-secret", "Get secret", async () => {
        const key = process.env.SECRET_KEY;
      })`,
      errors: [{ messageId: 'envAccess' }],
    },
    // process.env.API_KEY in handler
    {
      code: `server.tool("config", "Get config", async () => {
        return { content: [{ type: "text", text: process.env.API_KEY }] };
      })`,
      errors: [{ messageId: 'envAccess' }],
    },
    // Reading ~/.ssh/id_rsa in handler
    {
      code: `server.tool("get-key", "Get key", async () => {
        const key = readFileSync("~/.ssh/id_rsa", "utf-8");
      })`,
      errors: [{ messageId: 'credentialRead' }],
    },
    // Reading .env file in handler
    {
      code: `server.tool("get-env", "Get env", async () => {
        const env = readFileSync(".env", "utf-8");
      })`,
      errors: [{ messageId: 'credentialRead' }],
    },
    // Nested function with process.env
    {
      code: `server.tool("get-config", "Get config", async () => {
        const getKey = () => process.env.DB_PASSWORD;
        return getKey();
      })`,
      errors: [{ messageId: 'envAccess' }],
    },
    // FunctionExpression handler
    {
      code: `server.tool("get-secret", "Get secret", async function() {
        return process.env.TOKEN;
      })`,
      errors: [{ messageId: 'envAccess' }],
    },
  ],
});
