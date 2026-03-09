import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-mcpserver-reuse.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-mcpserver-reuse', rule, {
  valid: [
    // McpServer at top level — correct pattern
    {
      code: `const server = new McpServer({ name: "test", version: "1.0.0" });`,
    },
    // McpServer inside a main() function — common init pattern, not a handler
    {
      code: `async function main() {
        const server = new McpServer({ name: "test", version: "1.0.0" });
        const transport = new StdioServerTransport();
        await server.connect(transport);
      }`,
    },
    // McpServer in a factory function (not an HTTP handler callback)
    {
      code: `function createServer(name: string) {
        return new McpServer({ name, version: "1.0.0" });
      }`,
    },
    // Non-McpServer constructor in a handler — not our concern
    {
      code: `app.get("/", (req, res) => {
        const obj = new SomeOtherClass();
      })`,
    },
    // Non-McpServer in a loop
    {
      code: `for (let i = 0; i < 10; i++) {
        const obj = new SomeClass();
      }`,
    },
    // McpServer in a named arrow at module level (not passed as callback)
    {
      code: `const init = () => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      };`,
    },
  ],
  invalid: [
    // McpServer inside Express GET handler
    {
      code: `app.get("/mcp", (req, res) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // McpServer inside Express POST handler
    {
      code: `app.post("/mcp", (req, res) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // McpServer inside Express middleware
    {
      code: `app.use("/mcp", (req, res, next) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // McpServer inside http.createServer
    {
      code: `http.createServer((req, res) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // McpServer inside server.on('request')
    {
      code: `httpServer.on("request", (req, res) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // McpServer inside a for loop
    {
      code: `for (let i = 0; i < clients.length; i++) {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      }`,
      errors: [{ messageId: 'mcpServerInLoop' }],
    },
    // McpServer inside a while loop
    {
      code: `while (running) {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      }`,
      errors: [{ messageId: 'mcpServerInLoop' }],
    },
    // McpServer inside a for-of loop
    {
      code: `for (const client of clients) {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      }`,
      errors: [{ messageId: 'mcpServerInLoop' }],
    },
    // McpServer inside a do-while loop
    {
      code: `do {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      } while (shouldRetry)`,
      errors: [{ messageId: 'mcpServerInLoop' }],
    },
    // McpServer inside Express handler as FunctionExpression
    {
      code: `app.get("/mcp", async function(req, res) {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // McpServer inside router.put handler
    {
      code: `router.put("/mcp/:id", (req, res) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // McpServer inside router.delete handler
    {
      code: `router.delete("/mcp/:id", (req, res) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
      })`,
      errors: [{ messageId: 'mcpServerInHandler' }],
    },
    // Loop inside a handler — loop takes priority
    {
      code: `app.get("/mcp", (req, res) => {
        for (const id of req.body.ids) {
          const server = new McpServer({ name: id, version: "1.0.0" });
        }
      })`,
      errors: [{ messageId: 'mcpServerInLoop' }],
    },
  ],
});
