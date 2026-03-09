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
    // McpServer at top level — correct singleton pattern
    {
      code: `const server = new McpServer({ name: "test", version: "1.0.0" });`,
    },
    // McpServer inside a main() function — common init pattern
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
    // .connect() at module level — correct pattern
    {
      code: `
        const server = new McpServer({ name: "test", version: "1.0.0" });
        server.connect(transport);
      `,
    },
    // Per-request McpServer + connect in handler — correct CVE-2026-25536 fix
    {
      code: `app.post("/mcp", (req, res) => {
        const server = new McpServer({ name: "test", version: "1.0.0" });
        const transport = new StreamableHTTPServerTransport({ sessionId: req.id });
        server.connect(transport);
      })`,
    },
    // Per-request McpServer in http.createServer — also correct
    {
      code: `http.createServer((req, res) => {
        const mcpServer = new McpServer({ name: "test", version: "1.0.0" });
        mcpServer.connect(new StreamableHTTPServerTransport({}));
      })`,
    },
    // Per-request McpServer in Express middleware
    {
      code: `app.use("/mcp", (req, res, next) => {
        const srv = new McpServer({ name: "test", version: "1.0.0" });
        srv.connect(transport);
      })`,
    },
    // .connect() on a non-McpServer object in handler (not tracked)
    {
      code: `app.post("/mcp", (req, res) => {
        db.connect();
      })`,
    },
  ],
  invalid: [
    // Module-scope server.connect() inside Express POST handler (CVE-2026-25536)
    {
      code: `
        const server = new McpServer({ name: "test", version: "1.0.0" });
        app.post("/mcp", (req, res) => {
          server.connect(new SSEServerTransport("/messages", res));
        })
      `,
      errors: [{ messageId: 'connectInHandler' }],
    },
    // Module-scope server.connect() inside Express GET handler
    {
      code: `
        const server = new McpServer({ name: "test", version: "1.0.0" });
        app.get("/mcp", (req, res) => {
          server.connect(transport);
        })
      `,
      errors: [{ messageId: 'connectInHandler' }],
    },
    // Module-scope server.connect() inside http.createServer
    {
      code: `
        const mcpServer = new McpServer({ name: "test", version: "1.0.0" });
        http.createServer((req, res) => {
          mcpServer.connect(transport);
        })
      `,
      errors: [{ messageId: 'connectInHandler' }],
    },
    // Module-scope server.connect() inside server.on('request')
    {
      code: `
        const server = new McpServer({ name: "test", version: "1.0.0" });
        httpServer.on("request", (req, res) => {
          server.connect(transport);
        })
      `,
      errors: [{ messageId: 'connectInHandler' }],
    },
    // Module-scope server.connect() inside Express middleware
    {
      code: `
        const server = new McpServer({ name: "test", version: "1.0.0" });
        app.use("/mcp", (req, res, next) => {
          server.connect(transport);
        })
      `,
      errors: [{ messageId: 'connectInHandler' }],
    },
    // Module-scope server.connect() inside router.put
    {
      code: `
        const server = new McpServer({ name: "test", version: "1.0.0" });
        router.put("/mcp/:id", (req, res) => {
          server.connect(transport);
        })
      `,
      errors: [{ messageId: 'connectInHandler' }],
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
    // FunctionExpression handler — module-scope reuse
    {
      code: `
        const server = new McpServer({ name: "test", version: "1.0.0" });
        app.get("/mcp", async function(req, res) {
          server.connect(transport);
        })
      `,
      errors: [{ messageId: 'connectInHandler' }],
    },
  ],
});
