import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-shell-injection-in-tools.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-shell-injection-in-tools', rule, {
  valid: [
    // Tool handler with no exec calls
    {
      code: `server.tool("get-data", "Fetch data", async (params) => {
        return { content: [{ type: "text", text: "ok" }] };
      })`,
    },
    // execSync OUTSIDE a tool handler — not our concern
    {
      code: `
        const result = execSync("ls");
        server.tool("list", "List items", async () => {
          return { content: [{ type: "text", text: "ok" }] };
        })
      `,
    },
    // exec in a non-.tool() method
    {
      code: `server.resource("file:///{path}", async (uri) => {
        execSync("ls");
      })`,
    },
    // Not a method call
    {
      code: `tool("run", "Run command", async (params) => {
        execSync(params.cmd);
      })`,
    },
    // Tool with only name + handler, no exec
    {
      code: `server.tool("ping", async () => ({ content: [{ type: "text", text: "pong" }] }))`,
    },
  ],
  invalid: [
    // execSync directly in handler
    {
      code: `server.tool("run", "Run a command", async (params) => {
        const result = execSync(params.cmd);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execSync' } }],
    },
    // Member expression: child_process.execSync
    {
      code: `server.tool("run", "Run a command", async (params) => {
        const result = child_process.execSync(params.cmd);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execSync' } }],
    },
    // exec with callback
    {
      code: `server.tool("run", "Run a command", async (params) => {
        exec(params.cmd, (err, stdout) => {});
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'exec' } }],
    },
    // spawn
    {
      code: `server.tool("run", "Run process", async (params) => {
        spawn(params.cmd, params.args);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'spawn' } }],
    },
    // spawnSync
    {
      code: `server.tool("run", "Run process", async (params) => {
        spawnSync(params.cmd);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'spawnSync' } }],
    },
    // execFile
    {
      code: `server.tool("run", "Run file", async (params) => {
        execFile(params.path, (err) => {});
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execFile' } }],
    },
    // execFileSync
    {
      code: `server.tool("run", "Run file", async (params) => {
        execFileSync(params.path);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execFileSync' } }],
    },
    // Nested function inside handler — still flagged
    {
      code: `server.tool("run", "Run a command", async (params) => {
        const doWork = () => {
          execSync(params.cmd);
        };
        doWork();
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execSync' } }],
    },
    // Handler as FunctionExpression (not arrow)
    {
      code: `server.tool("run", "Run a command", async function(params) {
        execSync(params.cmd);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execSync' } }],
    },
    // require('child_process').execSync pattern
    {
      code: `server.tool("run", "Run a command", async (params) => {
        require('child_process').execSync(params.cmd);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execSync' } }],
    },
    // Multiple exec calls — each reported
    {
      code: `server.tool("run", "Run commands", async (params) => {
        execSync(params.cmd1);
        spawn(params.cmd2, []);
      })`,
      errors: [
        { messageId: 'execInHandler', data: { name: 'execSync' } },
        { messageId: 'execInHandler', data: { name: 'spawn' } },
      ],
    },
    // Custom additionalFunctions
    {
      code: `server.tool("run", "Run a command", async (params) => {
        shell(params.cmd);
      })`,
      options: [{ additionalFunctions: ['shell'] }],
      errors: [{ messageId: 'execInHandler', data: { name: 'shell' } }],
    },
    // Tool with schema (4-arg form) — handler is last arg
    {
      code: `server.tool("run", "Run a command", { cmd: z.string() }, async (params) => {
        execSync(params.cmd);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'execSync' } }],
    },
    // Aliased import: cp.exec
    {
      code: `server.tool("run", "Run a command", async (params) => {
        cp.exec(params.cmd);
      })`,
      errors: [{ messageId: 'execInHandler', data: { name: 'exec' } }],
    },
  ],
});
