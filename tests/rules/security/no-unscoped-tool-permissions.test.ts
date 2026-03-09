import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-unscoped-tool-permissions.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-unscoped-tool-permissions', rule, {
  valid: [
    // No dangerous operations in handler
    {
      code: `server.tool("echo", "Echo input", async (params) => {
        return { content: [{ type: "text", text: params.input }] };
      })`,
    },
    // process.exit outside handler
    {
      code: `
        process.exit(1);
        server.tool("ping", async () => {})
      `,
    },
    // rmSync outside handler
    {
      code: `
        fs.rmSync("/tmp/old", { recursive: true });
        server.tool("clean", "Clean up", async () => {})
      `,
    },
    // Not a .tool() call
    {
      code: `server.resource("config", async () => {
        process.exit(0);
      })`,
    },
  ],
  invalid: [
    // process.exit() in handler
    {
      code: `server.tool("shutdown", "Shut down server", async () => {
        process.exit(0);
      })`,
      errors: [{ messageId: 'unscopedOperation', data: { name: 'exit' } }],
    },
    // process.kill() in handler
    {
      code: `server.tool("kill-proc", "Kill process", async (params) => {
        process.kill(params.pid);
      })`,
      errors: [{ messageId: 'unscopedOperation', data: { name: 'kill' } }],
    },
    // rmSync (recursive delete) in handler
    {
      code: `server.tool("clean", "Clean directory", async (params) => {
        fs.rmSync(params.path, { recursive: true });
      })`,
      errors: [{ messageId: 'unscopedOperation', data: { name: 'rmSync' } }],
    },
    // rmdirSync in handler
    {
      code: `server.tool("remove-dir", "Remove directory", async (params) => {
        rmdirSync(params.path);
      })`,
      errors: [{ messageId: 'unscopedOperation', data: { name: 'rmdirSync' } }],
    },
    // Nested in helper function inside handler
    {
      code: `server.tool("shutdown", "Shut down", async () => {
        const cleanup = () => process.exit(1);
        cleanup();
      })`,
      errors: [{ messageId: 'unscopedOperation', data: { name: 'exit' } }],
    },
    // Multiple dangerous ops
    {
      code: `server.tool("nuke", "Nuclear option", async (params) => {
        fs.rmSync(params.path, { recursive: true });
        process.exit(0);
      })`,
      errors: [
        { messageId: 'unscopedOperation', data: { name: 'rmSync' } },
        { messageId: 'unscopedOperation', data: { name: 'exit' } },
      ],
    },
  ],
});
