import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-path-traversal-in-resources.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-path-traversal-in-resources', rule, {
  valid: [
    // Tool handler with no fs operations
    {
      code: `server.tool("echo", "Echo input", async (params) => {
        return { content: [{ type: "text", text: params.input }] };
      })`,
    },
    // readFileSync OUTSIDE a tool handler
    {
      code: `
        const config = readFileSync("config.json", "utf-8");
        server.tool("get-config", "Return config", async () => {
          return { content: [{ type: "text", text: config }] };
        })
      `,
    },
    // Not a method call
    {
      code: `tool("read", "Read file", async (params) => {
        readFileSync(params.path);
      })`,
    },
    // Tool with no handler args
    {
      code: `server.tool("ping", async () => ({ content: [{ type: "text", text: "pong" }] }))`,
    },
  ],
  invalid: [
    // readFileSync in tool handler
    {
      code: `server.tool("read-file", "Read a file", async (params) => {
        const data = readFileSync(params.path, "utf-8");
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readFileSync' } }],
    },
    // fs.readFileSync (member expression)
    {
      code: `server.tool("read-file", "Read a file", async (params) => {
        const data = fs.readFileSync(params.path, "utf-8");
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readFileSync' } }],
    },
    // readFile (async)
    {
      code: `server.tool("read-file", "Read a file", async (params) => {
        const data = await readFile(params.path, "utf-8");
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readFile' } }],
    },
    // writeFileSync
    {
      code: `server.tool("write-file", "Write a file", async (params) => {
        writeFileSync(params.path, params.content);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'writeFileSync' } }],
    },
    // createReadStream
    {
      code: `server.tool("stream-file", "Stream a file", async (params) => {
        const stream = createReadStream(params.path);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'createReadStream' } }],
    },
    // readdir
    {
      code: `server.tool("list-dir", "List directory", async (params) => {
        const files = readdirSync(params.dir);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readdirSync' } }],
    },
    // unlink
    {
      code: `server.tool("delete-file", "Delete a file", async (params) => {
        unlinkSync(params.path);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'unlinkSync' } }],
    },
    // stat
    {
      code: `server.tool("file-info", "Get file info", async (params) => {
        const info = statSync(params.path);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'statSync' } }],
    },
    // Nested function inside handler
    {
      code: `server.tool("read-file", "Read a file", async (params) => {
        const load = () => readFileSync(params.path, "utf-8");
        return load();
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readFileSync' } }],
    },
    // Handler as FunctionExpression
    {
      code: `server.tool("read-file", "Read a file", async function(params) {
        readFileSync(params.path);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readFileSync' } }],
    },
    // Multiple fs calls
    {
      code: `server.tool("copy-file", "Copy a file", async (params) => {
        const data = readFileSync(params.src, "utf-8");
        writeFileSync(params.dest, data);
      })`,
      errors: [
        { messageId: 'fsInHandler', data: { name: 'readFileSync' } },
        { messageId: 'fsInHandler', data: { name: 'writeFileSync' } },
      ],
    },
    // 4-arg form with schema
    {
      code: `server.tool("read-file", "Read a file", { path: z.string() }, async (params) => {
        readFileSync(params.path);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readFileSync' } }],
    },
    // Custom additionalFunctions
    {
      code: `server.tool("read-file", "Read a file", async (params) => {
        readJson(params.path);
      })`,
      options: [{ additionalFunctions: ['readJson'] }],
      errors: [{ messageId: 'fsInHandler', data: { name: 'readJson' } }],
    },
    // rename
    {
      code: `server.tool("move-file", "Move a file", async (params) => {
        renameSync(params.oldPath, params.newPath);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'renameSync' } }],
    },
    // chmod
    {
      code: `server.tool("set-perms", "Set permissions", async (params) => {
        chmodSync(params.path, 0o755);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'chmodSync' } }],
    },
    // NEW: readFileSync inside .resource() handler
    {
      code: `server.resource("file:///{path}", async (uri) => {
        readFileSync(uri.path);
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'readFileSync' } }],
    },
    // NEW: writeFileSync inside .resource() handler
    {
      code: `server.resource("config", "config://main", async (uri) => {
        writeFileSync("/tmp/out", "data");
      })`,
      errors: [{ messageId: 'fsInHandler', data: { name: 'writeFileSync' } }],
    },
  ],
});
