import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-dynamic-tool-registration.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-dynamic-tool-registration', rule, {
  valid: [
    // Static string literal name
    {
      code: `server.tool("get-data", "Fetch data", async () => {})`,
    },
    // Static template literal name (no expressions)
    {
      code: 'server.tool(`get-data`, "Fetch data", async () => {})',
    },
    // 4-arg form, all static
    {
      code: `server.tool("run", "Run command", { cmd: z.string() }, async () => {})`,
    },
    // Not a .tool() call
    {
      code: `server.resource(dynamicName, async () => {})`,
    },
    // 2-arg form, static name
    {
      code: `server.tool("ping", async () => {})`,
    },
  ],
  invalid: [
    // Variable as tool name
    {
      code: `server.tool(toolName, "Fetch data", async () => {})`,
      errors: [{ messageId: 'dynamicName' }],
    },
    // Function call as tool name
    {
      code: `server.tool(getName(), "Fetch data", async () => {})`,
      errors: [{ messageId: 'dynamicName' }],
    },
    // Template literal with expression as name
    {
      code: 'server.tool(`tool-${type}`, "Fetch data", async () => {})',
      errors: [{ messageId: 'dynamicName' }],
    },
    // Template literal with expression as description
    {
      code: 'server.tool("get-data", `Fetch ${type} data`, async () => {})',
      errors: [{ messageId: 'dynamicDescription' }],
    },
    // Both name and description dynamic
    {
      code: 'server.tool(getName(), `Fetch ${type} data`, async () => {})',
      errors: [
        { messageId: 'dynamicName' },
        { messageId: 'dynamicDescription' },
      ],
    },
  ],
});
