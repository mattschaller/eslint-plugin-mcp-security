import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-eval-in-handler.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-eval-in-handler', rule, {
  valid: [
    // Tool handler with no eval
    {
      code: `server.tool("calc", "Calculate result", async (params) => {
        return { content: [{ type: "text", text: String(params.a + params.b) }] };
      })`,
    },
    // eval OUTSIDE a tool handler
    {
      code: `
        const result = eval("1 + 1");
        server.tool("get-result", "Get result", async () => {
          return { content: [{ type: "text", text: String(result) }] };
        })
      `,
    },
    // eval in a non-.tool() method
    {
      code: `server.resource("expr:///{code}", async (uri) => {
        eval(uri.code);
      })`,
    },
    // JSON.parse is safe
    {
      code: `server.tool("parse", "Parse JSON", async (params) => {
        const data = JSON.parse(params.json);
      })`,
    },
  ],
  invalid: [
    // eval() directly in handler
    {
      code: `server.tool("run-code", "Execute code", async (params) => {
        const result = eval(params.code);
      })`,
      errors: [{ messageId: 'evalInHandler', data: { name: 'eval' } }],
    },
    // new Function()
    {
      code: `server.tool("run-code", "Execute code", async (params) => {
        const fn = new Function("return " + params.code);
        fn();
      })`,
      errors: [
        { messageId: 'evalInHandler', data: { name: 'new Function()' } },
      ],
    },
    // vm.runInNewContext
    {
      code: `server.tool("sandbox", "Run in sandbox", async (params) => {
        vm.runInNewContext(params.code, {});
      })`,
      errors: [
        { messageId: 'evalInHandler', data: { name: 'runInNewContext' } },
      ],
    },
    // vm.runInThisContext
    {
      code: `server.tool("run", "Run code", async (params) => {
        vm.runInThisContext(params.code);
      })`,
      errors: [
        { messageId: 'evalInHandler', data: { name: 'runInThisContext' } },
      ],
    },
    // vm.runInContext
    {
      code: `server.tool("run", "Run code", async (params) => {
        vm.runInContext(params.code, context);
      })`,
      errors: [
        { messageId: 'evalInHandler', data: { name: 'runInContext' } },
      ],
    },
    // vm.compileFunction
    {
      code: `server.tool("compile", "Compile code", async (params) => {
        vm.compileFunction(params.code, []);
      })`,
      errors: [
        { messageId: 'evalInHandler', data: { name: 'compileFunction' } },
      ],
    },
    // Nested eval inside helper function
    {
      code: `server.tool("run-code", "Execute code", async (params) => {
        const run = () => eval(params.code);
        run();
      })`,
      errors: [{ messageId: 'evalInHandler', data: { name: 'eval' } }],
    },
    // Handler as FunctionExpression
    {
      code: `server.tool("run-code", "Execute code", async function(params) {
        eval(params.code);
      })`,
      errors: [{ messageId: 'evalInHandler', data: { name: 'eval' } }],
    },
    // Multiple eval patterns in one handler
    {
      code: `server.tool("run-code", "Execute code", async (params) => {
        eval(params.expr);
        const fn = new Function(params.body);
      })`,
      errors: [
        { messageId: 'evalInHandler', data: { name: 'eval' } },
        { messageId: 'evalInHandler', data: { name: 'new Function()' } },
      ],
    },
    // 4-arg form with schema
    {
      code: `server.tool("run-code", "Execute code", { code: z.string() }, async (params) => {
        eval(params.code);
      })`,
      errors: [{ messageId: 'evalInHandler', data: { name: 'eval' } }],
    },
    // Custom additionalFunctions
    {
      code: `server.tool("run-code", "Execute code", async (params) => {
        safeEval(params.code);
      })`,
      options: [{ additionalFunctions: ['safeEval'] }],
      errors: [{ messageId: 'evalInHandler', data: { name: 'safeEval' } }],
    },
  ],
});
