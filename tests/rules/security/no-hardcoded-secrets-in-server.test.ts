import { RuleTester } from '@typescript-eslint/rule-tester';
import * as parser from '@typescript-eslint/parser';
import { afterAll } from 'vitest';
import rule from '../../../src/rules/security/no-hardcoded-secrets-in-server.js';

RuleTester.afterAll = afterAll;

const ruleTester = new RuleTester({
  languageOptions: { parser },
});

ruleTester.run('no-hardcoded-secrets-in-server', rule, {
  valid: [
    // Environment variable access (not hardcoded)
    {
      code: `const apiKey = process.env.API_KEY;`,
    },
    // Short string — not a secret
    {
      code: `const x = "hello";`,
    },
    // Normal string, no secret pattern
    {
      code: `const greeting = "Welcome to the MCP server!";`,
    },
    // Key pattern but using env var
    {
      code: `const config = { api_key: process.env.KEY };`,
    },
    // Template literal with expression (dynamic)
    {
      code: 'const key = `sk-${getKey()}`;',
    },
  ],
  invalid: [
    // OpenAI-style secret key
    {
      code: `const key = "sk-abcdefghijklmnopqrstuvwxyz1234567890";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
    // GitHub PAT
    {
      code: `const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890aaaa";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
    // AWS access key ID
    {
      code: `const awsKey = "AKIAIOSFODNN7EXAMPLE";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
    // Slack token
    {
      code: `const slack = "xoxb-1234567890-abcdefghij";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
    // Bearer token in header
    {
      code: `const auth = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcde";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
    // Database connection string with password
    {
      code: `const db = "postgres://admin:secretpass@localhost:5432/mydb";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
    // MongoDB connection string
    {
      code: `const mongo = "mongodb://user:password@host:27017/db";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
    // api_key assignment in string
    {
      code: `const config = "api_key = 'sk-1234567890abcdef'";`,
      errors: [{ messageId: 'hardcodedSecret' }],
    },
  ],
});
