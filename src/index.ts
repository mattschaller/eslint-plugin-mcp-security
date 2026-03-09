import noCredentialPatternInDescription from './rules/security/no-credential-pattern-in-description.js';

import type { TSESLint } from '@typescript-eslint/utils';

type Plugin = TSESLint.FlatConfig.Plugin & {
  configs: Record<string, TSESLint.FlatConfig.Config>;
};

const plugin: Plugin = {
  meta: {
    name: 'eslint-plugin-mcp',
    version: '0.1.0',
  },
  rules: {
    'no-credential-pattern-in-description': noCredentialPatternInDescription,
  },
  configs: {},
};

plugin.configs.recommended = {
  plugins: {
    mcp: plugin,
  },
  rules: {
    'mcp/no-credential-pattern-in-description': 'error',
  },
};

plugin.configs.security = plugin.configs.recommended;

export default plugin;
