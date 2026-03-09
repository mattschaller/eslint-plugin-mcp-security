import noCredentialPatternInDescription from './rules/security/no-credential-pattern-in-description.js';
import noExecWithExternalInput from './rules/security/no-exec-with-external-input.js';
import noPathTraversalInHandler from './rules/security/no-path-traversal-in-handler.js';
import noEvalInHandler from './rules/security/no-eval-in-handler.js';
import noMcpserverReuse from './rules/security/no-mcpserver-reuse.js';

import type { TSESLint } from '@typescript-eslint/utils';

type Plugin = TSESLint.FlatConfig.Plugin & {
  configs: Record<string, TSESLint.FlatConfig.Config>;
};

const plugin: Plugin = {
  meta: {
    name: 'eslint-plugin-mcp-security',
    version: '0.1.0',
  },
  rules: {
    'no-credential-pattern-in-description': noCredentialPatternInDescription,
    'no-exec-with-external-input': noExecWithExternalInput,
    'no-path-traversal-in-handler': noPathTraversalInHandler,
    'no-eval-in-handler': noEvalInHandler,
    'no-mcpserver-reuse': noMcpserverReuse,
  },
  configs: {},
};

plugin.configs.recommended = {
  plugins: {
    'mcp-security': plugin,
  },
  rules: {
    'mcp-security/no-credential-pattern-in-description': 'error',
    'mcp-security/no-exec-with-external-input': 'error',
    'mcp-security/no-path-traversal-in-handler': 'error',
    'mcp-security/no-eval-in-handler': 'error',
    'mcp-security/no-mcpserver-reuse': 'error',
  },
};

plugin.configs.security = plugin.configs.recommended;

export default plugin;
