import noCredentialPathsInDescriptions from './rules/security/no-credential-paths-in-descriptions.js';
import noShellInjectionInTools from './rules/security/no-shell-injection-in-tools.js';
import noPathTraversalInResources from './rules/security/no-path-traversal-in-resources.js';
import noEvalInHandler from './rules/security/no-eval-in-handler.js';
import noMcpserverReuse from './rules/security/no-mcpserver-reuse.js';

import type { TSESLint } from '@typescript-eslint/utils';

type Plugin = TSESLint.FlatConfig.Plugin & {
  configs: Record<string, TSESLint.FlatConfig.Config>;
};

const plugin: Plugin = {
  meta: {
    name: 'eslint-plugin-mcp-security',
    version: '0.2.0',
  },
  rules: {
    'no-credential-paths-in-descriptions': noCredentialPathsInDescriptions,
    'no-shell-injection-in-tools': noShellInjectionInTools,
    'no-path-traversal-in-resources': noPathTraversalInResources,
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
    'mcp-security/no-credential-paths-in-descriptions': 'error',
    'mcp-security/no-shell-injection-in-tools': 'error',
    'mcp-security/no-path-traversal-in-resources': 'error',
    'mcp-security/no-eval-in-handler': 'error',
    'mcp-security/no-mcpserver-reuse': 'error',
  },
};

plugin.configs.security = plugin.configs.recommended;

export default plugin;
