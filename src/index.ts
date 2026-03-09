import noCredentialPathsInDescriptions from './rules/security/no-credential-paths-in-descriptions.js';
import noShellInjectionInTools from './rules/security/no-shell-injection-in-tools.js';
import noPathTraversalInResources from './rules/security/no-path-traversal-in-resources.js';
import noEvalInHandler from './rules/security/no-eval-in-handler.js';
import noMcpserverReuse from './rules/security/no-mcpserver-reuse.js';
import noDuplicateToolNames from './rules/security/no-duplicate-tool-names.js';
import requireToolInputSchema from './rules/security/require-tool-input-schema.js';
import noDynamicToolRegistration from './rules/security/no-dynamic-tool-registration.js';
import noHardcodedSecretsInServer from './rules/security/no-hardcoded-secrets-in-server.js';
import noUnvalidatedToolInput from './rules/security/no-unvalidated-tool-input.js';
import noSensitiveDataInToolResult from './rules/security/no-sensitive-data-in-tool-result.js';
import noUnscopedToolPermissions from './rules/security/no-unscoped-tool-permissions.js';
import requireAuthCheckInHandler from './rules/security/require-auth-check-in-handler.js';

import { createRequire } from 'node:module';
import type { TSESLint } from '@typescript-eslint/utils';

const require = createRequire(import.meta.url);
const { version } = require('../package.json') as { version: string };

type Plugin = TSESLint.FlatConfig.Plugin & {
  configs: Record<string, TSESLint.FlatConfig.Config>;
};

const plugin: Plugin = {
  meta: {
    name: 'eslint-plugin-mcp-security',
    version,
  },
  rules: {
    'no-credential-paths-in-descriptions': noCredentialPathsInDescriptions,
    'no-shell-injection-in-tools': noShellInjectionInTools,
    'no-path-traversal-in-resources': noPathTraversalInResources,
    'no-eval-in-handler': noEvalInHandler,
    'no-mcpserver-reuse': noMcpserverReuse,
    'no-duplicate-tool-names': noDuplicateToolNames,
    'require-tool-input-schema': requireToolInputSchema,
    'no-dynamic-tool-registration': noDynamicToolRegistration,
    'no-hardcoded-secrets-in-server': noHardcodedSecretsInServer,
    'no-unvalidated-tool-input': noUnvalidatedToolInput,
    'no-sensitive-data-in-tool-result': noSensitiveDataInToolResult,
    'no-unscoped-tool-permissions': noUnscopedToolPermissions,
    'require-auth-check-in-handler': requireAuthCheckInHandler,
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
    'mcp-security/no-duplicate-tool-names': 'error',
    'mcp-security/require-tool-input-schema': 'error',
    'mcp-security/no-dynamic-tool-registration': 'warn',
    'mcp-security/no-hardcoded-secrets-in-server': 'error',
    'mcp-security/no-unvalidated-tool-input': 'error',
    'mcp-security/no-sensitive-data-in-tool-result': 'error',
    'mcp-security/no-unscoped-tool-permissions': 'warn',
    'mcp-security/require-auth-check-in-handler': 'warn',
  },
};

plugin.configs.security = plugin.configs.recommended;

export default plugin;
