import { ESLintUtils } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolDescriptionNode,
  getStaticStringValue,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattdanielbrown/eslint-plugin-mcp/blob/main/docs/rules/${name}.md`,
);

const CREDENTIAL_PATTERNS: ReadonlyArray<{ pattern: RegExp; label: string }> = [
  // Credential directories
  { pattern: /~\/\.ssh\b/, label: '~/.ssh (SSH keys)' },
  { pattern: /~\/\.aws\b/, label: '~/.aws (AWS credentials)' },
  { pattern: /~\/\.gnupg\b/, label: '~/.gnupg (GPG keys)' },
  { pattern: /~\/\.config\/gcloud/, label: 'GCloud credentials' },
  { pattern: /~\/\.azure\b/, label: '~/.azure (Azure credentials)' },
  { pattern: /~\/\.kube\b/, label: '~/.kube (Kubernetes config)' },
  { pattern: /~\/\.docker\/config\.json/, label: 'Docker credentials' },
  { pattern: /~\/\.npmrc\b/, label: '~/.npmrc (npm auth tokens)' },

  // Credential files by name
  { pattern: /\.env\b/, label: '.env (environment secrets)' },
  { pattern: /\bid_rsa\b/, label: 'SSH private key (id_rsa)' },
  { pattern: /\bid_ed25519\b/, label: 'SSH private key (id_ed25519)' },
  { pattern: /\bid_ecdsa\b/, label: 'SSH private key (id_ecdsa)' },

  // System credential files
  { pattern: /\/etc\/shadow\b/, label: '/etc/shadow' },
  { pattern: /\/etc\/passwd\b/, label: '/etc/passwd' },

  // Key/cert file extensions
  { pattern: /\.pem\b/, label: 'PEM certificate/key file' },
  { pattern: /\.p12\b/, label: 'PKCS#12 key file' },
  { pattern: /\.pfx\b/, label: 'PFX key file' },
  { pattern: /\.keystore\b/, label: 'Java keystore' },

  // Cloud credential references
  { pattern: /aws_access_key/i, label: 'AWS access key' },
  { pattern: /aws_secret/i, label: 'AWS secret' },
];

type MessageIds = 'credentialPattern';

type Options = [
  {
    additionalPatterns?: string[];
    ignorePatterns?: string[];
  },
];

export default createRule<Options, MessageIds>({
  name: 'no-credential-pattern-in-description',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow credential file references in MCP tool descriptions to prevent prompt injection credential harvesting (SANDWORM_MODE/McpInject)',
    },
    messages: {
      credentialPattern:
        'Tool description references credential path "{{match}}" ({{label}}). ' +
        'This matches the SANDWORM_MODE/McpInject attack pattern where malicious MCP servers ' +
        'embed prompt injections that harvest credentials via tool descriptions read by AI agents.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          additionalPatterns: {
            type: 'array',
            items: { type: 'string' },
            description: 'Additional regex patterns to flag in tool descriptions.',
          },
          ignorePatterns: {
            type: 'array',
            items: { type: 'string' },
            description:
              'Regex patterns to exclude from credential detection (e.g., for security audit tools that legitimately reference these paths).',
          },
        },
        additionalProperties: false,
      },
    ],
  },
  defaultOptions: [{}],
  create(context) {
    return {
      CallExpression(node) {
        if (!isToolMethodCall(node)) return;

        const descNode = getToolDescriptionNode(node);
        if (!descNode) return;

        const text = getStaticStringValue(descNode);
        const options = context.options[0] ?? {};

        // Build ignore set
        const ignoreRegexps = (options.ignorePatterns ?? []).map(
          (p) => new RegExp(p, 'i'),
        );

        // Build full pattern list
        const allPatterns = [...CREDENTIAL_PATTERNS];
        for (const p of options.additionalPatterns ?? []) {
          allPatterns.push({
            pattern: new RegExp(p, 'i'),
            label: 'custom pattern',
          });
        }

        for (const { pattern, label } of allPatterns) {
          const match = text.match(pattern);
          if (!match) continue;

          // Check if this match should be ignored
          if (ignoreRegexps.some((re) => re.test(match[0]))) continue;

          context.report({
            node: descNode,
            messageId: 'credentialPattern',
            data: {
              match: match[0],
              label,
            },
          });
          // Report first match per description to reduce noise
          return;
        }
      },
    };
  },
});
