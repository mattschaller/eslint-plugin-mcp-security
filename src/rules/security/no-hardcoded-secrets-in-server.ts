import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import { SECRET_PATTERNS } from '../../utils/patterns.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

type MessageIds = 'hardcodedSecret';

export default createRule<[], MessageIds>({
  name: 'no-hardcoded-secrets-in-server',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow hardcoded API keys, tokens, and credentials in MCP server source files',
    },
    messages: {
      hardcodedSecret:
        'Hardcoded secret detected: {{label}}. ' +
        'Use environment variables or a secrets manager instead of embedding credentials in source code.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    function checkStringValue(node: TSESTree.Node, raw: string): void {
      for (const { pattern, label } of SECRET_PATTERNS) {
        if (pattern.test(raw)) {
          context.report({
            node,
            messageId: 'hardcodedSecret',
            data: { label },
          });
          return; // One report per literal
        }
      }
    }

    return {
      Literal(node) {
        if (typeof node.value === 'string' && node.value.length >= 8) {
          checkStringValue(node, node.value);
        }
      },
      TemplateLiteral(node) {
        if (node.quasis.length === 1 && node.expressions.length === 0) {
          const text = node.quasis[0].value.cooked ?? node.quasis[0].value.raw;
          if (text.length >= 8) {
            checkStringValue(node, text);
          }
        }
      },
    };
  },
});
