import { ESLintUtils, AST_NODE_TYPES } from '@typescript-eslint/utils';
import { isToolMethodCall } from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

function isStaticString(node: { type: string; value?: unknown; expressions?: unknown[] }): boolean {
  if (node.type === AST_NODE_TYPES.Literal && typeof node.value === 'string') return true;
  if (node.type === AST_NODE_TYPES.TemplateLiteral && (node.expressions as unknown[]).length === 0) return true;
  return false;
}

type MessageIds = 'dynamicName' | 'dynamicDescription';

export default createRule<[], MessageIds>({
  name: 'no-dynamic-tool-registration',
  meta: {
    type: 'suggestion',
    docs: {
      description:
        'Require static string literals for MCP tool names and descriptions to prevent dynamic tool injection',
    },
    messages: {
      dynamicName:
        'Tool name must be a static string literal. Dynamic tool names allow runtime ' +
        'manipulation of the tool registry, enabling tool injection attacks.',
      dynamicDescription:
        'Tool description must be a static string literal. Dynamic descriptions can be ' +
        'manipulated at runtime to inject prompt instructions (SANDWORM_MODE).',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    return {
      CallExpression(node) {
        if (!isToolMethodCall(node)) return;
        if (node.arguments.length < 1) return;

        // Check tool name (first argument) — must be a static string
        const firstArg = node.arguments[0];
        if (!isStaticString(firstArg)) {
          context.report({
            node: firstArg,
            messageId: 'dynamicName',
          });
        }

        // Check description (2nd argument when it's in description position)
        // Description position: 3+ args and 2nd arg is not an object (schema)
        if (node.arguments.length >= 3) {
          const secondArg = node.arguments[1];
          // If 2nd arg is an object, it's a schema, not a description
          if (secondArg.type === AST_NODE_TYPES.ObjectExpression) return;
          // If it's an identifier referencing a schema variable, skip
          if (secondArg.type === AST_NODE_TYPES.Identifier) return;

          if (!isStaticString(secondArg)) {
            context.report({
              node: secondArg,
              messageId: 'dynamicDescription',
            });
          }
        }
      },
    };
  },
});
