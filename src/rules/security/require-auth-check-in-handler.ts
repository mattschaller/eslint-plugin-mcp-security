import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolHandlerNode,
  getToolNameNode,
  getStaticStringValue,
} from '../../utils/mcp-ast-helpers.js';
import { AUTH_IDENTIFIERS } from '../../utils/patterns.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

type MessageIds = 'missingAuthCheck';

export default createRule<[], MessageIds>({
  name: 'require-auth-check-in-handler',
  meta: {
    type: 'suggestion',
    docs: {
      description:
        'Require authentication/authorization checks in MCP tool handlers to prevent unauthorized access',
    },
    messages: {
      missingAuthCheck:
        'Tool "{{name}}" handler has no authentication or authorization check. ' +
        'Tool handlers should verify caller identity or permissions. ' +
        'Look for auth/verify/session/token/context checks in the handler body.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    return {
      CallExpression(node) {
        if (!isToolMethodCall(node)) return;

        const handler = getToolHandlerNode(node);
        if (!handler) return;

        // Check if handler body contains any auth-related identifiers
        if (hasAuthIdentifier(handler)) return;

        const nameNode = getToolNameNode(node);
        const name = nameNode ? getStaticStringValue(nameNode) : '<unknown>';

        context.report({
          node: handler,
          messageId: 'missingAuthCheck',
          data: { name },
        });
      },
    };
  },
});

function hasAuthIdentifier(
  node: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression,
): boolean {
  return walkNode(node.body);
}

function walkNode(node: TSESTree.Node): boolean {
  if (node.type === AST_NODE_TYPES.Identifier) {
    const lower = node.name.toLowerCase();
    for (const authId of AUTH_IDENTIFIERS) {
      if (lower.includes(authId.toLowerCase())) return true;
    }
  }

  if (node.type === AST_NODE_TYPES.MemberExpression) {
    if (walkNode(node.object)) return true;
    if (walkNode(node.property)) return true;
    return false;
  }

  // Walk child nodes
  for (const key of Object.keys(node)) {
    if (key === 'parent') continue;
    const value = (node as unknown as Record<string, unknown>)[key];

    if (value && typeof value === 'object') {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item && typeof item === 'object' && 'type' in item) {
            if (walkNode(item as TSESTree.Node)) return true;
          }
        }
      } else if ('type' in value) {
        if (walkNode(value as TSESTree.Node)) return true;
      }
    }
  }

  return false;
}
