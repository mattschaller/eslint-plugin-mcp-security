import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolHandlerNode,
  getCalleeName,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

const CREDENTIAL_READ_FUNCTIONS = new Set([
  'readFileSync',
  'readFile',
  'createReadStream',
]);

type MessageIds = 'envAccess' | 'credentialRead';

export default createRule<[], MessageIds>({
  name: 'no-sensitive-data-in-tool-result',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow process.env access and credential file reads in MCP tool handlers to prevent sensitive data leakage in tool results',
    },
    messages: {
      envAccess:
        'process.env access inside an MCP tool handler. ' +
        'Environment variables often contain secrets (API keys, tokens, database passwords). ' +
        'Tool results are visible to the AI agent and may be logged or forwarded.',
      credentialRead:
        'Reading credential file "{{path}}" inside an MCP tool handler. ' +
        'Credential files should not be read and returned as tool results.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    const toolHandlerNodes = new Set<TSESTree.Node>();
    let insideToolHandler = 0;

    const enterHandler = (node: TSESTree.Node): void => {
      if (toolHandlerNodes.has(node)) {
        insideToolHandler++;
      }
    };

    const exitHandler = (node: TSESTree.Node): void => {
      if (toolHandlerNodes.has(node)) {
        insideToolHandler--;
        toolHandlerNodes.delete(node);
      }
    };

    // Credential file path patterns to detect
    const credPathPatterns = [
      /~\/\.ssh/,
      /~\/\.aws/,
      /~\/\.gnupg/,
      /~\/\.npmrc/,
      /~\/\.kube/,
      /\.env\b/,
      /\/etc\/shadow/,
      /\/etc\/passwd/,
      /id_rsa/,
      /id_ed25519/,
    ];

    return {
      CallExpression(node) {
        if (isToolMethodCall(node)) {
          const handler = getToolHandlerNode(node);
          if (handler) {
            toolHandlerNodes.add(handler);
          }
        }

        if (insideToolHandler > 0) {
          const name = getCalleeName(node);
          if (name && CREDENTIAL_READ_FUNCTIONS.has(name) && node.arguments.length > 0) {
            const pathArg = node.arguments[0];
            if (
              pathArg.type === AST_NODE_TYPES.Literal &&
              typeof pathArg.value === 'string'
            ) {
              for (const pattern of credPathPatterns) {
                if (pattern.test(pathArg.value)) {
                  context.report({
                    node,
                    messageId: 'credentialRead',
                    data: { path: pathArg.value },
                  });
                  break;
                }
              }
            }
          }
        }
      },
      MemberExpression(node) {
        if (insideToolHandler === 0) return;

        // Detect process.env access
        if (
          node.object.type === AST_NODE_TYPES.MemberExpression &&
          node.object.object.type === AST_NODE_TYPES.Identifier &&
          node.object.object.name === 'process' &&
          node.object.property.type === AST_NODE_TYPES.Identifier &&
          node.object.property.name === 'env'
        ) {
          context.report({
            node,
            messageId: 'envAccess',
          });
        }

        // Also catch direct process.env (without property access)
        if (
          node.object.type === AST_NODE_TYPES.Identifier &&
          node.object.name === 'process' &&
          node.property.type === AST_NODE_TYPES.Identifier &&
          node.property.name === 'env'
        ) {
          // Only flag if parent is not already a MemberExpression (avoid double-report)
          const parent = node.parent;
          if (
            !parent ||
            parent.type !== AST_NODE_TYPES.MemberExpression ||
            parent.object !== node
          ) {
            context.report({
              node,
              messageId: 'envAccess',
            });
          }
        }
      },
      ArrowFunctionExpression: enterHandler,
      'ArrowFunctionExpression:exit': exitHandler,
      FunctionExpression: enterHandler,
      'FunctionExpression:exit': exitHandler,
    };
  },
});
