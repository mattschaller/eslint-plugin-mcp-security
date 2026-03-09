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

const DANGEROUS_OPERATIONS = new Set([
  'exit',          // process.exit()
  'kill',          // process.kill()
  'rmSync',        // fs.rmSync (recursive delete)
  'rmdir',         // fs.rmdir
  'rmdirSync',     // fs.rmdirSync
]);

const DANGEROUS_MEMBER_CALLS = new Map([
  ['exit', 'process'],
  ['kill', 'process'],
]);

type MessageIds = 'unscopedOperation';

export default createRule<[], MessageIds>({
  name: 'no-unscoped-tool-permissions',
  meta: {
    type: 'suggestion',
    docs: {
      description:
        'Disallow dangerous operations like process.exit() and recursive delete inside MCP tool handlers without permission guards',
    },
    messages: {
      unscopedOperation:
        'Dangerous operation "{{name}}" inside an MCP tool handler without a permission guard. ' +
        'Tool handlers should not call process.exit(), process.kill(), or perform recursive deletes. ' +
        'These operations can cause denial of service or data loss.',
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
          if (name && DANGEROUS_OPERATIONS.has(name)) {
            context.report({
              node,
              messageId: 'unscopedOperation',
              data: { name },
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
