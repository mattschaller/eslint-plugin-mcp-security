import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolHandlerNode,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp/blob/main/docs/rules/${name}.md`,
);

const DANGEROUS_EVAL_CALLS = new Set([
  'eval',
  // vm module methods
  'runInNewContext',
  'runInThisContext',
  'runInContext',
  'compileFunction',
]);

const DANGEROUS_CONSTRUCTORS = new Set(['Function']);

type MessageIds = 'evalInHandler';

type Options = [
  {
    additionalFunctions?: string[];
  },
];

export default createRule<Options, MessageIds>({
  name: 'no-eval-in-handler',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow eval, new Function(), and vm code execution inside MCP tool handlers to prevent code injection (CWE-94)',
    },
    messages: {
      evalInHandler:
        'Code execution via "{{name}}" inside an MCP tool handler. ' +
        'Tool parameters flowing into eval/Function/vm enable arbitrary code injection (CWE-94). ' +
        '67% of MCP implementations have code injection vulnerabilities (Endor Labs). ' +
        'Use safe alternatives like JSON.parse() for data or a sandboxed interpreter.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          additionalFunctions: {
            type: 'array',
            items: { type: 'string' },
            description:
              'Additional function names to flag inside tool handlers.',
          },
        },
        additionalProperties: false,
      },
    ],
  },
  defaultOptions: [{}],
  create(context) {
    const toolHandlerNodes = new Set<TSESTree.Node>();
    let insideToolHandler = 0;

    const options = context.options[0] ?? {};
    const extraFns = new Set(options.additionalFunctions ?? []);

    function getCalleeName(node: TSESTree.CallExpression): string | null {
      if (node.callee.type === AST_NODE_TYPES.Identifier) {
        return node.callee.name;
      }
      if (
        node.callee.type === AST_NODE_TYPES.MemberExpression &&
        node.callee.property.type === AST_NODE_TYPES.Identifier
      ) {
        return node.callee.property.name;
      }
      return null;
    }

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
          if (name && (DANGEROUS_EVAL_CALLS.has(name) || extraFns.has(name))) {
            context.report({
              node,
              messageId: 'evalInHandler',
              data: { name },
            });
          }
        }
      },
      NewExpression(node) {
        if (insideToolHandler > 0) {
          if (
            node.callee.type === AST_NODE_TYPES.Identifier &&
            DANGEROUS_CONSTRUCTORS.has(node.callee.name)
          ) {
            context.report({
              node,
              messageId: 'evalInHandler',
              data: { name: `new ${node.callee.name}()` },
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
