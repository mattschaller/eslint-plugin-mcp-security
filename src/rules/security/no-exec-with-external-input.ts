import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolHandlerNode,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattdanielbrown/eslint-plugin-mcp/blob/main/docs/rules/${name}.md`,
);

const DANGEROUS_FUNCTIONS = new Set([
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
]);

type MessageIds = 'execInHandler';

type Options = [
  {
    additionalFunctions?: string[];
  },
];

export default createRule<Options, MessageIds>({
  name: 'no-exec-with-external-input',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow shell execution functions inside MCP tool handlers to prevent command injection (CVE-2025-6514, CWE-78)',
    },
    messages: {
      execInHandler:
        'Shell execution function "{{name}}" inside an MCP tool handler. ' +
        'Tool parameters flowing into shell commands enable command injection (CWE-78). ' +
        'CVE-2025-6514: mcp-remote RCE via unvalidated input passed to execSync. ' +
        'Validate inputs against an allowlist or avoid shell execution entirely.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          additionalFunctions: {
            type: 'array',
            items: { type: 'string' },
            description:
              'Additional function names to flag inside tool handlers (e.g., "shell", "run").',
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
    const dangerousFns = new Set([
      ...DANGEROUS_FUNCTIONS,
      ...(options.additionalFunctions ?? []),
    ]);

    function getCalleeName(node: TSESTree.CallExpression): string | null {
      // Direct call: execSync(...)
      if (node.callee.type === AST_NODE_TYPES.Identifier) {
        return node.callee.name;
      }
      // Member expression: cp.execSync(...), child_process.spawn(...)
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
        // Mark tool handler functions for tracking
        if (isToolMethodCall(node)) {
          const handler = getToolHandlerNode(node);
          if (handler) {
            toolHandlerNodes.add(handler);
          }
        }

        // Flag dangerous calls inside tool handlers
        if (insideToolHandler > 0) {
          const name = getCalleeName(node);
          if (name && dangerousFns.has(name)) {
            context.report({
              node,
              messageId: 'execInHandler',
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
