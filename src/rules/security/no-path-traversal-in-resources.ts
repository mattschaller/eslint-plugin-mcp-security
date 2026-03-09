import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import {
  isToolOrResourceMethodCall,
  getToolHandlerNode,
  getCalleeName,
} from '../../utils/mcp-ast-helpers.js';
import { FS_FUNCTIONS } from '../../utils/patterns.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

type MessageIds = 'fsInHandler';

type Options = [
  {
    additionalFunctions?: string[];
  },
];

export default createRule<Options, MessageIds>({
  name: 'no-path-traversal-in-resources',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow filesystem operations inside MCP tool and resource handlers to prevent path traversal attacks (CWE-22)',
    },
    messages: {
      fsInHandler:
        'Filesystem function "{{name}}" inside an MCP tool/resource handler. ' +
        'Tool parameters containing "../" sequences enable path traversal (CWE-22). ' +
        '82% of MCP server implementations are vulnerable (Endor Labs). ' +
        'Validate paths with path.resolve() and verify they stay within an allowed directory.',
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
    const handlerNodes = new Set<TSESTree.Node>();
    let insideHandler = 0;

    const options = context.options[0] ?? {};
    const dangerousFns = new Set([
      ...FS_FUNCTIONS,
      ...(options.additionalFunctions ?? []),
    ]);

    const enterHandler = (node: TSESTree.Node): void => {
      if (handlerNodes.has(node)) {
        insideHandler++;
      }
    };

    const exitHandler = (node: TSESTree.Node): void => {
      if (handlerNodes.has(node)) {
        insideHandler--;
        handlerNodes.delete(node);
      }
    };

    return {
      CallExpression(node) {
        if (isToolOrResourceMethodCall(node)) {
          const handler = getToolHandlerNode(node);
          if (handler) {
            handlerNodes.add(handler);
          }
        }

        if (insideHandler > 0) {
          const name = getCalleeName(node);
          if (name && dangerousFns.has(name)) {
            context.report({
              node,
              messageId: 'fsInHandler',
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
