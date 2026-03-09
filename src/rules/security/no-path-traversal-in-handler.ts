import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolHandlerNode,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattdanielbrown/eslint-plugin-mcp/blob/main/docs/rules/${name}.md`,
);

const FS_FUNCTIONS = new Set([
  // Reading
  'readFile',
  'readFileSync',
  'createReadStream',
  // Writing
  'writeFile',
  'writeFileSync',
  'createWriteStream',
  'appendFile',
  'appendFileSync',
  // Deletion
  'unlink',
  'unlinkSync',
  'rm',
  'rmSync',
  'rmdir',
  'rmdirSync',
  // Directory listing
  'readdir',
  'readdirSync',
  // File manipulation
  'rename',
  'renameSync',
  'copyFile',
  'copyFileSync',
  // Opening files
  'open',
  'openSync',
  // Metadata (information disclosure)
  'stat',
  'statSync',
  'lstat',
  'lstatSync',
  // Permissions
  'chmod',
  'chmodSync',
  'chown',
  'chownSync',
]);

type MessageIds = 'fsInHandler';

type Options = [
  {
    additionalFunctions?: string[];
  },
];

export default createRule<Options, MessageIds>({
  name: 'no-path-traversal-in-handler',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow filesystem operations inside MCP tool handlers to prevent path traversal attacks (CWE-22)',
    },
    messages: {
      fsInHandler:
        'Filesystem function "{{name}}" inside an MCP tool handler. ' +
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
    const toolHandlerNodes = new Set<TSESTree.Node>();
    let insideToolHandler = 0;

    const options = context.options[0] ?? {};
    const dangerousFns = new Set([
      ...FS_FUNCTIONS,
      ...(options.additionalFunctions ?? []),
    ]);

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
