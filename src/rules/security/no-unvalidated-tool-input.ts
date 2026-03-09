import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolHandlerNode,
  hasSchemaArgument,
  getToolNameNode,
  getStaticStringValue,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

type MessageIds = 'unvalidatedInput';

export default createRule<[], MessageIds>({
  name: 'no-unvalidated-tool-input',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow accessing tool handler arguments without an input schema, preventing unvalidated input usage',
    },
    messages: {
      unvalidatedInput:
        'Tool "{{name}}" handler accesses parameters without an input schema. ' +
        'Without schema validation, tool inputs are untyped and unvalidated, enabling injection attacks. ' +
        'Add a Zod schema to the .tool() registration.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    return {
      CallExpression(node) {
        if (!isToolMethodCall(node)) return;
        if (hasSchemaArgument(node)) return;

        const handler = getToolHandlerNode(node);
        if (!handler) return;

        // Check if handler has parameters (meaning it accesses args)
        if (handler.params.length === 0) return;

        const firstParam = handler.params[0];
        // If the first param is an identifier (not destructured to nothing), handler uses input
        if (
          firstParam.type === AST_NODE_TYPES.Identifier ||
          firstParam.type === AST_NODE_TYPES.ObjectPattern
        ) {
          const nameNode = getToolNameNode(node);
          const name = nameNode ? getStaticStringValue(nameNode) : '<unknown>';

          context.report({
            node: firstParam,
            messageId: 'unvalidatedInput',
            data: { name },
          });
        }
      },
    };
  },
});
