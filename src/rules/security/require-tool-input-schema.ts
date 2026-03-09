import { ESLintUtils } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  hasSchemaArgument,
  getToolNameNode,
  getStaticStringValue,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

type MessageIds = 'missingSchema';

export default createRule<[], MessageIds>({
  name: 'require-tool-input-schema',
  meta: {
    type: 'suggestion',
    docs: {
      description:
        'Require an input validation schema for every MCP tool registration to prevent unvalidated input handling',
    },
    messages: {
      missingSchema:
        'Tool "{{name}}" is registered without an input schema. ' +
        'Add a Zod schema argument to validate tool inputs and prevent injection attacks.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    return {
      CallExpression(node) {
        if (!isToolMethodCall(node)) return;
        if (hasSchemaArgument(node)) return;

        const nameNode = getToolNameNode(node);
        const name = nameNode ? getStaticStringValue(nameNode) : '<unknown>';

        context.report({
          node,
          messageId: 'missingSchema',
          data: { name },
        });
      },
    };
  },
});
