import { ESLintUtils, TSESTree } from '@typescript-eslint/utils';
import {
  isToolMethodCall,
  getToolNameNode,
  getStaticStringValue,
} from '../../utils/mcp-ast-helpers.js';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

type MessageIds = 'duplicateToolName';

export default createRule<[], MessageIds>({
  name: 'no-duplicate-tool-names',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow registering multiple MCP tools with the same name, which causes silent overwrites and unpredictable behavior',
    },
    messages: {
      duplicateToolName:
        'Duplicate tool name "{{name}}". A tool with this name was already registered. ' +
        'Duplicate registrations silently overwrite the previous handler.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    const seenNames = new Map<string, TSESTree.Node>();

    return {
      CallExpression(node) {
        if (!isToolMethodCall(node)) return;

        const nameNode = getToolNameNode(node);
        if (!nameNode) return;

        const name = getStaticStringValue(nameNode);

        if (seenNames.has(name)) {
          context.report({
            node: nameNode,
            messageId: 'duplicateToolName',
            data: { name },
          });
        } else {
          seenNames.set(name, nameNode);
        }
      },
    };
  },
});
