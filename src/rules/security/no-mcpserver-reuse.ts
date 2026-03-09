import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattdanielbrown/eslint-plugin-mcp/blob/main/docs/rules/${name}.md`,
);

const HTTP_HANDLER_METHODS = new Set([
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'use',
  'all',
  'options',
  'head',
  'createServer',
]);

type MessageIds = 'mcpServerInLoop' | 'mcpServerInHandler';

export default createRule<[], MessageIds>({
  name: 'no-mcpserver-reuse',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow McpServer instantiation inside request handlers or loops to prevent lifecycle issues (CVE-2026-25536)',
    },
    messages: {
      mcpServerInLoop:
        'new McpServer() inside a loop creates a new server instance per iteration, ' +
        'risking resource exhaustion and state confusion (CVE-2026-25536). ' +
        'Instantiate McpServer once at module level.',
      mcpServerInHandler:
        'new McpServer() inside a request handler creates a new server instance per request ' +
        '(CVE-2026-25536). Instantiate McpServer once at module level and manage transports per-request instead.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    const httpHandlerNodes = new Set<TSESTree.Node>();
    let insideHttpHandler = 0;
    let insideLoop = 0;

    function getLastFunctionArg(
      node: TSESTree.CallExpression,
    ): TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null {
      const lastArg = node.arguments[node.arguments.length - 1];
      if (!lastArg) return null;

      if (
        lastArg.type === AST_NODE_TYPES.ArrowFunctionExpression ||
        lastArg.type === AST_NODE_TYPES.FunctionExpression
      ) {
        return lastArg;
      }
      return null;
    }

    function isHttpHandlerRegistration(
      node: TSESTree.CallExpression,
    ): boolean {
      if (node.callee.type !== AST_NODE_TYPES.MemberExpression) return false;
      if (node.callee.property.type !== AST_NODE_TYPES.Identifier) return false;

      const method = node.callee.property.name;

      // Express-style: app.get(), router.post(), http.createServer()
      if (HTTP_HANDLER_METHODS.has(method)) return true;

      // Event-style: server.on('request', handler)
      if (method === 'on' && node.arguments.length >= 2) {
        const firstArg = node.arguments[0];
        if (
          firstArg.type === AST_NODE_TYPES.Literal &&
          (firstArg.value === 'request' || firstArg.value === 'connection')
        ) {
          return true;
        }
      }

      return false;
    }

    const enterFn = (node: TSESTree.Node): void => {
      if (httpHandlerNodes.has(node)) {
        insideHttpHandler++;
      }
    };

    const exitFn = (node: TSESTree.Node): void => {
      if (httpHandlerNodes.has(node)) {
        insideHttpHandler--;
        httpHandlerNodes.delete(node);
      }
    };

    return {
      CallExpression(node) {
        if (isHttpHandlerRegistration(node)) {
          const handler = getLastFunctionArg(node);
          if (handler) {
            httpHandlerNodes.add(handler);
          }
        }
      },
      NewExpression(node) {
        if (node.callee.type !== AST_NODE_TYPES.Identifier) return;
        if (node.callee.name !== 'McpServer') return;

        if (insideLoop > 0) {
          context.report({ node, messageId: 'mcpServerInLoop' });
        } else if (insideHttpHandler > 0) {
          context.report({ node, messageId: 'mcpServerInHandler' });
        }
      },
      ArrowFunctionExpression: enterFn,
      'ArrowFunctionExpression:exit': exitFn,
      FunctionExpression: enterFn,
      'FunctionExpression:exit': exitFn,
      ForStatement() {
        insideLoop++;
      },
      'ForStatement:exit'() {
        insideLoop--;
      },
      WhileStatement() {
        insideLoop++;
      },
      'WhileStatement:exit'() {
        insideLoop--;
      },
      DoWhileStatement() {
        insideLoop++;
      },
      'DoWhileStatement:exit'() {
        insideLoop--;
      },
      ForInStatement() {
        insideLoop++;
      },
      'ForInStatement:exit'() {
        insideLoop--;
      },
      ForOfStatement() {
        insideLoop++;
      },
      'ForOfStatement:exit'() {
        insideLoop--;
      },
    };
  },
});
